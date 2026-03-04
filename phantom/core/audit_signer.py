"""
Ed25519 Audit Chain Signer

Replaces HMAC-SHA256 (truncated to 64-bit) with Ed25519 digital signatures.
Key stored in user home directory (~/.phantom/keys/), NOT next to the log.

Usage:
    signer = AuditSigner()
    signed_entry = signer.sign_entry({"event": "tool_call", ...})
    signer.verify_entry(signed_entry, expected_seq=0, expected_prev_hash="")
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_logger = logging.getLogger(__name__)


class AuditSigner:
    """Ed25519 hash-chain signer for audit log entries."""

    KEY_DIR = Path.home() / ".phantom" / "keys"

    def __init__(self, key_dir: Path | None = None) -> None:
        self._key_dir = key_dir or self.KEY_DIR
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._private_key_path = self._key_dir / "audit_ed25519.key"
        self._public_key_path = self._key_dir / "audit_ed25519.pub"

        if self._private_key_path.exists():
            raw = self._private_key_path.read_bytes()
            self._private_key: Ed25519PrivateKey = serialization.load_pem_private_key(  # type: ignore[assignment]
                raw, password=None,
            )
        else:
            self._private_key = Ed25519PrivateKey.generate()
            # Save private key (owner-only permissions)
            pem = self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            self._private_key_path.write_bytes(pem)
            try:
                self._private_key_path.chmod(0o600)
            except OSError:
                pass  # Windows may not support chmod
            # Save public key
            pub_pem = self._private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._public_key_path.write_bytes(pub_pem)
            _logger.info(
                "Generated new Ed25519 audit signing key at %s", self._key_dir,
            )

        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._seq = 0
        self._prev_hash = ""

    def sign_entry(self, entry: dict) -> dict:
        """Sign entry; adds _seq, _prev_hash, _sig fields."""
        entry["_seq"] = self._seq
        entry["_prev_hash"] = self._prev_hash
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=True).encode()
        sig = self._private_key.sign(payload)
        entry["_sig"] = base64.b64encode(sig).decode()
        self._prev_hash = hashlib.sha256(payload).hexdigest()
        self._seq += 1
        return entry

    def verify_entry(
        self, entry: dict, expected_seq: int, expected_prev_hash: str,
    ) -> bool:
        """Verify entry signature and chain linkage."""
        from phantom.core.exceptions import AuditTamperError

        sig_b64 = entry.pop("_sig", None)
        if not sig_b64:
            raise AuditTamperError("Entry missing _sig field")
        sig = base64.b64decode(sig_b64)

        if entry.get("_seq") != expected_seq:
            entry["_sig"] = sig_b64
            raise AuditTamperError(
                f"Sequence mismatch: expected {expected_seq}, got {entry.get('_seq')}",
            )
        if entry.get("_prev_hash") != expected_prev_hash:
            entry["_sig"] = sig_b64
            raise AuditTamperError("Hash chain break detected")

        payload = json.dumps(entry, sort_keys=True, ensure_ascii=True).encode()
        try:
            self._public_key.verify(sig, payload)
        except Exception as e:
            entry["_sig"] = sig_b64
            raise AuditTamperError(f"Signature verification failed: {e}") from e

        entry["_sig"] = sig_b64
        return True

    def verify_chain(self, entries: list[dict]) -> bool:
        """Verify entire chain from entry 0."""
        prev_hash = ""
        for i, entry in enumerate(entries):
            entry_copy = dict(entry)
            self.verify_entry(entry_copy, expected_seq=i, expected_prev_hash=prev_hash)
            # Compute hash for chaining (same as sign_entry)
            entry_no_sig = {k: v for k, v in entry.items() if k != "_sig"}
            payload = json.dumps(
                entry_no_sig, sort_keys=True, ensure_ascii=True,
            ).encode()
            prev_hash = hashlib.sha256(payload).hexdigest()
        return True
