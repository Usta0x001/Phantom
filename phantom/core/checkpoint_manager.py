"""
Signed Checkpoint Manager

Atomic write + Ed25519 signature on every checkpoint.
Verification-before-load: no field is read until signature is verified.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from phantom.core.audit_signer import AuditSigner
from phantom.core.exceptions import CheckpointTamperError

_logger = logging.getLogger(__name__)


class CheckpointManager:
    """Signed, atomic checkpoint save/load."""

    def __init__(self, signer: AuditSigner | None = None) -> None:
        self._signer = signer or AuditSigner()

    def save_checkpoint(self, state_dict: dict, checkpoint_path: Path) -> None:
        """Atomic signed checkpoint write."""
        signed = self._signer.sign_entry({"checkpoint": state_dict})
        data = json.dumps(signed, ensure_ascii=True, default=str).encode()

        # Atomic write: temp file in same directory → os.replace
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(checkpoint_path.parent),
            prefix=".ckpt_",
            suffix=".tmp",
        )
        try:
            os.write(fd, data)
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp_path, str(checkpoint_path))
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def load_checkpoint(self, checkpoint_path: Path) -> dict:
        """Load and verify checkpoint BEFORE deserializing state.

        Raises CheckpointTamperError if signature is invalid.
        """
        raw = checkpoint_path.read_bytes()
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as e:
            raise CheckpointTamperError(f"Checkpoint is not valid JSON: {e}") from e

        # Verify signature FIRST — before reading any state data
        sig = entry.get("_sig")
        if not sig:
            raise CheckpointTamperError(
                "Checkpoint has no signature — refusing to load",
            )

        try:
            self._signer.verify_entry(
                dict(entry),
                expected_seq=entry.get("_seq", -1),
                expected_prev_hash=entry.get("_prev_hash", ""),
            )
        except Exception as e:
            raise CheckpointTamperError(
                f"Checkpoint signature invalid: {e}",
            ) from e

        # Signature verified — safe to read state
        return entry.get("checkpoint", {})
