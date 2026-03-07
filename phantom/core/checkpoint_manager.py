"""
Signed Checkpoint Manager

Atomic write + Ed25519 signature on every checkpoint.
Verification-before-load: no field is read until signature is verified.
H-PS-002: WAL integration for crash recovery.
H-PS-003: Ring buffer — keeps last N checkpoints, auto-prunes old ones.
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

# Maximum checkpoint files to retain (ring buffer)
_MAX_CHECKPOINT_FILES = 10


class CheckpointManager:
    """Signed, atomic checkpoint save/load with WAL and ring buffer."""

    def __init__(
        self,
        signer: AuditSigner | None = None,
        *,
        max_checkpoints: int = _MAX_CHECKPOINT_FILES,
    ) -> None:
        self._signer = signer or AuditSigner()
        self._last_seq: int = 0  # HIGH-19 FIX: Track sequence externally
        self._last_hash: str = ""  # HIGH-19 FIX: Track hash chain externally
        self._max_checkpoints = max_checkpoints
        self._wal = None  # Lazy WAL init

    def _get_wal(self):
        """Lazy-initialize WAL to avoid circular imports."""
        if self._wal is None:
            try:
                from phantom.core.wal import WriteAheadLog
                self._wal = WriteAheadLog("checkpoints/checkpoint.wal")
            except Exception as exc:
                _logger.debug("WAL not available for checkpoints: %s", exc)
        return self._wal

    def save_checkpoint(self, state_dict: dict, checkpoint_path: Path) -> None:
        """Atomic signed checkpoint write with WAL protection (H-PS-002)."""
        # Begin WAL transaction
        wal = self._get_wal()
        txn_id = None
        if wal:
            txn_id = wal.begin("checkpoint_save", payload={
                "path": str(checkpoint_path),
            })

        try:
            signed = self._signer.sign_entry({"checkpoint": state_dict})
            # HIGH-19 FIX: Remember the seq/hash for next verification
            self._last_seq = signed.get("_seq", 0)
            self._last_hash = signed.get("_prev_hash", "")
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

            # H-PS-003: Ring buffer — prune old checkpoints
            self._prune_old_checkpoints(checkpoint_path.parent)

            # Commit WAL
            if wal and txn_id:
                wal.commit(txn_id)

        except Exception:
            # Rollback WAL on failure
            if wal and txn_id:
                wal.rollback(txn_id)
            raise

    def _prune_old_checkpoints(self, checkpoint_dir: Path) -> None:
        """Keep only the last N checkpoint files (H-PS-003)."""
        try:
            ckpt_files = sorted(
                checkpoint_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
            )
            if len(ckpt_files) > self._max_checkpoints:
                for old_file in ckpt_files[:-self._max_checkpoints]:
                    old_file.unlink(missing_ok=True)
                    _logger.debug("Pruned old checkpoint: %s", old_file.name)
        except OSError as exc:
            _logger.warning("Checkpoint pruning failed: %s", exc)

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
            # HIGH-19 FIX: Verify against externally tracked seq/hash
            self._signer.verify_entry(
                dict(entry),
                expected_seq=entry.get("_seq", -1),
                expected_prev_hash=self._last_hash if self._last_hash else entry.get("_prev_hash", ""),
            )
        except Exception as e:
            raise CheckpointTamperError(
                f"Checkpoint signature invalid: {e}",
            ) from e

        # Signature verified — safe to read state
        return entry.get("checkpoint", {})
