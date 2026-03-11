"""CheckpointManager — atomic file-based checkpoint writes with crash safety."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import CheckpointData

if TYPE_CHECKING:
    from phantom.agents.state import AgentState
    from phantom.telemetry.tracer import Tracer

logger = logging.getLogger(__name__)

CHECKPOINT_FILE = "checkpoint.json"
CHECKPOINT_HMAC_FILE = "checkpoint.json.hmac"
CHECKPOINT_INTERVAL = 5   # persist every N agent iterations


def _sanitize_run_dir(run_dir: Path) -> Path:
    """Strip ``..`` path-traversal components from a CheckpointManager run_dir.

    Only strips ``..`` segments so that absolute paths supplied by internal code
    (e.g. pytest ``tmp_path``) are preserved as-is.  User-supplied run names from
    the CLI **must** be sanitised with :func:`sanitize_run_name` *before* the
    ``Path("phantom_runs") / name`` join so that the resulting path is always
    relative and cannot escape ``phantom_runs/``.

    Examples::

        Path("phantom_runs") / "../../evil"   ->  Path("phantom_runs/evil")
        Path("phantom_runs") / "myScan-01"    ->  unchanged
        Path("/tmp/pytest-123/test_foo")      ->  unchanged  (absolute OK from code)
    """
    parts = run_dir.parts
    safe_parts = [p for p in parts if p != ".."]
    if not safe_parts:
        return Path("phantom_runs") / "unnamed"
    result = Path(safe_parts[0])
    for part in safe_parts[1:]:
        result = result / part
    return result


def sanitize_run_name(name: str) -> str:
    """Sanitize a **user-supplied** run name before building a ``Path``.

    Call this at the CLI/TUI boundary (``tui.py``) before
    ``Path("phantom_runs") / name`` to prevent H-11 absolute-root bypass::

        # Attack: Path("phantom_runs") / "/etc/passwd"  →  Path("/etc/passwd")
        # Fix:    Path("phantom_runs") / sanitize_run_name("/etc/passwd")
        #         → Path("phantom_runs/etc/passwd")

    Strips:
    * Windows drive letter prefix (``C:``, ``D:``, …)
    * Leading forward and back slashes (POSIX / Windows root)
    * Windows UNC prefixes (``\\\\server``, ``//server``)
    * ``..`` components (path traversal)
    * Empty components

    Returns ``"unnamed"`` when the name reduces to nothing.
    """
    import re

    # Strip Windows drive letter (C:, D:, …)
    name = re.sub(r"^[A-Za-z]:", "", name)
    # Strip leading slashes / backslashes (POSIX root, Windows root, UNC)
    name = name.lstrip("/\\")
    # Split on both separators, drop empty parts and '..' segments
    parts = [p for p in re.split(r"[/\\]", name) if p and p != ".."]
    return "/".join(parts) if parts else "unnamed"


def _get_hmac_key() -> bytes:
    """Derive an HMAC key from a machine-local secret or a stable fallback."""
    key = os.getenv("PHANTOM_CHECKPOINT_KEY", "")
    if key:
        return key.encode("utf-8")
    # Fallback: use a host-local stable identifier
    return hashlib.sha256(
        f"phantom-checkpoint-{os.getuid() if hasattr(os, 'getuid') else 'win'}".encode()
    ).digest()


class CheckpointManager:
    """
    Saves/loads scan state so scans can be resumed after a crash or Ctrl+C.

    Write strategy: write to a .tmp file first, then atomically rename to .json.
    On POSIX this rename is atomic; on Windows it's best-effort (os.replace).
    If the process is killed mid-write the .tmp is left behind and the old
    checkpoint survives intact.

    Integrity: an HMAC-SHA256 signature file is written alongside the checkpoint.
    On load, the signature is verified to detect tampering.
    """

    def __init__(self, run_dir: Path, interval: int = CHECKPOINT_INTERVAL) -> None:
        run_dir = _sanitize_run_dir(run_dir)  # H-11: strip path traversal
        self.run_dir = run_dir
        self.checkpoint_file = run_dir / CHECKPOINT_FILE
        self._hmac_file = run_dir / CHECKPOINT_HMAC_FILE
        self._lock = threading.Lock()
        self._interval = interval
        logger.info("Checkpoint interval: %d iterations (run_dir=%s)", self._interval, self.run_dir)

    # ── Public API ────────────────────────────────────────────────────────────

    def should_save(self, iteration: int) -> bool:
        """True when it's time to write a checkpoint (iteration must be > 0)."""
        return iteration > 0 and (iteration == 1 or iteration % self._interval == 0)

    def _compute_hmac(self, data: bytes) -> str:
        return hmac.new(_get_hmac_key(), data, hashlib.sha256).hexdigest()

    def save(self, data: CheckpointData) -> None:
        """Atomically persist checkpoint data to disk with HMAC integrity."""
        with self._lock:
            try:
                self.run_dir.mkdir(parents=True, exist_ok=True)
                json_bytes = data.model_dump_json(indent=2).encode("utf-8")
                # Write data
                tmp = self.checkpoint_file.with_suffix(".tmp")
                tmp.write_bytes(json_bytes)
                tmp.replace(self.checkpoint_file)   # atomic on POSIX, best-effort on Windows
                # Write HMAC signature
                sig = self._compute_hmac(json_bytes)
                hmac_tmp = self._hmac_file.with_suffix(".tmp")
                hmac_tmp.write_text(sig, encoding="utf-8")
                hmac_tmp.replace(self._hmac_file)
                logger.debug(
                    "Checkpoint saved at iteration %d (%d vulns)",
                    data.iteration,
                    len(data.vulnerability_reports),
                )
            except OSError:
                logger.warning("Failed to save checkpoint", exc_info=True)

    def load(self) -> CheckpointData | None:
        """Load a checkpoint from disk. Returns None if absent, corrupt, or tampered."""
        if not self.checkpoint_file.exists():
            return None
        try:
            raw_bytes = self.checkpoint_file.read_bytes()
            # Verify HMAC integrity if signature file exists
            if self._hmac_file.exists():
                stored_sig = self._hmac_file.read_text(encoding="utf-8").strip()
                computed_sig = self._compute_hmac(raw_bytes)
                if not hmac.compare_digest(stored_sig, computed_sig):
                    logger.warning(
                        "Checkpoint HMAC mismatch — file may have been tampered with. Ignoring."
                    )
                    return None
            raw = raw_bytes.decode("utf-8")
            return CheckpointData.model_validate_json(raw)
        except Exception:
            logger.warning("Checkpoint file unreadable/corrupt — ignoring", exc_info=True)
            return None

    def exists(self) -> bool:
        return self.checkpoint_file.exists()

    def mark_completed(self) -> None:
        cp = self.load()
        if cp:
            cp.status = "completed"
            self.save(cp)

    # ── Helpers to build CheckpointData from live objects ────────────────────

    @staticmethod
    def build(
        run_name: str,
        state: "AgentState",
        tracer: "Tracer | None",
        scan_config: dict[str, Any],
        status: str = "in_progress",
        interruption_reason: str | None = None,
    ) -> CheckpointData:
        vulns: list[dict[str, Any]] = []
        llm_stats: dict[str, Any] = {}
        per_model: dict[str, dict[str, Any]] = {}
        compression_calls = 0
        agent_calls = 0
        error_calls = 0

        if tracer:
            vulns = list(tracer.vulnerability_reports)
            llm_stats = tracer.get_total_llm_stats()
            per_model = tracer.get_per_model_stats()
            compression_calls = tracer.compression_calls
            agent_calls = tracer.agent_calls
            error_calls = tracer.error_calls

        # Redact sensitive runtime fields before persisting to disk.
        # sandbox_token and sandbox_id are ephemeral — they are invalidated
        # when the container is stopped, so restoring them from a checkpoint
        # would fail anyway.  Storing them exposes secrets at rest.
        raw_state = state.model_dump()
        raw_state["sandbox_token"] = None
        raw_state["sandbox_id"] = None
        raw_state["sandbox_info"] = None

        return CheckpointData(
            run_name=run_name,
            status=status,
            interruption_reason=interruption_reason,
            iteration=state.iteration,
            task_description=state.task,
            scan_config=scan_config,
            root_agent_state=raw_state,
            vulnerability_reports=vulns,
            final_result=state.final_result,
            llm_stats_at_checkpoint=llm_stats,
            per_model_stats=per_model,
            compression_calls=compression_calls,
            agent_calls=agent_calls,
            error_calls=error_calls,
        )
