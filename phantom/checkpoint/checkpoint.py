"""CheckpointManager — atomic file-based checkpoint writes with crash safety."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import CheckpointData

if TYPE_CHECKING:
    from phantom.agents.state import AgentState
    from phantom.telemetry.tracer import Tracer

logger = logging.getLogger(__name__)

CHECKPOINT_FILE = "checkpoint.json"
CHECKPOINT_INTERVAL = 5   # persist every N agent iterations


class CheckpointManager:
    """
    Saves/loads scan state so scans can be resumed after a crash or Ctrl+C.

    Write strategy: write to a .tmp file first, then atomically rename to .json.
    On POSIX this rename is atomic; on Windows it's best-effort (os.replace).
    If the process is killed mid-write the .tmp is left behind and the old
    checkpoint survives intact.
    """

    def __init__(self, run_dir: Path, interval: int = CHECKPOINT_INTERVAL) -> None:
        self.run_dir = run_dir
        self.checkpoint_file = run_dir / CHECKPOINT_FILE
        self._lock = threading.Lock()
        self._interval = interval
        logger.info("Checkpoint interval: %d iterations (run_dir=%s)", self._interval, self.run_dir)

    # ── Public API ────────────────────────────────────────────────────────────

    def should_save(self, iteration: int) -> bool:
        """True when it's time to write a checkpoint (iteration must be > 0)."""
        return iteration > 0 and (iteration == 1 or iteration % self._interval == 0)

    def save(self, data: CheckpointData) -> None:
        """Atomically persist checkpoint data to disk."""
        with self._lock:
            try:
                self.run_dir.mkdir(parents=True, exist_ok=True)
                tmp = self.checkpoint_file.with_suffix(".tmp")
                tmp.write_text(data.model_dump_json(indent=2), encoding="utf-8")
                tmp.replace(self.checkpoint_file)   # atomic on POSIX, best-effort on Windows
                logger.debug(
                    "Checkpoint saved at iteration %d (%d vulns)",
                    data.iteration,
                    len(data.vulnerability_reports),
                )
            except OSError:
                logger.warning("Failed to save checkpoint", exc_info=True)

    def load(self) -> CheckpointData | None:
        """Load a checkpoint from disk. Returns None if absent or corrupt."""
        if not self.checkpoint_file.exists():
            return None
        try:
            raw = self.checkpoint_file.read_text(encoding="utf-8")
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

        return CheckpointData(
            run_name=run_name,
            status=status,
            interruption_reason=interruption_reason,
            iteration=state.iteration,
            task_description=state.task,
            scan_config=scan_config,
            root_agent_state=state.model_dump(),
            vulnerability_reports=vulns,
            final_result=state.final_result,
            llm_stats_at_checkpoint=llm_stats,
            per_model_stats=per_model,
            compression_calls=compression_calls,
            agent_calls=agent_calls,
            error_calls=error_calls,
        )
