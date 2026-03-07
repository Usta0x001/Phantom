"""
Write-Ahead Log (WAL) — Hardening H-PS-001

Provides crash-consistent persistence for critical state.

Design:
  - Append-only log file with JSONL entries
  - Each write is: WAL.begin() → modify state → WAL.commit()
  - If process crashes between begin/commit, WAL.recover() replays
  - Ring buffer: keeps last N entries, truncates old ones
  - Uses fsync for durability on every commit

Usage:
    wal = WriteAheadLog(path="scan_wal.jsonl")
    txn = wal.begin("checkpoint", payload={"state": "RECON"})
    # ... do work ...
    wal.commit(txn)

    # On startup:
    pending = wal.recover()
    for entry in pending:
        replay(entry)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

# Maximum WAL entries before truncation (ring buffer)
_MAX_WAL_ENTRIES = 2000


@dataclass
class WALEntry:
    """A single WAL transaction entry."""
    txn_id: str
    operation: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending | committed | rolled_back
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "operation": self.operation,
            "payload": self.payload,
            "status": self.status,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WALEntry:
        return cls(
            txn_id=data["txn_id"],
            operation=data["operation"],
            payload=data.get("payload", {}),
            status=data.get("status", "pending"),
            timestamp=data.get("timestamp", 0.0),
        )


class WriteAheadLog:
    """Append-only WAL with ring buffer and crash recovery."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_entries: int = _MAX_WAL_ENTRIES,
    ) -> None:
        self._path = Path(path)
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._active_txns: dict[str, WALEntry] = {}
        self._entry_count = 0
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Count existing entries
        if self._path.exists():
            try:
                with self._path.open("r", encoding="utf-8") as f:
                    self._entry_count = sum(1 for _ in f)
            except Exception:
                self._entry_count = 0

    def begin(self, operation: str, *, payload: dict[str, Any] | None = None) -> str:
        """Begin a WAL transaction. Returns txn_id."""
        txn_id = uuid.uuid4().hex[:16]
        entry = WALEntry(
            txn_id=txn_id,
            operation=operation,
            payload=payload or {},
            status="pending",
        )

        with self._lock:
            self._append(entry)
            self._active_txns[txn_id] = entry
            _logger.debug("WAL begin: txn=%s op=%s", txn_id, operation)

        return txn_id

    def commit(self, txn_id: str) -> bool:
        """Commit a WAL transaction. Returns True on success."""
        with self._lock:
            entry = self._active_txns.pop(txn_id, None)
            if entry is None:
                _logger.warning("WAL commit: unknown txn=%s", txn_id)
                return False

            entry.status = "committed"
            self._append(entry)
            _logger.debug("WAL commit: txn=%s", txn_id)
            return True

    def rollback(self, txn_id: str) -> bool:
        """Rollback a WAL transaction. Returns True on success."""
        with self._lock:
            entry = self._active_txns.pop(txn_id, None)
            if entry is None:
                _logger.warning("WAL rollback: unknown txn=%s", txn_id)
                return False

            entry.status = "rolled_back"
            self._append(entry)
            _logger.debug("WAL rollback: txn=%s", txn_id)
            return True

    def recover(self) -> list[WALEntry]:
        """Recover pending (uncommitted) transactions after crash.

        Reads the WAL file and returns entries that were started
        but never committed or rolled back.
        """
        if not self._path.exists():
            return []

        entries: dict[str, WALEntry] = {}

        with self._lock:
            try:
                with self._path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            entry = WALEntry.from_dict(data)
                            txn_id = entry.txn_id

                            if entry.status == "pending":
                                entries[txn_id] = entry
                            elif entry.status in ("committed", "rolled_back"):
                                entries.pop(txn_id, None)
                        except (json.JSONDecodeError, KeyError) as exc:
                            _logger.warning("WAL: corrupt entry skipped: %s", exc)
                            continue
            except Exception as exc:
                _logger.error("WAL recovery failed: %s", exc)
                return []

        pending = list(entries.values())
        if pending:
            _logger.warning(
                "WAL recovery: %d pending transactions found", len(pending)
            )
        return pending

    def _append(self, entry: WALEntry) -> None:
        """Append an entry to the WAL file with fsync."""
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._entry_count += 1

            # Ring buffer: truncate if over max
            if self._entry_count > self._max_entries:
                self._truncate()
        except OSError as exc:
            _logger.error("WAL write failed: %s", exc)

    def _truncate(self) -> None:
        """Keep only the last max_entries/2 entries (ring buffer)."""
        keep = self._max_entries // 2
        try:
            lines: list[str] = []
            with self._path.open("r", encoding="utf-8") as f:
                lines = f.readlines()

            if len(lines) <= keep:
                return

            # Atomic rewrite: write to temp then rename
            tmp = self._path.with_suffix(".wal.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                for line in lines[-keep:]:
                    f.write(line)
                f.flush()
                os.fsync(f.fileno())
            tmp.replace(self._path)
            self._entry_count = keep
            _logger.info("WAL truncated: kept last %d entries", keep)
        except OSError as exc:
            _logger.error("WAL truncation failed: %s", exc)

    @property
    def pending_count(self) -> int:
        """Number of active (uncommitted) transactions in memory."""
        return len(self._active_txns)

    @property
    def entry_count(self) -> int:
        return self._entry_count
