"""
Crash-Safe Audit Logger

Append-only, crash-safe audit logging for all Phantom operations.
Writes JSONL (JSON Lines) format for easy parsing and streaming.
Uses fsync to ensure data is written to disk even on unexpected termination.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Append-only crash-safe audit logger.

    Features:
    - JSONL format (one JSON object per line)
    - fsync after every write (crash-safe)
    - Thread-safe via lock
    - Automatic log rotation by size
    - Structured events with severity, category, metadata

    Usage:
        logger = AuditLogger(Path("phantom_runs/run_1234/audit.jsonl"))
        logger.log_event("scan_started", {"target": "example.com"})
        logger.log_tool_call("nmap_scan", {"target": "example.com"})
        logger.log_finding("SQL Injection", severity="critical")
    """

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB rotation threshold

    def __init__(self, log_path: Path, max_size: int = MAX_FILE_SIZE) -> None:
        self.log_path = log_path
        self.max_size = max_size
        self._lock = threading.Lock()
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure the log directory exists."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > self.max_size:
                timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
                rotated = self.log_path.with_suffix(f".{timestamp}.jsonl")
                self.log_path.rename(rotated)
        except OSError:
            pass  # Best effort rotation

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write a single audit entry with fsync for crash safety."""
        with self._lock:
            self._rotate_if_needed()
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    line = json.dumps(entry, default=str, ensure_ascii=False)
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as exc:
                _logger.warning("Audit log write failed: %s", exc)

    def log_event(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
        *,
        severity: str = "info",
        category: str = "general",
        agent_id: str | None = None,
    ) -> None:
        """
        Log a general audit event.

        Args:
            event_type: Type of event (e.g., "scan_started", "config_changed")
            data: Additional event data
            severity: Event severity (info, warning, error, critical)
            category: Event category (general, security, tool, agent, finding)
            agent_id: ID of the agent that generated this event
        """
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "category": category,
            "data": data or {},
        }
        if agent_id:
            entry["agent_id"] = agent_id
        self._write_entry(entry)

    def log_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        result_summary: str | None = None,
        success: bool = True,
        duration_ms: float | None = None,
    ) -> None:
        """Log a tool invocation."""
        self.log_event(
            "tool_call",
            {
                "tool_name": tool_name,
                "args": _sanitize_args(args or {}),
                "success": success,
                "result_summary": result_summary,
                "duration_ms": duration_ms,
            },
            category="tool",
            agent_id=agent_id,
        )

    def log_finding(
        self,
        title: str,
        *,
        severity: str = "medium",
        cwe: str | None = None,
        url: str | None = None,
        verified: bool = False,
        agent_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log a vulnerability finding."""
        self.log_event(
            "vulnerability_found",
            {
                "title": title,
                "finding_severity": severity,
                "cwe": cwe,
                "url": url,
                "verified": verified,
                **(details or {}),
            },
            severity="warning" if severity in ("low", "info") else "error",
            category="finding",
            agent_id=agent_id,
        )

    def log_scan_start(
        self,
        scan_id: str,
        targets: list[str],
        scan_mode: str = "deep",
        model: str | None = None,
    ) -> None:
        """Log scan initiation."""
        self.log_event(
            "scan_started",
            {
                "scan_id": scan_id,
                "targets": targets,
                "scan_mode": scan_mode,
                "model": model,
            },
            category="security",
        )

    def log_scan_end(
        self,
        scan_id: str,
        *,
        success: bool = True,
        findings_count: int = 0,
        duration_seconds: float | None = None,
        error: str | None = None,
    ) -> None:
        """Log scan completion."""
        self.log_event(
            "scan_completed",
            {
                "scan_id": scan_id,
                "success": success,
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "error": error,
            },
            severity="info" if success else "error",
            category="security",
        )

    def log_scope_violation(
        self, target: str, reason: str, agent_id: str | None = None
    ) -> None:
        """Log an out-of-scope access attempt."""
        self.log_event(
            "scope_violation",
            {"target": target, "reason": reason},
            severity="warning",
            category="security",
            agent_id=agent_id,
        )

    def log_agent_event(
        self,
        event_type: str,
        agent_id: str,
        agent_name: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Log agent lifecycle events (created, finished, error, stopped)."""
        self.log_event(
            f"agent_{event_type}",
            {"agent_name": agent_name, **(data or {})},
            category="agent",
            agent_id=agent_id,
        )

    def read_events(
        self,
        *,
        category: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Read audit events with optional filtering.

        Args:
            category: Filter by category
            severity: Filter by severity
            event_type: Filter by event type
            limit: Maximum number of events to return

        Returns:
            List of matching audit entries (most recent first)
        """
        # Use deque to keep only the last `limit` matching entries (memory-efficient)
        buf: deque[dict[str, Any]] = deque(maxlen=limit)

        if not self.log_path.exists():
            return []

        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if category and entry.get("category") != category:
                        continue
                    if severity and entry.get("severity") != severity:
                        continue
                    if event_type and entry.get("event_type") != event_type:
                        continue

                    buf.append(entry)
        except OSError:
            pass

        # Return most recent first
        return list(reversed(buf))

    def get_stats(self) -> dict[str, Any]:
        """Get audit log statistics."""
        events = self.read_events(limit=100_000)

        categories: dict[str, int] = {}
        severities: dict[str, int] = {}
        event_types: dict[str, int] = {}

        for event in events:
            cat = event.get("category", "unknown")
            sev = event.get("severity", "unknown")
            et = event.get("event_type", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
            severities[sev] = severities.get(sev, 0) + 1
            event_types[et] = event_types.get(et, 0) + 1

        return {
            "total_events": len(events),
            "by_category": categories,
            "by_severity": severities,
            "by_event_type": event_types,
            "log_file": str(self.log_path),
            "log_size_bytes": (
                self.log_path.stat().st_size if self.log_path.exists() else 0
            ),
        }


_global_audit_logger: AuditLogger | None = None


def get_global_audit_logger() -> AuditLogger | None:
    """Get the global audit logger instance."""
    return _global_audit_logger


def set_global_audit_logger(logger: AuditLogger) -> None:
    """Set the global audit logger instance."""
    global _global_audit_logger  # noqa: PLW0603
    _global_audit_logger = logger


def _sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive data from tool arguments before logging.

    Recursively sanitizes nested dicts and lists.
    """
    sensitive_keys = {"password", "token", "api_key", "secret", "credential", "auth",
                      "authorization", "cookie", "session"}

    def _sanitize_value(key: str, value: Any) -> Any:
        if any(s in key.lower() for s in sensitive_keys):
            return "***REDACTED***"
        if isinstance(value, dict):
            return {k: _sanitize_value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize_value(key, item) for item in value]
        if isinstance(value, str) and len(value) > 500:
            return value[:500] + "...[truncated]"
        return value

    return {k: _sanitize_value(k, v) for k, v in args.items()}
