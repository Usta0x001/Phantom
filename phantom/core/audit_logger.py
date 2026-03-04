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
    - PHT-017 FIX: HMAC chain for tamper detection

    Usage:
        logger = AuditLogger(Path("phantom_runs/run_1234/audit.jsonl"))
        logger.log_event("scan_started", {"target": "example.com"})
        logger.log_tool_call("nmap_scan", {"target": "example.com"})
        logger.log_finding("SQL Injection", severity="critical")
    """

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB rotation threshold

    def __init__(self, log_path: Path, max_size: int = MAX_FILE_SIZE, hmac_key: str | None = None) -> None:
        self.log_path = log_path
        self.max_size = max_size
        self._lock = threading.Lock()
        self._ensure_directory()

        # v0.9.39: Ed25519 audit chain signer (replaces HMAC when enabled)
        self._signer = None
        try:
            from phantom.core.feature_flags import is_enabled
            if is_enabled("PHANTOM_FF_ED25519_AUDIT"):
                from phantom.core.audit_signer import AuditSigner
                self._signer = AuditSigner()
                _logger.info("Ed25519 audit signing enabled")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Ed25519 audit signer unavailable: %s — falling back to HMAC", exc)

        # PHT-017 FIX: HMAC chain for tamper detection (legacy / fallback)
        # SEC-004 FIX: No more hardcoded default key — generate unique per-run key
        import hashlib
        import secrets
        if hmac_key:
            self._hmac_key = hmac_key.encode()
        else:
            # Generate and persist a unique key per audit log
            key_path = self.log_path.with_suffix(".hmac_key")
            if key_path.exists():
                try:
                    self._hmac_key = key_path.read_text(encoding="utf-8").strip().encode()
                except Exception:
                    _logger.warning("SEC-004: Could not read HMAC key from %s — generating new key", key_path)
                    self._hmac_key = secrets.token_hex(32).encode()
            else:
                generated_key = secrets.token_hex(32)
                self._hmac_key = generated_key.encode()
                try:
                    key_path.write_text(generated_key, encoding="utf-8")
                    key_path.chmod(0o600)
                except OSError:
                    _logger.warning("SEC-004: Could not persist HMAC key to %s", key_path)
            _logger.info("SEC-004: Using unique per-run HMAC key (not default)")
        self._prev_hash = hashlib.sha256(b"genesis").hexdigest()[:16]
        # H6 FIX: On resume, verify existing chain and pick up from last hash
        if self.log_path.exists():
            self._verify_and_resume_chain()

    def _verify_and_resume_chain(self) -> None:
        """H6 FIX: Verify HMAC chain integrity on resume and set _prev_hash to continue."""
        import hashlib
        import hmac as _hmac

        prev = hashlib.sha256(b"genesis").hexdigest()[:16]
        last_valid_hash = prev
        tampered = False
        line_count = 0

        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    line_count += 1
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        tampered = True
                        break

                    stored_prev = entry.get("_prev_hash", "")
                    stored_hmac = entry.get("_hmac", "")

                    if stored_prev != prev:
                        tampered = True
                        break

                    # Recompute HMAC: remove _hmac from entry, compute
                    verify_entry = {k: v for k, v in entry.items() if k != "_hmac"}
                    verify_line = json.dumps(verify_entry, default=str, ensure_ascii=False)
                    expected = _hmac.new(
                        self._hmac_key, (prev + verify_line).encode(), hashlib.sha256
                    ).hexdigest()[:16]

                    if expected != stored_hmac:
                        tampered = True
                        break

                    last_valid_hash = stored_hmac
                    prev = stored_hmac

        except OSError as exc:
            _logger.warning("H6: Could not verify audit chain: %s", exc)
            return

        if tampered:
            _logger.error(
                "AUDIT CHAIN TAMPERED: integrity check failed at line %d. "
                "Previous entries may have been modified.",
                line_count,
            )
            # Log the tamper detection event itself
            self._prev_hash = last_valid_hash
            self._write_entry({
                "timestamp": datetime.now(UTC).isoformat(),
                "event_type": "audit_chain_tamper_detected",
                "severity": "critical",
                "category": "security",
                "data": {"failed_at_line": line_count},
            })
        else:
            self._prev_hash = last_valid_hash
            if line_count > 0:
                _logger.info("H6: Audit chain verified OK (%d entries)", line_count)

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
            _logger.debug("Audit log rotation failed", exc_info=True)

    def _compute_hmac(self, data: str) -> str:
        """Compute HMAC-SHA256 for tamper detection chain."""
        import hashlib
        import hmac as _hmac
        return _hmac.new(self._hmac_key, data.encode(), hashlib.sha256).hexdigest()[:16]

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write a single audit entry with fsync for crash safety and HMAC chain."""
        with self._lock:
            self._rotate_if_needed()
            try:
                # v0.9.39: Ed25519 signing (preferred) or HMAC chain (fallback)
                if self._signer:
                    entry = self._signer.sign_entry(entry)
                    line = json.dumps(entry, default=str, ensure_ascii=False)
                else:
                    # Legacy HMAC chain
                    entry["_prev_hash"] = self._prev_hash
                    line = json.dumps(entry, default=str, ensure_ascii=False)
                    entry_hmac = self._compute_hmac(self._prev_hash + line)
                    entry["_hmac"] = entry_hmac
                    self._prev_hash = entry_hmac
                    line = json.dumps(entry, default=str, ensure_ascii=False)

                with self.log_path.open("a", encoding="utf-8") as f:
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
            _logger.debug("Failed to read audit events", exc_info=True)

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
