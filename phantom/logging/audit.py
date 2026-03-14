"""Phantom Audit Logger — comprehensive debug/testing logging layer.

Enable with ``PHANTOM_AUDIT_LOG=true``.

Writes two files per run into ``phantom_runs/<run_id>/``:
  - ``audit.jsonl``   — ndjson, one JSON event record per line (machine-readable)
  - ``audit.log``     — human-readable summary (one line per event)

What gets logged
----------------
- ``llm.request``      — every message list sent to the LLM (full content)
- ``llm.response``     — every LLM reply + token counts + cost delta
- ``llm.error``        — every LLM error (before retries exhausted)
- ``tool.start``       — tool name + full arguments before execution
- ``tool.result``      — tool result (first 4 KB) + wall-clock duration
- ``tool.error``       — tool exceptions
- ``agent.created``    — every agent instantiation (type, task, parent)
- ``agent.iteration``  — every agent loop iteration
- ``agent.completed``  — agent success with final result + duration
- ``agent.failed``     — agent failure
- ``rate_limit.hit``   — consecutive RL hits + backoff schedule
- ``rate_limit.abort`` — agent aborted due to max consecutive RL hits
- ``quarantine.block`` — terminal commands blocked by C-04 quarantine mode
- ``checkpoint.saved`` — checkpoint file writes
- ``security.event``   — ad-hoc security-relevant events
- ``run.started``      — audit session initialised

WARNING: All data is written WITHOUT sanitisation/redaction.
DO NOT enable in production against sensitive targets unless you have reviewed
the data-handling implications.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_instance: "AuditLogger | None" = None
_instance_lock = threading.Lock()


def _is_enabled() -> bool:
    return os.getenv("PHANTOM_AUDIT_LOG", "false").lower() == "true"


def get_audit_logger() -> "AuditLogger | None":
    """Return the active AuditLogger singleton, or None if disabled/not initialised."""
    return _instance


def init_audit_logger(run_id: str, run_dir: Path | None = None) -> "AuditLogger":
    """Initialise (or reinitialise) the singleton AuditLogger for a new run.

    Safe to call multiple times — each call replaces the previous singleton.
    When ``PHANTOM_AUDIT_LOG`` is falsy the returned logger is a no-op.
    """
    global _instance  # noqa: PLW0603
    with _instance_lock:
        _instance = AuditLogger(run_id=run_id, run_dir=run_dir)
        return _instance


class AuditLogger:
    """Thread-safe, always-on (when enabled) audit event logger.

    All public methods are safe to call even when ``enabled=False``; they
    become instant no-ops so call-sites need no guard code.
    """

    def __init__(self, run_id: str, run_dir: Path | None = None) -> None:
        self.run_id = run_id
        self.enabled = _is_enabled()
        self._lock = threading.Lock()

        if self.enabled:
            if run_dir is None:
                import re as _re
                # Sanitize run_id before using it in a path to prevent traversal
                # (e.g. run_id="../../etc/evil" must not escape phantom_runs/)
                _safe_id = _re.sub(r"^[A-Za-z]:", "", run_id.replace("\x00", "")).lstrip("/\\")
                _safe_id = "/".join(
                    p for p in _re.split(r"[/\\]", _safe_id) if p and p != ".."
                ) or "unnamed"
                _safe_id = _safe_id[:128]
                base = Path.cwd() / "phantom_runs"
                base.mkdir(exist_ok=True)
                run_dir = base / _safe_id
            run_dir.mkdir(parents=True, exist_ok=True)
            self._jsonl_path: Path | None = run_dir / "audit.jsonl"
            self._log_path: Path | None = run_dir / "audit.log"
            self._write({
                "event_type": "run.started",
                "payload": {
                    "run_id": run_id,
                    "jsonl_path": str(self._jsonl_path),
                    "log_path": str(self._log_path),
                    "pid": os.getpid(),
                },
            })
        else:
            self._jsonl_path = None
            self._log_path = None

    # ─── Internal writers ────────────────────────────────────────────────────

    def _write(self, record: dict[str, Any]) -> None:
        """Append one event record to both output files. Never raises."""
        if not self.enabled:
            return
        record.setdefault("timestamp", datetime.now(UTC).isoformat())
        record["run_id"] = self.run_id
        with self._lock:
            # JSONL
            if self._jsonl_path:
                try:
                    with open(self._jsonl_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                except OSError:
                    logger.debug("audit: failed to write jsonl record")
            # Human-readable log
            if self._log_path:
                try:
                    ev = record.get("event_type", "?")
                    ts = record.get("timestamp", "")
                    actor = record.get("actor") or {}
                    agent_id = actor.get("agent_id", "") if isinstance(actor, dict) else ""
                    summary = self._summarize(record)
                    line = f"[{ts}] [{ev:30s}] agent={agent_id:<24s} {summary}\n"
                    with open(self._log_path, "a", encoding="utf-8") as f:
                        f.write(line)
                except OSError:
                    logger.debug("audit: failed to write log record")

    def _summarize(self, record: dict[str, Any]) -> str:  # noqa: PLR0911
        ev = record.get("event_type", "")
        p = record.get("payload") or {}
        if not isinstance(p, dict):
            return str(p)[:120]
        if ev == "llm.request":
            return (
                f"model={p.get('model','?')} "
                f"messages={p.get('message_count',0)} "
                f"chars={p.get('input_chars',0)}"
            )
        if ev == "llm.response":
            tools = len(p.get("tool_invocations") or [])
            return (
                f"model={p.get('model','?')} "
                f"in={p.get('tokens_in',0)} out={p.get('tokens_out',0)} "
                f"cost=${p.get('cost_usd',0):.4f} "
                f"tools={tools} "
                f"dur={p.get('duration_ms',0):.0f}ms"
            )
        if ev == "llm.error":
            return (
                f"model={p.get('model','?')} "
                f"attempt={p.get('attempt',0)} "
                f"err={str(p.get('error',''))[:100]}"
            )
        if ev in ("tool.start", "tool.result", "tool.error"):
            extra = f"dur={p.get('duration_ms',0):.0f}ms" if "duration_ms" in p else ""
            status = "ERR" if ev == "tool.error" else "ok"
            return f"tool={p.get('tool_name','?')} exec={p.get('exec_id','?')} {extra} {status}"
        if ev == "rate_limit.hit":
            return (
                f"model={p.get('model','?')} "
                f"consecutive={p.get('consecutive',0)}/{p.get('max_consecutive','?')} "
                f"backoff={p.get('backoff_s',0):.0f}s"
            )
        if ev == "rate_limit.abort":
            return f"model={p.get('model','?')} hits={p.get('consecutive',0)} ABORTING"
        if ev == "quarantine.block":
            cmd = str(p.get("command", ""))
            return f"chars={p.get('blocked_chars')} cmd={cmd[:60]!r}"
        if ev in ("agent.created", "agent.completed", "agent.failed"):
            return (
                f"name={p.get('name','?')} "
                f"type={p.get('agent_type','?')} "
                f"task={str(p.get('task',''))[:80]!r}"
            )
        if ev == "agent.iteration":
            return f"iter={p.get('iteration',0)}/{p.get('max_iterations',0)}"
        if ev == "checkpoint.saved":
            return f"dir={p.get('run_dir','?')} iter={p.get('iteration',0)}"
        if ev == "llm.preflight_reduction":
            return (
                f"stage={p.get('stage','?')} attempt={p.get('attempt','?')} "
                f"chars={p.get('chars_before','?')}→{p.get('chars_after','?')} "
                f"tokens={p.get('tokens_before','?')}→{p.get('tokens_after','?')}"
            )
        if ev == "tool.result_truncated":
            return (
                f"tool={p.get('tool_name','?')} chars={p.get('chars_before','?')}→"
                f"{p.get('chars_after','?')} limit={p.get('limit','?')}"
            )
        if ev == "llm.image_eviction":
            return (
                f"kept={p.get('kept_images','?')} evicted={p.get('evicted_images','?')} "
                f"bytes={p.get('bytes_before','?')}→{p.get('bytes_after','?')}"
            )
        return json.dumps(p, default=str)[:120]

    # ─── LLM ─────────────────────────────────────────────────────────────────

    def log_llm_request(
        self,
        agent_id: str,
        model: str,
        messages: list[dict[str, Any]],
        request_id: str | None = None,
    ) -> str:
        """Log the full message list sent to the LLM. Returns a request_id."""
        if not self.enabled:
            return request_id or uuid.uuid4().hex[:12]
        rid = request_id or uuid.uuid4().hex[:12]
        input_chars = sum(len(str(m.get("content", ""))) for m in messages)
        self._write({
            "event_type": "llm.request",
            "actor": {"agent_id": agent_id},
            "payload": {
                "request_id": rid,
                "model": model,
                "message_count": len(messages),
                "input_chars": input_chars,
                "messages": messages,            # full content — may be large
            },
        })
        return rid

    def log_llm_response(
        self,
        agent_id: str,
        request_id: str,
        model: str,
        response_text: str,
        tool_invocations: list[dict[str, Any]] | None,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
        duration_ms: float,
    ) -> None:
        """Log a completed LLM response with stats."""
        self._write({
            "event_type": "llm.response",
            "actor": {"agent_id": agent_id},
            "payload": {
                "request_id": request_id,
                "model": model,
                "response_text": response_text[:10_000],  # cap; full text may be huge
                "response_chars": len(response_text),
                "tool_invocations": tool_invocations,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "cost_usd": round(cost_usd, 6),
                "duration_ms": round(duration_ms, 1),
            },
            "status": "completed",
        })

    def log_llm_error(
        self,
        agent_id: str,
        model: str,
        error: str,
        attempt: int,
        request_id: str | None = None,
    ) -> None:
        """Log an LLM call failure."""
        self._write({
            "event_type": "llm.error",
            "actor": {"agent_id": agent_id},
            "payload": {
                "request_id": request_id,
                "model": model,
                "error": error[:500],
                "attempt": attempt,
            },
            "status": "error",
        })

    def log_compression(
        self,
        agent_id: str,
        model: str,
        messages_in: int,
        messages_out: int,
        tokens_before: int,
        chunk_size: int,
        duration_ms: float,
    ) -> None:
        """Log a memory-compression cycle so the watch layer can detect idle overhead."""
        self._write({
            "event_type": "llm.compression",
            "actor": {"agent_id": agent_id},
            "payload": {
                "model": model,
                "messages_in": messages_in,
                "messages_out": messages_out,
                "tokens_before": tokens_before,
                "chunk_size": chunk_size,
                "duration_ms": round(duration_ms, 1),
            },
        })

    def log_preflight_reduction(
        self,
        agent_id: str,
        stage: str,
        attempt: int,
        chars_before: int,
        chars_after: int,
        tokens_before: int,
        tokens_after: int,
        max_request_chars: int,
        max_request_tokens: int,
    ) -> None:
        self._write({
            "event_type": "llm.preflight_reduction",
            "actor": {"agent_id": agent_id},
            "payload": {
                "stage": stage,
                "attempt": attempt,
                "chars_before": chars_before,
                "chars_after": chars_after,
                "tokens_before": tokens_before,
                "tokens_after": tokens_after,
                "max_request_chars": max_request_chars,
                "max_request_tokens": max_request_tokens,
            },
        })

    # ─── Tools ───────────────────────────────────────────────────────────────

    def log_tool_start(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> str:
        """Log a tool invocation before execution. Returns exec_id for correlation."""
        if not self.enabled:
            return uuid.uuid4().hex[:12]
        exec_id = uuid.uuid4().hex[:12]
        self._write({
            "event_type": "tool.start",
            "actor": {"agent_id": agent_id},
            "payload": {
                "exec_id": exec_id,
                "tool_name": tool_name,
                "args": args,
            },
        })
        return exec_id

    def log_tool_result(
        self,
        exec_id: str,
        agent_id: str,
        tool_name: str,
        result: Any,
        duration_ms: float,
    ) -> None:
        """Log a successful tool result."""
        result_preview = str(result)[:4_096] if result is not None else None
        self._write({
            "event_type": "tool.result",
            "actor": {"agent_id": agent_id},
            "payload": {
                "exec_id": exec_id,
                "tool_name": tool_name,
                "result_preview": result_preview,
                "result_chars": len(str(result)) if result is not None else 0,
                "duration_ms": round(duration_ms, 1),
            },
            "status": "completed",
        })

    def log_tool_error(
        self,
        exec_id: str,
        agent_id: str,
        tool_name: str,
        error: str,
        duration_ms: float,
    ) -> None:
        """Log a tool execution error."""
        self._write({
            "event_type": "tool.error",
            "actor": {"agent_id": agent_id},
            "payload": {
                "exec_id": exec_id,
                "tool_name": tool_name,
                "error": error[:500],
                "duration_ms": round(duration_ms, 1),
            },
            "status": "error",
        })

    def log_tool_result_truncation(
        self,
        agent_id: str,
        tool_name: str,
        chars_before: int,
        chars_after: int,
        limit: int,
        burst_applied: bool,
    ) -> None:
        self._write({
            "event_type": "tool.result_truncated",
            "actor": {"agent_id": agent_id},
            "payload": {
                "tool_name": tool_name,
                "chars_before": chars_before,
                "chars_after": chars_after,
                "limit": limit,
                "burst_applied": burst_applied,
            },
        })

    def log_image_eviction(
        self,
        agent_id: str,
        kept_images: int,
        evicted_images: int,
        bytes_before: int,
        bytes_after: int,
        max_total_image_bytes: int,
    ) -> None:
        self._write({
            "event_type": "llm.image_eviction",
            "actor": {"agent_id": agent_id},
            "payload": {
                "kept_images": kept_images,
                "evicted_images": evicted_images,
                "bytes_before": bytes_before,
                "bytes_after": bytes_after,
                "max_total_image_bytes": max_total_image_bytes,
            },
        })

    # ─── Agents ──────────────────────────────────────────────────────────────

    def log_agent_created(
        self,
        agent_id: str,
        name: str,
        task: str,
        parent_id: str | None,
        agent_type: str,
        model: str,
    ) -> None:
        """Log agent instantiation."""
        self._write({
            "event_type": "agent.created",
            "actor": {"agent_id": agent_id},
            "payload": {
                "name": name,
                "task": task,
                "parent_id": parent_id,
                "agent_type": agent_type,
                "model": model,
                "is_root": parent_id is None,
            },
        })

    def log_agent_iteration(
        self,
        agent_id: str,
        iteration: int,
        max_iterations: int,
    ) -> None:
        """Log the start of each agent loop iteration."""
        self._write({
            "event_type": "agent.iteration",
            "actor": {"agent_id": agent_id},
            "payload": {
                "iteration": iteration,
                "max_iterations": max_iterations,
            },
        })

    def log_agent_completed(
        self,
        agent_id: str,
        name: str,
        task: str,
        result: dict[str, Any] | None,
        iterations: int,
        duration_ms: float,
    ) -> None:
        """Log successful agent completion."""
        self._write({
            "event_type": "agent.completed",
            "actor": {"agent_id": agent_id},
            "payload": {
                "name": name,
                "task": task[:200],
                "result_keys": list(result.keys()) if isinstance(result, dict) else None,
                "success": (result or {}).get("success"),
                "iterations": iterations,
                "duration_ms": round(duration_ms, 1),
            },
            "status": "completed",
        })

    def log_agent_failed(
        self,
        agent_id: str,
        name: str,
        error: str,
        iterations: int,
        duration_ms: float,
    ) -> None:
        """Log agent failure."""
        self._write({
            "event_type": "agent.failed",
            "actor": {"agent_id": agent_id},
            "payload": {
                "name": name,
                "error": error[:500],
                "iterations": iterations,
                "duration_ms": round(duration_ms, 1),
            },
            "status": "failed",
        })

    # ─── Rate limits ─────────────────────────────────────────────────────────

    def log_rate_limit_hit(
        self,
        agent_id: str,
        model: str,
        consecutive: int,
        max_consecutive: int,
        backoff_s: float,
    ) -> None:
        """Log a rate-limit backoff decision."""
        self._write({
            "event_type": "rate_limit.hit",
            "actor": {"agent_id": agent_id},
            "payload": {
                "model": model,
                "consecutive": consecutive,
                "max_consecutive": max_consecutive,
                "backoff_s": round(backoff_s, 1),
            },
        })

    def log_rate_limit_abort(
        self,
        agent_id: str,
        model: str,
        consecutive: int,
        max_consecutive: int,
        abort_message: str,
    ) -> None:
        """Log that the agent is being aborted due to too many consecutive RL hits."""
        self._write({
            "event_type": "rate_limit.abort",
            "actor": {"agent_id": agent_id},
            "payload": {
                "model": model,
                "consecutive": consecutive,
                "max_consecutive": max_consecutive,
                "abort_message": abort_message[:500],
            },
            "status": "aborted",
        })

    # ─── Security events ─────────────────────────────────────────────────────

    def log_quarantine_block(
        self,
        agent_id: str,
        command: str,
        blocked_chars: list[str],
    ) -> None:
        """Log a terminal quarantine block (C-04)."""
        self._write({
            "event_type": "quarantine.block",
            "actor": {"agent_id": agent_id},
            "payload": {
                "command": command[:500],
                "command_len": len(command),
                "blocked_chars": blocked_chars,
            },
            "status": "blocked",
        })

    def log_security_event(
        self,
        event_subtype: str,
        agent_id: str | None,
        details: dict[str, Any],
    ) -> None:
        """Log an ad-hoc security-relevant event."""
        self._write({
            "event_type": f"security.{event_subtype}",
            "actor": {"agent_id": agent_id} if agent_id else None,
            "payload": details,
        })

    # ─── Checkpoints ─────────────────────────────────────────────────────────

    def log_checkpoint(
        self,
        agent_id: str,
        run_dir: str,
        iteration: int,
    ) -> None:
        """Log a checkpoint save."""
        self._write({
            "event_type": "checkpoint.saved",
            "actor": {"agent_id": agent_id},
            "payload": {
                "run_dir": run_dir,
                "iteration": iteration,
            },
        })

    # ─── Stats ───────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Read audit.jsonl and return summary statistics.

        Useful for verifying what was logged after a test run.
        """
        if not self.enabled or not self._jsonl_path or not self._jsonl_path.exists():
            return {"enabled": False, "reason": "disabled or file not found"}

        counts: dict[str, int] = {}
        total_tokens_in = 0
        total_tokens_out = 0
        total_cost = 0.0
        total_tool_calls = 0
        total_llm_requests = 0
        agents_seen: set[str] = set()

        try:
            with open(self._jsonl_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ev = rec.get("event_type", "unknown")
                    counts[ev] = counts.get(ev, 0) + 1
                    actor = rec.get("actor") or {}
                    if isinstance(actor, dict) and actor.get("agent_id"):
                        agents_seen.add(actor["agent_id"])
                    if ev == "llm.response":
                        p = rec.get("payload") or {}
                        total_tokens_in += p.get("tokens_in", 0)
                        total_tokens_out += p.get("tokens_out", 0)
                        total_cost += p.get("cost_usd", 0.0)
                        total_llm_requests += 1
                    elif ev == "tool.start":
                        total_tool_calls += 1
        except OSError:
            return {"enabled": True, "error": "could not read audit.jsonl"}

        return {
            "enabled": True,
            "jsonl_path": str(self._jsonl_path),
            "log_path": str(self._log_path),
            "event_counts": counts,
            "total_events": sum(counts.values()),
            "total_llm_requests": total_llm_requests,
            "total_tokens_in": total_tokens_in,
            "total_tokens_out": total_tokens_out,
            "total_cost_usd": round(total_cost, 6),
            "total_tool_calls": total_tool_calls,
            "agents_seen": sorted(agents_seen),
        }
