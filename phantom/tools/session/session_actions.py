"""Session management tools — persist and reuse authenticated sessions.

Many web applications issue cookies or tokens on login.  Without session
management, each sub-agent re-authenticates independently, burning API calls
and risking rate-limiting or account lockout.

These tools provide a process-wide, thread-safe session store so any agent
can:
  1. Log in once and store the resulting cookies/tokens (`session_login`)
  2. Retrieve a stored session to reuse in subsequent requests (`session_get`)
  3. Refresh / update a session that has expired or needs rotation (`session_refresh`)
"""

import threading
from datetime import UTC, datetime
from typing import Any

from phantom.tools.registry import register_tool


# ── Process-wide session store ────────────────────────────────────────────────
_LOCK = threading.RLock()

# Key: session_id (caller-chosen label, e.g. "admin_login", "user_alice")
# Value: dict with cookies, headers, tokens, metadata
_SESSIONS: dict[str, dict[str, Any]] = {}
# ─────────────────────────────────────────────────────────────────────────────


def _mask_value(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "****"
    return value[:2] + "***" + value[-2:]


def _safe_session_repr(session: dict[str, Any]) -> dict[str, Any]:
    safe = dict(session)
    for key in ("cookies", "headers", "tokens"):
        items = safe.get(key, {})
        if isinstance(items, dict):
            safe[key] = {str(k): _mask_value(str(v)) for k, v in items.items()}
    return safe


# ── Public Python API ─────────────────────────────────────────────────────────

def get_session(session_id: str) -> dict[str, Any] | None:
    """Return the stored session dict for *session_id*, or None."""
    with _LOCK:
        return _SESSIONS.get(session_id)


def store_session(
    session_id: str,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    tokens: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
    agent_name: str = "unknown",
) -> None:
    """Store a session under *session_id*."""
    with _LOCK:
        _SESSIONS[session_id] = {
            "session_id": session_id,
            "cookies": cookies or {},
            "headers": headers or {},
            "tokens": tokens or {},
            "extra": extra or {},
            "agent_name": agent_name,
            "stored_at": datetime.now(UTC).isoformat(),
            "last_used": None,
        }


def clear_sessions() -> None:
    """Reset the session store (useful between test runs)."""
    with _LOCK:
        _SESSIONS.clear()


# ── Tool implementations ──────────────────────────────────────────────────────





