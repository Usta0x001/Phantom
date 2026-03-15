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

@register_tool(sandbox_execution=False)
def session_login(
    agent_state: Any,
    session_id: str,
    cookies: str = "",
    headers: str = "",
    tokens: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Store an authenticated session so other agents can reuse it without re-logging-in.

    After performing a login (via terminal curl, browser, or python), call this tool
    with the resulting cookies/headers/tokens so they are available process-wide.

    ``cookies``, ``headers``, and ``tokens`` should each be a semicolon-separated
    list of ``key=value`` pairs.  For example::

        cookies = "session=abc123; csrf=xyz"
        headers = "Authorization=Bearer eyJ..."
        tokens  = "access_token=abc; refresh_token=def"
    """
    try:
        def _parse_kv(raw: str) -> dict[str, str]:
            result: dict[str, str] = {}
            for pair in raw.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    result[k.strip()] = v.strip()
            return result

        parsed_cookies = _parse_kv(cookies) if cookies.strip() else {}
        parsed_headers = _parse_kv(headers) if headers.strip() else {}
        parsed_tokens = _parse_kv(tokens) if tokens.strip() else {}
        extra = {"notes": notes} if notes.strip() else {}

        agent_name = getattr(agent_state, "agent_name", "unknown")
        store_session(
            session_id=session_id,
            cookies=parsed_cookies,
            headers=parsed_headers,
            tokens=parsed_tokens,
            extra=extra,
            agent_name=agent_name,
        )
        return {
            "success": True,
            "session_id": session_id,
            "message": (
                f"Session '{session_id}' stored with "
                f"{len(parsed_cookies)} cookie(s), "
                f"{len(parsed_headers)} header(s), "
                f"{len(parsed_tokens)} token(s)."
            ),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "session_id": session_id}


@register_tool(sandbox_execution=False)
def session_get(
    agent_state: Any,
    session_id: str,
) -> dict[str, Any]:
    """Retrieve a stored session so you can reuse its cookies/headers/tokens.

    Returns ``{"found": True, "session": {...}}`` if the session exists, or
    ``{"found": False}`` if it has not been stored yet — in which case you
    should perform a fresh login and call ``session_login`` to store it.
    """
    try:
        with _LOCK:
            session = _SESSIONS.get(session_id)
            if session:
                # Update last_used timestamp
                _SESSIONS[session_id] = dict(session)
                _SESSIONS[session_id]["last_used"] = datetime.now(UTC).isoformat()

        if session:
            return {
                "success": True,
                "found": True,
                "session": {
                    "session_id": session["session_id"],
                    "cookies": session.get("cookies", {}),
                    "headers": session.get("headers", {}),
                    "tokens": session.get("tokens", {}),
                    "extra": session.get("extra", {}),
                    "stored_at": session.get("stored_at"),
                    "agent_name": session.get("agent_name"),
                },
            }
        return {
            "success": True,
            "found": False,
            "message": (
                f"Session '{session_id}' not found. "
                "Perform a login and call session_login to store it."
            ),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "found": False}


@register_tool(sandbox_execution=False)
def session_refresh(
    agent_state: Any,
    session_id: str,
    cookies: str = "",
    headers: str = "",
    tokens: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Update (refresh) an existing stored session with new credentials.

    Use this when a session token has expired and you have performed a new
    login or token refresh.  Parameters are the same as ``session_login``.
    If the session does not exist yet, it is created (same as ``session_login``).
    """
    try:
        def _parse_kv(raw: str) -> dict[str, str]:
            result: dict[str, str] = {}
            for pair in raw.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    result[k.strip()] = v.strip()
            return result

        parsed_cookies = _parse_kv(cookies) if cookies.strip() else {}
        parsed_headers = _parse_kv(headers) if headers.strip() else {}
        parsed_tokens = _parse_kv(tokens) if tokens.strip() else {}
        extra: dict[str, Any] = {"notes": notes} if notes.strip() else {}

        agent_name = getattr(agent_state, "agent_name", "unknown")

        with _LOCK:
            existed = session_id in _SESSIONS
            existing = _SESSIONS.get(session_id, {})
            # Merge: new values overwrite existing ones per-key
            merged_cookies = {**existing.get("cookies", {}), **parsed_cookies}
            merged_headers = {**existing.get("headers", {}), **parsed_headers}
            merged_tokens = {**existing.get("tokens", {}), **parsed_tokens}
            merged_extra = {**existing.get("extra", {}), **extra}
            _SESSIONS[session_id] = {
                "session_id": session_id,
                "cookies": merged_cookies,
                "headers": merged_headers,
                "tokens": merged_tokens,
                "extra": merged_extra,
                "agent_name": agent_name,
                "stored_at": existing.get("stored_at") or datetime.now(UTC).isoformat(),
                "refreshed_at": datetime.now(UTC).isoformat(),
                "last_used": None,
            }

        action = "updated" if existed else "created"
        return {
            "success": True,
            "session_id": session_id,
            "action": action,
            "message": (
                f"Session '{session_id}' {action} with "
                f"{len(merged_cookies)} cookie(s), "
                f"{len(merged_headers)} header(s), "
                f"{len(merged_tokens)} token(s)."
            ),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "session_id": session_id}
