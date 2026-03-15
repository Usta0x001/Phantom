"""Scan registry — global thread-safe deduplication of scanned targets.

The root cause of runaway cost is agents re-scanning the same endpoint,
port, or path that a sibling agent already scanned.  This module provides
a process-wide registry so any agent can record what it has already tested
and check whether another agent has already covered a surface before
starting a new scan.

Thread-safety guarantee: all mutations and reads are protected by a single
re-entrant lock, so concurrent sub-agents cannot race on the registry.
"""

import threading
from datetime import UTC, datetime
from typing import Any

from phantom.tools.registry import register_tool


# ── Process-wide state ────────────────────────────────────────────────────────
_LOCK = threading.RLock()

# Key: canonical target string (lowercased, stripped)
# Value: dict with metadata about the scan
_REGISTRY: dict[str, dict[str, Any]] = {}
# ─────────────────────────────────────────────────────────────────────────────


def _canonical(target: str) -> str:
    """Normalise a target string so minor variations don't bypass dedup."""
    return target.strip().lower().rstrip("/")


# ── Public Python API (used by other internal modules) ───────────────────────

def is_registered(target: str) -> bool:
    """Return True if *target* is already in the registry."""
    with _LOCK:
        return _canonical(target) in _REGISTRY


def register(target: str, scan_type: str, agent_name: str) -> None:
    """Add *target* to the registry.  No-op if already present."""
    key = _canonical(target)
    with _LOCK:
        if key not in _REGISTRY:
            _REGISTRY[key] = {
                "target": target,
                "scan_type": scan_type,
                "agent_name": agent_name,
                "registered_at": datetime.now(UTC).isoformat(),
            }


def clear_registry() -> None:
    """Reset the registry (useful between test runs)."""
    with _LOCK:
        _REGISTRY.clear()


# ── Tool implementations ──────────────────────────────────────────────────────

@register_tool(sandbox_execution=False)
def check_scan_registry(
    agent_state: Any,
    target: str,
) -> dict[str, Any]:
    """Check whether *target* has already been scanned in this run.

    Returns ``{"already_scanned": True, "details": {...}}`` if it has, or
    ``{"already_scanned": False}`` if it has not — in which case you should
    proceed with the scan and call ``register_scan_target`` afterwards.
    """
    try:
        key = _canonical(target)
        with _LOCK:
            entry = _REGISTRY.get(key)
        if entry:
            return {
                "success": True,
                "already_scanned": True,
                "details": entry,
                "message": (
                    f"Target '{target}' was already scanned by agent "
                    f"'{entry.get('agent_name', 'unknown')}' "
                    f"({entry.get('scan_type', 'unknown')} scan) at "
                    f"{entry.get('registered_at', 'unknown')}. "
                    "Skip this scan to avoid duplicate work."
                ),
            }
        return {
            "success": True,
            "already_scanned": False,
            "message": f"Target '{target}' has not been scanned yet — safe to proceed.",
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "already_scanned": False}


@register_tool(sandbox_execution=False)
def register_scan_target(
    agent_state: Any,
    target: str,
    scan_type: str = "general",
) -> dict[str, Any]:
    """Register *target* as scanned so other agents can skip it.

    Call this immediately before (or immediately after) running a scan so
    that concurrent or future agents don't duplicate the work.

    ``scan_type`` should be a short label such as ``"port_scan"``,
    ``"directory_fuzz"``, ``"sqli"``, ``"xss"``, etc.
    """
    try:
        key = _canonical(target)
        agent_name = getattr(agent_state, "agent_name", "unknown")
        with _LOCK:
            already = key in _REGISTRY
            if not already:
                _REGISTRY[key] = {
                    "target": target,
                    "scan_type": scan_type,
                    "agent_name": agent_name,
                    "registered_at": datetime.now(UTC).isoformat(),
                }
        if already:
            return {
                "success": True,
                "registered": False,
                "message": f"Target '{target}' was already in the registry — no change made.",
            }
        return {
            "success": True,
            "registered": True,
            "message": (
                f"Registered '{target}' as scanned ({scan_type}) by agent '{agent_name}'."
            ),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "registered": False}
