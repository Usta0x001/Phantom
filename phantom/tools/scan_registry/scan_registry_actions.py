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



