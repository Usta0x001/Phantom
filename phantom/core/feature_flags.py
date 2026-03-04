"""
Feature Flag System for Phantom Hardening

All v0.9.39 hardening changes are gated behind flags.
Flags default to True for v0.9.39 GA, but can be flipped to False
for rollback without code changes.

Flags are read from environment variables:
  PHANTOM_FF_SCOPE_ENFORCEMENT=true
  PHANTOM_FF_OUTPUT_SANITIZER=true
  ...
"""

from __future__ import annotations

import logging
import os

_logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, bool] = {
    "PHANTOM_FF_SCOPE_ENFORCEMENT": True,
    "PHANTOM_FF_OUTPUT_SANITIZER": True,
    "PHANTOM_FF_TOOL_FIREWALL": True,
    "PHANTOM_FF_ED25519_AUDIT": True,
    "PHANTOM_FF_SIGNED_CHECKPOINTS": True,
    "PHANTOM_FF_MTLS": False,          # Default OFF — requires Docker image rebuild
    "PHANTOM_FF_EGRESS_ENFORCEMENT": True,
    "PHANTOM_FF_FINISH_GUARD": True,
    "PHANTOM_FF_LEDGER_SANITIZE": True,
    "PHANTOM_FF_COMPRESSOR_SANITIZE": True,
    "PHANTOM_FF_PARALLEL_SAFETY": True,
}

_cache: dict[str, bool] = {}


def is_enabled(flag_name: str) -> bool:
    """Check if a feature flag is enabled."""
    if flag_name in _cache:
        return _cache[flag_name]

    env_val = os.getenv(flag_name)
    if env_val is not None:
        result = env_val.lower() in ("true", "1", "yes")
    else:
        result = _DEFAULTS.get(flag_name, False)

    _cache[flag_name] = result
    return result


def clear_cache() -> None:
    """Clear flag cache (for testing)."""
    _cache.clear()


def get_all_flags() -> dict[str, bool]:
    """Get all flag states."""
    return {name: is_enabled(name) for name in _DEFAULTS}
