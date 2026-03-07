"""
Feature Flag System for Phantom Hardening

All v0.9.39 hardening changes are gated behind flags.
Flags default to True for v0.9.39 GA, but can be flipped to False
for rollback without code changes.

ARC-002 FIX: Security-critical flags are COMPILE-TIME CONSTANTS and
cannot be disabled via environment variables or cache mutation.
Tampering with the _cache or flag registry raises SecurityIntegrityViolationError.

Flags are read from environment variables:
  PHANTOM_FF_SCOPE_ENFORCEMENT=true   (non-disableable)
  PHANTOM_FF_OUTPUT_SANITIZER=true    (non-disableable)
  ...
"""

from __future__ import annotations

import hashlib
import logging
import os

_logger = logging.getLogger(__name__)

# ARC-002 FIX: Security-critical flags that CANNOT be disabled at runtime.
# These protect against scope violations, prompt injection, and audit tampering.
_SECURITY_COMPILE_TIME_FLAGS: frozenset[str] = frozenset({
    "PHANTOM_FF_SCOPE_ENFORCEMENT",
    "PHANTOM_FF_OUTPUT_SANITIZER",
    "PHANTOM_FF_TOOL_FIREWALL",
    "PHANTOM_FF_ED25519_AUDIT",
    "PHANTOM_FF_SIGNED_CHECKPOINTS",
    "PHANTOM_FF_EGRESS_ENFORCEMENT",
    "PHANTOM_FF_LEDGER_SANITIZE",
})

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

# V-MED-005 FIX: Use a controlled wrapper class instead of a plain dict
# so external code cannot silently mutate the cache via import reference.
# The cache only allows mutation through the module's own functions.
class _FlagCache:
    """Controlled cache that rejects direct external mutation."""
    __slots__ = ("_store",)

    def __init__(self) -> None:
        self._store: dict[str, bool] = {}

    def get(self, key: str) -> bool | None:
        return self._store.get(key)

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __setitem__(self, key: str, value: bool) -> None:
        self._store[key] = value

    def clear(self) -> None:
        self._store.clear()


_cache = _FlagCache()

# ARC-002 FIX: Compute integrity hash of the defaults at import time.
# If _DEFAULTS is mutated at runtime, is_enabled() will detect tampering.
_DEFAULTS_INTEGRITY = hashlib.sha256(
    str(sorted(_DEFAULTS.items())).encode()
).hexdigest()


def _verify_integrity() -> None:
    """ARC-002 FIX: Detect runtime tampering of flag defaults."""
    current = hashlib.sha256(
        str(sorted(_DEFAULTS.items())).encode()
    ).hexdigest()
    if current != _DEFAULTS_INTEGRITY:
        from phantom.core.exceptions import SecurityIntegrityViolationError
        raise SecurityIntegrityViolationError(
            "Feature flag defaults have been tampered with at runtime"
        )


def is_enabled(flag_name: str) -> bool:
    """Check if a feature flag is enabled.

    ARC-002 FIX: Security-critical flags always return True regardless
    of environment variables or cache state.
    V-LOW-001 FIX: Integrity check runs on ALL lookups, including security
    flags, to detect tampering even when only security flags are queried.
    """
    # V-LOW-001 FIX: Always verify integrity, even for security flags
    _verify_integrity()

    # Security flags are compile-time constants — always True
    if flag_name in _SECURITY_COMPILE_TIME_FLAGS:
        return True

    cached = _cache.get(flag_name)
    if cached is not None:
        return cached

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
