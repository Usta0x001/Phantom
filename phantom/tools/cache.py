"""Tool Result Caching Layer - EFFICIENCY FIX CRIT-04

This module provides a caching layer for idempotent tool results to eliminate
redundant tool calls. Based on efficiency audit findings:
- 21% of tool calls are identical duplicates
- Expected savings: $0.15-0.30/scan, 200-500ms per cached hit

The cache uses:
- LRU eviction with configurable max size
- TTL-based expiration for freshness
- Deterministic hashing of tool name + arguments
- Whitelist of cacheable (idempotent) tools
"""

import hashlib
import json
import logging
import time
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from phantom.config.config import Config


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CACHEABLE TOOLS WHITELIST
# ════════════════════════════════════════════════════════════════════════════════
# Only idempotent tools that return the same result for the same input.
# Tools with side effects (terminal_execute, browser_action, etc.) are NOT cached.
# This is a conservative whitelist - add tools only after verifying idempotency.

CACHEABLE_TOOLS: frozenset[str] = frozenset({
    # Read-only file operations
    "read_file",
    "list_directory",
    "glob_files",
    "search_files",
    "file_search",
    "list_files",
    
    # Read-only registry/state queries
    "get_scope_rules",
    "scope_rules",
    "list_scan_notes",
    "get_scan_notes",
    "list_todos",
    "get_todos",
    "list_notes",
    
    # Read-only proxy queries
    "get_proxy_history",
    "proxy_history",
    "get_request_details",
    "list_requests",
    "view_request",
    
    # Static web requests (GET only, auth-safe)
    "send_request",
    
    # Documentation/help queries
    "get_tool_help",
    "list_tools",
})


# Tools that should NEVER be cached (have side effects or are non-deterministic)
NON_CACHEABLE_TOOLS: frozenset[str] = frozenset({
    "terminal_execute",
    "browser_action", 
    "create_vulnerability_report",
    "add_scan_note",
    "update_todo",
    "spawn_agent",
    "finish_scan",
    "agent_finish",
    "send_oast_payload",
    "python_execute",
    "file_edit",
    "file_write",
})


@dataclass
class CacheEntry:
    """A single cached tool result with metadata."""
    result: Any
    created_at: float
    hits: int = 0
    tool_name: str = ""
    args_hash: str = ""


@dataclass 
class CacheStats:
    """Statistics for cache performance monitoring."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_saved_ms: float = 0.0  # Estimated time saved
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "hit_rate": round(self.hit_rate, 4),
            "total_saved_ms": round(self.total_saved_ms, 2),
        }


class ToolResultCache:
    """LRU cache for idempotent tool results with TTL expiration.
    
    Thread-safe via an internal lock.
    
    Usage:
        cache = ToolResultCache()
        
        # Check cache before execution
        cached = cache.get("send_request", {"url": "https://example.com"})
        if cached is not None:
            return cached
            
        # Execute tool and cache result
        result = await execute_tool(...)
        cache.put("send_request", {"url": "https://example.com"}, result)
    """
    
    # Default execution time estimate for savings calculation (ms)
    ESTIMATED_EXEC_TIME_MS = 350.0
    
    def __init__(
        self,
        max_size: int | None = None,
        ttl_seconds: float | None = None,
        enabled: bool | None = None,
    ):
        """Initialize the cache.
        
        Args:
            max_size: Maximum number of entries. Default from config or 500.
            ttl_seconds: Time-to-live in seconds. Default from config or 300 (5 min).
            enabled: Whether caching is enabled. Default from config or True.
        """
        # Load from config with fallbacks
        self._enabled = enabled if enabled is not None else (
            (Config.get("phantom_tool_cache_enabled") or "true").lower() in ("true", "1", "yes")
        )
        self._max_size = max_size if max_size is not None else int(
            Config.get("phantom_tool_cache_max_size") or "500"
        )
        self._ttl = ttl_seconds if ttl_seconds is not None else float(
            Config.get("phantom_tool_cache_ttl") or "300"
        )
        
        # LRU cache storage: key -> CacheEntry
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._stats = CacheStats()
        self._lock = threading.RLock()
        
        logger.debug(
            "ToolResultCache initialized: enabled=%s max_size=%d ttl=%.0fs",
            self._enabled, self._max_size, self._ttl
        )
        
        if not self._enabled:
            logger.warning("ToolResultCache is DISABLED - all calls will be cache misses")
    
    @property
    def enabled(self) -> bool:
        """Whether caching is currently enabled."""
        return self._enabled
    
    @property
    def stats(self) -> CacheStats:
        """Get current cache statistics."""
        return self._stats
    
    def _make_key(self, tool_name: str, kwargs: dict[str, Any]) -> str:
        """Generate a deterministic cache key from tool name and arguments.
        
        Uses SHA-256 hash of canonical JSON representation for consistency.
        For send_request, normalizes ephemeral parameters that don't affect cacheability.
        """
        # Normalize kwargs for cacheability
        normalized = kwargs.copy()
        
        if tool_name == "send_request" and "method" in normalized:
            normalized["method"] = normalized["method"].upper()
        
        # Sort keys for deterministic ordering
        try:
            canonical = json.dumps(
                {"tool": tool_name, "args": normalized},
                sort_keys=True,
                ensure_ascii=True,
                default=str,  # Handle non-serializable types
            )
        except (TypeError, ValueError):
            # Fallback for complex types
            canonical = f"{tool_name}:{repr(sorted(normalized.items()))}"
        
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]
    
    def _is_send_request_cache_safe(self, kwargs: dict[str, Any] | None) -> bool:
        if not kwargs:
            return False

        method = str(kwargs.get("method", "")).strip().upper()
        if method != "GET":
            return False

        body = kwargs.get("body", "")
        if isinstance(body, str) and body.strip():
            return False
        if body not in ("", None) and not isinstance(body, str):
            return False

        headers = kwargs.get("headers")
        if headers is None:
            return True
        if not isinstance(headers, dict):
            return False

        sensitive_headers = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token",
        }
        for key in headers:
            if str(key).strip().lower() in sensitive_headers:
                return False

        return True

    def is_cacheable(self, tool_name: str, kwargs: dict[str, Any] | None = None) -> bool:
        """Check if a tool's results can be cached.

        Returns True only for whitelisted idempotent tools.
        """
        if not self._enabled:
            return False
        if tool_name in NON_CACHEABLE_TOOLS:
            return False
        if tool_name == "send_request":
            return self._is_send_request_cache_safe(kwargs)
        return tool_name in CACHEABLE_TOOLS
    
    def get(self, tool_name: str, kwargs: dict[str, Any]) -> Any | None:
        """Retrieve a cached result if available and not expired.
        
        Args:
            tool_name: Name of the tool
            kwargs: Tool arguments (used for cache key)
            
        Returns:
            Cached result if hit, None if miss or expired
        """
        if not self._enabled:
            return None
            
        if not self.is_cacheable(tool_name, kwargs):
            # Not cacheable - this is expected for most tools
            return None
        
        key = self._make_key(tool_name, kwargs)
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats.misses += 1
                logger.debug("Cache miss: %s (not in cache)", tool_name)
                return None
            
            # Check TTL expiration
            age = time.monotonic() - entry.created_at
            if age > self._ttl:
                self._cache.pop(key, None)
                self._stats.expirations += 1
                self._stats.misses += 1
                logger.debug("Cache expired: %s (age=%.1fs)", tool_name, age)
                return None
            
            # Cache hit - move to end for LRU and update stats
            self._cache.move_to_end(key)
            entry.hits += 1
            self._stats.hits += 1
            self._stats.total_saved_ms += self.ESTIMATED_EXEC_TIME_MS
        
        logger.info(
            "✅ Cache HIT: %s (age=%.1fs, total_hits=%d, saved_ms=%.0f)",
            tool_name, age, entry.hits, self._stats.total_saved_ms
        )
        return entry.result
    
    def put(
        self,
        tool_name: str,
        kwargs: dict[str, Any],
        result: Any,
    ) -> bool:
        """Store a tool result in the cache.
        
        Args:
            tool_name: Name of the tool
            kwargs: Tool arguments (used for cache key)
            result: The result to cache
            
        Returns:
            True if cached, False if not cacheable or disabled
        """
        if not self._enabled or not self.is_cacheable(tool_name, kwargs):
            return False
        
        # Don't cache error results
        if isinstance(result, str) and result.strip().lower().startswith("error"):
            return False
        if isinstance(result, dict) and "error" in result:
            return False
        
        key = self._make_key(tool_name, kwargs)

        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
                self._stats.evictions += 1
                logger.debug("Cache eviction: LRU entry removed")

            # Store new entry
            self._cache[key] = CacheEntry(
                result=result,
                created_at=time.monotonic(),
                tool_name=tool_name,
                args_hash=key,
            )

        logger.debug("Cache put: %s (cache_size=%d)", tool_name, len(self._cache))
        return True
    
    def invalidate(self, tool_name: str | None = None) -> int:
        """Invalidate cache entries.
        
        Args:
            tool_name: If provided, only invalidate entries for this tool.
                      If None, clear entire cache.
                      
        Returns:
            Number of entries invalidated
        """
        with self._lock:
            if tool_name is None:
                count = len(self._cache)
                self._cache.clear()
                logger.debug("Cache cleared: %d entries invalidated", count)
                return count
        
            # Remove entries for specific tool
            to_remove = [
                key for key, entry in self._cache.items()
                if entry.tool_name == tool_name
            ]
            for key in to_remove:
                self._cache.pop(key, None)

        logger.debug("Cache invalidated: %s (%d entries)", tool_name, len(to_remove))
        return len(to_remove)
    
    def get_stats_summary(self) -> dict[str, Any]:
        """Get a summary of cache statistics for audit logging."""
        with self._lock:
            return {
                **self._stats.to_dict(),
                "cache_size": len(self._cache),
                "max_size": self._max_size,
                "ttl_seconds": self._ttl,
                "enabled": self._enabled,
            }


# ════════════════════════════════════════════════════════════════════════════════
# GLOBAL CACHE INSTANCE
# ════════════════════════════════════════════════════════════════════════════════
# Single global instance shared across all tool executions in a scan.
# Lazy initialization on first access.

_GLOBAL_CACHE: ToolResultCache | None = None
_GLOBAL_CACHE_LOCK = threading.Lock()


def get_tool_cache() -> ToolResultCache:
    """Get or create the global tool result cache."""
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        with _GLOBAL_CACHE_LOCK:
            if _GLOBAL_CACHE is None:
                _GLOBAL_CACHE = ToolResultCache()
    return _GLOBAL_CACHE


def reset_tool_cache() -> None:
    """Reset the global cache (for testing or new scans)."""
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is not None:
        _GLOBAL_CACHE.invalidate()
    _GLOBAL_CACHE = None
