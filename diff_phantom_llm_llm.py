diff --git a/phantom/llm/llm.py b/phantom/llm/llm.py
index 595605b..5f57c34 100644
--- a/phantom/llm/llm.py
+++ b/phantom/llm/llm.py
@@ -2,9 +2,7 @@ import asyncio
 import json
 import logging
 import os
-import re
 import time
-import threading
 from collections.abc import AsyncIterator
 from dataclasses import dataclass, field
 from typing import Any
@@ -21,20 +19,15 @@ from phantom.llm.config import LLMConfig
 from phantom.llm.memory_compressor import MemoryCompressor
 from phantom.llm.tracked_completion import tracked_acompletion
 from phantom.llm.utils import (
-    _truncate_to_first_function,
     fix_incomplete_tool_call,
     normalize_tool_format,
     parse_tool_invocations,
     strip_thinking_blocks,
 )
-from phantom.skills import load_skills
 from phantom.tools import get_tools_prompt
 from phantom.tools.dynamic_tools import (
     get_compact_tools_prompt,
     get_compact_tools_prompt_subset,
-    get_tool_subset_categories,
-    get_related_tools_for_name,
-    get_tools_for_context,
     get_tools_for_task,
     get_tools_for_subset_mode,
     get_tools_prompt_subset,
@@ -66,8 +59,8 @@ class RequestStats:
     output_tokens: int = 0
     cached_tokens: int = 0
     cost: float = 0.0
-    requests: int = 0           # calls with accounted token usage
-    completed_requests: int = 0  # compatibility mirror of requests
+    requests: int = 0
+    completed_requests: int = 0
 
     def to_dict(self) -> dict[str, int | float]:
         return {
@@ -87,24 +80,39 @@ class RequestStats:
         self.requests = 0
         self.completed_requests = 0
 
-_GLOBAL_TOTAL_STATS = RequestStats()
-_GLOBAL_PER_MODEL_STATS: dict[str, RequestStats] = {}
-_GLOBAL_RATE_LIMIT_UNTIL: float = 0.0
-_GLOBAL_STATS_LOCK = threading.Lock()
 
-_GLOBAL_TOKEN_DRIFT_EVENTS: list[dict[str, int | float | str]] = []
-_GLOBAL_USAGE_EVENTS: list[dict[str, int | float | str]] = []
+@dataclass
+class SharedLLMState:
+    """Shared mutable state formerly stored as module-level globals.
+
+    Encapsulating in a class makes the dependency explicit and testable.
+    """
+
+    total_stats: RequestStats = field(default_factory=RequestStats)
+    per_model_stats: dict[str, RequestStats] = field(default_factory=dict)
+    rate_limit_until: float = 0.0
+    token_drift_events: list[dict[str, int | float | str]] = field(default_factory=list)
+    usage_events: list[dict[str, int | float | str]] = field(default_factory=list)
+    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
+
+    def reset(self) -> None:
+        self.total_stats.reset()
+        self.per_model_stats.clear()
+        self.token_drift_events.clear()
+        self.usage_events.clear()
+        self.rate_limit_until = 0.0
+
+
+# Default shared state for backward compatibility.
+_DEFAULT_SHARED_STATE = SharedLLMState()
 
 
-def reset_global_llm_stats() -> None:
-    with _GLOBAL_STATS_LOCK:
-        _GLOBAL_TOTAL_STATS.reset()
-        _GLOBAL_PER_MODEL_STATS.clear()
-        _GLOBAL_TOKEN_DRIFT_EVENTS.clear()
-        _GLOBAL_USAGE_EVENTS.clear()
+def reset_global_llm_stats(shared_state: SharedLLMState | None = None) -> None:
+    state = shared_state or _DEFAULT_SHARED_STATE
+    state.reset()
 
 
-def _record_token_drift(
+async def _record_token_drift_async(
     model_name: str,
     estimated_tokens: int,
     actual_prompt_tokens: int,
@@ -112,6 +120,7 @@ def _record_token_drift(
     accounted_input_tokens: int,
     accounted_output_tokens: int,
     accounted_cost: float,
+    shared_state: SharedLLMState | None = None,
 ) -> None:
     drift = max(actual_prompt_tokens, 0) - max(estimated_tokens, 0)
     threshold_raw = Config.get("phantom_token_drift_warn_threshold") or "2000"
@@ -127,14 +136,17 @@ def _record_token_drift(
         "actual_completion_tokens": int(max(actual_completion_tokens, 0)),
         "accounted_input_tokens": int(max(accounted_input_tokens, 0)),
         "accounted_output_tokens": int(max(accounted_output_tokens, 0)),
-        "accounted_total_tokens": int(max(accounted_input_tokens, 0) + max(accounted_output_tokens, 0)),
+        "accounted_total_tokens": int(
+            max(accounted_input_tokens, 0) + max(accounted_output_tokens, 0)
+        ),
         "accounted_cost": float(max(accounted_cost, 0.0)),
         "drift": int(drift),
     }
-    with _GLOBAL_STATS_LOCK:
-        _GLOBAL_TOKEN_DRIFT_EVENTS.append(event)
-        if len(_GLOBAL_TOKEN_DRIFT_EVENTS) > 200:
-            del _GLOBAL_TOKEN_DRIFT_EVENTS[:-200]
+    state = shared_state or _DEFAULT_SHARED_STATE
+    async with state.lock:
+        state.token_drift_events.append(event)
+        if len(state.token_drift_events) > 200:
+            del state.token_drift_events[:-200]
 
     if abs(drift) > threshold:
         logger.warning(
@@ -148,14 +160,14 @@ def _record_token_drift(
         )
 
 
-def get_token_drift_events() -> list[dict[str, int | float | str]]:
-    with _GLOBAL_STATS_LOCK:
-        return list(_GLOBAL_TOKEN_DRIFT_EVENTS)
+def get_token_drift_events(shared_state: SharedLLMState | None = None) -> list[dict[str, int | float | str]]:
+    state = shared_state or _DEFAULT_SHARED_STATE
+    return list(state.token_drift_events)
 
 
-def get_usage_events() -> list[dict[str, int | float | str]]:
-    with _GLOBAL_STATS_LOCK:
-        return list(_GLOBAL_USAGE_EVENTS)
+def get_usage_events(shared_state: SharedLLMState | None = None) -> list[dict[str, int | float | str]]:
+    state = shared_state or _DEFAULT_SHARED_STATE
+    return list(state.usage_events)
 
 
 def _estimate_input_tokens_for_model(
@@ -185,9 +197,7 @@ def _estimate_output_tokens_for_response(response: Any) -> int:
                 content = getattr(message, "content", "") or ""
                 if isinstance(content, list):
                     text_parts = [
-                        str(part.get("text", ""))
-                        for part in content
-                        if isinstance(part, dict)
+                        str(part.get("text", "")) for part in content if isinstance(part, dict)
                     ]
                     content = "\n".join(p for p in text_parts if p)
     except Exception:  # noqa: BLE001
@@ -217,8 +227,8 @@ def _extract_cost_for_model(model_name: str, response: Any) -> float:
                 cached = getattr(prompt_details, "cached_tokens", 0) or 0
             tok_in = max(0, tok_in - min(cached, tok_in))
             return (tok_in * rate_in + tok_out * rate_out) / 1_000_000
-    except Exception:  # noqa: BLE001
-        pass
+    except Exception as _cost_err:  # noqa: BLE001
+        logger.debug("Cost extraction (rate-based) failed", exc_info=True)
 
     try:
         if hasattr(response, "_hidden_params"):
@@ -226,8 +236,8 @@ def _extract_cost_for_model(model_name: str, response: Any) -> float:
         cost = completion_cost(response, model=model_name) or 0.0
         if cost > 0:
             return cost
-    except Exception:  # noqa: BLE001
-        pass
+    except Exception as _cost_err:  # noqa: BLE001
+        logger.debug("Cost extraction (completion_cost) failed", exc_info=True)
 
     try:
         usage = getattr(response, "usage", None)
@@ -243,16 +253,14 @@ def _extract_cost_for_model(model_name: str, response: Any) -> float:
             candidates = [model_name, bare, bare.lower(), model_name.lower()]
             model_cost_lower = {k.lower(): v for k, v in litellm.model_cost.items()}
             for candidate in candidates:
-                info = litellm.model_cost.get(candidate) or model_cost_lower.get(
-                    candidate.lower()
-                )
+                info = litellm.model_cost.get(candidate) or model_cost_lower.get(candidate.lower())
                 if info:
                     r_in = info.get("input_cost_per_token", 0) or 0
                     r_out = info.get("output_cost_per_token", 0) or 0
                     if r_in or r_out:
                         return (tok_in * r_in) + (tok_out * r_out)
-    except Exception:  # noqa: BLE001
-        pass
+    except Exception as _cost_err:  # noqa: BLE001
+        logger.debug("Cost extraction (model_cost lookup) failed", exc_info=True)
     return 0.0
 
 
@@ -262,11 +270,11 @@ def record_external_completion_usage(
     messages: list[dict[str, Any]] | None = None,
     estimated_tokens: int | None = None,
 ) -> None:
-    with _GLOBAL_STATS_LOCK:
-        _GLOBAL_TOTAL_STATS.requests += 1
-        if model_name not in _GLOBAL_PER_MODEL_STATS:
-            _GLOBAL_PER_MODEL_STATS[model_name] = RequestStats()
-        _GLOBAL_PER_MODEL_STATS[model_name].requests += 1
+    state = _DEFAULT_SHARED_STATE
+    state.total_stats.requests += 1
+    if model_name not in state.per_model_stats:
+        state.per_model_stats[model_name] = RequestStats()
+    state.per_model_stats[model_name].requests += 1
 
     actual_prompt_tokens = 0
     actual_completion_tokens = 0
@@ -294,51 +302,57 @@ def record_external_completion_usage(
 
     cost = _extract_cost_for_model(model_name, response)
 
-    with _GLOBAL_STATS_LOCK:
-        _GLOBAL_TOTAL_STATS.input_tokens += int(input_tokens)
-        _GLOBAL_TOTAL_STATS.output_tokens += int(output_tokens)
-        _GLOBAL_TOTAL_STATS.cached_tokens += int(cached_tokens)
-        _GLOBAL_TOTAL_STATS.cost += float(cost)
-        _GLOBAL_TOTAL_STATS.completed_requests += 1
-
-        if model_name not in _GLOBAL_PER_MODEL_STATS:
-            _GLOBAL_PER_MODEL_STATS[model_name] = RequestStats()
-        model_stats = _GLOBAL_PER_MODEL_STATS[model_name]
-        model_stats.input_tokens += int(input_tokens)
-        model_stats.output_tokens += int(output_tokens)
-        model_stats.cached_tokens += int(cached_tokens)
-        model_stats.cost += float(cost)
-        model_stats.completed_requests += 1
-
-        _GLOBAL_USAGE_EVENTS.append(
-            {
-                "model": model_name,
-                "input_tokens": int(input_tokens),
-                "output_tokens": int(output_tokens),
-                "cached_tokens": int(cached_tokens),
-                "total_tokens": int(input_tokens) + int(output_tokens),
-                "cost": float(cost),
-            }
-        )
-        if len(_GLOBAL_USAGE_EVENTS) > 500:
-            del _GLOBAL_USAGE_EVENTS[:-500]
-
-    _record_token_drift(
-        model_name=model_name,
-        estimated_tokens=int(estimated_tokens or 0),
-        actual_prompt_tokens=int(actual_prompt_tokens),
-        actual_completion_tokens=int(actual_completion_tokens),
-        accounted_input_tokens=int(input_tokens),
-        accounted_output_tokens=int(output_tokens),
-        accounted_cost=float(cost),
+    state.total_stats.input_tokens += int(input_tokens)
+    state.total_stats.output_tokens += int(output_tokens)
+    state.total_stats.cached_tokens += int(cached_tokens)
+    state.total_stats.cost += float(cost)
+    state.total_stats.completed_requests += 1
+
+    if model_name not in state.per_model_stats:
+        state.per_model_stats[model_name] = RequestStats()
+    model_stats = state.per_model_stats[model_name]
+    model_stats.input_tokens += int(input_tokens)
+    model_stats.output_tokens += int(output_tokens)
+    model_stats.cached_tokens += int(cached_tokens)
+    model_stats.cost += float(cost)
+    model_stats.completed_requests += 1
+
+    state.usage_events.append(
+        {
+            "model": model_name,
+            "input_tokens": int(input_tokens),
+            "output_tokens": int(output_tokens),
+            "cached_tokens": int(cached_tokens),
+            "total_tokens": int(input_tokens) + int(output_tokens),
+            "cost": float(cost),
+        }
     )
+    if len(state.usage_events) > 500:
+        del state.usage_events[:-500]
+
+    # NOTE: _record_token_drift is now async-only; fire-and-forget from sync context
+    import asyncio
+    try:
+        asyncio.create_task(
+            _record_token_drift_async(
+                model_name=model_name,
+                estimated_tokens=int(estimated_tokens or 0),
+                actual_prompt_tokens=int(actual_prompt_tokens),
+                actual_completion_tokens=int(actual_completion_tokens),
+                accounted_input_tokens=int(input_tokens),
+                accounted_output_tokens=int(output_tokens),
+                accounted_cost=float(cost),
+            )
+        )
+    except RuntimeError:
+        pass
 
 
 def validate_llm_accounting_invariants() -> dict[str, Any]:
-    with _GLOBAL_STATS_LOCK:
-        total = _GLOBAL_TOTAL_STATS
-        usage_events = list(_GLOBAL_USAGE_EVENTS)
-        drift_event_count = len(_GLOBAL_TOKEN_DRIFT_EVENTS)
+    state = _DEFAULT_SHARED_STATE
+    total = state.total_stats
+    usage_events = list(state.usage_events)
+    drift_event_count = len(state.token_drift_events)
 
     usage_event_count = len(usage_events)
     summed_input = sum(int(e.get("input_tokens", 0) or 0) for e in usage_events)
@@ -382,139 +396,6 @@ def validate_llm_accounting_invariants() -> dict[str, Any]:
 # is allowed (HALF_OPEN). If it succeeds, circuit closes; if it fails, circuit
 # reopens for another 60s.
 
-from enum import Enum
-
-
-class CircuitState(Enum):
-    CLOSED = "closed"      # Normal operation
-    OPEN = "open"          # Blocking requests (failure threshold exceeded)
-    HALF_OPEN = "half_open"  # Testing if service recovered
-
-
-@dataclass
-class CircuitBreaker:
-    """Circuit breaker to prevent cascading LLM failures.
-    
-    Tracks failure rate and temporarily blocks requests when threshold is exceeded.
-    """
-    failure_threshold: int | None = None  # None = use default, otherwise use this value
-    timeout_seconds: float = 60.0   # How long to wait before testing recovery
-    _state: CircuitState = field(default_factory=lambda: CircuitState.CLOSED)
-    _failure_count: int = 0
-    _last_failure_time: float = 0.0
-    _lock: threading.Lock = field(default_factory=threading.Lock)
-    
-    def __post_init__(self) -> None:
-        """Initialize from config if available."""
-        # Use explicit value if provided, otherwise fall back to config, then default of 5
-        if self.failure_threshold is None:
-            threshold = Config.get("phantom_circuit_breaker_threshold")
-            if threshold:
-                try:
-                    self.failure_threshold = max(1, int(threshold))
-                except ValueError:
-                    self.failure_threshold = 5
-            else:
-                self.failure_threshold = 5
-        
-        timeout = Config.get("phantom_circuit_breaker_timeout")
-        if timeout:
-            try:
-                self.timeout_seconds = max(1.0, float(timeout))
-            except ValueError:
-                pass
-    
-    def record_success(self) -> None:
-        """Record successful request - resets failure counter and closes circuit."""
-        with self._lock:
-            self._failure_count = 0
-            self._state = CircuitState.CLOSED
-    
-    def record_failure(self) -> None:
-        """Record failed request - may open circuit if threshold exceeded."""
-        with self._lock:
-            self._failure_count += 1
-            self._last_failure_time = time.monotonic()
-            
-            if self._failure_count >= self.failure_threshold:
-                self._state = CircuitState.OPEN
-                logger.warning(
-                    "Circuit breaker OPEN: %d consecutive LLM failures. "
-                    "Blocking requests for %.0fs to prevent cascading failures.",
-                    self._failure_count,
-                    self.timeout_seconds,
-                )
-    
-    def allow_request(self) -> bool:
-        """Check if a request should be allowed based on circuit state.
-        
-        Returns:
-            True if request allowed, False if blocked by open circuit
-        """
-        with self._lock:
-            if self._state == CircuitState.CLOSED:
-                return True
-            
-            if self._state == CircuitState.OPEN:
-                # Check if timeout elapsed - transition to HALF_OPEN for testing
-                elapsed = time.monotonic() - self._last_failure_time
-                if elapsed >= self.timeout_seconds:
-                    self._state = CircuitState.HALF_OPEN
-                    logger.info(
-                        "Circuit breaker HALF_OPEN: Testing LLM recovery after %.0fs cooldown.",
-                        elapsed,
-                    )
-                    return True  # Allow one test request
-                return False  # Still in timeout - block request
-            
-            # HALF_OPEN: allow request (will close on success or reopen on failure)
-            return True
-    
-    def get_state(self) -> CircuitState:
-        """Get current circuit state."""
-        with self._lock:
-            return self._state
-    
-    def reset(self) -> None:
-        """Manually reset circuit to CLOSED state."""
-        with self._lock:
-            self._failure_count = 0
-            self._state = CircuitState.CLOSED
-
-
-# Global circuit breaker instance (per-process singleton)
-_CIRCUIT_BREAKER = CircuitBreaker()
-
-
-def _is_circuit_breaker_enabled() -> bool:
-    raw = (Config.get("phantom_circuit_breaker_enabled") or "true").strip().lower()
-    return raw in {"1", "true", "yes", "on"}
-
-# ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-
-class _TokenRateLimiter:
-    def __init__(self) -> None:
-        self._calls_by_model: dict[str, list[float]] = {}
-
-    def _limit(self) -> int:
-        raw = os.getenv("PHANTOM_LLM_RATE_LIMIT_PER_MINUTE", "1000")
-        try:
-            parsed = int(raw)
-        except ValueError:
-            return 1000
-        return max(parsed, 1)
-
-    def check_and_record(self, model: str) -> bool:
-        now = time.monotonic()
-        window_start = now - 60.0
-        calls = self._calls_by_model.setdefault(model, [])
-        calls[:] = [stamp for stamp in calls if stamp >= window_start]
-        if len(calls) >= self._limit():
-            return False
-        calls.append(now)
-        return True
-
 
 class LLM:
     # Scan mode downgrade order for adaptive mode
@@ -522,20 +403,30 @@ class LLM:
         "deep": "standard",
         "standard": "quick",
     }
+    _prompt_cache: dict[tuple[str, str, tuple[str, ...]], str] = {}
+    _MAX_PROMPT_CACHE_ENTRIES: int = 100
 
-    def __init__(self, config: LLMConfig, agent_name: str | None = None):
+    def __init__(
+        self,
+        config: LLMConfig,
+        agent_name: str | None = None,
+        shared_state: SharedLLMState | None = None,
+    ):
         self.config = config
         self.agent_name = agent_name
         self._prompt_agent_name = agent_name
         self.agent_id: str | None = None
-        self._total_stats = _GLOBAL_TOTAL_STATS
+        # FIX: each LLM instance gets its own SharedLLMState by default,
+        # preventing unintended budget sharing across agents.
+        # FIX: default to the module-level shared state so all LLM instances
+        # contribute to global stats that the tracer reads.
+        self._shared_state = shared_state or _DEFAULT_SHARED_STATE
+        self._total_stats = self._shared_state.total_stats
         # Per-model breakdown: model_name -> RequestStats (only agent iteration calls)
-        self._per_model_stats = _GLOBAL_PER_MODEL_STATS
+        self._per_model_stats = self._shared_state.per_model_stats
         # Call type counters
-        self._agent_calls: int = 0    # LLM calls during agent loop iterations
-        self._error_calls: int = 0    # LLM calls that ended in an error (after retries)
+        self._agent_calls: int = 0  # LLM calls during agent loop iterations
         self.memory_compressor = MemoryCompressor(model_name=config.litellm_model)
-        self._prompt_cache: dict[tuple[str, str, tuple[str, ...]], str] = {}
         self._extra_tool_names: set[str] = set()
         self.runtime_allowed_tools = self._resolve_runtime_allowed_tools()
         self.system_prompt = self._load_system_prompt(self._prompt_agent_name)
@@ -569,15 +460,21 @@ class LLM:
         except ValueError:
             self._adaptive_threshold = 0.8
 
-    def _prompt_cache_key(self, agent_name: str | None, tool_names: tuple[str, ...]) -> tuple[str, str, tuple[str, ...]]:
+    def _prompt_cache_key(
+        self, agent_name: str | None, tool_names: tuple[str, ...]
+    ) -> tuple[str, str, tuple[str, ...], str, str]:
+        import os
+
         return (
             str(agent_name or ""),
             str(self.config.scan_mode or ""),
             tool_names,
+            os.environ.get("PHANTOM_TARGET_URL", ""),
+            os.environ.get("PHANTOM_SKILLS", ""),
         )
 
     def _select_tool_names(self, agent_name: str | None) -> list[str]:
-        subset_mode = (Config.get("phantom_tool_subset") or "core-fast").lower()
+        subset_mode = (Config.get("phantom_tool_subset") or "core").lower()
         if subset_mode == "full":
             from phantom.tools import get_tool_names
 
@@ -626,19 +523,13 @@ class LLM:
 
         try:
             prompt_dir = get_phantom_resource_path("agents", agent_name)
-            skills_dir = get_phantom_resource_path("skills")
             env = Environment(
-                loader=FileSystemLoader([prompt_dir, skills_dir]),
-                autoescape=select_autoescape(enabled_extensions=('jinja', 'html', 'htm', 'xml'), default_for_string=False),
+                loader=FileSystemLoader([prompt_dir]),
+                autoescape=select_autoescape(
+                    enabled_extensions=("jinja", "html", "htm", "xml"), default_for_string=False
+                ),
             )
 
-            skills_to_load = [
-                *list(self.config.skills or []),
-                f"scan_modes/{self.config.scan_mode}",
-            ]
-            skill_content = load_skills(skills_to_load)
-            env.globals["get_skill"] = lambda name: skill_content.get(name, "")
-
             if len(tool_names) == 0:
                 tools_prompt_fn = get_compact_tools_prompt
             else:
@@ -649,9 +540,9 @@ class LLM:
 
             result = template.render(
                 get_tools_prompt=tools_prompt_fn,
-                loaded_skill_names=list(skill_content.keys()),
                 phantom_port_range=os.environ.get("PHANTOM_PORT_RANGE", ""),
-                **skill_content,
+                target_url=os.environ.get("PHANTOM_TARGET_URL", ""),
+                enabled_tool_names=tool_names,
             )
             prompt = str(result)
             if not prompt.strip():
@@ -661,13 +552,16 @@ class LLM:
             logger.error("Failed to load system prompt for agent %s", agent_name, exc_info=True)
             prompt = self._build_fallback_system_prompt(tool_names)
 
+        # FIX H3: cap prompt cache to prevent unbounded growth
+        if len(self._prompt_cache) >= self._MAX_PROMPT_CACHE_ENTRIES:
+            self._prompt_cache.clear()
         self._prompt_cache[cache_key] = prompt
         return prompt
 
     def _build_fallback_system_prompt(self, tool_names: tuple[str, ...]) -> str:
         try:
             if tool_names:
-                tools_prompt = get_tools_prompt_subset(list(tool_names))
+                tools_prompt = get_tools_prompt_subset(list(tool_names), use_compact=True)
             else:
                 tools_prompt = get_compact_tools_prompt()
         except Exception:  # noqa: BLE001
@@ -726,21 +620,22 @@ class LLM:
     async def generate(
         self, conversation_history: list[dict[str, Any]]
     ) -> AsyncIterator[LLMResponse]:
-        global _GLOBAL_RATE_LIMIT_UNTIL
-        now = time.monotonic()
-        if now < _GLOBAL_RATE_LIMIT_UNTIL:
-            wait_time = _GLOBAL_RATE_LIMIT_UNTIL - now
-            logger.warning("Global rate limit in effect, agent '%s' sleeping for %.1fs...", self.agent_name, wait_time)
+        wait_time = 0.0
+        should_sleep = False
+        async with self._shared_state.lock:
+            now = time.monotonic()
+            if now < self._shared_state.rate_limit_until:
+                wait_time = self._shared_state.rate_limit_until - now
+                should_sleep = True
+                logger.warning(
+                    "Global rate limit in effect, agent '%s' sleeping for %.1fs...",
+                    self.agent_name,
+                    wait_time,
+                )
+        if should_sleep:
             await asyncio.sleep(wait_time)
 
-        # RELIABILITY REC MED-5: Check circuit breaker before making request
-        if _is_circuit_breaker_enabled() and not _CIRCUIT_BREAKER.allow_request():
-            raise LLMRequestFailedError(
-                message="LLM circuit breaker is OPEN - too many consecutive failures",
-                details=f"Circuit state: {_CIRCUIT_BREAKER.get_state().value}. Wait before retrying."
-            )
-
-        self._check_budget()
+        await self._check_budget()
         self._agent_calls += 1
         messages = await self._prepare_messages(conversation_history)
         messages = await self._enforce_request_size_limits(messages)
@@ -749,102 +644,100 @@ class LLM:
 
         # Optionally switch model based on routing config
         original_model = self.config.litellm_model
-        if self._routing_enabled:
-            routed = self._pick_routing_model(messages)
-            if routed and routed != original_model:
-                logger.debug("Routing: switching model %s ΓåÆ %s", original_model, routed)
-                self.config.litellm_model = routed
-        primary_model = self.config.litellm_model
-
-        primary_exhausted = False
-        _last_error: Exception | None = None
-        # 429 errors get a separate, higher retry budget to survive long rate-limit windows
-        ratelimit_max_retries = int(Config.get("phantom_llm_ratelimit_max_retries") or "10")
-        for attempt in range(ratelimit_max_retries + 1):
-            try:
-                async for response in self._stream(messages):
-                    yield response
-                # Restore routing override after successful call
-                self.config.litellm_model = original_model
-                self._check_adaptive_scan_mode()
-                return  # noqa: TRY300
-            except LLMRequestFailedError:
-                self.config.litellm_model = original_model
-                raise
-            except Exception as e:  # noqa: BLE001
-                # Extract error code once ΓÇö used for exhaustion check and backoff
-                code = getattr(e, "status_code", None) or getattr(
-                    getattr(e, "response", None), "status_code", None
-                )
-                # Rate-limit errors use the larger ratelimit_max_retries budget.
-                # Unknown-code errors are capped to avoid long blind retry loops.
-                if code == 429:
-                    effective_max = ratelimit_max_retries
-                elif code is None:
-                    effective_max = min(max_retries, unknown_error_max_retries)
-                else:
-                    effective_max = max_retries
-                if attempt >= effective_max or not self._should_retry(e):
-                    _last_error = e
-                    primary_exhausted = True
-                    break
-                # Emit audit event so retries are visible in the audit log
-                _retry_audit = (
-                    __import__("phantom.logging.audit", fromlist=["get_audit_logger"])
-                    .get_audit_logger()
-                )
-                if _retry_audit:
-                    _retry_audit.log_llm_error(
-                        agent_id=self.agent_id or "unknown",
-                        model=self.config.litellm_model,
-                        error=str(e)[:500],
-                        attempt=attempt + 1,
-                    )
-                # Longer backoff for rate limits (429) ΓÇö up to 120 s; others up to 10 s
-                if code == 429:
-                    wait = min(120, 4 * (2**attempt))
-                    logger.warning(
-                        "Rate limit hit (attempt %d/%d); backing off %.0fs globally...",
-                        attempt + 1, ratelimit_max_retries, wait,
+        try:
+            if self._routing_enabled:
+                routed = self._pick_routing_model(messages)
+                if routed and routed != original_model:
+                    logger.debug("Routing: switching model %s ΓåÆ %s", original_model, routed)
+                    self.config.litellm_model = routed
+            primary_model = self.config.litellm_model
+
+            primary_exhausted = False
+            _last_error: Exception | None = None
+            # 429 errors get a separate, higher retry budget to survive long rate-limit windows
+            ratelimit_max_retries = int(Config.get("phantom_llm_ratelimit_max_retries") or "10")
+            for attempt in range(ratelimit_max_retries + 1):
+                try:
+                    async for response in self._stream(messages):
+                        yield response
+                    self._check_adaptive_scan_mode()
+                    return  # noqa: TRY300
+                except LLMRequestFailedError:
+                    raise
+                except Exception as e:  # noqa: BLE001
+                    # Extract error code once ΓÇö used for exhaustion check and backoff
+                    code = getattr(e, "status_code", None) or getattr(
+                        getattr(e, "response", None), "status_code", None
                     )
-                    with _GLOBAL_STATS_LOCK:
-                        _GLOBAL_RATE_LIMIT_UNTIL = max(_GLOBAL_RATE_LIMIT_UNTIL, time.monotonic() + wait)
-                else:
-                    wait = min(10, 2 * (2**attempt))
-                await asyncio.sleep(wait)
-
-        # Primary model exhausted ΓÇö try fallback if configured
-        if (
-            primary_exhausted
-            and self._fallback_llm_name
-            and self._fallback_llm_name != primary_model
-        ):
-            logger.warning(
-                "Primary model %s exhausted ΓÇö retrying with fallback %s",
-                primary_model,
-                self._fallback_llm_name,
-            )
-            try:
-                self.config.litellm_model = self._fallback_llm_name
-                async for response in self._stream(messages):
-                    yield response
-                self._check_adaptive_scan_mode()  # honour cost budget after fallback too
-                return  # noqa: TRY300
-            except Exception as e:  # noqa: BLE001
-                self._error_calls += 1
-                self._raise_error(e)
-            finally:
-                # Always restore the original model, even if fallback raises.
-                self.config.litellm_model = original_model
-        elif primary_exhausted:
+                    # Rate-limit errors use the larger ratelimit_max_retries budget.
+                    # Unknown-code errors are capped to avoid long blind retry loops.
+                    if code == 429:
+                        effective_max = ratelimit_max_retries
+                    elif code is None:
+                        effective_max = min(max_retries, unknown_error_max_retries)
+                    else:
+                        effective_max = max_retries
+                    if attempt >= effective_max or not self._should_retry(e):
+                        _last_error = e
+                        primary_exhausted = True
+                        break
+                    # Emit audit event so retries are visible in the audit log
+                    _retry_audit = __import__(
+                        "phantom.logging.audit", fromlist=["get_audit_logger"]
+                    ).get_audit_logger()
+                    if _retry_audit:
+                        _retry_audit.log_llm_error(
+                            agent_id=self.agent_id or "unknown",
+                            model=self.config.litellm_model,
+                            error=str(e)[:500],
+                            attempt=attempt + 1,
+                        )
+                    # Longer backoff for rate limits (429) ΓÇö up to 120 s; others up to 10 s
+                    if code == 429:
+                        wait = min(120, 4 * (2**attempt))
+                        logger.warning(
+                            "Rate limit hit (attempt %d/%d); backing off %.0fs globally...",
+                            attempt + 1,
+                            ratelimit_max_retries,
+                            wait,
+                        )
+                        async with self._shared_state.lock:
+                            self._shared_state.rate_limit_until = max(
+                                self._shared_state.rate_limit_until, time.monotonic() + wait
+                            )
+                    else:
+                        wait = min(10, 2 * (2**attempt))
+                    await asyncio.sleep(wait)
+
+            # Primary model exhausted ΓÇö try fallback if configured
+            if (
+                primary_exhausted
+                and self._fallback_llm_name
+                and self._fallback_llm_name != primary_model
+            ):
+                logger.warning(
+                    "Primary model %s exhausted ΓÇö retrying with fallback %s",
+                    primary_model,
+                    self._fallback_llm_name,
+                )
+                # FIX: Enforce budget gate before burning money on fallback model.
+                await self._check_budget()
+                try:
+                    self.config.litellm_model = self._fallback_llm_name
+                    async for response in self._stream(messages):
+                        yield response
+                    self._check_adaptive_scan_mode()  # honour cost budget after fallback too
+                    return  # noqa: TRY300
+                except Exception as e:  # noqa: BLE001
+                    self._raise_error(e)
+            elif primary_exhausted:
+                last_err_str = f": {_last_error}" if _last_error else ""
+
+                raise LLMRequestFailedError(f"All retries exhausted for primary model{last_err_str}")
+        finally:
+            # QUICK WIN: guarantee original model is restored even if the generator
+            # is cancelled, closed, or an unexpected exception propagates.
             self.config.litellm_model = original_model
-            self._error_calls += 1
-            last_err_str = f": {_last_error}" if _last_error else ""
-            if _is_circuit_breaker_enabled():
-                _CIRCUIT_BREAKER.record_failure()
-            raise LLMRequestFailedError(
-                f"All retries exhausted for primary model{last_err_str}"
-            )
 
     async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
         accumulated = ""
@@ -860,6 +753,7 @@ class LLM:
 
         # ΓöÇΓöÇ Audit: log the outgoing request ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
         from phantom.logging.audit import get_audit_logger as _get_audit
+
         _audit = _get_audit()
         _audit_rid = (
             _audit.log_llm_request(
@@ -867,41 +761,52 @@ class LLM:
                 model=self.config.litellm_model,
                 messages=messages,
             )
-            if _audit else None
+            if _audit
+            else None
         )
         _audit_t0 = time.monotonic()
         # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
-        response = await tracked_acompletion(
-            **self._build_completion_args(messages),
-            stream=True,
-            reducer=self._safe_reduce_messages,
+        _completion_timeout = float(Config.get("phantom_llm_completion_timeout") or "300")
+        response = await asyncio.wait_for(
+            tracked_acompletion(
+                **self._build_completion_args(messages),
+                stream=True,
+                reducer=self._safe_reduce_messages,
+            ),
+            timeout=_completion_timeout,
         )
 
         async for chunk in response:
             chunks.append(chunk)
-            if done_streaming:
-                done_streaming += 1
-                if getattr(chunk, "usage", None) or done_streaming > 5:
-                    break
-                continue
             delta = self._get_chunk_content(chunk)
             if delta:
                 accumulated += delta
-                if "</function>" in accumulated or "</invoke>" in accumulated:
-                    end_tag = "</function>" if "</function>" in accumulated else "</invoke>"
-                    pos = accumulated.find(end_tag)
-                    accumulated = accumulated[: pos + len(end_tag)]
+            if done_streaming:
+                # After yielding the first tool call, continue accumulating
+                # but don't yield intermediate chunks to avoid display jitter.
+                # Still yield final content when we see usage metadata.
+                if getattr(chunk, "usage", None):
                     yield LLMResponse(content=accumulated)
-                    done_streaming = 1
-                    continue
+                    break
+                continue
+            if delta and ("</function>" in accumulated or "</invoke>" in accumulated):
+                # Yield partial content up to first function for streaming display,
+                # but keep accumulating full content so multi-tool calls are preserved.
+                end_tag = "</function>" if "</function>" in accumulated else "</invoke>"
+                pos = accumulated.find(end_tag)
+                display_accumulated = accumulated[: pos + len(end_tag)]
+                yield LLMResponse(content=display_accumulated)
+                done_streaming = 1
+                continue
+            if delta:
                 yield LLMResponse(content=accumulated)
 
         if chunks:
             rebuilt = stream_chunk_builder(chunks)
-            usage_delta = self._update_usage_stats(rebuilt, messages)
-            self._update_per_model_stats(usage_delta)
-            _record_token_drift(
+            usage_delta = await self._update_usage_stats(rebuilt, messages)
+            await self._update_per_model_stats(usage_delta)
+            await _record_token_drift_async(
                 model_name=self.config.litellm_model or "unknown",
                 estimated_tokens=self._estimate_input_tokens(messages),
                 actual_prompt_tokens=int(usage_delta.get("actual_prompt_tokens", 0) or 0),
@@ -911,7 +816,7 @@ class LLM:
                 accounted_cost=float(usage_delta.get("cost", 0.0) or 0.0),
             )
             request_cost = float(usage_delta.get("cost", 0.0) or 0.0)
-            with _GLOBAL_STATS_LOCK:
+            async with self._shared_state.lock:
                 total_input_tokens = self._total_stats.input_tokens
                 total_output_tokens = self._total_stats.output_tokens
                 total_cost = self._total_stats.cost
@@ -927,15 +832,13 @@ class LLM:
             )
             self._check_per_request_budget(request_cost)
 
-        # RELIABILITY REC MED-5: Record successful LLM call - close circuit
-        if _is_circuit_breaker_enabled():
-            _CIRCUIT_BREAKER.record_success()
-
         accumulated = normalize_tool_format(accumulated)
         # Strip thinking blocks before truncation so embedded tool calls do not
         # hide the real execution payload.
         accumulated = strip_thinking_blocks(accumulated)
-        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
+        # FIX: Removed _truncate_to_first_function which was discarding multi-tool calls.
+        # parse_tool_invocations uses finditer and extracts ALL complete <function> blocks.
+        accumulated = fix_incomplete_tool_call(accumulated)
         _parsed_tools = parse_tool_invocations(accumulated)
 
         # AUDIT-FIX-09: When the LLM produces text that looks like a tool call
@@ -970,20 +873,17 @@ class LLM:
             if len(available_tools) > 25:
                 available_preview += ", ..."
 
+            # FIX: Ultra-compact malformed notice. Previously ~200+ tokens, now ~40.
+            # Repeating the full tool list and 3 examples on every bad turn wasted
+            # context and compounded truncation. The LLM already has the catalog in
+            # the system prompt; it just needs a nudge to use exact names.
             malformed_notice = (
-                "[SYSTEM: Tool call malformed and NOT executed. Use exact XML tags and a REAL registered tool name.\n"
-                "Rules:\n"
-                "- Format: <function=get_scan_status></function> or <function=send_request><parameter=method>GET</parameter><parameter=url>http://example.com</parameter></function>\n"
-                "- Tool names are snake_case. Do NOT flatten underscores or invent aliases.\n"
-                "- If no args required, still call: <function=get_scan_status></function>.\n"
-                f"Available tools (subset): {available_preview}]\n"
+                "[SYSTEM: Malformed tool call ΓÇö NOT executed. "
+                "Use exact <function=NAME><parameter=KEY>VAL</parameter></function> format. "
+                f"Valid names include: {available_preview}]\n"
             )
-            if examples:
-                malformed_notice += "[SYSTEM: Valid examples]\n" + "\n".join(examples) + "\n"
 
-            accumulated = (
-                malformed_notice + accumulated
-            )
+            accumulated = malformed_notice + accumulated
 
         # ΓöÇΓöÇ Audit: log the completed response ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
         if _audit and _audit_rid:
@@ -1011,22 +911,12 @@ class LLM:
     ) -> list[dict[str, Any]]:
         messages = [{"role": "system", "content": self.system_prompt}]
 
-        if self.agent_name:
-            messages.append(
-                {
-                    "role": "user",
-                    "content": (
-                        f"\n\n<agent_identity>\n"
-                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
-                        f"<agent_name>{self.agent_name}</agent_name>\n"
-                        f"<agent_id>{self.agent_id}</agent_id>\n"
-                        f"</agent_identity>\n\n"
-                    ),
-                }
-            )
-
         # Remove thinking blocks before compression/truncation so embedded tool
         # calls do not get dropped or hidden before parsing.
+        # FIX: deep-copy each message dict so we don't mutate the caller's state.
+        from copy import deepcopy
+
+        messages = [deepcopy(msg) for msg in messages]
         for msg in messages:
             content = msg.get("content")
             if isinstance(content, str):
@@ -1059,23 +949,29 @@ class LLM:
                 self.memory_compressor.compress_history, compression_input, _state
             )
         )
-        conversation_history.clear()
-        conversation_history.extend(compressed)
+        # FIX: do NOT mutate the caller's list in place. Build a fresh list
+        # from compressed output so state.history remains intact.
         if _archive and _state is not None and hasattr(_state, "clear_archived_messages"):
             try:
                 _state.clear_archived_messages()
             except Exception:
                 pass
 
-        # ΓöÇΓöÇ Finding anchors injection ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-        # AUDIT-FIX-04: Re-inject high-signal findings continuously from iter 2+
-        # (was: only at 75% of max iterations, far too late for exploitation).
-        # This ensures the agent always "knows" about confirmed vulnerabilities
-        # even when the full history has been summarised away.
+        # ΓöÇΓöÇ Dynamic Context Injection ΓöÇΓöÇ
+        # Inject metadata as user context combined with the first real message
+        # This avoids consecutive user messages which breaks prompt caching alternation rules
+        dynamic_user_content = ""
+        if self.agent_name:
+            dynamic_user_content += (
+                f"<agent_identity>\n"
+                f"<meta>Internal metadata: do not echo or reference.</meta>\n"
+                f"<agent_name>{self.agent_name}</agent_name>\n"
+                f"<agent_id>{self.agent_id}</agent_id>\n"
+                f"</agent_identity>\n\n"
+            )
+
         _has_anchors = (
-            _state is not None
-            and hasattr(_state, "finding_anchors")
-            and _state.finding_anchors
+            _state is not None and hasattr(_state, "finding_anchors") and _state.finding_anchors
         )
         if _has_anchors:
             # Only inject if not already present in last 5 messages
@@ -1086,35 +982,82 @@ class LLM:
             if not _already_injected:
                 anchor_lines = []
                 for anchor in _state.finding_anchors[:15]:  # cap at 15
+                    status = str(anchor.get("status", "active")).lower()
+                    if status in {"transient", "invalidated", "superseded"}:
+                        continue
                     text = anchor.get("text", "").strip()
                     if text:
                         anchor_lines.append(f"- {text[:600]}")  # 600 chars, was 300
                 if anchor_lines:
-                    anchor_reminder = (
+                    dynamic_user_content += (
                         "<finding_anchors>\n"
                         "Confirmed signals from earlier in this scan ΓÇö "
                         "report any that have NOT been reported yet:\n"
                         + "\n".join(anchor_lines)
-                        + "\n</finding_anchors>"
+                        + "\n</finding_anchors>\n\n"
                     )
-                    messages.append({"role": "user", "content": anchor_reminder})
-        # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
-        messages.extend(compressed)
+        if dynamic_user_content:
+            if compressed and compressed[0].get("role") == "user":
+                first_msg = dict(compressed[0])
+                first_msg["content"] = dynamic_user_content + str(first_msg.get("content", ""))
+                messages.append(first_msg)
+                messages.extend(compressed[1:])
+            else:
+                messages.append({"role": "user", "content": dynamic_user_content.strip()})
+                messages.extend(compressed)
+        else:
+            messages.extend(compressed)
 
         if messages[-1].get("role") == "assistant":
             messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})
 
-        if self._is_anthropic() and self.config.enable_prompt_caching:
+        # FIX: merge consecutive user messages to respect Anthropic prompt-caching
+        # alternation rules and reduce token bloat from repeated role markers.
+        messages = self._merge_consecutive_same_role(messages)
+
+        # FIX: Use supports_prompt_caching() instead of _is_anthropic() so ALL
+        # supported providers (DeepSeek, Anthropic, OpenAI) get prompt caching.
+        if (
+            self.config.enable_prompt_caching
+            and supports_prompt_caching(self.config.canonical_model)
+        ):
             messages = self._add_cache_control(messages)
 
         return messages
 
+    def _merge_consecutive_same_role(
+        self, messages: list[dict[str, Any]]
+    ) -> list[dict[str, Any]]:
+        """Merge consecutive messages with the same role to avoid breaking
+        provider-specific caching / alternation rules."""
+        if not messages:
+            return messages
+        merged: list[dict[str, Any]] = []
+        for msg in messages:
+            role = msg.get("role")
+            content = msg.get("content", "")
+            if merged and merged[-1].get("role") == role:
+                prev = dict(merged[-1])
+                prev_content = prev.get("content", "")
+                if isinstance(prev_content, str) and isinstance(content, str):
+                    prev["content"] = prev_content + "\n\n" + content
+                elif isinstance(prev_content, list) and isinstance(content, list):
+                    prev["content"] = prev_content + content
+                else:
+                    prev["content"] = str(prev_content) + "\n\n" + str(content)
+                merged[-1] = prev
+            else:
+                merged.append(dict(msg))
+        return merged
+
     def _estimate_request_size(self, messages: list[dict[str, Any]]) -> tuple[int, int]:
         serialized = json.dumps(messages, ensure_ascii=False, default=str)
         chars = len(serialized)
         try:
-            estimated_tokens = litellm.token_counter(model=self.config.litellm_model, messages=messages)
+            estimated_tokens = litellm.token_counter(
+                model=self.config.litellm_model, messages=messages
+            )
         except Exception:  # noqa: BLE001
             estimated_tokens = max(chars // 4, 1)
         return chars, estimated_tokens
@@ -1156,7 +1099,9 @@ class LLM:
     ) -> list[dict[str, Any]]:
         max_request_chars = int(Config.get("phantom_max_request_chars") or "900000")
         max_request_tokens = int(
-            Config.get("phantom_max_request_estimated_tokens") or Config.get("phantom_ollama_context_length") or "220000"
+            Config.get("phantom_max_request_estimated_tokens")
+            or Config.get("phantom_ollama_context_length")
+            or "220000"
         )
         from phantom.logging.audit import get_audit_logger as _get_audit
 
@@ -1198,7 +1143,10 @@ class LLM:
             if attempt == 1:
                 before_chars, before_tokens = chars, est_tokens
                 current = self._safe_reduce_messages(current)
-                if self._is_anthropic() and self.config.enable_prompt_caching:
+                if (
+                    self.config.enable_prompt_caching
+                    and supports_prompt_caching(self.config.canonical_model)
+                ):
                     current = self._add_cache_control(current)
                 after_chars, after_tokens = self._estimate_request_size(current)
                 if _audit:
@@ -1233,8 +1181,7 @@ class LLM:
                 continue
 
         final_chars, final_tokens = self._estimate_request_size(current)
-        if _is_circuit_breaker_enabled():
-            _CIRCUIT_BREAKER.record_failure()
+
         raise LLMRequestFailedError(
             "Request preflight hard cap exceeded: "
             f"chars={final_chars} (limit={max_request_chars}), "
@@ -1256,9 +1203,9 @@ class LLM:
             return int(env_val)
         return None  # let the model use its full output budget
 
-    def _check_budget(self) -> None:
+    async def _check_budget(self) -> None:
         """Check budget and apply graceful degradation at thresholds.
-        
+
         EFFICIENCY FIX SCALE-P1.1: Graceful Limit Degradation
         - 80% budget: Warning logged, continue normally
         - 90% budget: Warning logged, reduce reasoning effort, suggest wrap-up
@@ -1277,21 +1224,28 @@ class LLM:
             return
         if max_cost <= 0:
             return
-            
+
         # Get current global cost
         try:
             from phantom.telemetry.tracer import get_global_tracer
+
             tracer = get_global_tracer()
-            if tracer:
-                traced_cost = tracer.get_total_llm_stats()["total"]["cost"]
-                current_cost = max(float(traced_cost or 0.0), float(self._total_stats.cost or 0.0))
-            else:
-                current_cost = self._total_stats.cost
+            # FIX: read both local and tracer cost while holding the lock so the
+            # check is atomic. Previously local cost was read, lock released, then
+            # tracer cost read ΓÇö a race window where concurrent agents could both pass.
+            async with self._shared_state.lock:
+                local_cost = float(self._total_stats.cost or 0.0)
+                if tracer:
+                    traced_cost = tracer.get_total_llm_stats()["total"]["cost"]
+                    current_cost = max(float(traced_cost or 0.0), local_cost)
+                else:
+                    current_cost = local_cost
         except Exception:  # noqa: BLE001
-            current_cost = self._total_stats.cost
-        
+            async with self._shared_state.lock:
+                current_cost = float(self._total_stats.cost or 0.0)
+
         budget_fraction = current_cost / max_cost
-        
+
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
         # 80% threshold: Warning, continue normally
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
@@ -1300,11 +1254,13 @@ class LLM:
             logger.warning(
                 "BUDGET ALERT: 80%% used ($%.4f / $%.4f). "
                 "Consider wrapping up current testing phase.",
-                current_cost, max_cost,
+                current_cost,
+                max_cost,
             )
             # Log to audit
             try:
                 from phantom.logging.audit import get_audit_logger as _get_audit
+
                 _audit = _get_audit()
                 if _audit:
                     _audit.log_security_event(
@@ -1319,7 +1275,7 @@ class LLM:
                     )
             except Exception:  # noqa: BLE001
                 pass
-        
+
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
         # 90% threshold: Warning + reduce reasoning effort + inject wrap-up hint
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
@@ -1328,9 +1284,10 @@ class LLM:
             logger.warning(
                 "BUDGET CRITICAL: 90%% used ($%.4f / $%.4f). "
                 "Reducing reasoning effort and preparing for graceful shutdown.",
-                current_cost, max_cost,
+                current_cost,
+                max_cost,
             )
-            
+
             # Reduce reasoning effort to save tokens
             if self._reasoning_effort in ("high", "xhigh"):
                 self._reasoning_effort = "medium"
@@ -1338,20 +1295,22 @@ class LLM:
             elif self._reasoning_effort == "medium":
                 self._reasoning_effort = "low"
                 logger.info("Reasoning effort reduced from medium to low to conserve budget")
-            
+
             # Auto-downgrade scan mode if adaptive is enabled
             if self._adaptive_scan_enabled:
                 new_mode = self._SCAN_MODE_DOWNGRADE.get(self.config.scan_mode)
                 if new_mode:
                     logger.warning(
                         "Auto-downgrading scan mode %s ΓåÆ %s due to 90%% budget",
-                        self.config.scan_mode, new_mode
+                        self.config.scan_mode,
+                        new_mode,
                     )
                     self._apply_scan_mode_change(new_mode)
-            
+
             # Log to audit
             try:
                 from phantom.logging.audit import get_audit_logger as _get_audit
+
                 _audit = _get_audit()
                 if _audit:
                     _audit.log_security_event(
@@ -1368,7 +1327,7 @@ class LLM:
                     )
             except Exception:  # noqa: BLE001
                 pass
-        
+
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
         # 100% threshold: Hard stop or advisory continue
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
@@ -1378,11 +1337,11 @@ class LLM:
             if abort_on_limit in ("false", "0", "no"):
                 logger.warning(
                     "Budget exceeded: $%.4f >= max $%.4f ΓÇö advisory mode, continuing.",
-                    current_cost, max_cost,
+                    current_cost,
+                    max_cost,
                 )
                 return
-            if _is_circuit_breaker_enabled():
-                _CIRCUIT_BREAKER.record_failure()
+
             raise LLMRequestFailedError(
                 f"Budget exceeded: ${current_cost:.4f} >= max ${max_cost:.4f}"
             )
@@ -1397,8 +1356,6 @@ class LLM:
         except ValueError:
             return
         if request_cost > ceiling:
-            if _is_circuit_breaker_enabled():
-                _CIRCUIT_BREAKER.record_failure()
             raise LLMRequestFailedError(
                 f"Per-request budget exceeded: ${request_cost:.4f} > ceiling ${ceiling:.4f}"
             )
@@ -1426,7 +1383,9 @@ class LLM:
                 pinned.append(
                     {
                         "role": "user",
-                        "content": "<pinned_facts>\n" + "\n".join(anchor_lines) + "\n</pinned_facts>",
+                        "content": "<pinned_facts>\n"
+                        + "\n".join(anchor_lines)
+                        + "\n</pinned_facts>",
                     }
                 )
 
@@ -1477,10 +1436,10 @@ class LLM:
                 blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                 return blocks
         except Exception:  # noqa: BLE001, S110  # nosec B110
-            pass
+            logger.debug("Thinking block extraction failed", exc_info=True)
         return None
 
-    def _update_per_model_stats(self, usage_delta: dict[str, int | float]) -> None:
+    async def _update_per_model_stats(self, usage_delta: dict[str, int | float]) -> None:
         """Track per-model token/cost breakdown (agent calls only)."""
         try:
             input_tokens = int(usage_delta.get("input_tokens", 0) or 0)
@@ -1489,7 +1448,7 @@ class LLM:
             cost = float(usage_delta.get("cost", 0.0) or 0.0)
 
             model_key = self.config.litellm_model or "unknown"
-            with _GLOBAL_STATS_LOCK:
+            async with self._shared_state.lock:
                 if model_key not in self._per_model_stats:
                     self._per_model_stats[model_key] = RequestStats()
                 stats = self._per_model_stats[model_key]
@@ -1500,24 +1459,24 @@ class LLM:
                 stats.requests += 1
                 stats.completed_requests += 1
         except Exception:  # noqa: BLE001, S110  # nosec B110
-            pass
+            logger.debug("Per-model stats update failed", exc_info=True)
 
     def _pick_routing_model(self, messages: list[dict[str, Any]]) -> str | None:
         """
         Decide which model to use based on conversation context.
         Heuristic: if the last user message looks like a tool result
-        (starts with <tool_result or <function_results), we're in an
-        "execution" phase ΓåÆ use tool model. Otherwise ΓåÆ reasoning model.
+        (starts with <tool_result or <function_results), we're in a
+        tool-turn ΓåÆ use tool model. Otherwise ΓåÆ reasoning model.
         """
         if not self._routing_enabled:
             return None
-        last_user = next(
-            (m for m in reversed(messages) if m.get("role") == "user"), None
-        )
+        last_user = next((m for m in reversed(messages) if m.get("role") == "user"), None)
         content = (last_user or {}).get("content", "") or ""
         if isinstance(content, list):
             content = " ".join(
-                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
+                p.get("text", "")
+                for p in content
+                if isinstance(p, dict) and p.get("type") == "text"
             )
         content_lower = content.strip().lower()
         is_tool_result = content_lower.startswith(("<tool_result", "<function_results"))
@@ -1543,6 +1502,7 @@ class LLM:
         # Use global cost (all agents) so the threshold is applied consistently.
         try:
             from phantom.telemetry.tracer import get_global_tracer
+
             tracer = get_global_tracer()
             current_cost = (
                 tracer.get_total_llm_stats()["total"]["cost"] if tracer else self._total_stats.cost
@@ -1589,9 +1549,7 @@ class LLM:
                     content = getattr(message, "content", "") or ""
                     if isinstance(content, list):
                         text_parts = [
-                            str(part.get("text", ""))
-                            for part in content
-                            if isinstance(part, dict)
+                            str(part.get("text", "")) for part in content if isinstance(part, dict)
                         ]
                         content = "\n".join(p for p in text_parts if p)
         except Exception:  # noqa: BLE001
@@ -1601,10 +1559,10 @@ class LLM:
             return 0
         return max(len(content) // 4, 1)
 
-    def _update_usage_stats(
+    async def _update_usage_stats(
         self,
         response: Any,
-        messages: list[dict[str, Any]] | None = None,
+        messages: list[dict[str, Any]],
     ) -> dict[str, int | float]:
         deltas: dict[str, int | float] = {
             "input_tokens": 0,
@@ -1636,7 +1594,7 @@ class LLM:
                 # Estimate tokens to avoid reporting 0 which breaks cost tracking
                 logger.warning(
                     "API response missing usage stats - estimating tokens (model=%s)",
-                    self.config.litellm_model
+                    self.config.litellm_model,
                 )
                 input_tokens = self._estimate_input_tokens(messages)
                 output_tokens = self._estimate_output_tokens(response)
@@ -1647,6 +1605,12 @@ class LLM:
 
                 cost = self._extract_cost(response)
 
+            # FIX: if API reports 0 input tokens but we have messages,
+            # fallback to estimation so budget tracking doesn't break.
+            if input_tokens == 0 and messages:
+                input_tokens = self._estimate_input_tokens(messages)
+                actual_prompt_tokens = input_tokens
+
             deltas = {
                 "input_tokens": int(input_tokens),
                 "output_tokens": int(output_tokens),
@@ -1656,7 +1620,7 @@ class LLM:
                 "actual_completion_tokens": int(actual_completion_tokens),
             }
 
-            with _GLOBAL_STATS_LOCK:
+            async with self._shared_state.lock:
                 self._total_stats.requests += 1
                 self._total_stats.input_tokens += int(deltas["input_tokens"])
                 self._total_stats.output_tokens += int(deltas["output_tokens"])
@@ -1664,7 +1628,7 @@ class LLM:
                 self._total_stats.cost += float(deltas["cost"])
                 self._total_stats.completed_requests += 1
 
-                _GLOBAL_USAGE_EVENTS.append(
+                self._shared_state.usage_events.append(
                     {
                         "model": self.config.litellm_model or "unknown",
                         "input_tokens": int(deltas["input_tokens"]),
@@ -1674,8 +1638,8 @@ class LLM:
                         "cost": float(deltas["cost"]),
                     }
                 )
-                if len(_GLOBAL_USAGE_EVENTS) > 500:
-                    del _GLOBAL_USAGE_EVENTS[:-500]
+                if len(self._shared_state.usage_events) > 500:
+                    del self._shared_state.usage_events[:-500]
 
         except Exception:  # noqa: BLE001, S110  # nosec B110
             return deltas
@@ -1717,6 +1681,7 @@ class LLM:
         # 4. Manual litellm.model_cost registry lookup (handles Azure/other prefixes).
         try:
             import litellm as _litellm
+
             usage = getattr(response, "usage", None)
             tok_in = getattr(usage, "prompt_tokens", 0) or 0
             tok_out = getattr(usage, "completion_tokens", 0) or 0
@@ -1729,9 +1694,7 @@ class LLM:
                 model_key = self.config.litellm_model or ""
                 bare = model_key.split("/", 1)[-1] if "/" in model_key else model_key
                 candidates = [model_key, bare, bare.lower(), model_key.lower()]
-                model_cost_lower = {
-                    k.lower(): v for k, v in _litellm.model_cost.items()
-                }
+                model_cost_lower = {k.lower(): v for k, v in _litellm.model_cost.items()}
                 for candidate in candidates:
                     info = _litellm.model_cost.get(candidate) or model_cost_lower.get(
                         candidate.lower()
@@ -1743,6 +1706,27 @@ class LLM:
                             return (tok_in * r_in) + (tok_out * r_out)
         except Exception:  # noqa: BLE001
             pass
+        # Cost returned 0.0 ΓÇö model pricing may be missing from registry.
+        # Log a warning so operators know budget tracking is blind.
+        _total_toks = 0
+        try:
+            _u = getattr(response, "usage", None)
+            if _u is not None:
+                _total_toks = (getattr(_u, "prompt_tokens", 0) or 0) + (
+                    getattr(_u, "completion_tokens", 0) or 0
+                )
+        except Exception:  # noqa: BLE001
+            pass
+        if _total_toks > 0:
+            _model = self.config.litellm_model or "unknown"
+            logger.warning(
+                "Cost returned $0.00 for model=%s with %d tokens ΓÇö "
+                "model pricing may be missing from litellm registry. "
+                "Budget tracking is blind. Add model to _PHANTOM_EXTRA_MODELS in llm/__init__.py "
+                "or set PHANTOM_COST_PER_1M_INPUT / PHANTOM_COST_PER_1M_OUTPUT.",
+                _model,
+                _total_toks,
+            )
         return 0.0
 
     def _is_context_too_large(self, e: Exception) -> bool:
@@ -1770,14 +1754,14 @@ class LLM:
                 "prompt is too long",
                 "exceeds the model",
                 # Additional provider-specific phrases
-                "model context limits",   # OpenRouter
-                "reduce context",          # generic
-                "request too large",       # HTTP proxies / gateways
-                "token count exceeds",     # Together AI / Mistral
-                "max context",             # some local models
-                "max_tokens",              # bad-param context errors
-                "message length",          # per-message size limits
-                "token budget",            # Cohere / Bedrock
+                "model context limits",  # OpenRouter
+                "reduce context",  # generic
+                "request too large",  # HTTP proxies / gateways
+                "token count exceeds",  # Together AI / Mistral
+                "max context",  # some local models
+                "max_tokens",  # bad-param context errors
+                "message length",  # per-message size limits
+                "token budget",  # Cohere / Bedrock
             )
         ):
             return True
@@ -1788,7 +1772,7 @@ class LLM:
                 r"(context|token).{0,30}exceed|"  # "context tokens exceeded"
                 r"too (many|large).{0,20}token|"  # "too many input tokens"
                 r"token.{0,20}(limit|max|over)|"  # "token limit reached"
-                r"limit.{0,20}token",               # "limit of N tokens"
+                r"limit.{0,20}token",  # "limit of N tokens"
                 msg,
             )
         )
@@ -1809,6 +1793,10 @@ class LLM:
             )
         ):
             return False
+        # FIX: Wire up dead-code _is_context_too_large to avoid wasting retries
+        # on unrecoverable context-length errors.
+        if self._is_context_too_large(e):
+            return False
         code = getattr(e, "status_code", None) or getattr(
             getattr(e, "response", None), "status_code", None
         )
@@ -1819,9 +1807,7 @@ class LLM:
         return code == 429 or (500 <= code < 600)
 
     def _raise_error(self, e: Exception) -> None:
-        # RELIABILITY REC MED-5: Record LLM failure for circuit breaker
-        if _is_circuit_breaker_enabled():
-            _CIRCUIT_BREAKER.record_failure()
+
         raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e
 
     def _is_anthropic(self) -> bool:
