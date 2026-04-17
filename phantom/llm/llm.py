import asyncio
import json
import logging
import os
import re
import time
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import litellm
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

logger = logging.getLogger(__name__)

from phantom.config import Config
from phantom.llm.config import LLMConfig
from phantom.llm.memory_compressor import MemoryCompressor
from phantom.llm.tracked_completion import tracked_acompletion
from phantom.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    normalize_tool_format,
    parse_tool_invocations,
    strip_thinking_blocks,
)
from phantom.skills import load_skills
from phantom.tools import get_tools_prompt
from phantom.tools.dynamic_tools import (
    get_tool_subset_categories,
    get_related_tools_for_name,
    get_tools_for_context,
    get_tools_for_task,
    get_tools_for_subset_mode,
    get_tools_prompt_subset,
)
from phantom.utils.resource_paths import get_phantom_resource_path


litellm.drop_params = True
litellm.modify_params = True


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0           # calls with accounted token usage
    completed_requests: int = 0  # compatibility mirror of requests

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
            "completed_requests": self.completed_requests,
        }

    def reset(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0
        self.cached_tokens = 0
        self.cost = 0.0
        self.requests = 0
        self.completed_requests = 0

_GLOBAL_TOTAL_STATS = RequestStats()
_GLOBAL_PER_MODEL_STATS: dict[str, RequestStats] = {}
_GLOBAL_RATE_LIMIT_UNTIL: float = 0.0
_GLOBAL_STATS_LOCK = threading.Lock()

_GLOBAL_TOKEN_DRIFT_EVENTS: list[dict[str, int | float | str]] = []
_GLOBAL_USAGE_EVENTS: list[dict[str, int | float | str]] = []


def reset_global_llm_stats() -> None:
    with _GLOBAL_STATS_LOCK:
        _GLOBAL_TOTAL_STATS.reset()
        _GLOBAL_PER_MODEL_STATS.clear()
        _GLOBAL_TOKEN_DRIFT_EVENTS.clear()
        _GLOBAL_USAGE_EVENTS.clear()


def _record_token_drift(
    model_name: str,
    estimated_tokens: int,
    actual_prompt_tokens: int,
    actual_completion_tokens: int,
    accounted_input_tokens: int,
    accounted_output_tokens: int,
    accounted_cost: float,
) -> None:
    drift = max(actual_prompt_tokens, 0) - max(estimated_tokens, 0)
    threshold_raw = Config.get("phantom_token_drift_warn_threshold") or "2000"
    try:
        threshold = max(int(threshold_raw), 1)
    except ValueError:
        threshold = 2000

    event = {
        "model": model_name,
        "estimated_tokens": int(max(estimated_tokens, 0)),
        "actual_prompt_tokens": int(max(actual_prompt_tokens, 0)),
        "actual_completion_tokens": int(max(actual_completion_tokens, 0)),
        "accounted_input_tokens": int(max(accounted_input_tokens, 0)),
        "accounted_output_tokens": int(max(accounted_output_tokens, 0)),
        "accounted_total_tokens": int(max(accounted_input_tokens, 0) + max(accounted_output_tokens, 0)),
        "accounted_cost": float(max(accounted_cost, 0.0)),
        "drift": int(drift),
    }
    with _GLOBAL_STATS_LOCK:
        _GLOBAL_TOKEN_DRIFT_EVENTS.append(event)
        if len(_GLOBAL_TOKEN_DRIFT_EVENTS) > 200:
            del _GLOBAL_TOKEN_DRIFT_EVENTS[:-200]

    if abs(drift) > threshold:
        logger.warning(
            "token drift exceeds threshold model=%s estimated=%d actual_prompt=%d actual_completion=%d drift=%d threshold=%d",
            model_name,
            estimated_tokens,
            actual_prompt_tokens,
            actual_completion_tokens,
            drift,
            threshold,
        )


def get_token_drift_events() -> list[dict[str, int | float | str]]:
    with _GLOBAL_STATS_LOCK:
        return list(_GLOBAL_TOKEN_DRIFT_EVENTS)


def get_usage_events() -> list[dict[str, int | float | str]]:
    with _GLOBAL_STATS_LOCK:
        return list(_GLOBAL_USAGE_EVENTS)


def _estimate_input_tokens_for_model(
    model_name: str,
    messages: list[dict[str, Any]] | None,
) -> int:
    if not messages:
        return 0
    try:
        estimated = litellm.token_counter(model=model_name, messages=messages)
        return max(int(estimated), 1)
    except Exception:  # noqa: BLE001
        try:
            serialized = json.dumps(messages, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            serialized = str(messages)
        return max(len(serialized) // 4, 1)


def _estimate_output_tokens_for_response(response: Any) -> int:
    content = ""
    try:
        if hasattr(response, "choices") and response.choices:
            first_choice = response.choices[0]
            if hasattr(first_choice, "message") and first_choice.message:
                message = first_choice.message
                content = getattr(message, "content", "") or ""
                if isinstance(content, list):
                    text_parts = [
                        str(part.get("text", ""))
                        for part in content
                        if isinstance(part, dict)
                    ]
                    content = "\n".join(p for p in text_parts if p)
    except Exception:  # noqa: BLE001
        content = ""

    if not content:
        return 0
    return max(len(content) // 4, 1)


def _extract_cost_for_model(model_name: str, response: Any) -> float:
    if hasattr(response, "usage") and response.usage:
        direct_cost = getattr(response.usage, "cost", None)
        if direct_cost is not None:
            return float(direct_cost)

    try:
        rate_in = float(Config.get("phantom_cost_per_1m_input") or "0")
        rate_out = float(Config.get("phantom_cost_per_1m_output") or "0")
        if rate_in > 0 or rate_out > 0:
            usage = getattr(response, "usage", None) or {}
            tok_in = getattr(usage, "prompt_tokens", 0) or 0
            tok_out = getattr(usage, "completion_tokens", 0) or 0
            cached = 0
            prompt_details = getattr(usage, "prompt_tokens_details", None)
            if prompt_details is not None:
                cached = getattr(prompt_details, "cached_tokens", 0) or 0
            tok_in = max(0, tok_in - min(cached, tok_in))
            return (tok_in * rate_in + tok_out * rate_out) / 1_000_000
    except Exception:  # noqa: BLE001
        pass

    try:
        if hasattr(response, "_hidden_params"):
            response._hidden_params.pop("custom_llm_provider", None)
        cost = completion_cost(response, model=model_name) or 0.0
        if cost > 0:
            return cost
    except Exception:  # noqa: BLE001
        pass

    try:
        usage = getattr(response, "usage", None)
        tok_in = getattr(usage, "prompt_tokens", 0) or 0
        tok_out = getattr(usage, "completion_tokens", 0) or 0
        cached = 0
        prompt_details = getattr(usage, "prompt_tokens_details", None)
        if prompt_details is not None:
            cached = getattr(prompt_details, "cached_tokens", 0) or 0
        tok_in = max(0, tok_in - min(cached, tok_in))
        if tok_in or tok_out:
            bare = model_name.split("/", 1)[-1] if "/" in model_name else model_name
            candidates = [model_name, bare, bare.lower(), model_name.lower()]
            model_cost_lower = {k.lower(): v for k, v in litellm.model_cost.items()}
            for candidate in candidates:
                info = litellm.model_cost.get(candidate) or model_cost_lower.get(
                    candidate.lower()
                )
                if info:
                    r_in = info.get("input_cost_per_token", 0) or 0
                    r_out = info.get("output_cost_per_token", 0) or 0
                    if r_in or r_out:
                        return (tok_in * r_in) + (tok_out * r_out)
    except Exception:  # noqa: BLE001
        pass
    return 0.0


def record_external_completion_usage(
    response: Any,
    model_name: str,
    messages: list[dict[str, Any]] | None = None,
    estimated_tokens: int | None = None,
) -> None:
    with _GLOBAL_STATS_LOCK:
        _GLOBAL_TOTAL_STATS.requests += 1
        if model_name not in _GLOBAL_PER_MODEL_STATS:
            _GLOBAL_PER_MODEL_STATS[model_name] = RequestStats()
        _GLOBAL_PER_MODEL_STATS[model_name].requests += 1

    actual_prompt_tokens = 0
    actual_completion_tokens = 0
    cached_tokens = 0
    input_tokens = 0
    output_tokens = 0

    if hasattr(response, "usage") and response.usage:
        actual_prompt_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
        actual_completion_tokens = getattr(response.usage, "completion_tokens", 0) or 0
        input_tokens = actual_prompt_tokens
        output_tokens = actual_completion_tokens
        if hasattr(response.usage, "prompt_tokens_details"):
            prompt_details = response.usage.prompt_tokens_details
            if hasattr(prompt_details, "cached_tokens"):
                cached_tokens = prompt_details.cached_tokens or 0
        if cached_tokens > input_tokens:
            cached_tokens = input_tokens
        input_tokens = max(0, input_tokens - cached_tokens)
    else:
        input_tokens = _estimate_input_tokens_for_model(model_name, messages)
        output_tokens = _estimate_output_tokens_for_response(response)
        actual_prompt_tokens = input_tokens
        actual_completion_tokens = output_tokens

    cost = _extract_cost_for_model(model_name, response)

    with _GLOBAL_STATS_LOCK:
        _GLOBAL_TOTAL_STATS.input_tokens += int(input_tokens)
        _GLOBAL_TOTAL_STATS.output_tokens += int(output_tokens)
        _GLOBAL_TOTAL_STATS.cached_tokens += int(cached_tokens)
        _GLOBAL_TOTAL_STATS.cost += float(cost)
        _GLOBAL_TOTAL_STATS.completed_requests += 1

        if model_name not in _GLOBAL_PER_MODEL_STATS:
            _GLOBAL_PER_MODEL_STATS[model_name] = RequestStats()
        model_stats = _GLOBAL_PER_MODEL_STATS[model_name]
        model_stats.input_tokens += int(input_tokens)
        model_stats.output_tokens += int(output_tokens)
        model_stats.cached_tokens += int(cached_tokens)
        model_stats.cost += float(cost)
        model_stats.completed_requests += 1

        _GLOBAL_USAGE_EVENTS.append(
            {
                "model": model_name,
                "input_tokens": int(input_tokens),
                "output_tokens": int(output_tokens),
                "cached_tokens": int(cached_tokens),
                "total_tokens": int(input_tokens) + int(output_tokens),
                "cost": float(cost),
            }
        )
        if len(_GLOBAL_USAGE_EVENTS) > 500:
            del _GLOBAL_USAGE_EVENTS[:-500]

    _record_token_drift(
        model_name=model_name,
        estimated_tokens=int(estimated_tokens or 0),
        actual_prompt_tokens=int(actual_prompt_tokens),
        actual_completion_tokens=int(actual_completion_tokens),
        accounted_input_tokens=int(input_tokens),
        accounted_output_tokens=int(output_tokens),
        accounted_cost=float(cost),
    )


def validate_llm_accounting_invariants() -> dict[str, Any]:
    with _GLOBAL_STATS_LOCK:
        total = _GLOBAL_TOTAL_STATS
        usage_events = list(_GLOBAL_USAGE_EVENTS)
        drift_event_count = len(_GLOBAL_TOKEN_DRIFT_EVENTS)

    usage_event_count = len(usage_events)
    summed_input = sum(int(e.get("input_tokens", 0) or 0) for e in usage_events)
    summed_output = sum(int(e.get("output_tokens", 0) or 0) for e in usage_events)
    summed_total = sum(int(e.get("total_tokens", 0) or 0) for e in usage_events)
    summed_cost = sum(float(e.get("cost", 0.0) or 0.0) for e in usage_events)

    checks = {
        "accounted_calls_eq_actual_calls": total.completed_requests == total.requests,
        "prompt_plus_completion_eq_total": summed_total == (summed_input + summed_output),
        "cumulative_total_matches_events": (
            total.input_tokens == summed_input
            and total.output_tokens == summed_output
            and abs(float(total.cost) - float(summed_cost)) < 1e-8
        ),
        "drift_events_recorded_for_calls": drift_event_count == usage_event_count,
    }

    return {
        "checks": checks,
        "summary": {
            "requests": total.requests,
            "completed_requests": total.completed_requests,
            "usage_events": usage_event_count,
            "drift_events": drift_event_count,
            "input_tokens": total.input_tokens,
            "output_tokens": total.output_tokens,
            "cost": float(total.cost),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# RELIABILITY REC MED-5: Circuit Breaker for LLM Failures
# ══════════════════════════════════════════════════════════════════════════════
# Prevents cascading failures by temporarily stopping LLM requests after repeated
# failures. Uses a 3-state pattern: CLOSED (normal), OPEN (blocking), HALF_OPEN (testing).
#
# Example: After 5 consecutive failures, circuit opens for 60s. During this time,
# requests fail-fast instead of retrying endlessly. After 60s, one test request
# is allowed (HALF_OPEN). If it succeeds, circuit closes; if it fails, circuit
# reopens for another 60s.

from enum import Enum


class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking requests (failure threshold exceeded)
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """Circuit breaker to prevent cascading LLM failures.
    
    Tracks failure rate and temporarily blocks requests when threshold is exceeded.
    """
    failure_threshold: int | None = None  # None = use default, otherwise use this value
    timeout_seconds: float = 60.0   # How long to wait before testing recovery
    _state: CircuitState = field(default_factory=lambda: CircuitState.CLOSED)
    _failure_count: int = 0
    _last_failure_time: float = 0.0
    
    def __post_init__(self) -> None:
        """Initialize from config if available."""
        # Use explicit value if provided, otherwise fall back to config, then default of 5
        if self.failure_threshold is None:
            threshold = Config.get("phantom_circuit_breaker_threshold")
            if threshold:
                try:
                    self.failure_threshold = max(1, int(threshold))
                except ValueError:
                    self.failure_threshold = 5
            else:
                self.failure_threshold = 5
        
        timeout = Config.get("phantom_circuit_breaker_timeout")
        if timeout:
            try:
                self.timeout_seconds = max(1.0, float(timeout))
            except ValueError:
                pass
    
    def record_success(self) -> None:
        """Record successful request - resets failure counter and closes circuit."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED
    
    def record_failure(self) -> None:
        """Record failed request - may open circuit if threshold exceeded."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker OPEN: %d consecutive LLM failures. "
                "Blocking requests for %.0fs to prevent cascading failures.",
                self._failure_count,
                self.timeout_seconds,
            )
    
    def allow_request(self) -> bool:
        """Check if a request should be allowed based on circuit state.
        
        Returns:
            True if request allowed, False if blocked by open circuit
        """
        if self._state == CircuitState.CLOSED:
            return True
        
        if self._state == CircuitState.OPEN:
            # Check if timeout elapsed - transition to HALF_OPEN for testing
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                logger.info(
                    "Circuit breaker HALF_OPEN: Testing LLM recovery after %.0fs cooldown.",
                    elapsed,
                )
                return True  # Allow one test request
            return False  # Still in timeout - block request
        
        # HALF_OPEN: allow request (will close on success or reopen on failure)
        return True
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state
    
    def reset(self) -> None:
        """Manually reset circuit to CLOSED state."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED


# Global circuit breaker instance (per-process singleton)
_CIRCUIT_BREAKER = CircuitBreaker()


def _is_circuit_breaker_enabled() -> bool:
    raw = (Config.get("phantom_circuit_breaker_enabled") or "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}

# ──────────────────────────────────────────────────────────────────────────────


class _TokenRateLimiter:
    def __init__(self) -> None:
        self._calls_by_model: dict[str, list[float]] = {}

    def _limit(self) -> int:
        raw = os.getenv("PHANTOM_LLM_RATE_LIMIT_PER_MINUTE", "1000")
        try:
            parsed = int(raw)
        except ValueError:
            return 1000
        return max(parsed, 1)

    def check_and_record(self, model: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        calls = self._calls_by_model.setdefault(model, [])
        calls[:] = [stamp for stamp in calls if stamp >= window_start]
        if len(calls) >= self._limit():
            return False
        calls.append(now)
        return True


class LLM:
    # Scan mode downgrade order for adaptive mode
    _SCAN_MODE_DOWNGRADE: dict[str, str] = {
        "deep": "standard",
        "standard": "quick",
    }

    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self._prompt_agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = _GLOBAL_TOTAL_STATS
        # Per-model breakdown: model_name -> RequestStats (only agent iteration calls)
        self._per_model_stats = _GLOBAL_PER_MODEL_STATS
        # Call type counters
        self._agent_calls: int = 0    # LLM calls during agent loop iterations
        self._error_calls: int = 0    # LLM calls that ended in an error (after retries)
        self.memory_compressor = MemoryCompressor(model_name=config.litellm_model)
        self._prompt_cache: dict[tuple[str, str, tuple[str, ...]], str] = {}
        self._extra_tool_names: set[str] = set()
        self.runtime_allowed_tools = self._resolve_runtime_allowed_tools()
        self.system_prompt = self._load_system_prompt(self._prompt_agent_name)

        reasoning = Config.get("phantom_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        elif config.scan_mode == "stealth":
            self._reasoning_effort = "low"
        else:
            self._reasoning_effort = "high"

        # FIX BUG-1: Budget warning flags must be instance variables, not class variables
        # Class-level variables caused shared state across all LLM instances, where
        # budget warnings fired once per process instead of once per agent
        self._budget_warning_80_emitted: bool = False
        self._budget_warning_90_emitted: bool = False

        # Fallback model: used when primary exhausts all retries
        self._fallback_llm_name = Config.get("phantom_fallback_llm") or None
        # Multi-model routing
        self._routing_enabled = (Config.get("phantom_routing_enabled") or "").lower() == "true"
        self._routing_reasoning_model = Config.get("phantom_routing_reasoning_model") or None
        self._routing_tool_model = Config.get("phantom_routing_tool_model") or None
        # Adaptive scan mode
        self._adaptive_scan_enabled = (Config.get("phantom_adaptive_scan") or "").lower() == "true"
        try:
            self._adaptive_threshold = float(Config.get("phantom_adaptive_scan_threshold") or "0.8")
        except ValueError:
            self._adaptive_threshold = 0.8

    def _prompt_cache_key(self, agent_name: str | None, tool_names: tuple[str, ...]) -> tuple[str, str, tuple[str, ...]]:
        return (
            str(agent_name or ""),
            str(self.config.scan_mode or ""),
            tool_names,
        )

    def _select_tool_names(self, agent_name: str | None) -> list[str]:
        subset_mode = (Config.get("phantom_tool_subset") or "core-fast").lower()
        if subset_mode == "full":
            from phantom.tools import get_tool_names

            return get_tool_names()

        task_description = ""
        state = getattr(self, "_agent_state", None)
        if state is not None:
            task_description = str(getattr(state, "task", "") or "").strip()

        selected: list[str] = []

        if task_description:
            task_tools = get_tools_for_task(task_description)
            selected = get_tools_for_subset_mode(subset_mode)
            if task_tools:
                selected = sorted(set(selected).union(task_tools))
        elif subset_mode == "full":
            from phantom.tools import get_tool_names

            selected = get_tool_names()
        else:
            selected = get_tools_for_subset_mode(subset_mode)

        if self._extra_tool_names:
            selected = sorted(set(selected).union(self._extra_tool_names))

        # Keep runtime allowlist and prompt-exposed tools aligned to registered
        # concrete tools (handles disabled modules like browser).
        from phantom.tools import get_tool_names

        available = set(get_tool_names())
        if selected:
            selected = sorted(set(selected).intersection(available))

        return selected

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

        tool_names = tuple(sorted(self._select_tool_names(agent_name)))
        cache_key = self._prompt_cache_key(agent_name, tool_names)
        if cache_key in self._prompt_cache:
            return self._prompt_cache[cache_key]

        try:
            prompt_dir = get_phantom_resource_path("agents", agent_name)
            skills_dir = get_phantom_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = [
                *list(self.config.skills or []),
                f"scan_modes/{self.config.scan_mode}",
            ]
            skill_content = load_skills(skills_to_load)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            if len(tool_names) == 0:
                tools_prompt_fn = get_tools_prompt
            else:
                tools_prompt_fn = lambda: get_tools_prompt_subset(list(tool_names))

            template_name = "system_prompt.jinja"
            template = env.get_template(template_name)

            result = template.render(
                get_tools_prompt=tools_prompt_fn,
                loaded_skill_names=list(skill_content.keys()),
                phantom_port_range=os.environ.get("PHANTOM_PORT_RANGE", ""),
                **skill_content,
            )
            prompt = str(result)
            if not prompt.strip():
                logger.error("System prompt rendered empty for agent %s", agent_name)
                prompt = self._build_fallback_system_prompt(tool_names)
        except Exception:  # noqa: BLE001
            logger.error("Failed to load system prompt for agent %s", agent_name, exc_info=True)
            prompt = self._build_fallback_system_prompt(tool_names)

        self._prompt_cache[cache_key] = prompt
        return prompt

    def _build_fallback_system_prompt(self, tool_names: tuple[str, ...]) -> str:
        try:
            if tool_names:
                tools_prompt = get_tools_prompt_subset(list(tool_names))
            else:
                tools_prompt = get_tools_prompt()
        except Exception:  # noqa: BLE001
            tools_prompt = ""

        return (
            "You are Phantom, an autonomous penetration-testing agent.\n"
            "Follow runtime tool contracts strictly.\n"
            "Use this exact tool format:\n"
            "<function=get_scan_status></function>\n"
            "<function=send_request>\n"
            "<parameter=method>GET</parameter>\n"
            "<parameter=url>https://target.example</parameter>\n"
            "</function>\n\n"
            f"{tools_prompt}"
        )

    def refresh_tool_prompt(self) -> None:
        """Rebuild system prompt and allowed tools from current agent state."""
        self.runtime_allowed_tools = self._resolve_runtime_allowed_tools()
        self.system_prompt = self._load_system_prompt(self._prompt_agent_name)

    def _apply_scan_mode_change(self, new_mode: str) -> None:
        if self.config.scan_mode == new_mode:
            return
        self.config.scan_mode = new_mode

        state = getattr(self, "_agent_state", None)
        if state is not None and hasattr(state, "scan_mode"):
            try:
                state.scan_mode = new_mode
            except Exception:
                pass

        self.refresh_tool_prompt()

    def _resolve_runtime_allowed_tools(self) -> set[str] | None:
        tool_names = self._select_tool_names(self._prompt_agent_name)
        if not tool_names:
            return None
        return set(tool_names)

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id
        self.refresh_tool_prompt()

    def set_agent_state(self, agent_state: Any) -> None:
        """Attach the agent state so compress_history and anchor injection can use it."""
        self._agent_state = agent_state
        setattr(agent_state, "_runtime_llm", self)
        self.refresh_tool_prompt()

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        global _GLOBAL_RATE_LIMIT_UNTIL
        now = time.monotonic()
        if now < _GLOBAL_RATE_LIMIT_UNTIL:
            wait_time = _GLOBAL_RATE_LIMIT_UNTIL - now
            logger.warning("Global rate limit in effect, agent '%s' sleeping for %.1fs...", self.agent_name, wait_time)
            await asyncio.sleep(wait_time)

        # RELIABILITY REC MED-5: Check circuit breaker before making request
        if _is_circuit_breaker_enabled() and not _CIRCUIT_BREAKER.allow_request():
            raise LLMRequestFailedError(
                message="LLM circuit breaker is OPEN - too many consecutive failures",
                details=f"Circuit state: {_CIRCUIT_BREAKER.get_state().value}. Wait before retrying."
            )

        self._check_budget()
        self._agent_calls += 1
        messages = await self._prepare_messages(conversation_history)
        messages = await self._enforce_request_size_limits(messages)
        max_retries = int(Config.get("phantom_llm_max_retries") or "5")
        unknown_error_max_retries = 2

        # Optionally switch model based on routing config
        original_model = self.config.litellm_model
        if self._routing_enabled:
            routed = self._pick_routing_model(messages)
            if routed and routed != original_model:
                logger.debug("Routing: switching model %s → %s", original_model, routed)
                self.config.litellm_model = routed
        primary_model = self.config.litellm_model

        primary_exhausted = False
        _last_error: Exception | None = None
        # 429 errors get a separate, higher retry budget to survive long rate-limit windows
        ratelimit_max_retries = int(Config.get("phantom_llm_ratelimit_max_retries") or "10")
        for attempt in range(ratelimit_max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                # Restore routing override after successful call
                self.config.litellm_model = original_model
                self._check_adaptive_scan_mode()
                return  # noqa: TRY300
            except LLMRequestFailedError:
                self.config.litellm_model = original_model
                raise
            except Exception as e:  # noqa: BLE001
                # Extract error code once — used for exhaustion check and backoff
                code = getattr(e, "status_code", None) or getattr(
                    getattr(e, "response", None), "status_code", None
                )
                # Rate-limit errors use the larger ratelimit_max_retries budget.
                # Unknown-code errors are capped to avoid long blind retry loops.
                if code == 429:
                    effective_max = ratelimit_max_retries
                elif code is None:
                    effective_max = min(max_retries, unknown_error_max_retries)
                else:
                    effective_max = max_retries
                if attempt >= effective_max or not self._should_retry(e):
                    _last_error = e
                    primary_exhausted = True
                    break
                # Emit audit event so retries are visible in the audit log
                _retry_audit = (
                    __import__("phantom.logging.audit", fromlist=["get_audit_logger"])
                    .get_audit_logger()
                )
                if _retry_audit:
                    _retry_audit.log_llm_error(
                        agent_id=self.agent_id or "unknown",
                        model=self.config.litellm_model,
                        error=str(e)[:500],
                        attempt=attempt + 1,
                    )
                # Longer backoff for rate limits (429) — up to 120 s; others up to 10 s
                if code == 429:
                    wait = min(120, 4 * (2**attempt))
                    logger.warning(
                        "Rate limit hit (attempt %d/%d); backing off %.0fs globally...",
                        attempt + 1, ratelimit_max_retries, wait,
                    )
                    _GLOBAL_RATE_LIMIT_UNTIL = max(_GLOBAL_RATE_LIMIT_UNTIL, time.monotonic() + wait)
                else:
                    wait = min(10, 2 * (2**attempt))
                await asyncio.sleep(wait)

        # Primary model exhausted — try fallback if configured
        if (
            primary_exhausted
            and self._fallback_llm_name
            and self._fallback_llm_name != primary_model
        ):
            logger.warning(
                "Primary model %s exhausted — retrying with fallback %s",
                primary_model,
                self._fallback_llm_name,
            )
            try:
                self.config.litellm_model = self._fallback_llm_name
                async for response in self._stream(messages):
                    yield response
                self._check_adaptive_scan_mode()  # honour cost budget after fallback too
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                self._error_calls += 1
                self._raise_error(e)
            finally:
                # Always restore the original model, even if fallback raises.
                self.config.litellm_model = original_model
        elif primary_exhausted:
            self.config.litellm_model = original_model
            self._error_calls += 1
            last_err_str = f": {_last_error}" if _last_error else ""
            if _is_circuit_breaker_enabled():
                _CIRCUIT_BREAKER.record_failure()
            raise LLMRequestFailedError(
                f"All retries exhausted for primary model{last_err_str}"
            )

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0
        rebuilt: Any | None = None  # holds stream_chunk_builder result to avoid double call
        usage_delta: dict[str, int | float] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cost": 0.0,
        }

        # ── Audit: log the outgoing request ───────────────────────────────────
        from phantom.logging.audit import get_audit_logger as _get_audit
        _audit = _get_audit()
        _audit_rid = (
            _audit.log_llm_request(
                agent_id=self.agent_id or "unknown",
                model=self.config.litellm_model,
                messages=messages,
            )
            if _audit else None
        )
        _audit_t0 = time.monotonic()
        # ─────────────────────────────────────────────────────────────────────

        response = await tracked_acompletion(
            **self._build_completion_args(messages),
            stream=True,
            reducer=self._safe_reduce_messages,
        )

        async for chunk in response:
            chunks.append(chunk)
            if done_streaming:
                done_streaming += 1
                if getattr(chunk, "usage", None) or done_streaming > 5:
                    break
                continue
            delta = self._get_chunk_content(chunk)
            if delta:
                accumulated += delta
                if "</function>" in accumulated or "</invoke>" in accumulated:
                    end_tag = "</function>" if "</function>" in accumulated else "</invoke>"
                    pos = accumulated.find(end_tag)
                    accumulated = accumulated[: pos + len(end_tag)]
                    yield LLMResponse(content=accumulated)
                    done_streaming = 1
                    continue
                yield LLMResponse(content=accumulated)

        if chunks:
            rebuilt = stream_chunk_builder(chunks)
            usage_delta = self._update_usage_stats(rebuilt, messages)
            self._update_per_model_stats(usage_delta)
            _record_token_drift(
                model_name=self.config.litellm_model or "unknown",
                estimated_tokens=self._estimate_input_tokens(messages),
                actual_prompt_tokens=int(usage_delta.get("actual_prompt_tokens", 0) or 0),
                actual_completion_tokens=int(usage_delta.get("actual_completion_tokens", 0) or 0),
                accounted_input_tokens=int(usage_delta.get("input_tokens", 0) or 0),
                accounted_output_tokens=int(usage_delta.get("output_tokens", 0) or 0),
                accounted_cost=float(usage_delta.get("cost", 0.0) or 0.0),
            )
            request_cost = float(usage_delta.get("cost", 0.0) or 0.0)
            with _GLOBAL_STATS_LOCK:
                total_input_tokens = self._total_stats.input_tokens
                total_output_tokens = self._total_stats.output_tokens
                total_cost = self._total_stats.cost
            logger.info(
                "llm_call model=%s scan_mode=%s tokens_in=%d tokens_out=%d "
                "request_cost=$%.4f cumulative_cost=$%.4f",
                self.config.litellm_model,
                self.config.scan_mode,
                total_input_tokens,
                total_output_tokens,
                request_cost,
                total_cost,
            )
            self._check_per_request_budget(request_cost)

        # RELIABILITY REC MED-5: Record successful LLM call - close circuit
        if _is_circuit_breaker_enabled():
            _CIRCUIT_BREAKER.record_success()

        accumulated = normalize_tool_format(accumulated)
        # Strip thinking blocks before truncation so embedded tool calls do not
        # hide the real execution payload.
        accumulated = strip_thinking_blocks(accumulated)
        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
        _parsed_tools = parse_tool_invocations(accumulated)

        # AUDIT-FIX-09: When the LLM produces text that looks like a tool call
        # but fails to parse, prepend a corrective message so the agent knows
        # its call was NOT executed and can reformat.
        _xml_markers = ["<function=", "<invoke ", "</function>"]
        _looks_like_tool = any(m in accumulated for m in _xml_markers)
        if _looks_like_tool and not _parsed_tools:
            available_tools = []
            try:
                from phantom.tools.registry import get_tool_names as _get_tool_names

                available_tools = sorted(_get_tool_names())
            except Exception:
                available_tools = []

            examples: list[str] = []
            if "get_scan_status" in available_tools:
                examples.append("<function=get_scan_status></function>")
            if "send_request" in available_tools:
                examples.append(
                    "<function=send_request><parameter=method>GET</parameter>"
                    "<parameter=url>http://example.com</parameter></function>"
                )
            if "python_action" in available_tools:
                examples.append(
                    "<function=python_action><parameter=action>new_session</parameter>"
                    "<parameter=code>import requests</parameter></function>"
                )

            available_preview = ", ".join(available_tools[:25])
            if len(available_tools) > 25:
                available_preview += ", ..."

            malformed_notice = (
                "[SYSTEM: Tool call malformed and NOT executed. Use exact XML tags and a REAL registered tool name.\n"
                "Rules:\n"
                "- Format: <function=get_scan_status></function> or <function=send_request><parameter=method>GET</parameter><parameter=url>http://example.com</parameter></function>\n"
                "- Tool names are snake_case. Do NOT flatten underscores or invent aliases.\n"
                "- If no args required, still call: <function=get_scan_status></function>.\n"
                f"Available tools (subset): {available_preview}]\n"
            )
            if examples:
                malformed_notice += "[SYSTEM: Valid examples]\n" + "\n".join(examples) + "\n"

            accumulated = (
                malformed_notice + accumulated
            )

        # ── Audit: log the completed response ────────────────────────────────
        if _audit and _audit_rid:
            _audit.log_llm_response(
                agent_id=self.agent_id or "unknown",
                request_id=_audit_rid,
                model=self.config.litellm_model,
                response_text=accumulated,
                tool_invocations=_parsed_tools,
                tokens_in=int(usage_delta.get("input_tokens", 0) or 0),
                tokens_out=int(usage_delta.get("output_tokens", 0) or 0),
                cost_usd=float(usage_delta.get("cost", 0.0) or 0.0),
                duration_ms=(time.monotonic() - _audit_t0) * 1000,
            )
        # ─────────────────────────────────────────────────────────────────────

        yield LLMResponse(
            content=accumulated,
            tool_invocations=_parsed_tools,
            thinking_blocks=self._extract_thinking(chunks, rebuilt),
        )

    async def _prepare_messages(
        self, conversation_history: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": self.system_prompt}]

        if self.agent_name:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"\n\n<agent_identity>\n"
                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
                        f"<agent_name>{self.agent_name}</agent_name>\n"
                        f"<agent_id>{self.agent_id}</agent_id>\n"
                        f"</agent_identity>\n\n"
                    ),
                }
            )

        # Remove thinking blocks before compression/truncation so embedded tool
        # calls do not get dropped or hidden before parsing.
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = strip_thinking_blocks(content)

        # Run compression in a thread to avoid blocking the async event loop.
        # The sync compress_history call can take 30s+ per chunk when LLM summarisation fires.
        _state = getattr(self, "_agent_state", None)
        _archive = []
        if _state is not None and hasattr(_state, "get_archived_messages"):
            try:
                _archive = list(_state.get_archived_messages())
            except Exception:
                _archive = []
        # Keep chronological order: archived history is older than live history.
        # Previous order (conversation + archive) inverted timeline and confused
        # the compressor's recent/old split.
        compression_input = _archive + conversation_history
        compression_input = [
            {
                **msg,
                "content": strip_thinking_blocks(msg.get("content", ""))
                if isinstance(msg.get("content", ""), str)
                else msg.get("content", ""),
            }
            for msg in compression_input
        ]
        compressed = list(
            await asyncio.to_thread(
                self.memory_compressor.compress_history, compression_input, _state
            )
        )
        conversation_history.clear()
        conversation_history.extend(compressed)
        if _archive and _state is not None and hasattr(_state, "clear_archived_messages"):
            try:
                _state.clear_archived_messages()
            except Exception:
                pass

        # ── Finding anchors injection ─────────────────────────────────────────
        # AUDIT-FIX-04: Re-inject high-signal findings continuously from iter 2+
        # (was: only at 75% of max iterations, far too late for exploitation).
        # This ensures the agent always "knows" about confirmed vulnerabilities
        # even when the full history has been summarised away.
        _has_anchors = (
            _state is not None
            and hasattr(_state, "finding_anchors")
            and _state.finding_anchors
        )
        if _has_anchors:
            # Only inject if not already present in last 5 messages
            _last_msgs = compressed[-5:] if len(compressed) >= 5 else compressed
            _already_injected = any(
                "finding_anchors" in str(m.get("content", "")) for m in _last_msgs
            )
            if not _already_injected:
                anchor_lines = []
                for anchor in _state.finding_anchors[:15]:  # cap at 15
                    text = anchor.get("text", "").strip()
                    if text:
                        anchor_lines.append(f"- {text[:600]}")  # 600 chars, was 300
                if anchor_lines:
                    anchor_reminder = (
                        "<finding_anchors>\n"
                        "Confirmed signals from earlier in this scan — "
                        "report any that have NOT been reported yet:\n"
                        + "\n".join(anchor_lines)
                        + "\n</finding_anchors>"
                    )
                    messages.append({"role": "user", "content": anchor_reminder})
        # ─────────────────────────────────────────────────────────────────────

        messages.extend(compressed)

        if messages[-1].get("role") == "assistant":
            messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        return messages

    def _estimate_request_size(self, messages: list[dict[str, Any]]) -> tuple[int, int]:
        serialized = json.dumps(messages, ensure_ascii=False, default=str)
        chars = len(serialized)
        try:
            estimated_tokens = litellm.token_counter(model=self.config.litellm_model, messages=messages)
        except Exception:  # noqa: BLE001
            estimated_tokens = max(chars // 4, 1)
        return chars, estimated_tokens

    def _drop_old_images_from_messages(
        self, messages: list[dict[str, Any]], keep_recent_images: int = 1
    ) -> list[dict[str, Any]]:
        image_count = 0
        transformed = [dict(m) for m in messages]

        for msg in reversed(transformed):
            content = msg.get("content")
            if not isinstance(content, list):
                continue

            new_content: list[dict[str, Any] | Any] = []
            for item in content:
                if not isinstance(item, dict) or item.get("type") != "image_url":
                    new_content.append(item)
                    continue

                if image_count >= keep_recent_images:
                    new_content.append(
                        {
                            "type": "text",
                            "text": "[Older image removed during request-size preflight]",
                        }
                    )
                else:
                    image_count += 1
                    new_content.append(item)

            msg["content"] = new_content

        return transformed

    async def _enforce_request_size_limits(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        max_request_chars = int(Config.get("phantom_max_request_chars") or "900000")
        max_request_tokens = int(
            Config.get("phantom_max_request_estimated_tokens") or Config.get("phantom_ollama_context_length") or "220000"
        )
        from phantom.logging.audit import get_audit_logger as _get_audit

        _audit = _get_audit()
        _agent_id = self.agent_id or "unknown"

        current = messages
        for attempt in range(4):
            chars, est_tokens = self._estimate_request_size(current)
            if chars <= max_request_chars and est_tokens <= max_request_tokens:
                return current

            logger.warning(
                "LLM preflight request too large (attempt %d): chars=%d/%d est_tokens=%d/%d",
                attempt + 1,
                chars,
                max_request_chars,
                est_tokens,
                max_request_tokens,
            )

            if attempt == 0:
                before_chars, before_tokens = chars, est_tokens
                current = self._drop_old_images_from_messages(current, keep_recent_images=1)
                after_chars, after_tokens = self._estimate_request_size(current)
                if _audit:
                    _audit.log_preflight_reduction(
                        agent_id=_agent_id,
                        stage="drop_old_images",
                        attempt=attempt + 1,
                        chars_before=before_chars,
                        chars_after=after_chars,
                        tokens_before=before_tokens,
                        tokens_after=after_tokens,
                        max_request_chars=max_request_chars,
                        max_request_tokens=max_request_tokens,
                    )
                continue
            if attempt == 1:
                before_chars, before_tokens = chars, est_tokens
                current = self._safe_reduce_messages(current)
                if self._is_anthropic() and self.config.enable_prompt_caching:
                    current = self._add_cache_control(current)
                after_chars, after_tokens = self._estimate_request_size(current)
                if _audit:
                    _audit.log_preflight_reduction(
                        agent_id=_agent_id,
                        stage="safe_reduce",
                        attempt=attempt + 1,
                        chars_before=before_chars,
                        chars_after=after_chars,
                        tokens_before=before_tokens,
                        tokens_after=after_tokens,
                        max_request_chars=max_request_chars,
                        max_request_tokens=max_request_tokens,
                    )
                continue
            if attempt == 2:
                before_chars, before_tokens = chars, est_tokens
                current = self._safe_reduce_messages(current)
                after_chars, after_tokens = self._estimate_request_size(current)
                if _audit:
                    _audit.log_preflight_reduction(
                        agent_id=_agent_id,
                        stage="safe_reduce",
                        attempt=attempt + 1,
                        chars_before=before_chars,
                        chars_after=after_chars,
                        tokens_before=before_tokens,
                        tokens_after=after_tokens,
                        max_request_chars=max_request_chars,
                        max_request_tokens=max_request_tokens,
                    )
                continue

        final_chars, final_tokens = self._estimate_request_size(current)
        if _is_circuit_breaker_enabled():
            _CIRCUIT_BREAKER.record_failure()
        raise LLMRequestFailedError(
            "Request preflight hard cap exceeded: "
            f"chars={final_chars} (limit={max_request_chars}), "
            f"estimated_tokens={final_tokens} (limit={max_request_tokens})"
        )

    def _get_max_tokens(self) -> int | None:
        """Return an explicit output-token cap ONLY when the user has set one.

        R-01 regression fix: Strix never passed max_tokens, letting the model
        use its full output budget.  Phantom added hard caps (4k/6k/8k) which
        truncated the model mid-thought before it could call
        create_vulnerability_report — the #1 root cause of 0 findings.

        Now we only honour an explicit env-var override; otherwise return None
        so that _build_completion_args omits the parameter entirely.
        """
        env_val = Config.get("llm_max_tokens")
        if env_val:
            return int(env_val)
        return None  # let the model use its full output budget (Strix behaviour)

    def _check_budget(self) -> None:
        """Check budget and apply graceful degradation at thresholds.
        
        EFFICIENCY FIX SCALE-P1.1: Graceful Limit Degradation
        - 80% budget: Warning logged, continue normally
        - 90% budget: Warning logged, reduce reasoning effort, suggest wrap-up
        - 100% budget: Stop or continue based on PHANTOM_COST_ABORT_ON_LIMIT

        Uses the *global* scan cost aggregated across all agent instances via the
        Tracer, so sub-agents cannot each individually spend up to max_cost.
        Falls back to this agent's local stats when the Tracer is unavailable.
        """
        max_cost_str = Config.get("phantom_max_cost")
        if not max_cost_str:
            return
        try:
            max_cost = float(max_cost_str)
        except ValueError:
            return
        if max_cost <= 0:
            return
            
        # Get current global cost
        try:
            from phantom.telemetry.tracer import get_global_tracer
            tracer = get_global_tracer()
            if tracer:
                traced_cost = tracer.get_total_llm_stats()["total"]["cost"]
                current_cost = max(float(traced_cost or 0.0), float(self._total_stats.cost or 0.0))
            else:
                current_cost = self._total_stats.cost
        except Exception:  # noqa: BLE001
            current_cost = self._total_stats.cost
        
        budget_fraction = current_cost / max_cost
        
        # ════════════════════════════════════════════════════════════════════
        # 80% threshold: Warning, continue normally
        # ════════════════════════════════════════════════════════════════════
        if budget_fraction >= 0.80 and not self._budget_warning_80_emitted:
            self._budget_warning_80_emitted = True
            logger.warning(
                "BUDGET ALERT: 80%% used ($%.4f / $%.4f). "
                "Consider wrapping up current testing phase.",
                current_cost, max_cost,
            )
            # Log to audit
            try:
                from phantom.logging.audit import get_audit_logger as _get_audit
                _audit = _get_audit()
                if _audit:
                    _audit.log_security_event(
                        "budget_warning_80",
                        self.agent_id,
                        {
                            "current_cost": round(current_cost, 4),
                            "max_cost": max_cost,
                            "percentage": round(budget_fraction * 100, 1),
                            "action": "warning_only",
                        },
                    )
            except Exception:  # noqa: BLE001
                pass
        
        # ════════════════════════════════════════════════════════════════════
        # 90% threshold: Warning + reduce reasoning effort + inject wrap-up hint
        # ════════════════════════════════════════════════════════════════════
        if budget_fraction >= 0.90 and not self._budget_warning_90_emitted:
            self._budget_warning_90_emitted = True
            logger.warning(
                "BUDGET CRITICAL: 90%% used ($%.4f / $%.4f). "
                "Reducing reasoning effort and preparing for graceful shutdown.",
                current_cost, max_cost,
            )
            
            # Reduce reasoning effort to save tokens
            if self._reasoning_effort in ("high", "xhigh"):
                self._reasoning_effort = "medium"
                logger.info("Reasoning effort reduced from high/xhigh to medium to conserve budget")
            elif self._reasoning_effort == "medium":
                self._reasoning_effort = "low"
                logger.info("Reasoning effort reduced from medium to low to conserve budget")
            
            # Auto-downgrade scan mode if adaptive is enabled
            if self._adaptive_scan_enabled:
                new_mode = self._SCAN_MODE_DOWNGRADE.get(self.config.scan_mode)
                if new_mode:
                    logger.warning(
                        "Auto-downgrading scan mode %s → %s due to 90%% budget",
                        self.config.scan_mode, new_mode
                    )
                    self._apply_scan_mode_change(new_mode)
            
            # Log to audit
            try:
                from phantom.logging.audit import get_audit_logger as _get_audit
                _audit = _get_audit()
                if _audit:
                    _audit.log_security_event(
                        "budget_warning_90",
                        self.agent_id,
                        {
                            "current_cost": round(current_cost, 4),
                            "max_cost": max_cost,
                            "percentage": round(budget_fraction * 100, 1),
                            "action": "degradation_applied",
                            "reasoning_effort": self._reasoning_effort,
                            "scan_mode": self.config.scan_mode,
                        },
                    )
            except Exception:  # noqa: BLE001
                pass
        
        # ════════════════════════════════════════════════════════════════════
        # 100% threshold: Hard stop or advisory continue
        # ════════════════════════════════════════════════════════════════════
        if current_cost >= max_cost:
            # Rec 2 (SF-001): Respect abort-on-limit flag.
            abort_on_limit = (Config.get("phantom_cost_abort_on_limit") or "true").lower()
            if abort_on_limit in ("false", "0", "no"):
                logger.warning(
                    "Budget exceeded: $%.4f >= max $%.4f — advisory mode, continuing.",
                    current_cost, max_cost,
                )
                return
            if _is_circuit_breaker_enabled():
                _CIRCUIT_BREAKER.record_failure()
            raise LLMRequestFailedError(
                f"Budget exceeded: ${current_cost:.4f} >= max ${max_cost:.4f}"
            )

    def _check_per_request_budget(self, request_cost: float) -> None:
        """Hard-stop if a single LLM call exceeds PHANTOM_PER_REQUEST_CEILING."""
        ceiling_str = Config.get("phantom_per_request_ceiling")
        if not ceiling_str:
            return
        try:
            ceiling = float(ceiling_str)
        except ValueError:
            return
        if request_cost > ceiling:
            if _is_circuit_breaker_enabled():
                _CIRCUIT_BREAKER.record_failure()
            raise LLMRequestFailedError(
                f"Per-request budget exceeded: ${request_cost:.4f} > ceiling ${ceiling:.4f}"
            )

    def _safe_reduce_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        pinned: list[dict[str, Any]] = []
        state = getattr(self, "_agent_state", None)
        anchors = []
        if state is not None:
            anchors = list(getattr(state, "finding_anchors", []) or [])

        if anchors:
            anchor_lines = []
            for anchor in anchors[:15]:
                status = str(anchor.get("status", "active")).lower()
                if status in {"invalidated", "superseded"}:
                    continue
                text = str(anchor.get("text", "")).strip()
                if text:
                    anchor_lines.append(f"- {text[:600]}")
            if anchor_lines:
                pinned.append(
                    {
                        "role": "user",
                        "content": "<pinned_facts>\n" + "\n".join(anchor_lines) + "\n</pinned_facts>",
                    }
                )

        keep_recent = max(12, int(Config.get("phantom_safe_reduce_last_k") or "20"))
        recent = non_system[-keep_recent:]
        return system_msgs + pinned + recent

    def _build_completion_args(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._supports_vision():
            messages = self._strip_images(messages)

        args: dict[str, Any] = {
            "model": self.config.litellm_model,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
        }

        # R-01: Only pass max_tokens if explicitly configured via env var.
        # Strix never capped output; Phantom's caps caused truncated responses.
        _max_tok = self._get_max_tokens()
        if _max_tok is not None:
            args["max_tokens"] = _max_tok

        if self.config.api_key:
            args["api_key"] = self.config.api_key
        if self.config.api_base:
            args["api_base"] = self.config.api_base
        if self._supports_reasoning():
            args["reasoning_effort"] = self._reasoning_effort

        return args

    def _get_chunk_content(self, chunk: Any) -> str:
        if chunk.choices and hasattr(chunk.choices[0], "delta"):
            return getattr(chunk.choices[0].delta, "content", "") or ""
        return ""

    def _extract_thinking(
        self, chunks: list[Any], rebuilt: Any | None = None
    ) -> list[dict[str, Any]] | None:
        if not chunks or not self._supports_reasoning():
            return None
        try:
            # Reuse the already-rebuilt response when available to avoid a second
            # stream_chunk_builder() call (which is CPU-heavy on large streams).
            resp = rebuilt if rebuilt is not None else stream_chunk_builder(chunks)
            if resp.choices and hasattr(resp.choices[0].message, "thinking_blocks"):
                blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                return blocks
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return None

    def _update_per_model_stats(self, usage_delta: dict[str, int | float]) -> None:
        """Track per-model token/cost breakdown (agent calls only)."""
        try:
            input_tokens = int(usage_delta.get("input_tokens", 0) or 0)
            output_tokens = int(usage_delta.get("output_tokens", 0) or 0)
            cached_tokens = int(usage_delta.get("cached_tokens", 0) or 0)
            cost = float(usage_delta.get("cost", 0.0) or 0.0)

            model_key = self.config.litellm_model or "unknown"
            with _GLOBAL_STATS_LOCK:
                if model_key not in self._per_model_stats:
                    self._per_model_stats[model_key] = RequestStats()
                stats = self._per_model_stats[model_key]
                stats.input_tokens += input_tokens
                stats.output_tokens += output_tokens
                stats.cached_tokens += cached_tokens
                stats.cost += cost
                stats.requests += 1
                stats.completed_requests += 1
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _pick_routing_model(self, messages: list[dict[str, Any]]) -> str | None:
        """
        Decide which model to use based on conversation context.
        Heuristic: if the last user message looks like a tool result
        (starts with <tool_result or <function_results), we're in an
        "execution" phase → use tool model. Otherwise → reasoning model.
        """
        if not self._routing_enabled:
            return None
        last_user = next(
            (m for m in reversed(messages) if m.get("role") == "user"), None
        )
        content = (last_user or {}).get("content", "") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
            )
        content_lower = content.strip().lower()
        is_tool_result = content_lower.startswith(("<tool_result", "<function_results"))
        if is_tool_result and self._routing_tool_model:
            return self._routing_tool_model
        if not is_tool_result and self._routing_reasoning_model:
            return self._routing_reasoning_model
        return None

    def _check_adaptive_scan_mode(self) -> None:
        """Downgrade scan mode if *global* cost has exceeded the adaptive threshold."""
        if not self._adaptive_scan_enabled:
            return
        max_cost_str = Config.get("phantom_max_cost")
        if not max_cost_str:
            return
        try:
            max_cost = float(max_cost_str)
        except ValueError:
            return
        if max_cost <= 0:
            return
        # Use global cost (all agents) so the threshold is applied consistently.
        try:
            from phantom.telemetry.tracer import get_global_tracer
            tracer = get_global_tracer()
            current_cost = (
                tracer.get_total_llm_stats()["total"]["cost"] if tracer else self._total_stats.cost
            )
        except Exception:  # noqa: BLE001
            current_cost = self._total_stats.cost
        fraction = current_cost / max_cost
        if fraction >= self._adaptive_threshold:
            new_mode = self._SCAN_MODE_DOWNGRADE.get(self.config.scan_mode)
            if new_mode:
                # debug-level: this fires after every successful LLM call, routing
                # to stderr at WARNING level causes PowerShell NativeCommandError.
                logger.debug(
                    "adaptive scan: cost=%.4f (%.1f%% of $%.2f) downgrading %s -> %s",
                    self._total_stats.cost,
                    fraction * 100,
                    max_cost,
                    self.config.scan_mode,
                    new_mode,
                )
                self._apply_scan_mode_change(new_mode)

    def _estimate_input_tokens(self, messages: list[dict[str, Any]] | None) -> int:
        if not messages:
            return 0

        try:
            estimated = litellm.token_counter(model=self.config.litellm_model, messages=messages)
            return max(int(estimated), 1)
        except Exception:  # noqa: BLE001
            try:
                serialized = json.dumps(messages, ensure_ascii=False, default=str)
            except Exception:  # noqa: BLE001
                serialized = str(messages)
            return max(len(serialized) // 4, 1)

    def _estimate_output_tokens(self, response: Any) -> int:
        content = ""
        try:
            if hasattr(response, "choices") and response.choices:
                first_choice = response.choices[0]
                if hasattr(first_choice, "message") and first_choice.message:
                    message = first_choice.message
                    content = getattr(message, "content", "") or ""
                    if isinstance(content, list):
                        text_parts = [
                            str(part.get("text", ""))
                            for part in content
                            if isinstance(part, dict)
                        ]
                        content = "\n".join(p for p in text_parts if p)
        except Exception:  # noqa: BLE001
            content = ""

        if not content:
            return 0
        return max(len(content) // 4, 1)

    def _update_usage_stats(
        self,
        response: Any,
        messages: list[dict[str, Any]] | None = None,
    ) -> dict[str, int | float]:
        deltas: dict[str, int | float] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cost": 0.0,
            "actual_prompt_tokens": 0,
            "actual_completion_tokens": 0,
        }
        try:
            if hasattr(response, "usage") and response.usage:
                actual_prompt_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                actual_completion_tokens = getattr(response.usage, "completion_tokens", 0) or 0
                input_tokens = actual_prompt_tokens
                output_tokens = actual_completion_tokens

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0
                if cached_tokens > input_tokens:
                    cached_tokens = input_tokens
                input_tokens = max(0, input_tokens - cached_tokens)

                cost = self._extract_cost(response)
            else:
                # CRITICAL FIX: Some API providers (OpenRouter, cached responses) don't return usage
                # Estimate tokens to avoid reporting 0 which breaks cost tracking
                logger.warning(
                    "API response missing usage stats - estimating tokens (model=%s)",
                    self.config.litellm_model
                )
                input_tokens = self._estimate_input_tokens(messages)
                output_tokens = self._estimate_output_tokens(response)
                cached_tokens = 0
                cost = 0.0
                actual_prompt_tokens = input_tokens
                actual_completion_tokens = output_tokens

                cost = self._extract_cost(response)

            deltas = {
                "input_tokens": int(input_tokens),
                "output_tokens": int(output_tokens),
                "cached_tokens": int(cached_tokens),
                "cost": float(cost),
                "actual_prompt_tokens": int(actual_prompt_tokens),
                "actual_completion_tokens": int(actual_completion_tokens),
            }

            with _GLOBAL_STATS_LOCK:
                self._total_stats.requests += 1
                self._total_stats.input_tokens += int(deltas["input_tokens"])
                self._total_stats.output_tokens += int(deltas["output_tokens"])
                self._total_stats.cached_tokens += int(deltas["cached_tokens"])
                self._total_stats.cost += float(deltas["cost"])
                self._total_stats.completed_requests += 1

                _GLOBAL_USAGE_EVENTS.append(
                    {
                        "model": self.config.litellm_model or "unknown",
                        "input_tokens": int(deltas["input_tokens"]),
                        "output_tokens": int(deltas["output_tokens"]),
                        "cached_tokens": int(deltas["cached_tokens"]),
                        "total_tokens": int(deltas["input_tokens"]) + int(deltas["output_tokens"]),
                        "cost": float(deltas["cost"]),
                    }
                )
                if len(_GLOBAL_USAGE_EVENTS) > 500:
                    del _GLOBAL_USAGE_EVENTS[:-500]

        except Exception:  # noqa: BLE001, S110  # nosec B110
            return deltas

        return deltas

    def _extract_cost(self, response: Any) -> float:
        # 1. API-reported cost (if provider returns it directly)
        if hasattr(response, "usage") and response.usage:
            direct_cost = getattr(response.usage, "cost", None)
            if direct_cost is not None:
                return float(direct_cost)
        # 2. User-configured rates (from config file / env vars) — checked before
        # litellm so explicit user overrides take priority over built-in pricing.
        try:
            rate_in = float(Config.get("phantom_cost_per_1m_input") or "0")
            rate_out = float(Config.get("phantom_cost_per_1m_output") or "0")
            if rate_in > 0 or rate_out > 0:
                usage = getattr(response, "usage", None) or {}
                tok_in = getattr(usage, "prompt_tokens", 0) or 0
                tok_out = getattr(usage, "completion_tokens", 0) or 0
                cached = 0
                prompt_details = getattr(usage, "prompt_tokens_details", None)
                if prompt_details is not None:
                    cached = getattr(prompt_details, "cached_tokens", 0) or 0
                tok_in = max(0, tok_in - min(cached, tok_in))
                return (tok_in * rate_in + tok_out * rate_out) / 1_000_000
        except Exception:  # noqa: BLE001
            pass
        # 3. litellm built-in pricing via completion_cost.
        try:
            if hasattr(response, "_hidden_params"):
                response._hidden_params.pop("custom_llm_provider", None)
            cost = completion_cost(response, model=self.config.canonical_model) or 0.0
            if cost > 0:
                return cost
        except Exception:  # noqa: BLE001
            pass
        # 4. Manual litellm.model_cost registry lookup (handles Azure/other prefixes).
        try:
            import litellm as _litellm
            usage = getattr(response, "usage", None)
            tok_in = getattr(usage, "prompt_tokens", 0) or 0
            tok_out = getattr(usage, "completion_tokens", 0) or 0
            cached = 0
            prompt_details = getattr(usage, "prompt_tokens_details", None)
            if prompt_details is not None:
                cached = getattr(prompt_details, "cached_tokens", 0) or 0
            tok_in = max(0, tok_in - min(cached, tok_in))
            if tok_in or tok_out:
                model_key = self.config.litellm_model or ""
                bare = model_key.split("/", 1)[-1] if "/" in model_key else model_key
                candidates = [model_key, bare, bare.lower(), model_key.lower()]
                model_cost_lower = {
                    k.lower(): v for k, v in _litellm.model_cost.items()
                }
                for candidate in candidates:
                    info = _litellm.model_cost.get(candidate) or model_cost_lower.get(
                        candidate.lower()
                    )
                    if info:
                        r_in = info.get("input_cost_per_token", 0) or 0
                        r_out = info.get("output_cost_per_token", 0) or 0
                        if r_in or r_out:
                            return (tok_in * r_in) + (tok_out * r_out)
        except Exception:  # noqa: BLE001
            pass
        return 0.0

    def _is_context_too_large(self, e: Exception) -> bool:
        """Detect 'request body too large' / context-window-exceeded errors from any provider.

        Covers OpenAI, Anthropic, Gemini, OpenRouter, Mistral, Cohere, Together AI and
        generic HTTP-proxy 400/413 responses.
        """
        import re as _re

        msg = str(e).lower()
        if any(
            phrase in msg
            for phrase in (
                "request body too large",
                "context_length_exceeded",
                "maximum context length",
                "too many tokens",
                "reduce the length",
                "input is too long",
                "string too long",
                "payload too large",
                "context window",
                "tokens in your prompt",
                "prompt is too long",
                "exceeds the model",
                # Additional provider-specific phrases
                "model context limits",   # OpenRouter
                "reduce context",          # generic
                "request too large",       # HTTP proxies / gateways
                "token count exceeds",     # Together AI / Mistral
                "max context",             # some local models
                "max_tokens",              # bad-param context errors
                "message length",          # per-message size limits
                "token budget",            # Cohere / Bedrock
            )
        ):
            return True
        # Regex catch-all for dynamic phrasing across providers
        return bool(
            _re.search(
                r"exceed.{0,30}(context|token)|"  # "would exceed model context"
                r"(context|token).{0,30}exceed|"  # "context tokens exceeded"
                r"too (many|large).{0,20}token|"  # "too many input tokens"
                r"token.{0,20}(limit|max|over)|"  # "token limit reached"
                r"limit.{0,20}token",               # "limit of N tokens"
                msg,
            )
        )

    def _should_retry(self, e: Exception) -> bool:
        lower_msg = str(e).lower()
        if any(
            marker in lower_msg
            for marker in (
                "invalid api key",
                "authentication",
                "unauthorized",
                "forbidden",
                "insufficient_quota",
                "model_not_found",
                "unsupported parameter",
                "invalid_request_error",
            )
        ):
            return False
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        if code is None:
            return True
        # Retry on rate limits (429) and server errors (5xx).
        # Do NOT retry auth failures (401/403), bad requests (400/422), not found (404).
        return code == 429 or (500 <= code < 600)

    def _raise_error(self, e: Exception) -> None:
        # RELIABILITY REC MED-5: Record LLM failure for circuit breaker
        if _is_circuit_breaker_enabled():
            _CIRCUIT_BREAKER.record_failure()
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    def _is_anthropic(self) -> bool:
        if not self.config.model_name:
            return False
        return any(p in self.config.model_name.lower() for p in ["anthropic/", "claude"])

    def _supports_vision(self) -> bool:
        try:
            return bool(supports_vision(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _supports_reasoning(self) -> bool:
        try:
            return bool(supports_reasoning(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _strip_images(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image_url":
                        text_parts.append("[Image removed - model doesn't support vision]")
                result.append({**msg, "content": "\n".join(text_parts)})
            else:
                result.append(msg)
        return result

    def _add_cache_control(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not messages or not supports_prompt_caching(self.config.canonical_model):
            return messages

        result = list(messages)

        if result[0].get("role") == "system":
            content = result[0]["content"]
            result[0] = {
                **result[0],
                "content": [
                    {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
                ]
                if isinstance(content, str)
                else content,
            }
        return result
