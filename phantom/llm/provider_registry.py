"""
Provider Registry — Multi-Model Fallback Support

Manages LLM provider configurations with automatic fallback chains.
If the primary model fails (rate limit, quota, outage), falls back
to the next provider in the chain.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from phantom.config import Config

logger = logging.getLogger(__name__)

# ─── OpenRouter model metadata cache ───────────────────────────────────────
# Populated lazily on first use of an unknown openrouter/* model.
# Maps  openrouter_model_id → {"context_window": int, "cost_input": float, "cost_output": float}
# e.g.  "google/gemini-flash-1.5" → {"context_window": 1_000_000, ...}
_OR_MODEL_CACHE: dict[str, dict[str, Any]] = {}
_OR_FETCH_STARTED: bool = False
_OR_FETCH_LOCK = threading.Lock()


def _background_fetch_openrouter_models() -> None:
    """Fetch all OpenRouter model metadata in a daemon thread.

    Updates the module-level ``_OR_MODEL_CACHE`` so subsequent calls to
    ``get_context_window()`` use exact values instead of pattern guesses.
    The function is a no-op if the fetch already ran or fails for any reason.
    """
    global _OR_FETCH_STARTED
    try:
        import urllib.request as _req
        import json as _json
        from phantom.config import Config as _Cfg

        api_key = _Cfg.get("llm_api_key") or _Cfg.get("openrouter_api_key") or ""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        request = _req.Request(
            "https://openrouter.ai/api/v1/models",
            headers=headers,
        )
        with _req.urlopen(request, timeout=5) as resp:  # noqa: S310
            data = _json.loads(resp.read().decode())

        fetched = 0
        for model in data.get("data", []):
            model_id = model.get("id", "")
            if not model_id:
                continue
            ctx = model.get("context_length") or model.get("context_window")
            pricing = model.get("pricing") or {}
            entry: dict[str, Any] = {}
            if ctx:
                try:
                    entry["context_window"] = int(ctx)
                except (TypeError, ValueError):
                    pass
            if "prompt" in pricing:
                try:
                    # OpenRouter pricing is per-token; convert to per-1K
                    entry["cost_input"] = float(pricing["prompt"]) * 1000
                except (TypeError, ValueError):
                    pass
            if "completion" in pricing:
                try:
                    entry["cost_output"] = float(pricing["completion"]) * 1000
                except (TypeError, ValueError):
                    pass
            if entry:
                _OR_MODEL_CACHE[model_id.lower()] = entry
                fetched += 1

        logger.info("OpenRouter model cache populated: %d models", fetched)
    except Exception:  # noqa: BLE001
        logger.debug("OpenRouter model metadata fetch failed (non-fatal)", exc_info=True)


def _ensure_openrouter_cache(model_name: str) -> None:
    """Trigger a one-time background fetch when an openrouter/* model is used."""
    global _OR_FETCH_STARTED
    if not model_name.lower().startswith("openrouter/"):
        return
    with _OR_FETCH_LOCK:
        if _OR_FETCH_STARTED:
            return
        _OR_FETCH_STARTED = True
    t = threading.Thread(target=_background_fetch_openrouter_models, daemon=True)
    t.start()


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration for a single LLM provider."""

    model: str
    api_key_env: str = ""  # env var name OR literal key
    api_base: str = ""
    max_tokens: int = 8192
    context_window: int = 128_000
    rate_limit_rpm: int = 30
    supports_vision: bool = False
    supports_reasoning: bool = False
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0


# ── Known provider presets ──────────────────────────────────────────

PROVIDER_PRESETS: dict[str, ProviderConfig] = {
    # Groq (free tier)
    "groq/llama-3.3-70b-versatile": ProviderConfig(
        model="groq/llama-3.3-70b-versatile",
        api_key_env="GROQ_API_KEY",
        context_window=128_000,
        rate_limit_rpm=30,
    ),
    "groq/llama-3.1-8b-instant": ProviderConfig(
        model="groq/llama-3.1-8b-instant",
        api_key_env="GROQ_API_KEY",
        context_window=128_000,
        rate_limit_rpm=30,
    ),
    "groq/llama3-70b-8192": ProviderConfig(
        model="groq/llama3-70b-8192",
        api_key_env="GROQ_API_KEY",
        context_window=8_192,
        rate_limit_rpm=30,
    ),
    # OpenAI
    "gpt-4o": ProviderConfig(
        model="gpt-4o",
        api_key_env="OPENAI_API_KEY",
        context_window=128_000,
        supports_vision=True,
        cost_per_1k_input=0.0025,
        cost_per_1k_output=0.01,
    ),
    "gpt-4o-mini": ProviderConfig(
        model="gpt-4o-mini",
        api_key_env="OPENAI_API_KEY",
        context_window=128_000,
        supports_vision=True,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
    ),
    # Anthropic
    "anthropic/claude-sonnet-4-20250514": ProviderConfig(
        model="anthropic/claude-sonnet-4-20250514",
        api_key_env="ANTHROPIC_API_KEY",
        context_window=200_000,
        supports_vision=True,
        supports_reasoning=True,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
    ),
    "anthropic/claude-3-5-haiku-latest": ProviderConfig(
        model="anthropic/claude-3-5-haiku-latest",
        api_key_env="ANTHROPIC_API_KEY",
        context_window=200_000,
        supports_vision=True,
        cost_per_1k_input=0.001,
        cost_per_1k_output=0.005,
    ),
    # Google Gemini
    "gemini/gemini-2.5-flash": ProviderConfig(
        model="gemini/gemini-2.5-flash",
        api_key_env="GEMINI_API_KEY",
        context_window=1_000_000,
        supports_vision=True,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
    ),
    # Ollama (local)
    "ollama/llama3:70b": ProviderConfig(
        model="ollama/llama3:70b",
        api_base="http://localhost:11434",
        context_window=128_000,
        rate_limit_rpm=999,
    ),
    # ── OpenRouter ────────────────────────────────────────────────────────
    # Paid models
    "openrouter/deepseek/deepseek-v3.2": ProviderConfig(
        model="openrouter/deepseek/deepseek-v3.2",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=163_840,
        max_tokens=16_384,
        rate_limit_rpm=200,
        supports_vision=False,
        supports_reasoning=True,
        cost_per_1k_input=0.00025,
        cost_per_1k_output=0.0004,
    ),
    "openrouter/meta-llama/llama-3.3-70b-instruct": ProviderConfig(
        model="openrouter/meta-llama/llama-3.3-70b-instruct",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=128_000,
        rate_limit_rpm=200,
        supports_vision=False,
    ),
    "openrouter/google/gemma-3-27b-it:free": ProviderConfig(
        model="openrouter/google/gemma-3-27b-it:free",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=131_072,
        rate_limit_rpm=20,
        supports_vision=False,
    ),
    "openrouter/meta-llama/llama-3.3-70b-instruct:free": ProviderConfig(
        model="openrouter/meta-llama/llama-3.3-70b-instruct:free",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=128_000,
        rate_limit_rpm=20,
        supports_vision=False,
    ),
    "openrouter/nousresearch/hermes-3-llama-3.1-405b:free": ProviderConfig(
        model="openrouter/nousresearch/hermes-3-llama-3.1-405b:free",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=131_072,
        rate_limit_rpm=20,
        supports_vision=False,
    ),
    "openrouter/qwen/qwen3-coder:free": ProviderConfig(
        model="openrouter/qwen/qwen3-coder:free",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=262_000,
        rate_limit_rpm=20,
        supports_vision=False,
    ),
    "openrouter/mistralai/mistral-small-3.1-24b-instruct:free": ProviderConfig(
        model="openrouter/mistralai/mistral-small-3.1-24b-instruct:free",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=128_000,
        rate_limit_rpm=20,
        supports_vision=False,
    ),
    # NOTE: openrouter/deepseek/deepseek-v3.2 is defined above with full config
    # (context_window=163_840, rate_limit_rpm=200). Do NOT duplicate here.
    "openrouter/google/gemini-2.5-flash": ProviderConfig(
        model="openrouter/google/gemini-2.5-flash",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=1_000_000,
        max_tokens=16_384,
        rate_limit_rpm=200,
        supports_vision=True,
        supports_reasoning=True,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
    ),
    "openrouter/deepseek/deepseek-chat-v3-0324": ProviderConfig(
        model="openrouter/deepseek/deepseek-chat-v3-0324",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=163_840,
        max_tokens=16_384,
        rate_limit_rpm=200,
        supports_vision=False,
        supports_reasoning=True,
        cost_per_1k_input=0.0008,
        cost_per_1k_output=0.002,
    ),
    "openrouter/deepseek/deepseek-v3.1-terminus": ProviderConfig(
        model="openrouter/deepseek/deepseek-v3.1-terminus",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=163_840,
        max_tokens=16_384,
        rate_limit_rpm=60,
        supports_vision=False,
        supports_reasoning=True,
        cost_per_1k_input=0.00021,
        cost_per_1k_output=0.00079,
    ),
    "openrouter/x-ai/grok-4.1-fast": ProviderConfig(
        model="openrouter/x-ai/grok-4.1-fast",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=2_000_000,
        max_tokens=16_384,
        rate_limit_rpm=60,
        supports_vision=True,
        supports_reasoning=True,
        cost_per_1k_input=0.0002,
        cost_per_1k_output=0.0005,
    ),
    "openrouter/anthropic/claude-sonnet-4": ProviderConfig(
        model="openrouter/anthropic/claude-sonnet-4",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=200_000,
        supports_vision=True,
        supports_reasoning=True,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
    ),
    "openrouter/openai/gpt-4o": ProviderConfig(
        model="openrouter/openai/gpt-4o",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=128_000,
        supports_vision=True,
        cost_per_1k_input=0.0025,
        cost_per_1k_output=0.01,
    ),
    # ── MiniMax (OpenRouter) ───────────────────────────────────────────────
    "openrouter/minimax/minimax-m2.5": ProviderConfig(
        model="openrouter/minimax/minimax-m2.5",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=1_000_000,
        max_tokens=40_000,
        rate_limit_rpm=60,
        supports_vision=False,
        supports_reasoning=False,
        cost_per_1k_input=0.0003,
        cost_per_1k_output=0.0011,
    ),
    # ── Qwen (OpenRouter) ──
    "openrouter/qwen/qwen3-next-80b-a3b-thinking": ProviderConfig(
        model="openrouter/qwen/qwen3-next-80b-a3b-thinking",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=131_072,
        max_tokens=16_384,
        rate_limit_rpm=60,
        supports_vision=False,
        supports_reasoning=True,
        cost_per_1k_input=0.00016,
        cost_per_1k_output=0.0007,
    ),
    "openrouter/qwen/qwen3.5-35b-a3b": ProviderConfig(
        model="openrouter/qwen/qwen3.5-35b-a3b",
        api_key_env="LLM_API_KEY",
        api_base="https://openrouter.ai/api/v1",
        context_window=131_072,
        max_tokens=16_384,
        rate_limit_rpm=60,
        supports_vision=False,
        supports_reasoning=False,
        cost_per_1k_input=0.00014,
        cost_per_1k_output=0.0006,
    ),
}

# ── Context window lookup (covers models not in presets) ────────────

MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    "groq/": 128_000,
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-3.5-turbo": 16_385,
    "anthropic/claude-3": 200_000,
    "anthropic/claude-sonnet-4": 200_000,
    "gemini/": 1_000_000,
    "ollama/": 128_000,
    "mistral/": 32_000,
    "deepseek/": 128_000,
    # OpenRouter prefix (generic fallback — specific models in PROVIDER_PRESETS)
    "openrouter/": 128_000,
}

# Fine-grained substring patterns for dynamic model name matching.
# Checked IN ORDER — first match wins.  Applied after exact + prefix lookup.
# These cover any model (openrouter or bare) that isn't in PROVIDER_PRESETS.
_CONTEXT_WINDOW_PATTERNS: list[tuple[str, int]] = [
    ("gemini",    1_000_000),   # all Gemini variants have ≥1M ctx
    ("claude",      200_000),   # all Claude variants
    ("minimax",   1_000_000),
    ("grok-2",    131_072),
    ("grok",      131_072),
    ("deepseek",  163_840),
    ("qwen3",     131_072),
    ("qwen",      131_072),
    ("llama-3",   128_000),
    ("llama3",    128_000),
    ("llama",     128_000),
    ("mistral",   128_000),
    ("mixtral",   32_768),
    ("hermes",    131_072),
    ("command",   128_000),
    ("phi-3",     128_000),
    ("phi",       128_000),
    ("solar",      32_768),
    ("o3",        200_000),
    ("o1",        128_000),
    ("gpt-4o",    128_000),
    ("gpt-4",     128_000),
]

# Routing prefix → api_base URL (for models unknown to PROVIDER_PRESETS).
# litellm handles most routing natively, but some providers need explicit base.
_ROUTING_API_BASES: list[tuple[str, str]] = [
    ("openrouter/", "https://openrouter.ai/api/v1"),
    ("ollama/",     "http://localhost:11434"),
]


def infer_api_base(model_name: str) -> str | None:
    """Return the api_base for a model based on its routing prefix.

    Used for models NOT in PROVIDER_PRESETS so they are routed correctly
    without requiring explicit LLM_API_BASE environment variables.
    """
    m = model_name.lower()
    for prefix, base in _ROUTING_API_BASES:
        if m.startswith(prefix):
            return base
    return None


def get_context_window(model_name: str) -> int:
    """Get context window size for a model (best-effort lookup).

    Resolution order:
    1. Exact match in PROVIDER_PRESETS (authoritative)
    2. OpenRouter live metadata cache (populated in background on first use)
    3. Specific prefix match
    4. Substring pattern match
    5. Generic prefix fallback
    6. Hard default: 128K
    """
    model = model_name.lower()

    # 1. Exact match in presets
    if model in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[model].context_window

    # Trigger background cache population for openrouter models
    _ensure_openrouter_cache(model_name)

    # 2. OpenRouter live cache — model ID is the part after "openrouter/"
    if model.startswith("openrouter/"):
        or_id = model[len("openrouter/"):]
        cached = _OR_MODEL_CACHE.get(or_id)
        if cached and "context_window" in cached:
            return cached["context_window"]

    # 3. Prefix match (e.g. "groq/", "gemini/")
    for prefix, window in MODEL_CONTEXT_WINDOWS.items():
        if model.startswith(prefix) and window != 128_000:
            return window

    # 4. Substring pattern match — works for openrouter/vendor/model-name
    for pattern, window in _CONTEXT_WINDOW_PATTERNS:
        if pattern in model:
            return window

    # 5. Prefix fallback (includes generic openrouter/ → 128K)
    for prefix, window in MODEL_CONTEXT_WINDOWS.items():
        if model.startswith(prefix):
            return window

    # 6. Hard default
    return 128_000


def get_provider_max_tokens(model_name: str) -> int:
    """Get the max output tokens for a model.

    L2-FIX: Returns the configured max_tokens for known providers,
    or a sensible default (8192) for unknown models.  This value is
    used to constrain LLM response length in API calls.
    """
    model = model_name.lower()

    # Exact match in presets
    if model in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[model].max_tokens

    # Default — most models support at least 8K output
    return 8192


@dataclass
class FallbackChain:
    """Ordered list of providers to try."""

    providers: list[str] = field(default_factory=list)
    _current_idx: int = 0
    _failures: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_config(cls) -> FallbackChain:
        """Build fallback chain from environment/config.

        Reads PHANTOM_LLM for primary model.
        Reads PHANTOM_LLM_FALLBACK for comma-separated fallback models.
        """
        primary = Config.get("phantom_llm") or ""
        fallback_raw = Config.get("phantom_llm_fallback") or ""

        providers = [primary] if primary else []
        if fallback_raw:
            for m in fallback_raw.split(","):
                m = m.strip()
                if m and m not in providers:
                    providers.append(m)

        return cls(providers=providers)

    @property
    def current_model(self) -> str:
        """Get the currently active model."""
        if not self.providers:
            raise ValueError("No LLM providers configured. Set PHANTOM_LLM.")
        return self.providers[self._current_idx]

    def advance(self) -> str | None:
        """Move to the next provider in the chain. Returns new model or None."""
        if self._current_idx + 1 < len(self.providers):
            old = self.current_model
            self._current_idx += 1
            self._failures[old] = self._failures.get(old, 0) + 1
            logger.warning(
                "Falling back from %s to %s (failure #%d)",
                old,
                self.current_model,
                self._failures[old],
            )
            return self.current_model
        return None

    def reset(self) -> None:
        """Reset to primary provider (e.g., after successful request)."""
        self._current_idx = 0

    def get_config(self, model: str | None = None) -> ProviderConfig | None:
        """Get provider config for a model."""
        model = model or self.current_model
        return PROVIDER_PRESETS.get(model.lower())

    @property
    def has_fallback(self) -> bool:
        return len(self.providers) > 1

    @property
    def exhausted(self) -> bool:
        return self._current_idx >= len(self.providers) - 1
