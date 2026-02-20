"""
Provider Registry — Multi-Model Fallback Support

Manages LLM provider configurations with automatic fallback chains.
If the primary model fails (rate limit, quota, outage), falls back
to the next provider in the chain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from phantom.config import Config

logger = logging.getLogger(__name__)


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
}


def get_context_window(model_name: str) -> int:
    """Get context window size for a model (best-effort lookup)."""
    model = model_name.lower()

    # Exact match in presets
    if model in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[model].context_window

    # Prefix match
    for prefix, window in MODEL_CONTEXT_WINDOWS.items():
        if model.startswith(prefix):
            return window

    # Default fallback
    return 128_000


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
