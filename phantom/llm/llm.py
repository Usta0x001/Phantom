import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import litellm
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import acompletion, completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

from phantom.config import Config
from phantom.llm.config import LLMConfig
from phantom.llm.memory_compressor import MemoryCompressor
from phantom.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    parse_tool_invocations,
)
from phantom.skills import load_skills
from phantom.tools import get_tools_prompt
from phantom.utils.resource_paths import get_phantom_resource_path


litellm.drop_params = True
litellm.modify_params = True

logger = logging.getLogger(__name__)


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
    requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
        }


class LLM:
    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = RequestStats()

        # L1-FIX: Dynamic context window — use the provider registry to set
        # the memory compressor threshold based on the ACTUAL model context
        # window instead of the hardcoded 80K default.  Use 75% of the
        # model's window as compression threshold (safety margin for the
        # system prompt + response tokens).
        from phantom.llm.provider_registry import get_context_window
        model_context = get_context_window(config.model_name)
        dynamic_max_tokens = int(model_context * 0.75)
        self.memory_compressor = MemoryCompressor(
            model_name=config.model_name,
            max_tokens=dynamic_max_tokens,
        )
        logger.info(
            "LLM context: model=%s window=%d compression_threshold=%d",
            config.model_name, model_context, dynamic_max_tokens,
        )

        self.system_prompt = self._load_system_prompt(agent_name)

        reasoning = Config.get("phantom_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        else:
            self._reasoning_effort = "high"  # always high — profile overrides via scan_profile

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

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

            # v0.9.35: TOOL_PROFILES filtering REMOVED (H-12). Always
            # include ALL tools. Filtering hides tools like ffuf_parameter_fuzz,
            # arjun, jwt_tool, etc. which the agent needs for deep exploitation.
            tools_prompt_fn = lambda: get_tools_prompt()  # noqa: E731

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=tools_prompt_fn,
                loaded_skill_names=list(skill_content.keys()),
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            logger.critical(
                "Failed to load system prompt for agent %s! Agent will run without methodology.",
                agent_name,
                exc_info=True,
            )
            return ""

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    def set_agent_state(self, state: Any) -> None:
        """Give the memory compressor a reference to the agent state so it can
        read the findings ledger during compression.

        We store a *reference* intentionally — the compressor must see the
        live findings_ledger so compressions stay up-to-date.  This is safe
        because the compressor only reads the list; it never mutates it.
        """
        self.memory_compressor._agent_state = state

    def set_memory_threshold(self, max_tokens: int) -> None:
        """Override the memory compression threshold (e.g. from scan profile)."""
        self.memory_compressor.max_total_tokens = max_tokens

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)
        max_retries = int(Config.get("phantom_llm_max_retries") or "5")

        for attempt in range(max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                if attempt >= max_retries or not self._should_retry(e):
                    self._raise_error(e)
                import random as _rand
                wait = min(10, 2 * (2**attempt)) + _rand.uniform(0, 1)
                await asyncio.sleep(wait)

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0

        self._total_stats.requests += 1
        response = await acompletion(**self._build_completion_args(messages), stream=True)

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
                if "</function>" in accumulated:
                    # BUG-04 FIX: Use rfind to get LAST </function> — find() cuts at
                    # embedded </function> inside parameter values.
                    last_idx = accumulated.rfind("</function>")
                    accumulated = accumulated[:last_idx + len("</function>")]
                    yield LLMResponse(content=accumulated)
                    done_streaming = 1
                    continue
                yield LLMResponse(content=accumulated)

        if chunks:
            self._update_usage_stats(stream_chunk_builder(chunks))

        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
        yield LLMResponse(
            content=accumulated,
            tool_invocations=parse_tool_invocations(accumulated),
            thinking_blocks=self._extract_thinking(chunks),
        )

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

        # v0.9.35: In-place compression. Previously operated on a
        # copy, causing unbounded memory growth across 300 iterations.
        compressed = list(self.memory_compressor.compress_history(conversation_history))
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        return messages

    def _build_completion_args(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._supports_vision():
            messages = self._strip_images(messages)

        args: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
        }
        # v0.9.35: Only set temperature if explicitly configured.
        # When None, use the provider's default.
        if self.config.temperature is not None:
            args["temperature"] = self.config.temperature

            # v0.9.35: max_tokens cap REMOVED (H-01). Do NOT set max_tokens.
        # When set to 8192/16384, it truncates complex tool calls mid-output,
        # causing XML parse failures and lost exploitation progress.

        from phantom.llm.provider_registry import PROVIDER_PRESETS, get_provider_max_tokens

        preset = PROVIDER_PRESETS.get(self.config.model_name.lower())
        api_key: str | None = None
        api_base: str | None = None

        if preset:
            if preset.api_key_env:
                import os as _os
                api_key = _os.getenv(preset.api_key_env) or Config.get(preset.api_key_env.lower())
            if preset.api_base:
                api_base = preset.api_base
            # Do NOT fall back to generic LLM_API_BASE for known presets
        else:
            # Unknown model — use generic config
            api_key = Config.get("llm_api_key")
            api_base = (
                Config.get("llm_api_base")
                or Config.get("openai_api_base")
                or Config.get("litellm_base_url")
                or Config.get("ollama_api_base")
            )

        # Last resort key fallback
        if not api_key:
            api_key = Config.get("llm_api_key")

        if api_key:
            args["api_key"] = api_key
        if api_base:
            args["api_base"] = api_base
        if self._supports_reasoning():
            args["reasoning_effort"] = self._reasoning_effort

        return args

    def _get_chunk_content(self, chunk: Any) -> str:
        if chunk.choices and hasattr(chunk.choices[0], "delta"):
            return getattr(chunk.choices[0].delta, "content", "") or ""
        return ""

    def _extract_thinking(self, chunks: list[Any]) -> list[dict[str, Any]] | None:
        if not chunks or not self._supports_reasoning():
            return None
        try:
            resp = stream_chunk_builder(chunks)
            if resp.choices and hasattr(resp.choices[0].message, "thinking_blocks"):
                blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                return blocks
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return None

    def _update_usage_stats(self, response: Any) -> None:
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0)
                output_tokens = getattr(response.usage, "completion_tokens", 0)

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0

            try:
                cost = completion_cost(response) or 0.0
            except Exception:  # noqa: BLE001
                cost = 0.0

            # L4-FIX: Cost fallback estimator — when litellm.completion_cost()
            # returns 0 (unsupported model, custom OpenRouter route, etc.),
            # estimate cost from the provider registry's cost_per_1k rates.
            # Without this, spend appears free and cost limits never trigger.
            if cost == 0.0 and (input_tokens > 0 or output_tokens > 0):
                try:
                    from phantom.llm.provider_registry import PROVIDER_PRESETS
                    model_key = self.config.model_name.lower()
                    preset = PROVIDER_PRESETS.get(model_key)
                    if preset and (preset.cost_per_1k_input > 0 or preset.cost_per_1k_output > 0):
                        cost = (
                            (input_tokens / 1000) * preset.cost_per_1k_input
                            + (output_tokens / 1000) * preset.cost_per_1k_output
                        )
                        logger.debug(
                            "L4-FIX: Estimated cost $%.4f from registry rates "
                            "(%d in + %d out tokens)",
                            cost, input_tokens, output_tokens,
                        )
                except (ImportError, AttributeError):
                    pass

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost

            # ---- Cost Controller integration (PHT security control) ----
            try:
                from phantom.core.cost_controller import get_cost_controller
                cc = get_cost_controller()
                if cc is not None:
                    cc.record_usage(
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        cached_tokens=cached_tokens,
                        cost_usd=cost,
                    )
            except ImportError:
                pass

        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _should_retry(self, e: Exception) -> bool:
        # Always retry on transient network errors
        if isinstance(e, (ConnectionError, OSError, TimeoutError)):
            return True
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        return code is None or litellm._should_retry(code)

    def _raise_error(self, e: Exception) -> None:
        # Redact potential API keys/secrets from error details
        details = str(e)
        import re as _re
        # Redact various API key / token formats
        details = _re.sub(
            r"(sk-|key-|api[_-]?key[=: \"]*|bearer\s+|token[=: \"]*)[A-Za-z0-9\-_./]{8,}",
            r"\1[REDACTED]",
            details,
            flags=_re.IGNORECASE,
        )
        # Also redact anything that looks like a long hex/base64 secret
        details = _re.sub(
            r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
            "[REDACTED]",
            details,
        )
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", details) from e

    def _is_anthropic(self) -> bool:
        if not self.config.model_name:
            return False
        return any(p in self.config.model_name.lower() for p in ["anthropic/", "claude"])

    def _supports_vision(self) -> bool:
        try:
            return bool(supports_vision(model=self.config.model_name))
        except Exception:  # noqa: BLE001
            return False

    def _supports_reasoning(self) -> bool:
        try:
            return bool(supports_reasoning(model=self.config.model_name))
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
        if not messages or not supports_prompt_caching(self.config.model_name):
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
