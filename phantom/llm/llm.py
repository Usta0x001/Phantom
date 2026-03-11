import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import litellm
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import acompletion, completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

logger = logging.getLogger(__name__)

from phantom.config import Config
from phantom.llm.config import LLMConfig
from phantom.llm.memory_compressor import MemoryCompressor
from phantom.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    normalize_tool_format,
    parse_tool_invocations,
)
from phantom.skills import load_skills
from phantom.tools import get_tools_prompt
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
    # Scan mode downgrade order for adaptive mode
    _SCAN_MODE_DOWNGRADE: dict[str, str] = {
        "deep": "standard",
        "standard": "quick",
    }

    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = RequestStats()
        # Per-model breakdown: model_name -> RequestStats (only agent iteration calls)
        self._per_model_stats: dict[str, RequestStats] = {}
        # Call type counters
        self._agent_calls: int = 0    # LLM calls during agent loop iterations
        self._error_calls: int = 0    # LLM calls that ended in an error (after retries)
        self.memory_compressor = MemoryCompressor(model_name=config.litellm_model)
        self.system_prompt = self._load_system_prompt(agent_name)

        reasoning = Config.get("phantom_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        elif config.scan_mode == "stealth":
            self._reasoning_effort = "low"
        else:
            self._reasoning_effort = "high"

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

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=get_tools_prompt,
                loaded_skill_names=list(skill_content.keys()),
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        self._check_budget()
        self._agent_calls += 1
        messages = self._prepare_messages(conversation_history)
        max_retries = int(Config.get("phantom_llm_max_retries") or "5")

        # Optionally switch model based on routing config
        original_model = self.config.litellm_model
        if self._routing_enabled:
            routed = self._pick_routing_model(messages)
            if routed and routed != original_model:
                logger.debug("Routing: switching model %s → %s", original_model, routed)
                self.config.litellm_model = routed

        primary_exhausted = False
        for attempt in range(max_retries + 1):
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
                if self._is_context_too_large(e):
                    # Shrink context aggressively and retry immediately (no sleep)
                    logger.warning(
                        "Context too large for model %s — force-compressing and retrying "
                        "(attempt %d/%d)",
                        self.config.scan_mode,
                        attempt + 1,
                        max_retries,
                    )
                    messages = self._force_compress_messages(messages)
                    continue
                if attempt >= max_retries or not self._should_retry(e):
                    primary_exhausted = True
                    break
                # Longer backoff for rate limits (429) — up to 60 s; others up to 10 s
                code = getattr(e, "status_code", None) or getattr(
                    getattr(e, "response", None), "status_code", None
                )
                if code == 429:
                    wait = min(60, 4 * (2**attempt))
                else:
                    wait = min(10, 2 * (2**attempt))
                await asyncio.sleep(wait)

        # Primary model exhausted — try fallback if configured
        if primary_exhausted and self._fallback_llm_name:
            logger.warning(
                "Primary model %s exhausted — retrying with fallback %s",
                original_model,
                self._fallback_llm_name,
            )
            try:
                self.config.litellm_model = self._fallback_llm_name
                async for response in self._stream(messages):
                    yield response
                self.config.litellm_model = original_model
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                self.config.litellm_model = original_model
                self._error_calls += 1
                self._raise_error(e)
        elif primary_exhausted:
            self.config.litellm_model = original_model
            self._error_calls += 1
            raise LLMRequestFailedError("All retries exhausted for primary model")

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0

        cost_before = self._total_stats.cost
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
            self._update_usage_stats(rebuilt)
            self._update_per_model_stats(rebuilt)
            request_cost = self._total_stats.cost - cost_before
            logger.info(
                "llm_call model=%s scan_mode=%s tokens_in=%d tokens_out=%d "
                "request_cost=$%.4f cumulative_cost=$%.4f",
                self.config.litellm_model,
                self.config.scan_mode,
                self._total_stats.input_tokens,
                self._total_stats.output_tokens,
                request_cost,
                self._total_stats.cost,
            )
            self._check_per_request_budget(cost_before)

        accumulated = normalize_tool_format(accumulated)
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

        compressed = list(self.memory_compressor.compress_history(conversation_history))
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        if messages[-1].get("role") == "assistant":
            messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        return messages

    def _get_max_tokens(self) -> int:
        """Cap output tokens based on scan mode to control cost."""
        env_val = Config.get("llm_max_tokens")
        if env_val:
            return int(env_val)
        if self.config.scan_mode == "quick":
            return 4000
        if self.config.scan_mode == "stealth":
            return 6000
        return 8000  # standard / deep

    def _check_budget(self) -> None:
        """Hard-stop if PHANTOM_MAX_COST is set and exceeded."""
        max_cost_str = Config.get("phantom_max_cost")
        if not max_cost_str:
            return
        try:
            max_cost = float(max_cost_str)
        except ValueError:
            return
        if self._total_stats.cost >= max_cost:
            raise LLMRequestFailedError(
                f"Budget exceeded: ${self._total_stats.cost:.4f} >= max ${max_cost:.4f}"
            )

    def _check_per_request_budget(self, cost_before: float) -> None:
        """Hard-stop if a single LLM call exceeds PHANTOM_PER_REQUEST_CEILING."""
        ceiling_str = Config.get("phantom_per_request_ceiling")
        if not ceiling_str:
            return
        try:
            ceiling = float(ceiling_str)
        except ValueError:
            return
        request_cost = self._total_stats.cost - cost_before
        if request_cost > ceiling:
            raise LLMRequestFailedError(
                f"Per-request budget exceeded: ${request_cost:.4f} > ceiling ${ceiling:.4f}"
            )

    def _build_completion_args(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._supports_vision():
            messages = self._strip_images(messages)

        args: dict[str, Any] = {
            "model": self.config.litellm_model,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
            "max_tokens": self._get_max_tokens(),
        }

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

    def _update_per_model_stats(self, response: Any) -> None:
        """Track per-model token/cost breakdown (agent calls only)."""
        try:
            model_key = self.config.litellm_model or "unknown"
            if model_key not in self._per_model_stats:
                self._per_model_stats[model_key] = RequestStats()
            stats = self._per_model_stats[model_key]
            if hasattr(response, "usage") and response.usage:
                stats.input_tokens += getattr(response.usage, "prompt_tokens", 0) or 0
                stats.output_tokens += getattr(response.usage, "completion_tokens", 0) or 0
                cached = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    cached = getattr(response.usage.prompt_tokens_details, "cached_tokens", 0) or 0
                stats.cached_tokens += cached
                stats.cost += self._extract_cost(response)
            stats.requests += 1
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
        """Downgrade scan mode if cost has exceeded the adaptive threshold."""
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
        fraction = self._total_stats.cost / max_cost
        if fraction >= self._adaptive_threshold:
            new_mode = self._SCAN_MODE_DOWNGRADE.get(self.config.scan_mode)
            if new_mode:
                logger.warning(
                    "Adaptive scan: cost $%.4f is %.0f%% of max $%.4f — "
                    "downgrading scan mode %s → %s",
                    self._total_stats.cost,
                    fraction * 100,
                    max_cost,
                    self.config.scan_mode,
                    new_mode,
                )
                self.config.scan_mode = new_mode

    def _update_usage_stats(self, response: Any) -> None:
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                output_tokens = getattr(response.usage, "completion_tokens", 0) or 0

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

                cost = self._extract_cost(response)
            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0
                cost = 0.0

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost

        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _extract_cost(self, response: Any) -> float:
        if hasattr(response, "usage") and response.usage:
            direct_cost = getattr(response.usage, "cost", None)
            if direct_cost is not None:
                return float(direct_cost)
        try:
            if hasattr(response, "_hidden_params"):
                response._hidden_params.pop("custom_llm_provider", None)
            return completion_cost(response, model=self.config.canonical_model) or 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    def _is_context_too_large(self, e: Exception) -> bool:
        """Detect 'request body too large' / context-window-exceeded errors from any provider."""
        msg = str(e).lower()
        return any(
            phrase in msg
            for phrase in (
                "request body too large",
                "context_length_exceeded",
                "maximum context length",
                "too many tokens",
                "reduce the length",
                "input is too long",
            )
        )

    def _force_compress_messages(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Aggressively halve the non-system messages to recover from a context overflow."""
        from phantom.llm.memory_compressor import _summarize_messages, MIN_RECENT_MESSAGES

        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        if len(non_system) <= MIN_RECENT_MESSAGES:
            # Nothing we can compress further — just keep the tail
            return system_msgs + non_system[-MIN_RECENT_MESSAGES:]

        # Summarize the entire older half into one message
        keep_count = max(MIN_RECENT_MESSAGES, len(non_system) // 2)
        to_compress = non_system[:-keep_count]
        recent = non_system[-keep_count:]

        if to_compress:
            summary = _summarize_messages(
                to_compress,
                self.config.litellm_model,
                timeout=30,
            )
            self.memory_compressor.compression_calls += 1
            return system_msgs + [summary] + recent
        return system_msgs + recent

    def _should_retry(self, e: Exception) -> bool:
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        if code is None:
            return True  # Network/unknown error — always retry
        # Retry on rate limits (429) and server errors (5xx).
        # Do NOT retry auth failures (401/403), bad requests (400/422), not found (404).
        return code == 429 or (500 <= code < 600)

    def _raise_error(self, e: Exception) -> None:
        from phantom.telemetry import posthog

        posthog.error("llm_error", type(e).__name__)
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
