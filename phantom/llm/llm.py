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
from phantom.llm.provider_registry import FallbackChain, get_context_window
from phantom.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    parse_tool_invocations,
)
from phantom.skills import load_skills
from phantom.tools import get_tools_prompt
from phantom.utils.resource_paths import get_phantom_resource_path

_logger = logging.getLogger(__name__)


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
    # Token budget threshold - if prompt exceeds this, compact it
    _COMPACT_TOKEN_THRESHOLD = 8000

    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = RequestStats()
        self.memory_compressor = MemoryCompressor(model_name=config.model_name)
        self.system_prompt = self._load_system_prompt(agent_name)

        # Provider fallback chain (PHANTOM_LLM_FALLBACK env var)
        self._fallback_chain = FallbackChain.from_config()

        # Auto-compact for rate-limited providers
        self._compact_prompt_if_needed()

        reasoning = Config.get("phantom_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        else:
            self._reasoning_effort = "high"

    def _compact_prompt_if_needed(self) -> None:
        """Auto-compact system prompt ONLY when explicitly forced via env var.

        The full system prompt is critical for agent effectiveness.
        It is NEVER auto-switched — Groq models with small context windows
        should use the full prompt and let litellm handle truncation.
        """
        if not self.system_prompt:
            return

        force_compact = (Config.get("phantom_compact_prompt") or "").lower() == "true"

        if force_compact:
            _logger.warning(
                "PHANTOM_COMPACT_PROMPT=true: replacing full system prompt with compact version"
            )
            self.system_prompt = self._build_compact_prompt()

    def _build_compact_prompt(self) -> str:
        """Build a compact system prompt that fits within ~4k tokens."""
        from phantom.tools import get_tools_prompt

        # Get essential tool names only (no full XML schemas)
        tools_summary = self._get_tools_summary()

        return f"""You are Phantom, an advanced AI cybersecurity agent for penetration testing and vulnerability discovery.
You have FULL AUTHORIZATION for non-destructive penetration testing.

<rules>
- Work autonomously - never ask for permission or confirmation
- Every message MUST be a tool call. No plain text responses.
- One tool call per message. End with </function>
- Validate all findings with PoCs before reporting
- Create specialized subagents for each vulnerability type
- NEVER send empty messages - use wait_for_message if idle
</rules>

<tool_format>
<function=tool_name>
<parameter=param_name>value</parameter>
</function>
</tool_format>

<methodology>
1. Reconnaissance: Map attack surface (ports, services, endpoints, technologies)
2. Scanning: Run automated scanners (nuclei, sqlmap, ffuf, nmap)
3. Manual testing: Test for SQLi, XSS, SSRF, IDOR, RCE, auth bypass
4. Validation: Create PoCs for every finding
5. Reporting: Use create_vulnerability_report for confirmed vulns
</methodology>

<available_tools>
{tools_summary}
</available_tools>

<environment>
Docker container with Kali Linux. Tools: nmap, nuclei, sqlmap, ffuf, subfinder, httpx, gospider, zaproxy, semgrep, katana, arjun, jwt_tool, wafw00f, interactsh-client.
Work in /workspace. User: pentester (sudo available). No Docker inside sandbox.
</environment>

<agent_rules>
- Create agents in trees. Each agent has ONE specific task.
- Black-box: Discovery -> Validation -> Reporting (3 agents per vuln)
- Only reporting agents use create_vulnerability_report
- Max 5 skills per agent. Prefer 1-3 focused skills.
- Spawn agents reactively based on discoveries
</agent_rules>
"""

    def _get_tools_summary(self) -> str:
        """Get compact tool listing with just names and one-line descriptions."""
        from phantom.tools.registry import tools as all_tools

        lines = []
        for tool in all_tools:
            name = tool.get("name", "")
            desc = tool.get("description", "").split("\n")[0][:100]
            params = [p["name"] for p in tool.get("parameters", [])]
            params_str = ", ".join(params)
            lines.append(f"- {name}({params_str}): {desc}")
        return "\n".join(lines)

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
            import logging
            logging.getLogger(__name__).exception(
                "Failed to load system prompt for agent %s", agent_name
            )
            return ""

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = await self._prepare_messages(conversation_history)
        max_retries = int(Config.get("phantom_llm_max_retries") or "5")

        for attempt in range(max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                code = getattr(e, "status_code", None) or getattr(
                    getattr(e, "response", None), "status_code", None
                )

                # Try provider fallback on rate-limit or server error
                if code in (429, 500, 502, 503) and self._fallback_chain.has_fallback:
                    next_model = self._fallback_chain.advance()
                    if next_model:
                        _logger.warning(
                            "Provider fallback: switching to %s (attempt %d, code %s)",
                            next_model, attempt + 1, code,
                        )
                        self.config.model_name = next_model
                        continue

                if attempt >= max_retries or not self._should_retry(e):
                    self._raise_error(e)

                # Longer backoff for rate limits (Groq free tier needs ~60s)
                if code == 429:
                    wait = min(65, 15 * (attempt + 1))
                else:
                    wait = min(10, 2 * (2**attempt))
                _logger.info("LLM retry attempt %d/%d after %.0fs", attempt + 1, max_retries, wait)
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
                    accumulated = accumulated[
                        : accumulated.find("</function>") + len("</function>")
                    ]
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

    def _get_per_request_token_limit(self) -> int | None:
        """Return per-request token limit for the current model.

        Uses model-specific context windows from the provider registry,
        reserving space for the response. Groq free tier gets a stricter
        limit due to their per-request caps.
        """
        model = (self.config.model_name or "").lower()

        # Groq free tier has strict per-request limits
        if "groq/" in model:
            return 5500  # Groq free tier: 6000 limit, leave room for response

        # For all other models, use 85% of context window to leave room for response
        ctx = get_context_window(model)
        if ctx <= 16_384:
            return int(ctx * 0.75)  # smaller models: reserve more for response
        return int(ctx * 0.85)

    def _estimate_tokens(self, messages: list[dict[str, Any]]) -> int:
        """Quick token estimate: chars / 4."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += len(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        total += len(item.get("text", ""))
        return total // 4

    def _trim_messages_for_token_limit(
        self, messages: list[dict[str, Any]], limit: int
    ) -> list[dict[str, Any]]:
        """Trim conversation messages to fit within a per-request token limit.

        Strategy: Keep system messages and the most recent messages.
        Drop older non-system messages from the front.
        """
        if self._estimate_tokens(messages) <= limit:
            return messages

        # Separate system/identity messages from conversation
        prefix: list[dict[str, Any]] = []
        conversation: list[dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system" or "<agent_identity>" in str(
                msg.get("content", "")
            ):
                prefix.append(msg)
            else:
                conversation.append(msg)

        prefix_tokens = self._estimate_tokens(prefix)
        remaining = limit - prefix_tokens
        if remaining <= 200:
            # System prompt alone is too large; keep only last message
            return prefix + conversation[-1:]

        # Keep most recent messages that fit
        kept: list[dict[str, Any]] = []
        running = 0
        for msg in reversed(conversation):
            msg_tokens = self._estimate_tokens([msg])
            if running + msg_tokens > remaining:
                break
            kept.insert(0, msg)
            running += msg_tokens

        # Always keep at least the last message
        if not kept and conversation:
            kept = conversation[-1:]

        return prefix + kept

    async def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

        compressed = await self.memory_compressor.compress_history(conversation_history)
        messages.extend(compressed)

        # Trim messages for providers with strict per-request token limits
        token_limit = self._get_per_request_token_limit()
        if token_limit:
            messages = self._trim_messages_for_token_limit(messages, token_limit)

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

        # Support multi-key rotation for rate-limited providers (e.g. Groq free tier)
        api_key = self._get_next_api_key()
        if api_key:
            args["api_key"] = api_key
        if api_base := (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        ):
            args["api_base"] = api_base
        if self._supports_reasoning():
            args["reasoning_effort"] = self._reasoning_effort

        return args

    def _get_next_api_key(self) -> str | None:
        """Rotate between multiple API keys if provided (comma-separated)."""
        raw_key = Config.get("llm_api_key")
        if not raw_key:
            return None
        keys = [k.strip() for k in raw_key.split(",") if k.strip()]
        if len(keys) <= 1:
            return keys[0] if keys else None
        # Round-robin based on request count
        idx = self._total_stats.requests % len(keys)
        return keys[idx]

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

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost

        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _should_retry(self, e: Exception) -> bool:
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        if code is None:
            # Non-HTTP errors (TypeError, ValueError, etc.) are not retryable
            return False
        return litellm._should_retry(code)

    def _raise_error(self, e: Exception) -> None:
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

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
