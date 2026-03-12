import logging
from typing import Any

import litellm

from phantom.config.config import Config, resolve_llm_config


logger = logging.getLogger(__name__)


# Default fallback for unknown models — matches the 128K context window shared
# by most modern frontier LLMs (Kimi-K2.5, GPT-4o, Claude 3.x, etc.).
# The old value was 20_000 which caused compression to fire every ~4 iterations
# for any model not mapped in litellm's model registry.
MAX_TOTAL_TOKENS = 128_000
MIN_RECENT_MESSAGES = 12
# Hard ceiling on compression threshold regardless of model context window size.
# Prevents runaway context growth on models with very large windows (e.g. 200k+).
MAX_CONTEXT_CEILING = 120_000

# Max tokens for the compressor's own summarization call (cheap, non-thinking)
COMPRESSOR_MAX_TOKENS = 1500

# Fraction of context window to use as the compression trigger threshold.
# 0.6 means we start compressing when we've used 60% of the model's context.
# Leaves 40% headroom for system prompt + output tokens + overhead.
_CONTEXT_FILL_RATIO = 0.6


def _get_model_context_window(model: str) -> int:
    """Return the model's context window size, or MAX_TOTAL_TOKENS if unknown."""
    try:
        info = litellm.get_model_info(model)
        # litellm returns max_tokens (context window) or max_input_tokens
        ctx = info.get("max_input_tokens") or info.get("max_tokens")
        if ctx and isinstance(ctx, int) and ctx > 0:
            return int(ctx)
    except Exception:  # noqa: BLE001
        pass
    return MAX_TOTAL_TOKENS

SUMMARY_PROMPT_TEMPLATE = """You are an agent performing context
condensation for a security agent. Your job is to compress scan data while preserving
ALL operationally critical information for continuing the security assessment.

CRITICAL ELEMENTS TO PRESERVE:
- Discovered vulnerabilities and potential attack vectors
- Scan results and tool outputs (compressed but maintaining key findings)
- System architecture insights and potential weak points
- Progress made in the assessment
- Failed attempts and dead ends (to avoid duplication)
- Any decisions made about the testing approach

COMPRESSION GUIDELINES:
- Preserve exact technical details (URLs, paths, parameters, payloads)
- Summarize verbose tool outputs while keeping critical findings
- Maintain version numbers, specific technologies identified
- Keep exact error messages that might indicate vulnerabilities
- Compress repetitive or similar findings into consolidated form

Remember: Another security agent will use this summary to continue the assessment.
They must be able to pick up exactly where you left off without losing any
operational advantage or context needed to find vulnerabilities.

CONVERSATION SEGMENT TO SUMMARIZE:
{conversation}

Provide a technically precise summary that preserves all operational security context while
keeping the summary concise and to the point."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    content = msg.get("content", "")
    base = 0
    if isinstance(content, str):
        base = _count_tokens(content, model)
    elif isinstance(content, list):
        base = sum(
            _count_tokens(item.get("text", ""), model)
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )
    # Add a fixed overhead per tool_call entry to account for JSON structure
    tool_calls = msg.get("tool_calls") or []
    base += len(tool_calls) * 30
    return base


def _extract_message_text(msg: dict[str, Any]) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image_url":
                    parts.append("[IMAGE]")
        return " ".join(parts)

    return str(content)


def _summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
) -> dict[str, Any]:
    if not messages:
        empty_summary = "<context_summary message_count='0'>{text}</context_summary>"
        return {
            "role": "user",
            "content": empty_summary.format(text="No messages to summarize"),
        }

    # Allow a dedicated cheaper/faster model for compression summarization.
    # Falls back to the main scan model if PHANTOM_COMPRESSOR_LLM is not set.
    compressor_model = Config.get("phantom_compressor_llm") or model

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_message_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT_TEMPLATE.format(conversation=conversation)

    _, api_key, api_base = resolve_llm_config()

    try:
        completion_args: dict[str, Any] = {
            "model": compressor_model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
            "max_tokens": COMPRESSOR_MAX_TOKENS,
        }
        # BUG FIX D: only disable extended thinking for native Anthropic models.
        # Passing `thinking=None` to OpenAI-compatible (or Groq/Gemini) endpoints
        # is an unknown parameter that may trigger a 400 Bad Request on strict APIs.
        if compressor_model and compressor_model.startswith("anthropic/"):
            completion_args["thinking"] = None
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        logger.debug(
            "MemoryCompressor: summarizing %d messages with model=%s",
            len(messages),
            compressor_model,
        )
        response = litellm.completion(**completion_args)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            # LLM returned empty content — fall through to the best-effort text fallback.
            raise ValueError("LLM returned empty summary")
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "user",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Failed to summarize messages — returning best-effort text summary")
        # Return a compact text summary rather than discarding all but the first message.
        # Returning messages[0] would silently drop all other messages in the chunk.
        snippets = []
        for m in messages:
            text = _extract_message_text(m)[:120]
            if text:
                snippets.append(f"[{m.get('role', 'unknown')}] {text}")
        fallback_text = " | ".join(snippets) if snippets else "no content"
        return {
            "role": "user",
            "content": (
                f"<context_summary message_count='{len(messages)}' compressed='fallback'>"
                f"{fallback_text[:800]}"
                f"</context_summary>"
            ),
        }


def _handle_images(messages: list[dict[str, Any]], max_images: int) -> None:
    image_count = 0
    for msg in reversed(messages):
        content = msg.get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "image_url":
                    if image_count >= max_images:
                        item.update(
                            {
                                "type": "text",
                                "text": "[Previously attached image removed to preserve context]",
                            }
                        )
                    else:
                        image_count += 1


class MemoryCompressor:
    def __init__(
        self,
        max_images: int = 3,
        model_name: str | None = None,
        timeout: int | None = None,
    ):
        self.max_images = max_images
        self.model_name = model_name or Config.get("phantom_llm")
        self.timeout = timeout or int(Config.get("phantom_memory_compressor_timeout") or "30")

        if not self.model_name:
            raise ValueError("PHANTOM_LLM environment variable must be set and not empty")

        # Compute compression threshold from model's actual context window.
        # This ensures small-context models (e.g. kimi-k2.5 @ 8k) compress
        # early enough to never overflow their request body limit.
        env_override = Config.get("phantom_max_input_tokens")
        if env_override:
            self._max_total_tokens = int(env_override)
        else:
            ctx_window = _get_model_context_window(self.model_name)
            # Use configured ratio to leave room for system prompt + output tokens.
            # Capped by MAX_CONTEXT_CEILING to prevent excessive memory growth on
            # models with very large context windows (200k+ tokens).
            self._max_total_tokens = min(
                MAX_CONTEXT_CEILING,
                max(
                    MIN_RECENT_MESSAGES * 200,  # absolute minimum to not compress into nothing
                    int(ctx_window * _CONTEXT_FILL_RATIO),
                ),
            )
        logger.debug(
            "MemoryCompressor: model=%s context_window=%d -> max_total_tokens=%d",
            self.model_name,
            _get_model_context_window(self.model_name),
            self._max_total_tokens,
        )
        # Counter for compression LLM calls (separate from agent iteration calls)
        self.compression_calls: int = 0

    def compress_history(
        self,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compress conversation history to stay within token limits.

        Strategy:
        1. Handle image limits first
        2. Keep all system messages
        3. Keep minimum recent messages
        4. Summarize older messages when total tokens exceed limit

        The compression preserves:
        - All system messages unchanged
        - Most recent messages intact
        - Critical security context in summaries
        - Recent images for visual context
        - Technical details and findings
        """
        if not messages:
            return messages

        _handle_images(messages, self.max_images)

        system_msgs = []
        regular_msgs = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        recent_msgs = regular_msgs[-MIN_RECENT_MESSAGES:]
        old_msgs = regular_msgs[:-MIN_RECENT_MESSAGES]

        # Type assertion since we ensure model_name is not None in __init__
        model_name: str = self.model_name  # type: ignore[assignment]

        total_tokens = sum(
            _get_message_tokens(msg, model_name) for msg in system_msgs + regular_msgs
        )

        if total_tokens <= self._max_total_tokens * 0.9:
            return messages

        # Configurable chunk size — larger chunks = fewer compression LLM calls = less latency.
        # PHANTOM_COMPRESSOR_CHUNK_SIZE default is 10 (was hardcoded 5).
        chunk_size = int(Config.get("phantom_compressor_chunk_size") or "10")
        logger.info(
            "MemoryCompressor: firing compression total_tokens=%d threshold=%d "
            "old_msgs=%d chunk_size=%d",
            total_tokens, int(self._max_total_tokens * 0.9), len(old_msgs), chunk_size,
        )
        _t0 = __import__("time").monotonic()
        compressed = []
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]
            summary = _summarize_messages(chunk, model_name, self.timeout)
            if summary:
                compressed.append(summary)
                self.compression_calls += 1

        result = system_msgs + compressed + recent_msgs

        # Emit an audit event so the watch layer can track compression overhead.
        try:
            from phantom.logging.audit import get_audit_logger as _get_audit
            _audit = _get_audit()
            if _audit:
                _audit.log_compression(
                    agent_id="compressor",
                    model=Config.get("phantom_compressor_llm") or model_name,
                    messages_in=len(messages),
                    messages_out=len(result),
                    tokens_before=total_tokens,
                    chunk_size=chunk_size,
                    duration_ms=(__import__("time").monotonic() - _t0) * 1000,
                )
        except Exception:  # noqa: BLE001
            pass

        return result
