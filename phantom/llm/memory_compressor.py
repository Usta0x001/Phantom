import logging
import time
from typing import Any

import litellm

from phantom.config.config import Config, resolve_llm_config
from phantom.llm.tracked_completion import tracked_completion


logger = logging.getLogger(__name__)


# Default fallback for unknown models — matches the 128K context window shared
# by most modern frontier LLMs (Kimi-K2.5, GPT-4o, Claude 3.x, etc.).
# The old value was 20_000 which caused compression to fire every ~4 iterations
# for any model not mapped in litellm's model registry.
# Safer default: most deployed models are 32K-128K. Using 32K prevents late
# compression on smaller-context models while still being generous.
MAX_TOTAL_TOKENS = 32_000
# Number of recent messages kept verbatim during compression.
MIN_RECENT_MESSAGES = 20


# Hard ceiling on compression threshold regardless of model context window size.
# Prevents runaway context growth on models with very large windows (e.g. 200k+).
# FIX #2: Now configurable via PHANTOM_MAX_CONTEXT_CEILING environment variable
def _get_max_context_ceiling() -> int:
    ceiling_str = Config.get("phantom_max_context_ceiling")
    if ceiling_str:
        try:
            return int(ceiling_str)
        except ValueError:
            pass
    return 80_000

# Max tokens for the compressor's own summarization call (cheap, non-thinking)
# AUDIT-FIX-03: Increased from 3000 to 8000 so summaries preserve exploit detail.
COMPRESSOR_MAX_TOKENS = 8000


def _get_context_fill_ratio(context_window: int) -> float:
    """AUDIT-FIX-02: Model-aware compression ratio.

    Old: fixed 0.25 fired too aggressively on large-context models, wasting 75%
    of the context window. Now we scale by model capacity.
    """
    if context_window >= 100_000:
        return 0.65  # 128K model -> compress at ~83K tokens
    elif context_window >= 32_000:
        return 0.50  # 32K model -> compress at ~16K tokens
    else:
        return 0.40  # Small models -> conservative compression





def _get_model_context_window(model: str) -> int:
    """Return the model's context window size, or MAX_TOTAL_TOKENS if unknown."""
    # First check for explicit Ollama context length config
    ollama_ctx = Config.get("phantom_ollama_context_length")
    if ollama_ctx:
        try:
            ctx = int(ollama_ctx)
            if ctx > 0:
                return ctx
        except ValueError:
            pass

    # Try to get from litellm
    try:
        info = litellm.get_model_info(model)
        # litellm returns max_tokens (context window) or max_input_tokens
        ctx = info.get("max_input_tokens") or info.get("max_tokens")
        if ctx and isinstance(ctx, int) and ctx > 0:
            return int(ctx)
    except Exception:  # noqa: BLE001
        pass
    return MAX_TOTAL_TOKENS


SUMMARY_PROMPT_TEMPLATE = (
    "Summarize this pentest conversation. Preserve verbatim: URLs with vuln signals, "
    "injectable params, working payloads, session tokens/cookies, tool commands that "
    "found issues, HTTP status codes indicating vulns, open ports/services. "
    "Format: STATUS | PROGRESS | FINDINGS | DEAD ENDS | TECH STACK | AUTH STATE.\n\n"
    "{conversation}"
)


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.debug("Failed to count tokens for model %s", model)
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    # Count image URLs first so we can add the fixed vision charge on top of
    # whatever token counter returns (tiktoken does not count image payload).
    content = msg.get("content", "")
    image_count = 0
    if isinstance(content, list):
        image_count = sum(
            1 for item in content
            if isinstance(item, dict) and item.get("type") == "image_url"
        )

    try:
        base = int(litellm.token_counter(model=model, messages=[msg]))
    except Exception:  # noqa: BLE001
        # Fallback when litellm cannot count (unknown model, no tokenizer, etc.)
        base = 0
        if isinstance(content, str):
            base = _count_tokens(content, model)
        elif isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "text":
                    base += _count_tokens(item.get("text", ""), model)
                # image_url tokens added below

    # Vision models charge a fixed ~1024 tokens per image regardless of base64
    # payload size. tiktoken (used by litellm) counts text structure only.
    base += image_count * 1024

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


def _get_keep_recent(agent_state: Any | None) -> int:
    """Return number of recent messages to preserve during compression.

    These messages are kept verbatim and never summarized so the LLM always
    sees the current turn's context.
    """
    return 20


def _summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
) -> dict[str, Any]:
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
        response = tracked_completion(**completion_args)
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
        logger.warning("Failed to summarize messages — returning best-effort text summary")
        lines = []
        for m in messages:
            role = m.get("role", "unknown")
            text = _extract_message_text(m)
            if not text:
                continue
            lines.append(f"[{role}] {text}")

        fallback_text = "\n".join(lines) if lines else "no content"
        return {
            "role": "user",
            "content": (
                f"<context_summary message_count='{len(messages)}' compressed='fallback'>"
                f"{fallback_text[:8000]}"
                f"</context_summary>"
            ),
        }


def _handle_images(
    messages: list[dict[str, Any]],
    max_images: int,
    max_total_image_bytes: int,
) -> tuple[list[dict[str, Any]], int, int, int]:
    transformed: list[dict[str, Any]] = [{**msg} for msg in messages]
    image_count = 0
    kept_image_bytes = 0
    evicted = 0
    for msg in reversed(transformed):
        content = msg.get("content", [])
        if not isinstance(content, list):
            continue
        copied_content = list(content)
        for index, item in enumerate(copied_content):
            if isinstance(item, dict) and item.get("type") == "image_url":
                image_url = item.get("image_url", {})
                url = str(image_url.get("url", "")) if isinstance(image_url, dict) else str(image_url)
                image_bytes = len(url.encode("utf-8", errors="ignore"))
                if (
                    image_count >= max_images
                    or (kept_image_bytes + image_bytes) > max_total_image_bytes
                ):
                    copied_content[index] = {
                        "type": "text",
                        "text": "[Previously attached image removed to preserve context]",
                    }
                    evicted += 1
                else:
                    image_count += 1
                    kept_image_bytes += image_bytes
        msg["content"] = copied_content
    return transformed, image_count, evicted, kept_image_bytes


class MemoryCompressor:
    def __init__(
        self,
        max_images: int = 3,
        max_total_image_bytes: int = 300_000,
        model_name: str | None = None,
        timeout: int | None = None,
    ):
        self.max_images = max_images
        self.max_total_image_bytes = int(
            Config.get("phantom_max_total_image_bytes") or str(max_total_image_bytes)
        )
        self.model_name = model_name or Config.get("phantom_llm")
        # R-04 regression fix: Old versions used 30s timeout which was too short
        # for local models (Ollama). Increased to 180s to accommodate slower local inference.
        self.timeout = timeout or int(Config.get("phantom_memory_compressor_timeout") or "180")

        if not self.model_name:
            # Backward-compatibility fallback for isolated unit tests that
            # instantiate the compressor without full runtime config.
            self.model_name = "openai/gpt-4o-mini"

        # Compute compression threshold from model's actual context window.
        # This ensures small-context models (e.g. kimi-k2.5 @ 8k) compress
        # early enough to never overflow their request body limit.
        env_override = Config.get("phantom_max_input_tokens")
        if env_override:
            self._max_total_tokens = int(env_override)
        else:
            ctx_window = _get_model_context_window(self.model_name)
            # AUDIT-FIX-02: Use model-aware fill ratio instead of fixed 0.25.
            fill_ratio = _get_context_fill_ratio(ctx_window)
            # Capped by MAX_CONTEXT_CEILING to prevent excessive memory growth on
            # models with very large context windows (200k+ tokens).
            self._max_total_tokens = min(
                _get_max_context_ceiling(),
                max(
                    MIN_RECENT_MESSAGES * 200,  # absolute minimum to not compress into nothing
                    int(ctx_window * fill_ratio),
                ),
            )
        logger.debug(
            "MemoryCompressor: model=%s max_total_tokens=%d",
            self.model_name,
            self._max_total_tokens,
        )
        # Counter for compression LLM calls (separate from agent iteration calls)
        self.compression_calls: int = 0

    def compress_history(
        self,
        messages: list[dict[str, Any]],
        agent_state: Any | None = None,
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

        Sequential chunk summarization with fallback to best-effort text extraction.
        """
        if not messages:
            return messages

        runtime_llm = (
            getattr(agent_state, "_runtime_llm", None) if agent_state is not None else None
        )
        if runtime_llm is not None:
            routed_model = getattr(runtime_llm.config, "litellm_model", None)
            if routed_model and routed_model != self.model_name:
                self.model_name = routed_model
                ctx_window = _get_model_context_window(self.model_name)
                fill_ratio = _get_context_fill_ratio(ctx_window)
                self._max_total_tokens = min(
                    _get_max_context_ceiling(),
                    max(
                        MIN_RECENT_MESSAGES * 200,
                        int(ctx_window * fill_ratio),
                    ),
                )

        keep_recent = _get_keep_recent(agent_state)

        processed_messages, kept_images, evicted_images, image_payload_after = _handle_images(
            messages,
            self.max_images,
            self.max_total_image_bytes,
        )

        system_msgs = []
        regular_msgs = []
        for msg in processed_messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        recent_msgs = regular_msgs[-keep_recent:]
        old_msgs = regular_msgs[:-keep_recent]

        total_tokens = sum(
            _get_message_tokens(msg, self.model_name) for msg in system_msgs + regular_msgs
        )

        # Force compression once message count is very high, even if token
        # estimation says we're below threshold. This prevents long-chat drift.
        try:
            msg_trigger = int(Config.get("phantom_compressor_message_trigger") or "80")
        except ValueError:
            msg_trigger = 80
        message_pressure = len(regular_msgs) >= max(20, msg_trigger)

        if (
            total_tokens <= self._max_total_tokens * 0.9
            and evicted_images == 0
            and not message_pressure
        ):
            return processed_messages

        # Pentager ChainSummarizer was here, but removed due to catastrophic forgetting
        # as it permanently deleted old messages rather than summarizing them.

        # Configurable chunk size — larger chunks = fewer compression LLM calls = less latency.
        try:
            chunk_size = int(
                Config.get("phantom_compressor_chunk_size") or str(keep_recent // 2 or 1)
            )
        except ValueError:
            chunk_size = max(1, keep_recent // 2 or 1)
        chunk_size = max(1, chunk_size)
        logger.info(
            "MemoryCompressor: firing compression total_tokens=%d threshold=%d "
            "old_msgs=%d chunk_size=%d evicted_images=%d",
            total_tokens,
            int(self._max_total_tokens * 0.9),
            len(old_msgs),
            chunk_size,
            evicted_images,
        )
        _t0 = time.monotonic()

        compressed = []
        chunks_count = 0
        for i in range(0, len(old_msgs), chunk_size):
            summary = _summarize_messages(
                old_msgs[i : i + chunk_size], self.model_name, self.timeout
            )
            compressed.append(summary)
            self.compression_calls += 1
            chunks_count += 1

        result = system_msgs + compressed + recent_msgs

        # Calculate compression metrics
        tokens_after = sum(_get_message_tokens(msg, self.model_name) for msg in result)
        compression_ratio = 1.0 - (tokens_after / total_tokens) if total_tokens > 0 else 0.0
        duration_ms = (time.monotonic() - _t0) * 1000

        # Emit an audit event so the watch layer can track compression overhead.
        try:
            from phantom.logging.audit import get_audit_logger as _get_audit

            _audit = _get_audit()
            if _audit:
                if evicted_images > 0:
                    _audit.log_image_eviction(
                        agent_id="compressor",
                        kept_images=kept_images,
                        evicted_images=evicted_images,
                        bytes_after=image_payload_after,
                        max_total_image_bytes=self.max_total_image_bytes,
                    )
                _audit.log_compression(
                    agent_id="compressor",
                    model=Config.get("phantom_compressor_llm") or self.model_name,
                    messages_in=len(messages),
                    messages_out=len(result),
                    tokens_before=total_tokens,
                    tokens_after=tokens_after,
                    compression_ratio=round(compression_ratio, 4),
                    chunk_size=chunk_size,
                    chunks_processed=chunks_count,
                    duration_ms=duration_ms,
                )
        except Exception:  # noqa: BLE001
            pass

        return result
