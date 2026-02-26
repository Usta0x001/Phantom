import logging
from typing import Any

import litellm

from phantom.config import Config


logger = logging.getLogger(__name__)


MAX_TOTAL_TOKENS = 80_000
MAX_MESSAGES = 150
MIN_RECENT_MESSAGES = 12

SUMMARY_PROMPT_TEMPLATE = """You are performing context condensation for a security
assessment agent.  Compress the conversation while preserving every piece of
operationally critical information.  The agent that reads your output must be
able to continue the assessment exactly where it left off.

MUST PRESERVE (copy verbatim when possible):
1. **Exact URLs, endpoints, and parameters** discovered or tested
2. **Working payloads and PoC details** (SQL queries, XSS payloads, etc.)
3. **Credentials, tokens, API keys, session cookies** found
4. **Vulnerability findings** — type, location, severity, evidence
5. **HTTP status codes and response lengths** that indicate anomalies
6. **Technology stack** — exact versions (e.g. "Express 4.17.1", "Node 18.x")
7. **Failed attempts and dead ends** (so they are NOT repeated)
8. **Attack surface map** — which endpoints exist, which were tested, which remain
9. **Decision rationale** — why particular paths were chosen
10. **Subagent tasks and results** — what was delegated and what came back

COMPRESSION RULES:
- Strip duplicate/repeated tool outputs but keep ONE representative entry
- Condense verbose nmap/nuclei/httpx raw output into structured findings
- NEVER remove a URL, parameter name, or payload string
- Consolidate similar scan results (e.g. "ports 22,80,443,8080 open")
- Keep exact error messages that hint at vulnerabilities
- Preserve the chronological order of discoveries

CONVERSATION SEGMENT:
{conversation}

Write a technically precise summary preserving all details above."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    content = msg.get("content", "")
    if isinstance(content, str):
        return _count_tokens(content, model)
    if isinstance(content, list):
        return sum(
            _count_tokens(item.get("text", ""), model)
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return 0


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
            "role": "assistant",
            "content": empty_summary.format(text="No messages to summarize"),
        }

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_message_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT_TEMPLATE.format(conversation=conversation)

    api_key = Config.get("llm_api_key")
    api_base = (
        Config.get("llm_api_base")
        or Config.get("openai_api_base")
        or Config.get("litellm_base_url")
        or Config.get("ollama_api_base")
    )

    # Resolve provider-specific key / base for known presets
    try:
        from phantom.llm.provider_registry import PROVIDER_PRESETS
        import os as _os

        preset = PROVIDER_PRESETS.get(model.lower())
        if preset:
            if preset.api_key_env:
                _pkey = _os.getenv(preset.api_key_env) or Config.get(preset.api_key_env.lower())
                if _pkey:
                    api_key = _pkey
            if preset.api_base:
                api_base = preset.api_base
    except Exception:  # noqa: BLE001
        pass

    try:
        completion_args: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
        }
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        response = litellm.completion(**completion_args)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            return messages[0]
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "assistant",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Failed to summarize messages")
        return messages[0]


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
        max_tokens: int | None = None,
    ):
        self.max_images = max_images
        self.model_name = model_name or Config.get("phantom_llm")
        self.timeout = timeout or int(Config.get("phantom_memory_compressor_timeout") or "30")
        # Per-profile override; falls back to the module-level default
        self.max_total_tokens = max_tokens or MAX_TOTAL_TOKENS

        if not self.model_name:
            raise ValueError("PHANTOM_LLM environment variable must be set and not empty")

        # Optional back-reference to the agent state so we can read its
        # findings ledger during compression.  Set by the LLM class.
        self._agent_state: Any | None = None

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
        5. Inject findings ledger as a pinned context message (never lost)

        The compression preserves:
        - All system messages unchanged
        - Most recent messages intact
        - Critical security context in summaries
        - Recent images for visual context
        - Technical details and findings
        - Findings ledger (persistent, never compressed)
        """
        if not messages:
            return messages

        # Hard cap on message count to prevent unbounded memory growth
        if len(messages) > MAX_MESSAGES:
            messages = messages[-MAX_MESSAGES:]

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

        if total_tokens <= self.max_total_tokens * 0.9:
            return messages

        compressed = []
        chunk_size = 10
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]
            summary = _summarize_messages(chunk, model_name, self.timeout)
            if summary:
                compressed.append(summary)

        # Inject findings ledger as a pinned context message so it is
        # NEVER lost during compression.  The ledger is a compact list that
        # the agent (and subagents) can rely on for continuity.
        ledger_msg = self._build_ledger_message()

        result = system_msgs + compressed
        if ledger_msg:
            result.append(ledger_msg)
        result.extend(recent_msgs)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_ledger_message(self) -> dict[str, Any] | None:
        """Build a synthetic message from the agent's findings ledger and
        tested endpoint tracking."""
        state = self._agent_state
        if state is None:
            return None

        parts: list[str] = []

        # Findings ledger
        ledger = getattr(state, "findings_ledger", None)
        if ledger:
            text = "\n".join(f"- {f}" for f in ledger[-100:])
            parts.append(
                "<persistent_findings_ledger>\n"
                "The following is a PERSISTENT list of key discoveries that must\n"
                "not be forgotten.  Use this to avoid re-testing endpoints and\n"
                "to remember what has already been found.\n\n"
                f"{text}\n"
                "</persistent_findings_ledger>"
            )

        # Tested endpoint dedup summary
        endpoint_summary_fn = getattr(state, "get_tested_endpoints_summary", None)
        if endpoint_summary_fn:
            summary = endpoint_summary_fn()
            if summary:
                parts.append(
                    "<tested_endpoints>\n"
                    "Endpoints already tested — do NOT re-test these with the same\n"
                    "tool/technique.  Focus on UNTESTED endpoints and attack vectors.\n\n"
                    f"{summary}\n"
                    "</tested_endpoints>"
                )

        if not parts:
            return None

        return {
            "role": "user",
            "content": "\n\n".join(parts),
        }
