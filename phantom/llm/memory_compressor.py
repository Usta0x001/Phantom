import logging
from typing import Any

import litellm

from phantom.config import Config


logger = logging.getLogger(__name__)


MAX_TOTAL_TOKENS = 80_000
MAX_MESSAGES = 150
MIN_RECENT_MESSAGES = 20

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
    timeout: int = 60,
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

        # LOGIC-004 FIX: Log compression calls to audit trail so data flows
        # to external LLM providers are visible and auditable.
        try:
            from phantom.telemetry.audit_logger import get_global_audit_logger
            _audit = get_global_audit_logger()
            if _audit:
                _audit.log_event(
                    event_type="compression",
                    severity="info",
                    category="llm",
                    data={
                        "model": model,
                        "input_messages": len(messages),
                        "input_chars": len(conversation),
                        "output_chars": len(summary),
                        "provider": model.split("/")[0] if "/" in model else "unknown",
                    },
                )
        except Exception:  # noqa: BLE001
            pass  # Non-fatal — audit logging should never break compression

        if not summary.strip():
            return messages[0]
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "assistant",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Failed to summarize messages")
        # Return a single summary dict so the return type is consistent —
        # returning the raw list defeats the compression budget.
        error_summary = (
            "<context_summary message_count='{count}'>"
            "[Summarization failed — original context contained {count} messages]"
            "</context_summary>"
        )
        return {
            "role": "assistant",
            "content": error_summary.format(count=len(messages)),
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
        max_tokens: int | None = None,
    ):
        self.max_images = max_images
        self.model_name = model_name or Config.get("phantom_llm")
        self.timeout = timeout or int(Config.get("phantom_memory_compressor_timeout") or "60")
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

        # L3-FIX: Strip expired advisory messages before compression.
        # Advisories tagged with <advisory ttl='N' iter='M'> expire after N
        # iterations to prevent token accumulation from persistent warnings.
        import re as _adv_re
        current_iter = 0
        if self._agent_state and hasattr(self._agent_state, "iteration"):
            current_iter = self._agent_state.iteration
        if current_iter > 0:
            cleaned = []
            for msg in messages:
                content = msg.get("content", "")
                if isinstance(content, str) and "<advisory" in content:
                    m = _adv_re.search(r"ttl='(\d+)'\s+iter='(\d+)'", content)
                    if m:
                        ttl = int(m.group(1))
                        created_iter = int(m.group(2))
                        if current_iter - created_iter > ttl:
                            continue  # expired — drop
                cleaned.append(msg)
            messages = cleaned

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
            # Even when no compression needed, inject the findings ledger
            # so the agent always has access to persistent discoveries.
            ledger_msg = self._build_ledger_message()
            if ledger_msg:
                # Insert ledger just before the last few messages
                insert_idx = max(len(system_msgs), len(messages) - MIN_RECENT_MESSAGES)
                messages = messages[:insert_idx] + [ledger_msg] + messages[insert_idx:]
            return messages

        compressed = []
        chunk_size = 10
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]

            # PHT-014 FIX: Before summarizing, extract and pin critical
            # data (working payloads, PoC, exact URLs with params) so the
            # LLM summariser cannot lose them even if it hallucinates.
            critical_extracts: list[str] = []
            import re as _cre
            for cmsg in chunk:
                ctext = _extract_message_text(cmsg)
                # Preserve working payloads (SQL, XSS, command-injection strings)
                for payload in _cre.findall(
                    r"(?:payload|poc|proof.of.concept|working.exploit)[:\s]*(.{10,200})",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[PAYLOAD] {payload.strip()}")
                # Preserve URLs with query params (likely tested endpoints)
                for url in _cre.findall(r"https?://[^\s\"'<>]+\?[^\s\"'<>]+", ctext):
                    critical_extracts.append(f"[URL] {url.rstrip('.,;)')}")
                # Preserve HTTP status anomalies
                for anomaly in _cre.findall(
                    r"(?:status|HTTP)\s*(?:code)?\s*[:=]?\s*(4\d\d|5\d\d)\b[^.]{0,80}",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[HTTP] {anomaly.strip()}")
                # Preserve JWT tokens and Bearer auth
                for jwt in _cre.findall(
                    r"(?:Bearer\s+|token[\"']?\s*[:=]\s*[\"']?)(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[JWT] {jwt[:200]}")
                # Preserve Set-Cookie values
                for cookie in _cre.findall(
                    r"(?:Set-Cookie|cookie)[:\s]*([^\n;]{5,150})",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[COOKIE] {cookie.strip()}")
                # Preserve discovered API endpoints (REST paths)
                for endpoint in _cre.findall(
                    r"(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[a-zA-Z0-9/_\-.]+)",
                    ctext,
                ):
                    critical_extracts.append(f"[ENDPOINT] {endpoint}")
                # Preserve credentials found during scan
                for cred in _cre.findall(
                    r"(?:password|secret|api[_-]?key|admin)[:\s=]+([^\s\"']{3,80})",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[CRED] {cred.strip()}")
                # Preserve numeric IDs (for IDOR testing)
                for idor in _cre.findall(
                    r"(?:user[_-]?id|id|uid|basket[_-]?id)[\"']?\s*[:=]\s*(\d+)",
                    ctext, _cre.IGNORECASE,
                ):
                    critical_extracts.append(f"[ID] {idor}")

            summary = _summarize_messages(chunk, model_name, self.timeout)
            if summary:
                if isinstance(summary, list):
                    compressed.extend(summary)  # fallback returned all messages
                else:
                    # Append critical extracts that may have been lost
                    if critical_extracts:
                        extract_text = "\n".join(dict.fromkeys(critical_extracts))  # dedup
                        existing = summary.get("content", "")
                        summary["content"] = (
                            f"{existing}\n\n"
                            f"<critical_data_preserved>\n{extract_text}\n</critical_data_preserved>"
                        )
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
