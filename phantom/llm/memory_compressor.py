import asyncio
import hashlib
import json
import logging
import re
from typing import Any

import litellm

from phantom.config.config import Config, resolve_llm_config
from phantom.llm.tracked_completion import tracked_acompletion, tracked_completion


logger = logging.getLogger(__name__)


# Default fallback for unknown models — matches the 128K context window shared
# by most modern frontier LLMs (Kimi-K2.5, GPT-4o, Claude 3.x, etc.).
# The old value was 20_000 which caused compression to fire every ~4 iterations
# for any model not mapped in litellm's model registry.
MAX_TOTAL_TOKENS = 128_000
# FIX BUG-2: Increased from 10 to 15 - findings in messages 11-20 were getting
# summarized and losing exact payload details. Now more recent context preserved.
MIN_RECENT_MESSAGES = 15
# Hard ceiling on compression threshold regardless of model context window size.
# Prevents runaway context growth on models with very large windows (e.g. 200k+).
# FIX #2: Now configurable via PHANTOM_MAX_CONTEXT_CEILING environment variable
def _get_max_context_ceiling() -> int:
    from phantom.config.config import Config
    ceiling_str = Config.get("phantom_max_context_ceiling")
    if ceiling_str:
        try:
            return int(ceiling_str)
        except ValueError:
            pass
    return 80_000

MAX_CONTEXT_CEILING = _get_max_context_ceiling()

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

# Keywords that indicate a message contains a confirmed finding worth anchoring.
# ENHANCED: Added credentials, network info, and attack progression keywords
# to prevent context loss during memory compression.
_ANCHOR_KEYWORDS = (
    # Core vulnerability indicators
    "vulnerability", "vulnerabilit", "exploit", "sqli", "xss", "rce",
    "injection", "bypass", "authentication", "unauthorized", "open port",
    "open ports", "found:", "discovered", "confirmed", "critical", "high",
    "medium", "cve-", "owasp", "payload", "proof of concept", "poc",
    "create_vulnerability_report",
    # Vulnerability types
    "idor", "idor vulnerability", "idor allows",
    "csrf", "xsrf", "csrf vulnerability", "csrf allows",
    "ssrf", "xxe", "ssti", "template injection",
    "lfi", "rfi", "path traversal", "directory traversal",
    "weak password", "default credential", "hardcoded", "api key exposed",
    "jwt", "token", "jwt vulnerability", "broken access", "broken auth",
    "misconfiguration", "misconfigured",
    "sensitive data", "data exposure", "information disclosure",
    "race condition", "deserialization", "deserializ",
    "buffer overflow", "heap overflow", "stack overflow",
    "command injection", "os command", "remote code",
    "upload vulnerability", "file upload",
    "open redirect", "redirect vulnerability",
    "host header", "host header injection",
    "idor allows accessing", "idor allows viewing",
    "idor vulnerability allows",
    # ADDED: Credentials and secrets (prevent losing discovered credentials)
    "password", "passwd", "credential", "secret", "api_key", "apikey",
    "api-key", "bearer", "authorization", "auth_token", "access_token",
    "refresh_token", "private_key", "public_key", "ssh_key",
    # ADDED: Session and authentication tokens
    "session", "cookie", "session_id", "sessionid", "phpsessid",
    "jsessionid", "asp.net_sessionid", "csrf_token", "xsrf_token",
    # ADDED: Network and infrastructure (internal IPs, cloud metadata)
    "internal", "private", "localhost", "127.0.0.1", "0.0.0.0",
    "10.0.", "10.1.", "10.2.", "172.16.", "172.17.", "172.18.",
    "192.168.", "169.254.", "metadata.google", "169.254.169.254",
    "metadata", "aws", "gcp", "azure", "ec2", "iam", "s3 bucket",
    # ADDED: System and execution (prevent losing shell/command info)
    "shell", "command", "exec", "system", "eval", "subprocess",
    "admin", "root", "sudo", "privilege", "escalat", "elevated",
    # ADDED: Files and paths (prevent losing file discovery info)
    "upload", "download", "file", "/etc/", "/var/", "/tmp/",
    "config", "backup", ".env", ".git", "web.config", "wp-config",
    ".htaccess", "robots.txt", "sitemap", "swagger", "openapi",
    # ADDED: Testing context (preserve what was tested and findings)
    "endpoint", "parameter", "header", "query", "body", "form",
    "response", "status", "error", "exception", "stack trace",
    "500 internal", "403 forbidden", "401 unauthorized", "400 bad",
    # ADDED: Attack progression (preserve chaining information)
    "chain", "pivot", "escalat", "exfiltrat", "lateral", "post-exploit",
    "foothold", "persistence", "c2", "callback", "reverse shell",
    "bind shell", "webshell", "backdoor",
    # ADDED: WAF and bypass indicators
    "waf", "firewall", "blocked", "filtered", "sanitized", "encoded",
    "bypass", "evasion", "obfuscat",
    # ADDED: Out-of-band indicators
    "oast", "out-of-band", "dns callback", "http callback", "blind",
    "time-based", "sleep", "delay", "waitfor",
    
    # PLAN FIX: Add uncertain/possible findings (new keywords)
    "appears vulnerable", "might be", "potential", "possible issue",
    "suspect", "uncertain", "needs verification", "needs more testing",
    "初步发现", "可能存在", "待确认",  # Chinese: initial finding, may exist, pending confirmation
)

# PLAN FIX: Add keywords for uncertain/potential findings
_ANCHOR_UNCERTAIN_KEYWORDS = (
    "appears vulnerable", "might be", "potential issue", "possible issue",
    "suspect", "needs verification", "needs more testing", "初步发现",
    "可能存在", "待确认",
)
_ANCHOR_UNCERTAIN_PATTERN = re.compile(
    "|".join(re.escape(kw) for kw in _ANCHOR_UNCERTAIN_KEYWORDS),
    re.IGNORECASE
)

# HIGH-1 FIX: Precompiled regex for case-insensitive keyword matching.
# Uses re.IGNORECASE which avoids allocating a lowercased string copy.
# The regex approach also simplifies the code and handles edge cases better.
_ANCHOR_KEYWORDS_PATTERN = re.compile(
    "|".join(re.escape(kw) for kw in _ANCHOR_KEYWORDS),
    re.IGNORECASE
)


# FIX BUG-1: Anchor keywords that indicate CONFIRMED findings (not just testing context)
# Require at least one of these to consider message a "finding"
_ANCHOR_CONFIRM_KEYWORDS = (
    "found:", "confirmed", "critical", "vulnerability confirmed",
    "exploit successful", "poc", "proof of concept",
    "sqli confirmed", "xss confirmed", "rce confirmed",
    "authentication bypassed", "access gained", "shell obtained",
    "database exposed", "credentials captured", "command executed",
)
_ANCHOR_CONFIRM_PATTERN = re.compile(
    "|".join(re.escape(kw) for kw in _ANCHOR_CONFIRM_KEYWORDS),
    re.IGNORECASE
)

# Additional concrete-evidence markers so anchors prefer actionable findings
# over generic testing chatter.
_ANCHOR_EVIDENCE_KEYWORDS = (
    "status code:",
    "status=",
    "returned:",
    "received:",
    "response:",
    "extracted:",
    "sql error",
    "syntax error",
    "<script",
    "alert(",
    "token",
    "uid=",
    "admin@",
    "200",
)
_ANCHOR_EVIDENCE_PATTERN = re.compile(
    "|".join(re.escape(kw) for kw in _ANCHOR_EVIDENCE_KEYWORDS),
    re.IGNORECASE,
)

# FIX BUG-1: Keywords that indicate just "testing" (not findings) - require confirm keyword too
_ANCHOR_TESTING_KEYWORDS = (
    "testing", "trying", "attempting", "checking", "enumerating",
    "scanning", "probing", "searching", "looking for",
    "error:", "error -", "failed", "exception",
)
_ANCHOR_TESTING_PATTERN = re.compile(
    "|".join(re.escape(kw) for kw in _ANCHOR_TESTING_KEYWORDS),
    re.IGNORECASE
)


def _extract_anchors_from_chunk(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Scan a chunk of messages about to be compressed and return anchor dicts
    for any high-signal lines that should survive compression.

    FIX BUG-1: Now requires CONFIRM keywords, not just general keywords.
    A message with just "Testing SQLi" is NOT anchored - requires "found" or "confirmed".

    An anchor has the shape::

        {"text": "<extracted snippet>", "key": "<dedup key>", "source": "compressor"}
    """
    anchors: list[dict[str, Any]] = []
    for msg in messages:
        text = ""
        content = msg.get("content", "")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(part.get("text", ""))
            text = " ".join(parts)

        if not text:
            continue

        # FIX BUG-1: Check message characteristics
        has_confirm = _ANCHOR_CONFIRM_PATTERN.search(text) is not None
        has_general_vuln = _ANCHOR_KEYWORDS_PATTERN.search(text) is not None
        has_testing_language = _ANCHOR_TESTING_PATTERN.search(text) is not None
        has_uncertain = _ANCHOR_UNCERTAIN_PATTERN.search(text) is not None
        has_concrete_evidence = _ANCHOR_EVIDENCE_PATTERN.search(text) is not None
        
        # FIX BUG-1: Skip only if it's pure error without any vulnerability context
        if has_testing_language and not has_general_vuln and not has_confirm:
            continue

        # Prefer high-signal anchors:
        # - confirmed findings, or
        # - explicitly uncertain findings, or
        # - vulnerability indicators with concrete evidence.
        if has_confirm:
            confidence = "high"
        elif has_uncertain:
            confidence = "low"
        elif has_general_vuln and has_concrete_evidence:
            confidence = "medium"
        else:
            continue

        # Extract the first 1500 chars as the anchor snippet — increased from 600
        # to preserve enough detail for vulnerability reporting.
        snippet = text.strip()[:1500]
        if not snippet:
            continue

        anchors.append({
            "key": snippet[:80],
            "text": snippet,
            "source": "compressor",
            "confidence": confidence,
        })

    return anchors


def _get_model_context_window(model: str) -> int:
    """Return the model's context window size, or MAX_TOTAL_TOKENS if unknown."""
    # First check for explicit Ollama context length config
    from phantom.config.config import Config
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

SUMMARY_PROMPT_TEMPLATE = """You are a context compression agent for a penetration testing system.
Compress the scan data below while preserving ALL operationally critical information.

PRESERVE EXACTLY (copy verbatim, do NOT paraphrase):
- All URLs that showed vulnerability signals (full URL with path and query params)
- All parameter names confirmed as injectable or interesting
- All working payloads and exploit strings
- All session tokens, cookies, or credentials found
- All tool names and exact commands used that produced findings
- All HTTP status codes and response patterns indicating vulnerabilities
- All open ports and services discovered

Output format:
STATUS: (current phase)
PROGRESS: (what has been done)
FINDINGS: (list each finding with exact URL, parameter, and evidence)
DEAD ENDS: (list of failed attempts — tool + target + why it failed)
TECH STACK: (discovered technologies)
AUTH STATE: (any auth tokens/cookies obtained)

CONVERSATION SEGMENT TO SUMMARIZE:
{conversation}

Provide a technically precise summary. Copy vulnerability evidence verbatim."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    try:
        return int(litellm.token_counter(model=model, messages=[msg]))
    except Exception:  # noqa: BLE001
        pass
    content = msg.get("content", "")
    base = 0
    if isinstance(content, str):
        base = _count_tokens(content, model)
    elif isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                base += _count_tokens(item.get("text", ""), model)
            elif item.get("type") == "image_url":
                image_url = item.get("image_url", {})
                if isinstance(image_url, dict):
                    url = str(image_url.get("url", ""))
                else:
                    url = str(image_url)
                base += max(len(url) // 4, 256)
    tool_calls = msg.get("tool_calls") or []
    base += len(tool_calls) * 30
    return base


def _estimate_image_payload_bytes(messages: list[dict[str, Any]]) -> int:
    total = 0
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "image_url":
                continue
            image_url = item.get("image_url", {})
            if isinstance(image_url, dict):
                url = str(image_url.get("url", ""))
            else:
                url = str(image_url)
            total += len(url.encode("utf-8", errors="ignore"))
    return total


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


def _message_digest(msg: dict[str, Any]) -> str:
    try:
        payload = json.dumps(msg, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        payload = str(msg)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _message_evidence_score(msg: dict[str, Any]) -> float:
    text = _extract_message_text(msg)
    if not text:
        return 0.0

    score = 0.0
    if _ANCHOR_CONFIRM_PATTERN.search(text):
        score += 5.0
    if _ANCHOR_EVIDENCE_PATTERN.search(text):
        score += 3.0
    if _ANCHOR_UNCERTAIN_PATTERN.search(text):
        score += 1.0
    if _ANCHOR_KEYWORDS_PATTERN.search(text):
        score += 1.0
    score += min(len(text) / 250.0, 2.0)
    return round(score, 2)


def _get_phase_retention(agent_state: Any | None) -> tuple[str, int, int]:
    phase = "recon"
    scan_mode = "deep"
    if agent_state is not None:
        scan_mode = str(getattr(agent_state, "scan_mode", scan_mode)).lower()
        current_phase = getattr(agent_state, "current_phase", None)
        if current_phase is not None and hasattr(current_phase, "value"):
            phase = str(current_phase.value).lower()
        else:
            phase = str(getattr(agent_state, "phase", phase)).lower()

    if phase == "recon":
        return phase, 18, 12
    if phase == "testing":
        return phase, 20, 15
    if phase == "wrap_up":
        return phase, 24, 15
    if scan_mode == "stealth":
        return phase, 22, 10
    return phase, MIN_RECENT_MESSAGES, 15


def _build_structured_summary(
    messages: list[dict[str, Any]],
    phase: str,
    facts: list[dict[str, Any]],
    delta_facts: list[dict[str, Any]],
) -> str:
    lines = [f"PHASE: {phase.upper()}", f"MESSAGES: {len(messages)}", f"FACTS: {len(facts)}"]
    if delta_facts:
        lines.append(f"DELTA_FACTS: {len(delta_facts)}")
    for fact in facts[:12]:
        lines.append(f"- {fact['type']}: {fact['value'][:180]}")
    if delta_facts:
        lines.append("DELTA:")
        for fact in delta_facts[:8]:
            lines.append(f"- {fact['type']}: {fact['value'][:180]}")
    return "\n".join(lines)


_FACT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"https?://[^\s'\"]+|/[^\s'\"]+")),
    ("payload", re.compile(r"(?:'\s*or\s*'1'='1|union\s+select|<script[^>]*>|onerror=|onload=|sleep\(|waitfor\s+delay|../|\.\.\\|\$\{[^}]+\}|{{[^}]+}})", re.IGNORECASE)),
    ("status_code", re.compile(r"\b(?:status\s*code[:=]\s*)?(?:200|201|204|301|302|400|401|403|404|500)\b", re.IGNORECASE)),
    ("token", re.compile(r"\b(?:bearer|session_id|sessionid|csrf_token|auth_token|api[_-]?key|password|secret)\b", re.IGNORECASE)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("chain", re.compile(r"\b(?:ssrf\s*->\s*metadata|sqli\s*->\s*rce|pivot|chain|lateral)\b", re.IGNORECASE)),
)


def _extract_structured_facts(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for msg in messages:
        content = _extract_message_text(msg)
        if not content:
            continue

        role = str(msg.get("role", "unknown"))
        for fact_type, pattern in _FACT_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0).strip()
                if not value:
                    continue
                key = (fact_type, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                facts.append({
                    "type": fact_type,
                    "value": value[:500],
                    "role": role,
                    "source": msg.get("role", "unknown"),
                })

    return facts


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
        logger.exception("Failed to summarize messages — returning best-effort text summary")
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


# ════════════════════════════════════════════════════════════════════════════════
# EFFICIENCY FIX MEM-P1.1: Async Parallel Chunk Summarization
# ════════════════════════════════════════════════════════════════════════════════
# Previously: Sequential summarization of N chunks took N * 3-5s = 12-20s
# Now: Parallel summarization takes 3-5s total (4x speedup)

async def _async_summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Async version of _summarize_messages for parallel chunk processing.
    
    Uses litellm.acompletion for async LLM calls.
    """
    if not messages:
        empty_summary = "<context_summary message_count='0'>{text}</context_summary>"
        return {
            "role": "user",
            "content": empty_summary.format(text="No messages to summarize"),
        }

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
        if compressor_model and compressor_model.startswith("anthropic/"):
            completion_args["thinking"] = None
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        logger.debug(
            "MemoryCompressor (async): summarizing %d messages with model=%s",
            len(messages),
            compressor_model,
        )
        # Use async completion for parallel processing
        response = await tracked_acompletion(**completion_args)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            raise ValueError("LLM returned empty summary")
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "user",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Async summarization failed — returning best-effort fallback")
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


async def _parallel_summarize_chunks(
    chunks: list[list[dict[str, Any]]],
    model: str,
    timeout: int,
    max_concurrency: int = 4,
) -> list[dict[str, Any]]:
    """Summarize multiple chunks in parallel with bounded concurrency.
    
    Args:
        chunks: List of message chunks to summarize
        model: LLM model to use
        timeout: Timeout per summarization call
        max_concurrency: Maximum parallel LLM calls (default 4 to avoid rate limits)
    
    Returns:
        List of summary messages in order
    """
    if not chunks:
        return []
    
    # Use semaphore to limit concurrency and avoid rate limits
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def _bounded_summarize(chunk: list[dict[str, Any]]) -> dict[str, Any]:
        async with semaphore:
            return await _async_summarize_messages(chunk, model, timeout)
    
    # Run all summarizations in parallel
    tasks = [_bounded_summarize(chunk) for chunk in chunks]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Handle any exceptions - replace with fallback summaries
    summaries = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning("Parallel chunk %d failed: %s", i, result)
            # Create fallback summary
            chunk = chunks[i]
            lines = []
            for m in chunk:
                role = m.get("role", "unknown")
                text = _extract_message_text(m)
                if text:
                    lines.append(f"[{role}] {text[:500]}")
            fallback_text = "\n".join(lines) if lines else "no content"
            summaries.append({
                "role": "user",
                "content": (
                    f"<context_summary message_count='{len(chunk)}' compressed='fallback'>"
                    f"{fallback_text[:4000]}"
                    f"</context_summary>"
                ),
            })
        else:
            summaries.append(result)
    
    return summaries


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
        if isinstance(content, list):
            copied_content = [dict(item) if isinstance(item, dict) else item for item in content]
            for index, item in enumerate(content):
                if isinstance(item, dict) and item.get("type") == "image_url":
                    image_url = item.get("image_url", {})
                    if isinstance(image_url, dict):
                        url = str(image_url.get("url", ""))
                    else:
                        url = str(image_url)
                    image_bytes = len(url.encode("utf-8", errors="ignore"))
                    if image_count >= max_images or (kept_image_bytes + image_bytes) > max_total_image_bytes:
                        copied_content[index] = {
                            "type": "text",
                            "text": "[Previously attached image removed to preserve context]",
                        }
                        evicted += 1
                    else:
                        image_count += 1
                        kept_image_bytes += image_bytes
                        copied_content[index] = item
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
                MAX_CONTEXT_CEILING,
                max(
                    MIN_RECENT_MESSAGES * 200,  # absolute minimum to not compress into nothing
                    int(ctx_window * fill_ratio),
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
        
        EFFICIENCY FIX MEM-P1.1: Now uses parallel chunk summarization for 4x speedup.
        """
        if not messages:
            return messages

        runtime_llm = getattr(agent_state, "_runtime_llm", None) if agent_state is not None else None
        if runtime_llm is not None:
            routed_model = getattr(runtime_llm.config, "litellm_model", None)
            if routed_model and routed_model != self.model_name:
                self.model_name = routed_model
                ctx_window = _get_model_context_window(self.model_name)
                fill_ratio = _get_context_fill_ratio(ctx_window)
                self._max_total_tokens = min(
                    MAX_CONTEXT_CEILING,
                    max(
                        MIN_RECENT_MESSAGES * 200,
                        int(ctx_window * fill_ratio),
                    ),
                )

        phase, keep_recent, anchor_cap = _get_phase_retention(agent_state)

        image_payload_before = _estimate_image_payload_bytes(messages)
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

        # Type assertion since we ensure model_name is not None in __init__
        model_name: str = self.model_name  # type: ignore[assignment]

        total_tokens = sum(
            _get_message_tokens(msg, model_name) for msg in system_msgs + regular_msgs
        )

        image_pressure = image_payload_before > self.max_total_image_bytes

        # Force compression once message count is very high, even if token
        # estimation says we're below threshold. This prevents long-chat drift
        # and ensures anchor extraction is exercised on extended runs.
        try:
            msg_trigger = int(Config.get("phantom_compressor_message_trigger") or "80")
        except ValueError:
            msg_trigger = 80
        message_pressure = len(regular_msgs) >= max(20, msg_trigger)

        compression_state = {}
        if agent_state is not None and hasattr(agent_state, "compression_state"):
            try:
                state_value = getattr(agent_state, "compression_state") or {}
                if isinstance(state_value, dict):
                    compression_state = dict(state_value)
            except Exception:
                compression_state = {}

        last_digest = set(compression_state.get("last_digest", []))
        current_digest = [_message_digest(msg) for msg in old_msgs]
        delta_messages = [msg for msg, digest in zip(old_msgs, current_digest) if digest not in last_digest]
        structured_facts = _extract_structured_facts(regular_msgs)
        delta_facts = _extract_structured_facts(delta_messages)

        if agent_state is not None and hasattr(agent_state, "compression_state"):
            try:
                compression_state["structured_facts"] = structured_facts[-50:]
                compression_state["delta_facts"] = delta_facts[-25:]
                compression_state["last_phase"] = phase
                compression_state["last_keep_recent"] = keep_recent
                compression_state["last_chunk_size"] = max(1, keep_recent // 2 or 1)
                agent_state.compression_state = compression_state
            except Exception:
                pass

        if (
            total_tokens <= self._max_total_tokens * 0.9
            and not image_pressure
            and evicted_images == 0
            and not message_pressure
        ):
            if agent_state is not None and hasattr(agent_state, "compression_state"):
                try:
                    compression_state["last_digest"] = [_message_digest(msg) for msg in recent_msgs]
                    compression_state["last_phase"] = phase
                    compression_state["last_keep_recent"] = keep_recent
                    agent_state.compression_state = compression_state
                except Exception:
                    pass
            return processed_messages

        # Pentager ChainSummarizer was here, but removed due to catastrophic forgetting
        # as it permanently deleted old messages rather than summarizing them.

        # Configurable chunk size — larger chunks = fewer compression LLM calls = less latency.
        # PHANTOM_COMPRESSOR_CHUNK_SIZE default is phase-aware.
        try:
            chunk_size = int(Config.get("phantom_compressor_chunk_size") or str(keep_recent // 2 or 1))
        except ValueError:
            chunk_size = max(1, keep_recent // 2 or 1)
        chunk_size = max(1, chunk_size)
        logger.info(
            "MemoryCompressor: firing compression total_tokens=%d threshold=%d "
            "old_msgs=%d chunk_size=%d image_pressure=%s evicted_images=%d",
            total_tokens,
            int(self._max_total_tokens * 0.9),
            len(old_msgs),
            chunk_size,
            image_pressure,
            evicted_images,
        )
        _t0 = __import__("time").monotonic()

        # Extract high-signal anchors BEFORE compression
        if agent_state is not None and hasattr(agent_state, "add_finding_anchor"):
            for i in range(0, len(old_msgs), chunk_size):
                chunk = old_msgs[i : i + chunk_size]
                for anchor in _extract_anchors_from_chunk(chunk):
                    if isinstance(anchor, dict):
                        anchor["evidence_score"] = max(float(anchor.get("evidence_score", 0.0)), _message_evidence_score({"content": anchor.get("text", "")}))
                        anchor["confidence_score"] = max(float(anchor.get("confidence_score", 0.0)), anchor["evidence_score"])
                    agent_state.add_finding_anchor(anchor)

        if agent_state is not None and hasattr(agent_state, "compression_state"):
            try:
                compression_state["last_digest"] = current_digest[-keep_recent:]
                compression_state["last_phase"] = phase
                compression_state["last_keep_recent"] = keep_recent
                compression_state["structured_facts"] = structured_facts[-50:]
                compression_state["delta_facts"] = delta_facts[-25:]
                compression_state["last_chunk_size"] = chunk_size
                agent_state.compression_state = compression_state
            except Exception:
                pass
        
        # ════════════════════════════════════════════════════════════════════
        # EFFICIENCY FIX MEM-P1.1: Parallel Chunk Summarization
        # ════════════════════════════════════════════════════════════════════
        # Build list of chunks first
        chunks = []
        for i in range(0, len(old_msgs), chunk_size):
            chunks.append(old_msgs[i : i + chunk_size])
        
        # Check if we're in an async context or need to run synchronously
        parallel_enabled = (Config.get("phantom_compressor_parallel") or "true").lower() in ("true", "1", "yes")
        
        if parallel_enabled and len(chunks) > 1:
            # Use parallel compression when no loop is active. If called from
            # an active event loop context, fall back to deterministic sequential
            # processing instead of mutating the loop via nest_asyncio.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                compressed = asyncio.run(
                    _parallel_summarize_chunks(chunks, model_name, self.timeout)
                )
                self.compression_calls += len(compressed)
            else:
                compressed = []
                for chunk in chunks:
                    summary = _summarize_messages(chunk, model_name, self.timeout)
                    if summary:
                        compressed.append(summary)
                        self.compression_calls += 1
        else:
            # Sequential fallback for single chunk or when parallel is disabled
            compressed = []
            for chunk in chunks:
                summary = _summarize_messages(chunk, model_name, self.timeout)
                if summary:
                    compressed.append(summary)
                    self.compression_calls += 1
        # ────────────────────────────────────────────────────────────────────

        if structured_facts:
            qa_text = _build_structured_summary(old_msgs, phase, structured_facts[-20:], delta_facts[-10:])
            qa_summary = {
                "role": "user",
                "content": f"<context_summary message_count='{len(old_msgs)}' phase='{phase}' format='structured'>{qa_text}</context_summary>",
                "_structured_facts": structured_facts[-20:],
                "_delta_facts": delta_facts[-10:],
                "_summary_model": model_name,
            }
            if compressed:
                compressed[0] = qa_summary
            else:
                compressed.append(qa_summary)

        if agent_state is not None and hasattr(agent_state, "finding_anchors"):
            try:
                anchors = list(getattr(agent_state, "finding_anchors", []))
                if len(anchors) > anchor_cap:
                    anchors.sort(
                        key=lambda item: (
                            float(item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0),
                            item.get("key", ""),
                        ),
                        reverse=True,
                    )
                    agent_state.finding_anchors = anchors[:anchor_cap]
                if hasattr(agent_state, "prune_invalid_anchors"):
                    agent_state.prune_invalid_anchors()
            except Exception:
                pass

        result = system_msgs + compressed + recent_msgs
        
        # Calculate compression metrics
        tokens_after = sum(
            _get_message_tokens(msg, model_name) for msg in result
        )
        compression_ratio = 1.0 - (tokens_after / total_tokens) if total_tokens > 0 else 0.0
        duration_ms = (__import__("time").monotonic() - _t0) * 1000

        # Emit an audit event so the watch layer can track compression overhead.
        try:
            from phantom.logging.audit import get_audit_logger as _get_audit
            _audit = _get_audit()
            if _audit:
                if evicted_images > 0 or image_payload_before > self.max_total_image_bytes:
                    _audit.log_image_eviction(
                        agent_id="compressor",
                        kept_images=kept_images,
                        evicted_images=evicted_images,
                        bytes_before=image_payload_before,
                        bytes_after=image_payload_after,
                        max_total_image_bytes=self.max_total_image_bytes,
                    )
                # EFFICIENCY FIX MEM-P1.3: Enhanced compression metrics
                _audit.log_compression(
                    agent_id="compressor",
                    model=Config.get("phantom_compressor_llm") or model_name,
                    messages_in=len(messages),
                    messages_out=len(result),
                    tokens_before=total_tokens,
                    tokens_after=tokens_after,
                    compression_ratio=round(compression_ratio, 4),
                    chunk_size=chunk_size,
                    chunks_processed=len(chunks),
                    parallel_mode=parallel_enabled and len(chunks) > 1,
                    duration_ms=duration_ms,
                )
        except Exception:  # noqa: BLE001
            pass

        return result
