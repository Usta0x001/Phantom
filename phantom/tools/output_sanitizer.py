"""
Tool Output Sanitizer Pipeline

Cleans tool output BEFORE it enters the LLM context window.
5-stage pipeline:

  Stage 0: Unicode bidi/invisible character strip
  Stage 1: Tool grammar neutralization (<function=, </function>)
  Stage 2: Prompt override detection (regex patterns)
  Stage 3: Anomaly scoring + aggressive truncation on high score
  Stage 4: Hard length enforcement (50K chars / 15K tokens)
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata

_logger = logging.getLogger(__name__)

# ── Stage 0: Unicode control characters to strip ──
_INVISIBLE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00ad"
    r"\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u2000-\u200a"
    r"\u2028\u2029\u205f\u3000\uffa0]"
)

# ── Stage 1: Tool grammar patterns to neutralize ──
_GRAMMAR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Direct tool invocation syntax
    (re.compile(r"<function[=\s]", re.IGNORECASE), "&lt;function="),
    (re.compile(r"</function>", re.IGNORECASE), "&lt;/function&gt;"),
    (re.compile(r"<tool_call>", re.IGNORECASE), "&lt;tool_call&gt;"),
    (re.compile(r"</tool_call>", re.IGNORECASE), "&lt;/tool_call&gt;"),
    # Encoded variants that survive one decode pass
    (re.compile(r"&lt;function[=\s]", re.IGNORECASE), "[NEUTRALIZED:encoded_grammar]"),
    # ChatML-style markers
    (re.compile(r"<\|im_start\|>", re.IGNORECASE), "[NEUTRALIZED:chatml]"),
    (re.compile(r"<\|im_end\|>", re.IGNORECASE), "[NEUTRALIZED:chatml]"),
    # JSON tool-call patterns
    (re.compile(r'\{"?toolName"?\s*:\s*"', re.IGNORECASE), "[NEUTRALIZED:json_tool]"),
    (re.compile(r'\{"?tool_call"?\s*:\s*"', re.IGNORECASE), "[NEUTRALIZED:json_tool]"),
]

# ── Stage 2: Prompt override patterns ──
_PROMPT_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a?\s*\w+", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"override\s+(\w+\s+)?(system|instructions?|rules?|safety)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(safety|rules?|instructions?)", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+you\s+(will|must|should)", re.IGNORECASE),
    re.compile(r"system:\s*", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
]

# ── Constants ──
MAX_OUTPUT_CHARS = 50_000
ANOMALY_TRUNCATE_CHARS = 5_000
ANOMALY_THRESHOLD = 3


def sanitize_tool_output(raw: str, tool_name: str = "") -> str:
    """Main sanitization pipeline. Returns safe string for LLM context."""
    if not isinstance(raw, str):
        raw = str(raw)

    # Stage 0: Unicode normalization + invisible strip
    text = unicodedata.normalize("NFKC", raw)
    text = _INVISIBLE_RE.sub("", text)

    # Stage 1: Tool grammar neutralization
    grammar_hits = 0
    for pattern, replacement in _GRAMMAR_PATTERNS:
        count = len(pattern.findall(text))
        grammar_hits += count
        if count > 0:
            text = pattern.sub(replacement, text)

    # Stage 2: Prompt override detection
    prompt_hits = 0
    for pattern in _PROMPT_OVERRIDE_PATTERNS:
        count = len(pattern.findall(text))
        prompt_hits += count
        if count > 0:
            text = pattern.sub("[REDACTED:prompt_override]", text)

    # Stage 3: Anomaly scoring
    anomaly_score = grammar_hits + prompt_hits
    if anomaly_score > ANOMALY_THRESHOLD:
        _logger.warning(
            "High anomaly score (%d) in output from tool '%s' — "
            "truncating to %d chars for safety",
            anomaly_score, tool_name, ANOMALY_TRUNCATE_CHARS,
        )
        text = text[:ANOMALY_TRUNCATE_CHARS] + (
            f"\n\n[WARNING: Output truncated due to "
            f"{anomaly_score} suspicious patterns detected]"
        )

    # Stage 4: Hard length enforcement
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS] + "\n\n[...output truncated at 50K chars...]"

    return text


def tag_tool_output(tool_name: str, raw: str, sanitized: str) -> str:
    """Append integrity hash tags for post-hoc verification."""
    raw_hash = hashlib.sha256(raw.encode(errors="replace")).hexdigest()[:16]
    san_hash = hashlib.sha256(sanitized.encode(errors="replace")).hexdigest()[:16]
    return f"{sanitized}\n[INTEGRITY raw={raw_hash} san={san_hash}]"
