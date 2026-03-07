import json
import logging
import re
from typing import Any

import litellm

from phantom.config import Config


logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

YOU MUST RESPOND WITH EXACTLY THIS XML FORMAT AND NOTHING ELSE:

<dedupe_result>
<is_duplicate>true</is_duplicate>
<duplicate_id>vuln-0001</duplicate_id>
<confidence>0.95</confidence>
<reason>Both reports describe SQL injection in /api/login via the username parameter</reason>
</dedupe_result>

OR if not a duplicate:

<dedupe_result>
<is_duplicate>false</is_duplicate>
<duplicate_id></duplicate_id>
<confidence>0.90</confidence>
<reason>Different endpoints: candidate is /api/search, existing is /api/login</reason>
</dedupe_result>

RULES:
- is_duplicate MUST be exactly "true" or "false" (lowercase)
- duplicate_id MUST be the exact ID from existing reports or empty if not duplicate
- confidence MUST be a decimal (your confidence level in the decision)
- reason MUST be a specific explanation mentioning endpoint/parameter/root cause
- DO NOT include any text outside the <dedupe_result> tags"""


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    relevant_fields = [
        "id",
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "endpoint",
        "method",
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            # BUG-006 FIX: Redact secrets before sending to external LLM
            if isinstance(value, str):
                value = _redact_secrets(value)
            cleaned[field] = value

    return cleaned


# BUG-006 FIX: Pattern-based credential redaction for data sent to external LLM
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # API keys and tokens (generic patterns)
    (re.compile(r'(?i)(api[_-]?key|token|secret|password|passwd|credential|auth)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?'), r'\1=[REDACTED]'),
    # Bearer tokens
    (re.compile(r'(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer [REDACTED]'),
    # Basic auth
    (re.compile(r'(?i)Basic\s+[A-Za-z0-9+/]+=*'), 'Basic [REDACTED]'),
    # JWT tokens
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '[REDACTED_JWT]'),
    # AWS keys
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'), '[REDACTED_AWS_KEY]'),
    # Private keys
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    # Cookie values (session tokens)
    (re.compile(r'(?i)(session|sess|sid|jsessionid|phpsessid|csrf|xsrf)\s*=\s*([^\s;]{16,})'), r'\1=[REDACTED]'),
]


def _redact_secrets(text: str) -> str:
    """Remove credentials/tokens from text before external LLM call."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _extract_xml_field(content: str, field: str) -> str:
    pattern = rf"<{field}>(.*?)</{field}>"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    result_match = re.search(
        r"<dedupe_result>(.*?)</dedupe_result>", content, re.DOTALL | re.IGNORECASE
    )

    if not result_match:
        # Fallback: try to infer from raw text when LLM doesn't follow XML format
        content_lower = content.lower()
        if any(kw in content_lower for kw in ("not a duplicate", "not duplicate", "unique", "new vulnerability")):
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.7,
                "reason": f"Inferred from LLM text: {content[:200]}",
            }
        if any(kw in content_lower for kw in ("is a duplicate", "duplicate of", "same vulnerability", "already reported")):
            # Try to extract the duplicate ID from text
            id_match = re.search(r"(?:vuln|id|report)[-_]?(\d+)", content_lower)
            dup_id = f"vuln-{id_match.group(1)}" if id_match else ""
            return {
                "is_duplicate": True,
                "duplicate_id": dup_id,
                "confidence": 0.6,
                "reason": f"Inferred from LLM text: {content[:200]}",
            }
        # Final fallback: treat as not-duplicate with low confidence.
        # False negatives (missing a dup) are safer than false positives (dropping a unique vuln).
        logger.warning("No <dedupe_result> block found in response, defaulting to not-duplicate: %s", content[:500])
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.5,
            "reason": f"Could not parse LLM response; defaulting to not-duplicate: {content[:200]}",
        }

    result_content = result_match.group(1)

    is_duplicate_str = _extract_xml_field(result_content, "is_duplicate")
    duplicate_id = _extract_xml_field(result_content, "duplicate_id")
    confidence_str = _extract_xml_field(result_content, "confidence")
    reason = _extract_xml_field(result_content, "reason")

    is_duplicate = is_duplicate_str.lower() == "true"

    try:
        confidence = float(confidence_str) if confidence_str else 0.0
    except ValueError:
        confidence = 0.0

    return {
        "is_duplicate": is_duplicate,
        "duplicate_id": duplicate_id[:64] if duplicate_id else "",
        "confidence": confidence,
        "reason": reason[:500] if reason else "",
    }


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    # Fast path: if candidate endpoint+title doesn't overlap with ANY existing
    # report, skip the expensive LLM call entirely.
    cand_endpoint = (candidate.get("endpoint") or "").lower().strip()
    cand_title = (candidate.get("title") or "").lower().strip()
    has_overlap = False
    for existing in existing_reports:
        ex_endpoint = (existing.get("endpoint") or "").lower().strip()
        ex_title = (existing.get("title") or "").lower().strip()
        # Check for endpoint match + title similarity
        if cand_endpoint and ex_endpoint and cand_endpoint == ex_endpoint:
            has_overlap = True
            break
        # Check for title substring match (rough similarity)
        if cand_title and ex_title:
            _stopwords = {"in", "at", "the", "a", "via", "on", "for", "of", "to", "and"}
            cand_words = set(cand_title.split()) - _stopwords
            ex_words = set(ex_title.split()) - _stopwords
            if len(cand_words & ex_words) >= 3:
                has_overlap = True
                break
    if not has_overlap:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.95,
            "reason": "Fast path: no endpoint/title overlap with existing reports",
        }

    try:
        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]

        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        model_name = Config.get("phantom_llm")
        api_key = Config.get("llm_api_key")
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

        messages = [
            {"role": "system", "content": DEDUPE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Compare this candidate vulnerability against existing reports:\n\n"
                    f"{json.dumps(comparison_data, indent=2)}\n\n"
                    f"Respond with ONLY the <dedupe_result> XML block."
                ),
            },
        ]

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "timeout": 120,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = await litellm.acompletion(**completion_kwargs)

        content = response.choices[0].message.content
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            f"Deduplication check: is_duplicate={result['is_duplicate']}, "
            f"confidence={result['confidence']}, reason={result['reason'][:100]}"
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
