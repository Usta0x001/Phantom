import json
import logging
import re
from typing import Any

import litellm

from phantom.config.config import Config, resolve_llm_config
from phantom.llm.utils import resolve_phantom_model


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


# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: Report field sanitization patterns
# ════════════════════════════════════════════════════════════════════════════════
_REPORT_SANITIZATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # System prompt manipulation
    (re.compile(r"</?system\s*>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"\[/?system\]", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"<</?SYS>>", re.IGNORECASE), "[REMOVED]"),
    # Instruction override attempts
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"forget\s+(all\s+)?previous", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE), "[REMOVED]"),
    # Function/tool injection
    (re.compile(r"</function>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"</tool_result>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"<function=\w+>", re.IGNORECASE), "[REMOVED]"),
    # Role manipulation
    (re.compile(r"^assistant:\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^user:\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^system:\s*", re.IGNORECASE | re.MULTILINE), ""),
]


def _sanitize_report_field(value: str) -> str:
    """SECURITY FIX: Sanitize report field to remove prompt injection attempts.
    
    This prevents malicious vulnerability reports from injecting prompts that
    could manipulate the deduplication LLM into making incorrect decisions.
    """
    if not isinstance(value, str):
        return str(value) if value is not None else ""
    
    sanitized = value
    for pattern, replacement in _REPORT_SANITIZATION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    
    return sanitized


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
        "parameter",
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            # SECURITY FIX: Sanitize string fields before comparison
            if isinstance(value, str):
                value = _sanitize_report_field(value)
                if len(value) > 8000:
                    value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


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
        logger.warning(f"No <dedupe_result> block found in response: {content[:500]}")
        raise ValueError("No <dedupe_result> block found in response")

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


def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    # A6: Fast heuristic pre-check — skip LLM call if surfaces are clearly different
    candidate_endpoint = (candidate.get("endpoint") or "").strip().lower()
    candidate_param = (candidate.get("parameter") or "").strip().lower()
    candidate_method = (candidate.get("method") or "").strip().lower()

    has_any_surface_overlap = False
    for report in existing_reports:
        r_endpoint = (report.get("endpoint") or "").strip().lower()
        r_param = (report.get("parameter") or "").strip().lower()
        r_method = (report.get("method") or "").strip().lower()

        if candidate_endpoint and r_endpoint:
            if candidate_endpoint == r_endpoint:
                has_any_surface_overlap = True
                break

    if not has_any_surface_overlap and candidate_endpoint:
        logger.info(
            "A6: Heuristic dedupe skip — no surface overlap for endpoint=%s param=%s",
            candidate_endpoint[:60], candidate_param[:30],
        )
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "Heuristic: no surface overlap with existing reports",
        }

    try:
        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]

        # B4: Shrink payload — only send relevant fields, truncate descriptions,
        # limit to 5 most similar existing reports
        def _slim_report(r: dict[str, Any]) -> dict[str, Any]:
            return {
                "id": r.get("id", ""),
                "title": (r.get("title") or "")[:200],
                "endpoint": r.get("endpoint", ""),
                "method": r.get("method", ""),
                "parameter": r.get("parameter", ""),
                "description": (r.get("description") or "")[:300],
                "target": r.get("target", ""),
            }

        slim_candidate = _slim_report(candidate_cleaned)
        slim_existing = [_slim_report(r) for r in existing_cleaned[:20]]

        comparison_data = {"candidate": slim_candidate, "existing_reports": slim_existing}

        model_name, api_key, api_base = resolve_llm_config()
        # Fix 7: Use a dedicated cheaper model for deduplication if configured
        dedupe_model = Config.get("phantom_dedupe_llm")
        if dedupe_model:
            litellm_model, dedupe_api_key = resolve_phantom_model(dedupe_model)
            litellm_model = litellm_model or dedupe_model
            api_key = dedupe_api_key or Config.get("phantom_dedupe_api_key") or api_key
            api_base = Config.get("phantom_dedupe_api_base") or api_base
        else:
            litellm_model, _ = resolve_phantom_model(model_name)
            litellm_model = litellm_model or model_name

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
            "model": litellm_model,
            "messages": messages,
            "timeout": 120,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

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
