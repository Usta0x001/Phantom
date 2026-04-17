import contextlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

from phantom.tools.registry import register_tool


_CVSS_FIELDS = (
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
)


_background_tasks: set[Any] = set()

_TITLE_ATTEMPT_COUNTS: dict[str, int] = {}

_MAX_ATTEMPTS_PER_TITLE = 3


def _resolve_current_agent_state() -> Any | None:
    try:
        from phantom.tools.context import get_current_agent_id

        agent_id = (get_current_agent_id() or "").strip()
        if not agent_id or agent_id in {"default", "unknown"}:
            return None

        from phantom.tools.agents_graph import agents_graph_actions

        return agents_graph_actions._agent_states.get(agent_id)
    except Exception:  # noqa: BLE001
        return None


def _extract_vuln_class_from_report(title: str, cwe: str | None, description: str) -> str:
    """FIX 4: Extract vulnerability class for correlation engine."""
    title_lower = title.lower()
    desc_lower = description.lower()
    
    # Map common vulnerability keywords to classes
    vuln_patterns = {
        "sqli": ["sql injection", "sqli", "union select", "sqlmap"],
        "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
        "rce": ["remote code execution", "rce", "command execution"],
        "cmd_injection": ["command injection", "os command"],
        "ssrf": ["server-side request forgery", "ssrf"],
        "xxe": ["xml external entity", "xxe"],
        "ssti": ["server-side template injection", "ssti", "template injection"],
        "lfi": ["local file inclusion", "lfi", "path traversal", "directory traversal"],
        "idor": ["insecure direct object reference", "idor", "authorization"],
        "auth_bypass": ["authentication bypass", "auth bypass", "broken authentication"],
        "csrf": ["cross-site request forgery", "csrf"],
        "open_redirect": ["open redirect", "unvalidated redirect"],
    }
    
    # Check title and description
    for vuln_class, patterns in vuln_patterns.items():
        if any(p in title_lower or p in desc_lower for p in patterns):
            return vuln_class
    
    # Check CWE mapping
    if cwe:
        cwe_map = {
            "CWE-89": "sqli",
            "CWE-79": "xss",
            "CWE-78": "cmd_injection",
            "CWE-918": "ssrf",
            "CWE-611": "xxe",
            "CWE-94": "rce",
            "CWE-22": "lfi",
            "CWE-639": "auth_bypass",
            "CWE-352": "csrf",
            "CWE-601": "open_redirect",
        }
        return cwe_map.get(cwe, "")
    
    return ""  # Unknown vulnerability class


def parse_cvss_xml(xml_str: str) -> dict[str, str] | None:
    """Parse CVSS breakdown from XML tags or plain CVSS vector string.

    Accepts both XML format and plain CVSS vector strings like
    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' for more forgiving input.
    """
    if not xml_str or not xml_str.strip():
        return None
    result = {}
    # Try XML format first
    for field in _CVSS_FIELDS:
        match = re.search(rf"<{field}>(.*?)</{field}>", xml_str, re.DOTALL)
        if match:
            result[field] = match.group(1).strip()
    if result:
        return result

    # Fallback - try plain CVSS vector string (AV:N/AC:L/...)
    _vector_map = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S": "scope",
        "C": "confidentiality",
        "I": "integrity",
        "A": "availability",
    }
    # Strip "CVSS:3.1/" prefix if present
    clean = re.sub(r"^CVSS:[\d.]+/", "", xml_str.strip())
    for part in clean.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            field_name = _vector_map.get(key.strip().upper())
            if field_name:
                result[field_name] = val.strip().upper()
    return result if result else None


_SEVERITY_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    "CRITICAL": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "H",
        "availability": "H",
    },
    "HIGH": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "H",
        "availability": "N",
    },
    "MEDIUM": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "L",
        "integrity": "L",
        "availability": "N",
    },
    "LOW": {
        "attack_vector": "N",
        "attack_complexity": "H",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "L",
        "integrity": "N",
        "availability": "N",
    },
    "INFO": {
        "attack_vector": "N",
        "attack_complexity": "H",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "N",
        "integrity": "N",
        "availability": "N",
    },
}


def _cvss_from_severity(severity: str | None) -> dict[str, str] | None:
    if not severity:
        return None
    return _SEVERITY_CVSS_DEFAULTS.get(severity.upper().strip())


def parse_code_locations_xml(xml_str: str) -> list[dict[str, Any]] | None:
    if not xml_str or not xml_str.strip():
        return None
    locations = []
    for loc_match in re.finditer(r"<location>(.*?)</location>", xml_str, re.DOTALL):
        loc: dict[str, Any] = {}
        loc_content = loc_match.group(1)
        for field in (
            "file",
            "start_line",
            "end_line",
            "snippet",
            "label",
            "fix_before",
            "fix_after",
        ):
            field_match = re.search(rf"<{field}>(.*?)</{field}>", loc_content, re.DOTALL)
            if field_match:
                raw = field_match.group(1)
                value = (
                    raw.strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else raw.strip()
                )
                if field in ("start_line", "end_line"):
                    with contextlib.suppress(ValueError, TypeError):
                        loc[field] = int(value)
                elif value:
                    loc[field] = value
        if loc.get("file") and loc.get("start_line") is not None:
            locations.append(loc)
    return locations if locations else None


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def calculate_cvss_and_severity(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0]

        severity = base_severity.lower()

    except Exception:
        import logging

        logging.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return base_score, severity, vector


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    """
    Validate required fields for vulnerability reports.
    
    P1.2 ENHANCEMENT: SUSPECTED findings now require minimum evidence.
    Previously SUSPECTED could bypass all proof requirements, leading to
    false positives. Now requires observed_behavior documentation.
    """
    validation_errors: list[str] = []

    confidence = (kwargs.get("confidence") or "LIKELY").upper().strip()
    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
    }
    
    # P1.2 FIX: SUSPECTED findings still need minimum evidence
    if confidence == "SUSPECTED":
        # Require technical_analysis to contain specific observational data
        tech_analysis = kwargs.get("technical_analysis") or ""
        if len(tech_analysis.strip()) < 50:
            validation_errors.append(
                "SUSPECTED findings require at least 50 characters of technical_analysis "
                "describing what was observed (e.g., 'Sent payload X, received response Y')"
            )
        
        # Check for vague language that indicates lack of evidence
        _vague_phrases = (
            "might be vulnerable",
            "could be vulnerable", 
            "possibly vulnerable",
            "may be exploitable",
            "appears vulnerable",
            "seems vulnerable",
            "potential vulnerability",
        )
        tech_lower = tech_analysis.lower()
        if any(phrase in tech_lower for phrase in _vague_phrases):
            validation_errors.append(
                "SUSPECTED findings must describe SPECIFIC observations, not vague claims. "
                "Replace phrases like 'might be vulnerable' with concrete observations: "
                "'Sent [payload], observed [specific response behavior]'"
            )
    else:
        # LIKELY/VERIFIED require PoC
        required_fields["poc_script_code"] = (
            "PoC script/code is REQUIRED for LIKELY/VERIFIED confidence - "
            "provide the actual exploit/payload, or change confidence to SUSPECTED"
        )

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    return validation_errors


def _validate_cvss_parameters(**kwargs: str) -> list[str]:
    validation_errors: list[str] = []

    cvss_validations = {
        "attack_vector": ["N", "A", "L", "P"],
        "attack_complexity": ["L", "H"],
        "privileges_required": ["N", "L", "H"],
        "user_interaction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
    }

    for param_name, valid_values in cvss_validations.items():
        value = kwargs.get(param_name)
        if value not in valid_values:
            validation_errors.append(
                f"Invalid {param_name}: {value}. Must be one of: {valid_values}"
            )

    return validation_errors


def _normalize_variant_field(value: str | None) -> str:
    return (value or "").strip().lower()


_VAGUE_PROOF_PHRASES = (
    "might be vulnerable",
    "could be vulnerable",
    "possibly vulnerable",
    "may be exploitable",
    "appears vulnerable",
    "seems vulnerable",
    "potential vulnerability",
)


_CONCRETE_PROOF_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sent\s+.+?(payload|request)", re.IGNORECASE),
    re.compile(r"observ(ed|ing)\s+.+?(response|status|body)", re.IGNORECASE),
    re.compile(r"(status\s*code|http)\s*[:=]?\s*(200|201|204|301|302|400|401|403|404|500)", re.IGNORECASE),
    re.compile(r"(extract(ed|ion)|dump(ed)?)\s+.+?(table|row|credential|token|cookie|data)", re.IGNORECASE),
    re.compile(r"\b(uid=\d+|root:x:0:0|information_schema|union\s+select|alert\(|metadata\.google|169\.254\.169\.254)\b", re.IGNORECASE),
)


def _validate_exploit_proof_requirements(
    confidence: str,
    technical_analysis: str,
    poc_description: str | None,
    poc_script_code: str | None,
) -> list[str]:
    """Enforce proof requirements at runtime (not prompt-only)."""
    errors: list[str] = []
    confidence_norm = (confidence or "LIKELY").upper().strip()
    if confidence_norm == "SUSPECTED":
        return errors

    combined = "\n".join(
        [
            technical_analysis or "",
            poc_description or "",
            poc_script_code or "",
        ]
    ).strip()

    if not combined:
        errors.append(
            f"{confidence_norm} findings require concrete exploit evidence in technical_analysis/poc_description"
        )
        return errors

    combined_lower = combined.lower()
    has_vague_only = any(phrase in combined_lower for phrase in _VAGUE_PROOF_PHRASES)
    has_concrete = any(pattern.search(combined) for pattern in _CONCRETE_PROOF_PATTERNS)

    if confidence_norm == "VERIFIED":
        if not has_concrete:
            errors.append(
                "VERIFIED findings require concrete proof artifacts (payload sent + observed exploitable outcome)"
            )
    elif confidence_norm == "LIKELY":
        if not has_concrete:
            errors.append(
                "LIKELY findings require concrete observed behavior (include payload, response/status, and impact signal)"
            )

    if has_vague_only and not has_concrete:
        errors.append(
            "Evidence is too vague for LIKELY/VERIFIED confidence - provide concrete observations and artifacts"
        )

    return errors


# ============================================================================
# P0.2 ENHANCEMENT: Exploit Success Validation Patterns
# ============================================================================
# These patterns validate that an exploit WORKED, not just that the PoC executed.
# CORRECTED: Added Windows patterns, timing notes, and browser requirements.

_EXPLOIT_SUCCESS_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "sqli": [
        # Data extraction indicators
        (r"information_schema", "SQL schema access detected"),
        (r"table_name\s*[=:]", "Table enumeration detected"),
        (r"column_name\s*[=:]", "Column enumeration detected"),
        (r"mysql\.", "MySQL system database access"),
        (r"pg_catalog", "PostgreSQL catalog access"),
        (r"sqlite_master", "SQLite schema access"),
        (r"sysobjects|syscolumns", "MSSQL system tables access"),
        (r"\d+\s+(rows?|entries)\s+(returned|affected|in\s+set)", "Query returned rows/entries"),
        (r"\[\d+\s+entries?\]", "Entries count detected"),
        (r"UNION\s+SELECT.*FROM", "UNION-based extraction successful"),
        # Error-based extraction
        (r"extractvalue|updatexml|xmltype", "XML-based extraction"),
        # Boolean/Time indicators (note: timing must be validated by caller)
        # REMOVED: Time-based pattern returns false positives when PoC echoes payload text
        # Time-based SQLi requires ACTUAL timing validation (differential analysis), not text matching
        # Presence of sleep() string in output ≠ successful timing attack
        # (r"sleep\s*\(\s*\d+\s*\)|waitfor\s+delay|pg_sleep", "Time-based payload present"),
    ],
    "xss": [
        # Note: XSS requires browser execution - these are OUTPUT patterns only
        # Real validation needs headless browser
        (r"<script[^>]*>.*?</script>", "Script tags in response"),
        (r"on(error|load|click|mouse\w+)\s*=", "Event handler in response"),
        (r"javascript:", "JavaScript protocol in response"),
        # These indicate the PoC CLAIMS success but need browser verification
        (r"XSS_CONFIRMED|alert\s*\(\s*['\"]?(xss|1|document)", "XSS marker detected - REQUIRES BROWSER VERIFICATION"),
    ],
    "rce": [
        # Linux/Unix indicators
        (r"uid=\d+.*gid=\d+", "Unix id command output"),
        (r"root:x?:0:0", "Unix /etc/passwd content"),
        (r"/bin/(ba)?sh", "Shell path detected"),
        (r"www-data|apache|nginx|nobody", "Web server user detected"),
        (r"Linux\s+\w+\s+\d+\.\d+", "Linux uname output"),
        (r"total\s+\d+.*drwx", "Directory listing output"),
        # Windows indicators (CORRECTED: Added Windows patterns)
        (r"(NT AUTHORITY|BUILTIN)\\", "Windows system user"),
        (r"\\Users\\|\\Windows\\", "Windows path detected"),
        (r"Volume\s+Serial\s+Number", "Windows dir output"),
        (r"Microsoft\s+Windows\s+\[Version", "Windows cmd output"),
        (r"whoami.*\\", "Windows whoami output"),
        (r"ipconfig|systeminfo|hostname", "Windows command output"),
        (r"COMPUTERNAME=|USERDOMAIN=", "Windows environment"),
    ],
    "ssrf": [
        # Internal resource access indicators
        (r"169\.254\.169\.254", "AWS metadata endpoint"),
        (r"metadata\.google\.internal", "GCP metadata endpoint"),
        (r"localhost|127\.0\.0\.1|::1", "Localhost access"),
        (r"10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+", "Internal IP access"),
        (r"iam/security-credentials", "AWS credentials endpoint"),
        (r"computeMetadata/v1", "GCP metadata API"),
    ],
    "lfi": [
        # File content indicators
        (r"root:x?:0:0:", "/etc/passwd content"),
        (r"\[boot\s*loader\]", "Windows boot.ini content"),
        (r"<\?php", "PHP source code exposed"),
        (r"#!/bin/(ba)?sh|#!/usr/bin/(env\s+)?(python|perl|ruby)", "Script shebang exposed"),
        (r"DB_PASSWORD|DATABASE_URL|SECRET_KEY", "Config file content"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private key exposed"),
    ],
    "ssti": [
        # Template injection success
        (r"49(?!\d)", "7*7 calculation result (Jinja2/Twig)"),
        (r"7777777", "7*'7' string multiplication (Python)"),
        (r"class\s+'(str|int|list)", "Python type introspection"),
        (r"__mro__|__class__|__subclasses__", "Python MRO access"),
    ],
    "xxe": [
        # XXE success indicators
        (r"root:x?:0:0", "XXE file read (/etc/passwd)"),
        (r"ENTITY\s+\w+\s+SYSTEM", "XXE entity definition"),
        (r"<!DOCTYPE", "DTD in response (potential XXE)"),
    ],
}


def _validate_exploit_success(
    vuln_type: str,
    replay_output: str,
) -> tuple[str, str]:
    """
    P0.2 FIX: Validate that exploit actually succeeded, not just execution.
    
    Returns:
        (status, reason): 
        - 'EXPLOIT_CONFIRMED': Exploit definitely worked
        - 'EXECUTION_ONLY': PoC ran but no exploit indicators
        - 'REQUIRES_BROWSER': XSS needs browser validation
        - 'FAILED': Execution failed
    """
    vuln_lower = vuln_type.lower().strip()
    output_clean = replay_output.strip()
    
    if not output_clean:
        return ("FAILED", "No output from PoC execution")
    
    # Get patterns for this vuln type
    patterns = _EXPLOIT_SUCCESS_PATTERNS.get(vuln_lower, [])
    
    # Also try without numbers/suffixes (e.g., "sqli_blind" -> "sqli")
    if not patterns:
        for key in _EXPLOIT_SUCCESS_PATTERNS:
            if vuln_lower.startswith(key) or key in vuln_lower:
                patterns = _EXPLOIT_SUCCESS_PATTERNS[key]
                break
    
    for pattern, description in patterns:
        if re.search(pattern, output_clean, re.IGNORECASE):
            # Special case: XSS markers with script tags still need browser verification
            if vuln_lower == "xss" and "<script" in pattern.lower():
                return ("REQUIRES_BROWSER", "Script tags detected - requires browser verification")
            # Special case: XSS markers indicate need for browser verification
            if vuln_lower == "xss" and "REQUIRES BROWSER" in description:
                return ("REQUIRES_BROWSER", description)
            return ("EXPLOIT_CONFIRMED", description)
    
    # XSS special handling: always needs browser verification
    if vuln_lower == "xss":
        return ("REQUIRES_BROWSER", "XSS exploits require browser-based verification")
    
    # Execution succeeded but no exploit indicators
    return ("EXECUTION_ONLY", "PoC executed but no exploitation indicators found")


def _same_variant_surface(candidate: dict[str, Any], existing: dict[str, Any]) -> bool:
    endpoint_a = _normalize_variant_field(candidate.get("endpoint"))
    endpoint_b = _normalize_variant_field(existing.get("endpoint"))
    method_a = _normalize_variant_field(candidate.get("method"))
    method_b = _normalize_variant_field(existing.get("method"))
    param_a = _normalize_variant_field(candidate.get("parameter"))
    param_b = _normalize_variant_field(existing.get("parameter"))
    target_a = _normalize_variant_field(candidate.get("target"))
    target_b = _normalize_variant_field(existing.get("target"))

    if endpoint_a and endpoint_b and method_a and method_b:
        if param_a and param_b:
            return endpoint_a == endpoint_b and method_a == method_b and param_a == param_b
        return endpoint_a == endpoint_b and method_a == method_b

    if endpoint_a and endpoint_b:
        return endpoint_a == endpoint_b

    if target_a and target_b:
        return target_a == target_b

    return False


_VALID_REPLAY_STATUS = {
    "PENDING",
    "SKIPPED",
    "PASSED",
    "FAILED",
    "EXPLOIT_CONFIRMED",
    "EXECUTION_ONLY",
    "REQUIRES_BROWSER",
}


@register_tool(sandbox_execution=False)
def create_vulnerability_report(  # noqa: PLR0912
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    remediation_steps: str | None = None,
    cvss_breakdown: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    parameter: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: str | None = None,
    severity: str | None = None,
    # Confidence tier: VERIFIED/PoC auto-replayed, LIKELY/validated (default), SUSPECTED/discovery signal
    confidence: str = "LIKELY",
) -> dict[str, Any]:
    # Fill in defaults for optional fields
    if not poc_description:
        poc_description = description
    if not remediation_steps:
        remediation_steps = "See impact and technical analysis for remediation guidance."
    if not poc_script_code:
        poc_script_code = ""
    if not cvss_breakdown:
        cvss_breakdown = ""
    # A5: Pass confidence to _validate_required_fields so it can relax poc_script_code
    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        confidence=confidence,
    )

    parsed_cvss = parse_cvss_xml(cvss_breakdown)
    if not parsed_cvss:
        # Try severity-based auto-calculation
        parsed_cvss = _cvss_from_severity(severity)
        if not parsed_cvss:
            # Fallback default for SUSPECTED confidence
            if (confidence or "LIKELY").upper().strip() == "SUSPECTED":
                parsed_cvss = _cvss_from_severity("LOW")
            if not parsed_cvss:
                validation_errors.append("cvss: could not parse CVSS breakdown XML or vector string (provide cvss_breakdown XML or set severity=CRITICAL/HIGH/MEDIUM/LOW/INFO)")
    else:
        validation_errors.extend(_validate_cvss_parameters(**parsed_cvss))

    parsed_locations = parse_code_locations_xml(code_locations) if code_locations else None

    if parsed_locations:
        validation_errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            validation_errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            validation_errors.append(cwe_err)

    if validation_errors:
        # Track failed attempts so the agent knows not to retry endlessly
        title_key = title.strip().lower()
        _TITLE_ATTEMPT_COUNTS[title_key] = _TITLE_ATTEMPT_COUNTS.get(title_key, 0) + 1
        attempt_count = _TITLE_ATTEMPT_COUNTS[title_key]
        if attempt_count >= _MAX_ATTEMPTS_PER_TITLE:
            return {
                "success": False,
                "message": (
                    f"Validation failed ({attempt_count} attempts). "
                    f"Stop retrying — fix the errors below or change confidence to SUSPECTED "
                    f"to skip optional fields like cvss_breakdown and poc_script_code."
                ),
                "errors": validation_errors,
                "attempt_count": attempt_count,
            }
        return {
            "success": False,
            "message": "Validation failed",
            "errors": validation_errors,
            "attempt_count": attempt_count,
        }

    # Rec 10 (ER-001): Validate and normalise confidence tier.
    _VALID_CONFIDENCE = ("VERIFIED", "LIKELY", "SUSPECTED")
    confidence = (confidence or "LIKELY").upper().strip()
    if confidence not in _VALID_CONFIDENCE:
        confidence = "LIKELY"  # safe fallback

    proof_errors = _validate_exploit_proof_requirements(
        confidence=confidence,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
    )
    if proof_errors:
        title_key = title.strip().lower()
        _TITLE_ATTEMPT_COUNTS[title_key] = _TITLE_ATTEMPT_COUNTS.get(title_key, 0) + 1
        attempt_count = _TITLE_ATTEMPT_COUNTS[title_key]
        if attempt_count >= _MAX_ATTEMPTS_PER_TITLE:
            return {
                "success": False,
                "message": (
                    f"Proof validation failed ({attempt_count} attempts). Stop retrying with the same proof/confidence. "
                    "Retry once with confidence=SUSPECTED and concise technical_analysis containing: "
                    "payload sent, HTTP status, and observed exploit artifact."
                ),
                "errors": proof_errors,
                "attempt_count": attempt_count,
            }
        return {
            "success": False,
            "message": "Proof validation failed",
            "errors": proof_errors,
            "attempt_count": attempt_count,
        }

    # Rec 5 (ER-005): PoC auto-replay — schedule as background async task.
    replay_status = "PENDING"
    if confidence in {"LIKELY", "VERIFIED"} and poc_script_code and poc_script_code.strip():
        import asyncio

        async def _background_replay(
            _poc_code: str,
            _report_title: str,
            _confidence: str,
            _vuln_type: str,
            _agent_state: Any | None,
        ) -> None:
            _replay = "SKIPPED"
            try:
                from phantom.tools.executor import execute_tool

                replay_command = _build_replay_command(_poc_code)
                if not replay_command:
                    return

                if _agent_state is None:
                    return

                replay_result = await execute_tool(
                    "terminal_execute",
                    agent_state=_agent_state,
                    command=replay_command,
                    timeout=60,
                    trusted_command=True,
                )
                replay_out = str(replay_result or "")
                _exec_failure_patterns = (
                    "command not found",
                    "no such file or directory",
                    "traceback (most recent call last)",
                    "importerror:",
                    "modulenotfounderror:",
                    "segmentation fault",
                    "killed",
                    "permission denied",
                    "access is denied",
                    "not recognized as an internal or external command",
                )
                if not replay_out.strip():
                    _replay = "FAILED"
                elif any(p in replay_out.lower() for p in _exec_failure_patterns):
                    _replay = "FAILED"
                else:
                    _replay, _ = _validate_exploit_success(_vuln_type, replay_out)
            except Exception:  # noqa: BLE001
                _replay = "FAILED"

            try:
                from phantom.telemetry.tracer import get_global_tracer
                _tracer = get_global_tracer()
                if _tracer and hasattr(_tracer, "update_vulnerability_replay"):
                    new_confidence = _confidence
                    if _replay == "EXPLOIT_CONFIRMED":
                        new_confidence = "VERIFIED"
                    _tracer.update_vulnerability_replay(
                        title=_report_title,
                        replay_status=_replay,
                        confidence=new_confidence,
                    )
            except Exception:  # noqa: BLE001
                pass

        _detected_vuln_type = ""
        title_lower = title.lower()
        for vtype in (
            "sqli",
            "sql injection",
            "xss",
            "cross-site",
            "rce",
            "command injection",
            "ssrf",
            "lfi",
            "file inclusion",
            "ssti",
            "template injection",
            "xxe",
        ):
            if vtype in title_lower:
                _detected_vuln_type = vtype.split()[0]
                break
        if not _detected_vuln_type:
            _detected_vuln_type = "unknown"

        replay_agent_state = _resolve_current_agent_state()

        if replay_agent_state is None:
            replay_status = "SKIPPED"
        else:
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(
                    _background_replay(
                        poc_script_code,
                        title,
                        confidence,
                        _detected_vuln_type,
                        replay_agent_state,
                    )
                )
                _background_tasks.add(task)
                task.add_done_callback(lambda finished: _background_tasks.discard(finished))
                replay_status = "PENDING"
            except RuntimeError:
                replay_status = "SKIPPED"
    else:
        replay_status = "SKIPPED"

    if replay_status not in _VALID_REPLAY_STATUS:
        replay_status = "SKIPPED"

    if parsed_cvss is None:
        raise RuntimeError("CVSS parsing failed - should have been caught by validation")
    cvss_score, cvss_severity, cvss_vector = calculate_cvss_and_severity(**parsed_cvss)

    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return {
                "success": False,
                "message": f"Vulnerability report '{title}' was not persisted",
                "error": "Tracer unavailable - report storage failed",
            }

        from phantom.llm.dedupe import check_duplicate

        existing_reports = tracer.get_existing_vulnerabilities()

        if not parameter and endpoint:
            from urllib.parse import parse_qs

            ep = endpoint.strip()
            if "?" in ep:
                qs = parse_qs(ep.split("?", 1)[1])
                if qs:
                    parameter = list(qs.keys())[0]

        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter or "",
        }

        dedupe_result = check_duplicate(candidate, existing_reports)

        if dedupe_result.get("is_duplicate"):
            duplicate_id = dedupe_result.get("duplicate_id", "")
            dedupe_confidence = float(dedupe_result.get("confidence") or 0.0)

            duplicate_report = None
            for report in existing_reports:
                if report.get("id") == duplicate_id:
                    duplicate_report = report
                    break

            same_surface = bool(duplicate_report) and _same_variant_surface(
                candidate, duplicate_report or {}
            )

            if duplicate_id and dedupe_confidence >= 0.90 and same_surface:
                duplicate_title = (duplicate_report or {}).get("title", "Unknown")
                return {
                    "success": False,
                    "message": (
                        f"Potential duplicate of '{duplicate_title}' "
                        f"(id={duplicate_id[:8]}...). Do not re-report the same vulnerability."
                    ),
                    "duplicate_of": duplicate_id,
                    "duplicate_title": duplicate_title,
                    "confidence": dedupe_confidence,
                    "reason": dedupe_result.get("reason", ""),
                    "attempt_count": 0,
                }

        report_id = tracer.add_vulnerability_report(
            title=title,
            description=description,
            severity=cvss_severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            cvss=cvss_score,
            cvss_breakdown=parsed_cvss,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
            confidence=confidence,
            replay_status=replay_status,
        )

        if not report_id:
            return {
                "success": False,
                "message": "Failed to persist vulnerability report: tracer returned empty report_id",
            }

        title_key = title.strip().lower()
        _TITLE_ATTEMPT_COUNTS.pop(title_key, None)

        chain_suggestions = []
        try:
            from phantom.tools.hypothesis.hypothesis_actions import get_correlation_engine

            correlation_engine = get_correlation_engine()
            if correlation_engine is not None:
                vuln_class = _extract_vuln_class_from_report(title, cwe, description)
                if vuln_class:
                    result = correlation_engine.add_finding(
                        vuln_class=vuln_class,
                        surface=endpoint or target,
                        severity=cvss_severity.lower(),
                        details={
                            "report_id": report_id,
                            "title": title,
                            "cvss_score": cvss_score,
                            "confidence": confidence,
                        }
                    )
                    chain_suggestions = result.get("new_suggestions", [])
        except Exception:  # noqa: BLE001
            pass

        response = {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": cvss_severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "confidence": confidence,
            "replay_status": replay_status,
            "attempt_count": 0,
        }

        if chain_suggestions:
            response["chain_opportunities"] = chain_suggestions
            response["message"] += f" | {len(chain_suggestions)} attack chain(s) identified!"

        return response

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}


def _build_replay_command(poc_code: str) -> str:
    """Wrap PoC snippets into an executable command for terminal_execute.

    If the content already looks like a shell/python invocation, pass it through.
    Otherwise execute it as a Python heredoc so multiline scripts run correctly.
    """
    stripped = (poc_code or "").strip()
    if not stripped:
        return ""

    first = stripped.splitlines()[0].strip().lower()
    if first.startswith(("python", "curl", "bash", "sh", "pwsh", "powershell")):
        return stripped
    if stripped.startswith("#!/"):
        body = "\n".join(stripped.splitlines()[1:]).strip()
        if body:
            return f"python -c {json.dumps(body)}"
    return f"python -c {json.dumps(stripped)}"
