from typing import Any

from phantom.tools.registry import register_tool


# ── v0.9.33: Simplified vulnerability reporter ─────────────────────────
#
# The original create_vulnerability_report has 16+ params which is a
# huge barrier for the LLM to use correctly.  This lightweight wrapper
# needs only 5 params and auto-computes CVSS from severity string.

_SEVERITY_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    "critical": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "high":     {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "medium":   {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "low":      {"AV": "N", "AC": "H", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
}


@register_tool(sandbox_execution=False)
async def report_vulnerability(
    title: str,
    target: str,
    severity: str,
    description: str,
    proof: str,
) -> dict[str, Any]:
    """Report a discovered vulnerability with minimal friction.

    This is the PREFERRED way to report vulnerabilities.  Only 5 parameters
    required.  Use this instead of create_vulnerability_report for speed.

    Args:
        title: Short vulnerability title (e.g. "SQL Injection in /api/login")
        target: The URL or target where the vulnerability was found
        severity: One of: critical, high, medium, low
        description: Description of the vulnerability and its impact
        proof: Proof of concept — curl command, HTTP request, or steps to reproduce
    """
    severity = severity.strip().lower()
    if severity not in _SEVERITY_CVSS_DEFAULTS:
        return {"success": False, "message": f"Invalid severity '{severity}'. Must be critical/high/medium/low."}

    if not title or not title.strip():
        return {"success": False, "message": "Title cannot be empty."}
    if not target or not target.strip():
        return {"success": False, "message": "Target cannot be empty."}
    if not description or len(description.strip()) < 10:
        return {"success": False, "message": "Description must be at least 10 characters."}

    cvss_map = _SEVERITY_CVSS_DEFAULTS[severity]
    cvss_score, severity_str, cvss_vector = calculate_cvss_and_severity(
        cvss_map["AV"], cvss_map["AC"], cvss_map["PR"], cvss_map["UI"],
        cvss_map["S"], cvss_map["C"], cvss_map["I"], cvss_map["A"],
    )

    # Auto-derive fields the LLM shouldn't need to fill in manually
    impact = f"{severity.upper()} severity: {description[:200]}"
    remediation = f"Investigate and remediate: {title}"

    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return {"success": False, "message": "Tracer unavailable — report not stored."}

        # Light title-based dedup (avoids expensive LLM-based dedup call)
        existing = tracer.get_existing_vulnerabilities()
        for r in existing:
            if r.get("title", "").lower().strip() == title.lower().strip():
                return {
                    "success": False,
                    "message": f"Duplicate: '{title}' already reported.",
                    "duplicate_of": r.get("id", ""),
                }

        report_id = tracer.add_vulnerability_report(
            title=title.strip(),
            description=description[:1000],
            severity=severity_str,
            impact=impact,
            target=target.strip(),
            technical_analysis=description[:500],
            poc_description=proof[:1000],
            poc_script_code="",
            remediation_steps=remediation,
            cvss=cvss_score,
            cvss_breakdown=cvss_map,
            endpoint=target.split("?")[0] if "?" in target else target,
            method="GET",
        )

        return {
            "success": True,
            "message": f"Vulnerability '{title}' reported successfully!",
            "report_id": report_id,
            "severity": severity_str,
            "cvss_score": cvss_score,
        }

    except Exception as e:
        return {"success": False, "message": f"Report failed: {e!s}"}


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
        return 0.0, "unknown", ""
    else:
        return base_score, severity, vector


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    validation_errors: list[str] = []

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "remediation_steps": "Remediation steps cannot be empty",
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    # poc_script_code is strongly recommended but not blocking — a good
    # poc_description is sufficient.  This avoids rejecting real findings
    # because the LLM couldn't generate a perfect exploit script.
    poc_code = kwargs.get("poc_script_code")
    if not poc_code or not str(poc_code).strip():
        poc_desc = kwargs.get("poc_description", "")
        if not poc_desc or len(str(poc_desc).strip()) < 20:
            validation_errors.append(
                "Either poc_script_code or a detailed poc_description (20+ chars) is required"
            )

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


@register_tool(sandbox_execution=False)
async def create_vulnerability_report(
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    # CVSS Breakdown Components (optional — sensible defaults provided)
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "L",
    integrity: str = "L",
    availability: str = "N",
    # Optional fields
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    code_file: str | None = None,
    code_before: str | None = None,
    code_after: str | None = None,
    code_diff: str | None = None,
) -> dict[str, Any]:
    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
    )

    validation_errors.extend(
        _validate_cvss_parameters(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
    )

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    cvss_score, severity, cvss_vector = calculate_cvss_and_severity(
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
    )

    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            from phantom.llm.dedupe import check_duplicate

            existing_reports = tracer.get_existing_vulnerabilities()

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
            }

            dedupe_result = await check_duplicate(candidate, existing_reports)

            if dedupe_result.get("is_duplicate"):
                duplicate_id = dedupe_result.get("duplicate_id", "")

                duplicate_title = ""
                for report in existing_reports:
                    if report.get("id") == duplicate_id:
                        duplicate_title = report.get("title", "Unknown")
                        break

                return {
                    "success": False,
                    "message": (
                        f"Potential duplicate of '{duplicate_title}' "
                        f"(id={duplicate_id[:8]}...). Do not re-report the same vulnerability."
                    ),
                    "duplicate_of": duplicate_id,
                    "duplicate_title": duplicate_title,
                    "confidence": dedupe_result.get("confidence", 0.0),
                    "reason": dedupe_result.get("reason", ""),
                }

            cvss_breakdown = {
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "scope": scope,
                "confidentiality": confidentiality,
                "integrity": integrity,
                "availability": availability,
            }

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=description,
                severity=severity,
                impact=impact,
                target=target,
                technical_analysis=technical_analysis,
                poc_description=poc_description,
                poc_script_code=poc_script_code,
                remediation_steps=remediation_steps,
                cvss=cvss_score,
                cvss_breakdown=cvss_breakdown,
                endpoint=endpoint,
                method=method,
                cve=cve,
                code_file=code_file,
                code_before=code_before,
                code_after=code_after,
                code_diff=code_diff,
            )

            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity,
                "cvss_score": cvss_score,
            }

        import logging

        logging.warning("Current tracer not available - vulnerability report not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
    else:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created (not persisted)",
            "warning": "Report could not be persisted - tracer unavailable",
        }
