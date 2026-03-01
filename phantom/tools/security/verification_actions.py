"""Agent-accessible tools for vulnerability verification and knowledge store queries.

These tools let the LLM agent:
1. Check past scan knowledge before testing (avoid redundant work)
2. Look up MITRE ATT&CK enrichment for a vulnerability class
3. Verify a vulnerability using the automated verification engine
"""

import asyncio
import logging
from typing import Any

from phantom.config import Config
from phantom.tools.registry import register_tool

_logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=False)
def check_known_vulnerabilities(
    target: str,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Check the knowledge store for previously found vulnerabilities on a target."""
    try:
        from phantom.core.knowledge_store import get_knowledge_store

        store = get_knowledge_store()
        all_vulns = store.get_all_vulnerabilities()

        # Filter by target (loose match)
        target_lower = target.lower()
        matching = []
        for v in all_vulns:
            v_target = (v.target or "").lower()
            if target_lower in v_target or v_target in target_lower:
                matching.append({
                    "id": v.id,
                    "name": v.name,
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "vulnerability_class": v.vulnerability_class,
                    "endpoint": v.endpoint,
                    "status": v.status.value if hasattr(v.status, "value") else str(v.status),
                })

        if not matching:
            return {
                "success": True,
                "known_vulnerabilities": [],
                "message": f"No previously known vulnerabilities for target '{target}'",
                "suggestion": "This appears to be a fresh target. Proceed with full assessment.",
            }

        return {
            "success": True,
            "known_vulnerabilities": matching,
            "count": len(matching),
            "message": f"Found {len(matching)} previously known vulnerabilities for '{target}'",
            "suggestion": "Focus on NEW attack vectors. Skip re-testing known issues unless verifying fixes.",
        }

    except Exception as e:
        return {
            "success": True,
            "known_vulnerabilities": [],
            "message": f"Knowledge store unavailable: {e}",
            "suggestion": "Proceed with full assessment.",
        }


@register_tool(sandbox_execution=False)
def enrich_vulnerability(
    title: str,
    description: str,
    severity: str = "medium",
    agent_state: Any = None,
) -> dict[str, Any]:
    """Enrich a vulnerability finding with MITRE ATT&CK, CWE, and compliance mappings.
    
    Call this BEFORE create_vulnerability_report to get CWE/CAPEC/OWASP data
    that can be included in the report.
    """
    try:
        from phantom.core.mitre_enrichment import MITREEnricher

        enricher = MITREEnricher()
        finding = {
            "title": title,
            "description": description,
            "severity": severity,
        }
        result = enricher.enrich_finding(finding)

        enrichment = {
            "success": True,
            "cwes": result.get("cwe", []),
            "capecs": result.get("capec", []),
            "primary_cwe": result.get("primary_cwe"),
            "primary_cwe_name": result.get("primary_cwe_name"),
            "owasp_top10": result.get("owasp_top10"),
        }

        # Also get compliance mapping
        try:
            from phantom.core.compliance_mapper import ComplianceMapper

            mapper = ComplianceMapper()
            matches = mapper.map_findings([finding])
            if matches:
                frameworks_hit = list({m.framework for m in matches})
                enrichment["compliance_frameworks"] = frameworks_hit
        except Exception:
            _logger.debug("Compliance mapping enrichment failed", exc_info=True)

        return enrichment

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "MITRE enrichment unavailable. Proceed without enrichment data.",
        }


@register_tool(sandbox_execution=False)
async def verify_vulnerability(
    vuln_id: str,
    target: str,
    vulnerability_class: str,
    severity: str = "medium",
    endpoint: str | None = None,
    parameter: str | None = None,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Auto-verify a vulnerability using the verification engine.

    Runs exploit-verification strategies (time-based SQLi, error-based SQLi,
    boolean injection, DOM reflection, LFI, SSTI) against the target to
    confirm exploitability.

    Call this AFTER discovering a potential vulnerability but BEFORE
    create_vulnerability_report to increase confidence.
    """
    try:
        from phantom.core.verification_engine import VerificationEngine
        from phantom.models.vulnerability import (
            Vulnerability,
            VulnerabilitySeverity,
            VulnerabilityStatus,
        )

        severity_map = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO,
        }

        vuln = Vulnerability(
            id=vuln_id,
            name=f"Pending verification: {vulnerability_class}",
            vulnerability_class=vulnerability_class,
            severity=severity_map.get(severity.lower(), VulnerabilitySeverity.MEDIUM),
            status=VulnerabilityStatus.DETECTED,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description="Awaiting automated verification",
            detected_by="agent",
        )

        # Build HTTP client for verification probes
        http_client = None
        try:
            import httpx
            tls_verify = Config.get("phantom_verify_tls") != "false" if hasattr(Config, 'get') else False
            http_client = httpx.AsyncClient(
                timeout=15.0, verify=tls_verify, follow_redirects=True
            )
        except ImportError:
            pass

        # Wire terminal_execute_fn for command-based verification
        terminal_fn = None
        try:
            from phantom.tools.terminal.terminal_actions import terminal_execute
            terminal_fn = terminal_execute
        except ImportError:
            pass

        # Wire InteractshClient for OOB verification
        interactsh = None
        try:
            from phantom.core.interactsh_client import InteractshClient
            interactsh = InteractshClient(terminal_execute_fn=terminal_fn)
        except Exception:
            _logger.debug("InteractshClient not available for OOB verification", exc_info=True)

        engine = VerificationEngine(
            terminal_execute_fn=terminal_fn,
            http_client=http_client,
            interactsh_client=interactsh,
        )

        try:
            result = await engine.verify(vuln)
        finally:
            if http_client:
                await http_client.aclose()

        # Update agent state if verification succeeded
        if result.is_exploitable and agent_state:
            if hasattr(agent_state, "mark_vuln_verified"):
                agent_state.mark_vuln_verified(vuln_id)

        attempts_summary = []
        for attempt in result.attempts:
            attempts_summary.append({
                "method": attempt.method,
                "success": attempt.success,
                "confidence": attempt.confidence,
                "evidence": attempt.evidence or "",
                "payload": (attempt.payload or "")[:200],
            })

        return {
            "success": True,
            "verified": result.is_exploitable,
            "status": result.status.value,
            "confidence": max(
                (a.confidence for a in result.attempts if a.success), default=0.0
            ),
            "attempts": attempts_summary,
            "note": (
                "Verified — exploitability confirmed"
                if result.is_exploitable
                else "Not auto-verified — does NOT mean false positive. Manual review recommended."
            ),
        }

    except Exception as e:
        _logger.warning(f"Verification failed for {vuln_id}: {e}")
        return {
            "success": False,
            "verified": False,
            "error": str(e),
            "note": "Verification engine error. Proceed with manual assessment.",
        }
