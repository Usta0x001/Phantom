"""Agent-accessible tools for vulnerability verification and knowledge store queries.

These tools let the LLM agent:
1. Check past scan knowledge before testing (avoid redundant work)
2. Look up MITRE ATT&CK enrichment for a vulnerability class
"""

from typing import Any

from phantom.tools.registry import register_tool


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
            pass

        return enrichment

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "MITRE enrichment unavailable. Proceed without enrichment data.",
        }
