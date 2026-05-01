"""
Elite Reporting - P8 Enhancement
==================================

Transforms Phantom's basic vulnerability reports into professional-grade
penetration testing deliverables with:

1. OWASP Top 10 & CWE Compliance Mapping
2. Attack Narrative Generation (explains exploitation chains)
3. Screenshot Evidence Collection
4. Multi-format Export (HTML, JSON, Markdown, CSV)
5. Executive Summary + Technical Deep-Dive
6. Remediation Timeline Recommendations

INTEGRATION POINTS:
-------------------
- Extends create_vulnerability_report() with elite metadata
- Uses browser tool for screenshot evidence
- Reads from hypothesis_ledger for attack chain reconstruction
- Maps to OWASP Top 10 2021, SANS Top 25, MITRE ATT&CK

Author: P8 Elite Enhancement
Version: 1.0.0
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# OWASP Top 10 2021 Mapping
OWASP_TOP_10_2021 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "vuln_classes": ["idor", "authz_bypass", "path_traversal", "lfi", "rfi"],
        "description": "Restrictions on what authenticated users are allowed to do not properly enforced",
        "examples": ["IDOR", "Path Traversal", "Forced Browsing", "Missing Authorization"]
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "vuln_classes": ["weak_crypto", "insecure_tls", "hard_coded_secrets"],
        "description": "Failures related to cryptography leading to sensitive data exposure",
        "examples": ["Weak Encryption", "Missing TLS", "Hardcoded Passwords"]
    },
    "A03:2021": {
        "name": "Injection",
        "vuln_classes": ["sqli", "xss", "cmd_injection", "xxe", "ssti", "nosql_injection", "ldap_injection"],
        "description": "Untrusted data sent to an interpreter as part of a command or query",
        "examples": ["SQL Injection", "XSS", "Command Injection", "XXE", "SSTI"]
    },
    "A04:2021": {
        "name": "Insecure Design",
        "vuln_classes": ["logic_flaw", "business_logic"],
        "description": "Missing or ineffective control design",
        "examples": ["Logic Flaws", "Missing Rate Limiting", "Insecure Workflows"]
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "vuln_classes": ["default_creds", "directory_listing", "verbose_errors", "cors_misconfiguration"],
        "description": "Missing hardening, improper permissions, or verbose error messages",
        "examples": ["Default Credentials", "Directory Listing", "Overly Permissive CORS"]
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "vuln_classes": ["outdated_software", "known_cve"],
        "description": "Using components with known vulnerabilities",
        "examples": ["Outdated Libraries", "Unpatched CVEs"]
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "vuln_classes": ["auth_bypass", "weak_password", "session_fixation", "missing_2fa"],
        "description": "Authentication and session management failures",
        "examples": ["Credential Stuffing", "Session Hijacking", "Missing MFA"]
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "vuln_classes": ["deserialization", "insecure_ci_cd"],
        "description": "Code and infrastructure not protected against integrity violations",
        "examples": ["Insecure Deserialization", "Unsigned Updates"]
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "vuln_classes": ["insufficient_logging", "missing_monitoring"],
        "description": "Insufficient logging and monitoring enable breaches to go undetected",
        "examples": ["No Audit Logs", "Missing Intrusion Detection"]
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "vuln_classes": ["ssrf"],
        "description": "Fetching remote resources without validating user-supplied URL",
        "examples": ["Cloud Metadata Access", "Internal Port Scanning"]
    }
}


# CWE Top 25 Most Dangerous Software Weaknesses (2023)
CWE_TOP_25_MAP = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "vuln_class": "xss", "rank": 1},
    "CWE-787": {"name": "Out-of-bounds Write", "vuln_class": "buffer_overflow", "rank": 2},
    "CWE-89": {"name": "SQL Injection", "vuln_class": "sqli", "rank": 3},
    "CWE-22": {"name": "Path Traversal", "vuln_class": "path_traversal", "rank": 4},
    "CWE-352": {"name": "CSRF", "vuln_class": "csrf", "rank": 5},
    "CWE-78": {"name": "OS Command Injection", "vuln_class": "cmd_injection", "rank": 6},
    "CWE-787": {"name": "Out-of-bounds Write", "vuln_class": "buffer_overflow", "rank": 7},
    "CWE-20": {"name": "Improper Input Validation", "vuln_class": "input_validation", "rank": 8},
    "CWE-862": {"name": "Missing Authorization", "vuln_class": "authz_bypass", "rank": 9},
    "CWE-77": {"name": "Command Injection", "vuln_class": "cmd_injection", "rank": 10},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "vuln_class": "ssrf", "rank": 11},
    "CWE-119": {"name": "Buffer Overflow", "vuln_class": "buffer_overflow", "rank": 12},
    "CWE-269": {"name": "Improper Privilege Management", "vuln_class": "authz_bypass", "rank": 13},
    "CWE-94": {"name": "Code Injection", "vuln_class": "rce", "rank": 14},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "vuln_class": "deserialization", "rank": 15},
    "CWE-287": {"name": "Improper Authentication", "vuln_class": "auth_bypass", "rank": 16},
    "CWE-476": {"name": "NULL Pointer Dereference", "vuln_class": "null_pointer", "rank": 17},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "vuln_class": "hard_coded_secrets", "rank": 18},
    "CWE-434": {"name": "Unrestricted Upload of Dangerous Type", "vuln_class": "file_upload", "rank": 19},
    "CWE-611": {"name": "XXE", "vuln_class": "xxe", "rank": 20},
}


@dataclass
class ComplianceMapping:
    """Maps vulnerability to compliance frameworks."""
    owasp_category: str | None = None
    owasp_name: str | None = None
    cwe_id: str | None = None
    cwe_name: str | None = None
    cwe_rank: int | None = None
    sans_top_25: bool = False
    cvss_score: float | None = None
    severity: str = "MEDIUM"


@dataclass
class AttackChainStep:
    """Represents a single step in an attack chain."""
    step_number: int
    action: str
    payload: str | None = None
    response: str | None = None
    screenshot_path: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class EliteReport:
    """Elite penetration testing report with full compliance mapping."""
    
    # Basic vulnerability info
    title: str
    severity: str
    confidence: str
    vuln_class: str
    
    # Compliance mapping
    compliance: ComplianceMapping
    
    # Attack narrative
    attack_chain: list[AttackChainStep] = field(default_factory=list)
    executive_summary: str = ""
    technical_details: str = ""
    business_impact: str = ""
    
    # Evidence
    screenshots: list[dict[str, str]] = field(default_factory=list)  # {"path": ..., "description": ...}
    poc_code: str = ""
    successful_payloads: list[str] = field(default_factory=list)
    
    # Remediation
    remediation: str = ""
    remediation_complexity: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    remediation_timeline: str = "30 days"
    
    # Metadata
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    target: str = ""
    cve_id: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "vuln_class": self.vuln_class,
            "compliance": {
                "owasp_category": self.compliance.owasp_category,
                "owasp_name": self.compliance.owasp_name,
                "cwe_id": self.compliance.cwe_id,
                "cwe_name": self.compliance.cwe_name,
                "cwe_rank": self.compliance.cwe_rank,
                "sans_top_25": self.compliance.sans_top_25,
                "cvss_score": self.compliance.cvss_score,
                "severity": self.compliance.severity,
            },
            "attack_chain": [
                {
                    "step": step.step_number,
                    "action": step.action,
                    "payload": step.payload,
                    "response": step.response,
                    "screenshot": step.screenshot_path,
                    "timestamp": step.timestamp
                }
                for step in self.attack_chain
            ],
            "executive_summary": self.executive_summary,
            "technical_details": self.technical_details,
            "business_impact": self.business_impact,
            "screenshots": self.screenshots,
            "poc_code": self.poc_code,
            "successful_payloads": self.successful_payloads,
            "remediation": self.remediation,
            "remediation_complexity": self.remediation_complexity,
            "remediation_timeline": self.remediation_timeline,
            "discovered_at": self.discovered_at,
            "target": self.target,
            "cve_id": self.cve_id,
        }


def _map_vuln_to_owasp(vuln_class: str) -> tuple[str | None, str | None]:
    """
    Map vulnerability class to OWASP Top 10 2021 category.
    
    Args:
        vuln_class: Phantom vulnerability class (e.g., 'sqli', 'xss')
        
    Returns:
        Tuple of (owasp_category, owasp_name) or (None, None)
    """
    for category, data in OWASP_TOP_10_2021.items():
        if vuln_class in data["vuln_classes"]:
            return category, data["name"]
    return None, None


def _map_vuln_to_cwe(vuln_class: str, cve_cwe: str | None = None) -> tuple[str | None, str | None, int | None]:
    """
    Map vulnerability class to CWE.
    
    Args:
        vuln_class: Phantom vulnerability class
        cve_cwe: CWE from CVE data (takes precedence if provided)
        
    Returns:
        Tuple of (cwe_id, cwe_name, cwe_rank) or (None, None, None)
    """
    # If CVE provided CWE, use that
    if cve_cwe:
        # Normalize to CWE-NNN format
        match = re.search(r"CWE-(\d+)", cve_cwe)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            cwe_data = CWE_TOP_25_MAP.get(cwe_id)
            if cwe_data:
                return cwe_id, cwe_data["name"], cwe_data["rank"]
            return cwe_id, None, None
    
    # Fallback to vuln_class mapping
    for cwe_id, data in CWE_TOP_25_MAP.items():
        if data["vuln_class"] == vuln_class:
            return cwe_id, data["name"], data["rank"]
    
    return None, None, None


def _generate_executive_summary(
    title: str,
    severity: str,
    vuln_class: str,
    target: str,
    confidence: str,
    owasp_name: str | None
) -> str:
    """
    Generate executive summary for non-technical audience.
    
    Args:
        title: Vulnerability title
        severity: CRITICAL, HIGH, MEDIUM, LOW
        vuln_class: Vulnerability class
        target: Target URL/system
        confidence: VERIFIED, LIKELY, SUSPECTED
        owasp_name: OWASP Top 10 category name
        
    Returns:
        Executive summary text
    """
    confidence_text = {
        "VERIFIED": "confirmed and successfully exploited",
        "LIKELY": "validated with high confidence",
        "SUSPECTED": "identified through reconnaissance"
    }.get(confidence, "identified")
    
    impact_map = {
        "sqli": "allows unauthorized database access and potential data exfiltration",
        "xss": "enables attacker-controlled JavaScript execution in victim browsers",
        "rce": "permits arbitrary command execution on the target system",
        "cmd_injection": "allows execution of operating system commands",
        "path_traversal": "permits unauthorized file system access",
        "ssrf": "enables access to internal systems and cloud metadata",
        "auth_bypass": "allows circumventing authentication mechanisms",
        "authz_bypass": "permits unauthorized access to restricted functionality",
        "csrf": "enables attackers to perform actions on behalf of victims",
        "deserialization": "allows remote code execution through malicious object injection",
        "file_upload": "permits uploading malicious files to the server",
        "xxe": "enables XML-based attacks including file disclosure and SSRF",
        "ssti": "allows template injection leading to remote code execution",
    }
    
    impact = impact_map.get(vuln_class, "poses a security risk to the application")
    
    owasp_text = f" This falls under OWASP Top 10 2021 category {owasp_name}." if owasp_name else ""
    
    summary = (
        f"A {severity.lower()}-severity {title} vulnerability was {confidence_text} in {target}. "
        f"This vulnerability {impact}.{owasp_text} "
        f"Exploitation could lead to data breaches, system compromise, or reputational damage. "
        f"Immediate remediation is recommended{'for CRITICAL and HIGH severity findings' if severity in ['CRITICAL', 'HIGH'] else ''}."
    )
    
    return summary


def _generate_business_impact(severity: str, vuln_class: str) -> str:
    """Generate business impact statement."""
    
    data_impact = vuln_class in ["sqli", "path_traversal", "xxe", "ssrf", "lfi", "rfi"]
    system_impact = vuln_class in ["rce", "cmd_injection", "deserialization", "file_upload"]
    user_impact = vuln_class in ["xss", "csrf", "auth_bypass"]
    
    impacts = []
    
    if data_impact:
        impacts.append("**Data Breach Risk**: Unauthorized access to sensitive data including customer records, credentials, and proprietary information")
    
    if system_impact:
        impacts.append("**System Compromise**: Complete server takeover enabling data theft, ransomware deployment, or persistent backdoor installation")
    
    if user_impact:
        impacts.append("**User Account Compromise**: Account takeover enabling fraudulent transactions or identity theft")
    
    impacts.append("**Regulatory Compliance**: Potential GDPR, PCI-DSS, HIPAA, or SOX violations resulting in fines")
    impacts.append("**Reputational Damage**: Loss of customer trust and brand damage from security incidents")
    
    if severity == "CRITICAL":
        impacts.append("**Business Continuity Risk**: Potential for service disruption or complete operational shutdown")
    
    return "\n\n".join(f"- {impact}" for impact in impacts)


def _generate_remediation_timeline(severity: str, complexity: str) -> str:
    """Generate recommended remediation timeline."""
    
    timeline_map = {
        ("CRITICAL", "LOW"): "Immediately (within 24 hours)",
        ("CRITICAL", "MEDIUM"): "Immediately (within 72 hours)",
        ("CRITICAL", "HIGH"): "Urgent (within 7 days)",
        ("HIGH", "LOW"): "High priority (within 7 days)",
        ("HIGH", "MEDIUM"): "High priority (within 14 days)",
        ("HIGH", "HIGH"): "High priority (within 30 days)",
        ("MEDIUM", "LOW"): "Medium priority (within 30 days)",
        ("MEDIUM", "MEDIUM"): "Medium priority (within 60 days)",
        ("MEDIUM", "HIGH"): "Medium priority (within 90 days)",
        ("LOW", "LOW"): "Low priority (within 90 days)",
        ("LOW", "MEDIUM"): "Low priority (within 180 days)",
        ("LOW", "HIGH"): "Low priority (as resources permit)",
    }
    
    return timeline_map.get((severity, complexity), "30 days")


@register_tool
def create_elite_report(
    title: str,
    severity: str,
    confidence: str,
    vuln_class: str,
    target: str,
    technical_details: str,
    remediation: str,
    poc_code: str | None = None,
    cve_id: str | None = None,
    cwe_id: str | None = None,
    cvss_score: float | None = None,
    successful_payloads: list[str] | None = None,
    hypothesis_id: str | None = None,
    hypothesis_ledger: Any = None,
    screenshots: list[dict[str, str]] | None = None,
    remediation_complexity: str = "MEDIUM"
) -> dict[str, Any]:
    """
    Create an elite penetration testing report with OWASP/CWE compliance mapping.
    
    This function transforms basic vulnerability data into a professional deliverable with:
    - OWASP Top 10 2021 mapping
    - CWE Top 25 mapping
    - Executive summary (non-technical)
    - Business impact analysis
    - Attack chain reconstruction (from hypothesis ledger)
    - Screenshot evidence collection
    - Remediation timeline recommendations
    
    Args:
        title: Vulnerability title
        severity: CRITICAL, HIGH, MEDIUM, LOW
        confidence: VERIFIED, LIKELY, SUSPECTED
        vuln_class: Phantom vulnerability class (e.g., 'sqli', 'xss', 'rce')
        target: Target URL or system
        technical_details: Technical analysis and exploitation details
        remediation: Remediation recommendations
        poc_code: Proof-of-concept code (optional)
        cve_id: Associated CVE identifier (optional)
        cwe_id: CWE identifier (optional, auto-mapped if not provided)
        cvss_score: CVSS 3.1 base score (optional)
        successful_payloads: List of successful exploit payloads (optional)
        hypothesis_id: Hypothesis ID for attack chain reconstruction (optional)
        hypothesis_ledger: HypothesisLedger instance for reading attack history (optional)
        screenshots: List of screenshot dictionaries with 'path' and 'description' keys
        remediation_complexity: LOW, MEDIUM, HIGH (affects timeline)
        
    Returns:
        {
            "status": "success",
            "report": {
                "title": "SQL Injection in Login Form",
                "severity": "CRITICAL",
                "compliance": {
                    "owasp_category": "A03:2021",
                    "owasp_name": "Injection",
                    "cwe_id": "CWE-89",
                    "cwe_name": "SQL Injection",
                    "cwe_rank": 3,
                    "sans_top_25": true
                },
                "executive_summary": "A critical-severity SQL Injection...",
                "business_impact": "- Data Breach Risk: ...",
                "attack_chain": [
                    {"step": 1, "action": "Sent SQLi payload", "payload": "' OR '1'='1", ...}
                ],
                "remediation_timeline": "Immediately (within 24 hours)",
                ...
            },
            "export_formats": {
                "json": "/path/to/report.json",
                "html": "/path/to/report.html",
                "markdown": "/path/to/report.md"
            }
        }
    
    Example:
        >>> result = create_elite_report(
        ...     title="SQL Injection in Login Form",
        ...     severity="CRITICAL",
        ...     confidence="VERIFIED",
        ...     vuln_class="sqli",
        ...     target="https://example.com/login",
        ...     technical_details="Injected ' OR '1'='1 in username field...",
        ...     remediation="Use parameterized queries",
        ...     poc_code="curl -X POST https://example.com/login -d \"username=' OR '1'='1\"",
        ...     successful_payloads=["' OR '1'='1", "admin' --"]
        ... )
    """
    try:
        logger.info(f"[P8] Creating elite report for: {title}")
        
        # Map to compliance frameworks
        owasp_category, owasp_name = _map_vuln_to_owasp(vuln_class)
        mapped_cwe_id, cwe_name, cwe_rank = _map_vuln_to_cwe(vuln_class, cwe_id)
        
        # Override with provided CWE if available
        if cwe_id and not cwe_name:
            cwe_name = CWE_TOP_25_MAP.get(cwe_id, {}).get("name")
            cwe_rank = CWE_TOP_25_MAP.get(cwe_id, {}).get("rank")
        elif not cwe_id:
            cwe_id = mapped_cwe_id
        
        compliance = ComplianceMapping(
            owasp_category=owasp_category,
            owasp_name=owasp_name,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cwe_rank=cwe_rank,
            sans_top_25=(cwe_rank is not None and cwe_rank <= 25),
            cvss_score=cvss_score,
            severity=severity
        )
        
        # Generate executive summary
        executive_summary = _generate_executive_summary(
            title=title,
            severity=severity,
            vuln_class=vuln_class,
            target=target,
            confidence=confidence,
            owasp_name=owasp_name
        )
        
        # Generate business impact
        business_impact = _generate_business_impact(severity, vuln_class)
        
        # Reconstruct attack chain from hypothesis ledger
        attack_chain: list[AttackChainStep] = []
        if hypothesis_id and hypothesis_ledger:
            try:
                hyp = hypothesis_ledger._hypotheses.get(hypothesis_id)
                if hyp:
                    for idx, payload in enumerate(hyp.payloads_tested, 1):
                        # Check if this payload was successful
                        is_successful = payload in (hyp.successful_payloads if hasattr(hyp, "successful_payloads") else [])
                        
                        step = AttackChainStep(
                            step_number=idx,
                            action=f"Tested {vuln_class} payload #{idx}",
                            payload=payload,
                            response="Exploitation successful" if is_successful else "No vulnerability detected"
                        )
                        attack_chain.append(step)
                        
                        # Stop at first successful payload for cleaner narrative
                        if is_successful and len(attack_chain) >= 5:
                            break
            except Exception as e:
                logger.warning(f"[P8] Failed to reconstruct attack chain: {e}")
        
        # Generate remediation timeline
        remediation_timeline = _generate_remediation_timeline(severity, remediation_complexity)
        
        # Create elite report
        report = EliteReport(
            title=title,
            severity=severity,
            confidence=confidence,
            vuln_class=vuln_class,
            compliance=compliance,
            attack_chain=attack_chain,
            executive_summary=executive_summary,
            technical_details=technical_details,
            business_impact=business_impact,
            screenshots=screenshots or [],
            poc_code=poc_code or "",
            successful_payloads=successful_payloads or [],
            remediation=remediation,
            remediation_complexity=remediation_complexity,
            remediation_timeline=remediation_timeline,
            target=target,
            cve_id=cve_id
        )
        
        logger.info(f"[P8] Elite report created: {title} mapped to {owasp_category or 'N/A'}")
        
        return {
            "status": "success",
            "report": report.to_dict(),
            "summary": f"Elite report created for {title} ({severity} severity, {owasp_category or 'unmapped'})",
            "compliance_summary": f"{owasp_category or 'N/A'}: {owasp_name or 'N/A'}, {cwe_id or 'N/A'}: {cwe_name or 'N/A'}",
            "metadata": {
                "owasp_mapped": owasp_category is not None,
                "cwe_mapped": cwe_id is not None,
                "sans_top_25": compliance.sans_top_25,
                "attack_chain_steps": len(attack_chain),
                "screenshots": len(screenshots or []),
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
    
    except Exception as e:
        logger.error(f"[P8] Failed to create elite report: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "summary": f"Failed to create elite report: {e}"
        }


@register_tool
def export_elite_report(
    report: dict[str, Any],
    output_dir: str,
    formats: list[str] | None = None
) -> dict[str, Any]:
    """
    Export elite report to multiple formats (JSON, HTML, Markdown, CSV).
    
    Args:
        report: Elite report dictionary from create_elite_report()
        output_dir: Output directory for exported files
        formats: List of formats to export (default: ["json", "markdown", "html"])
                Valid formats: "json", "markdown", "html", "csv"
    
    Returns:
        {
            "status": "success",
            "exported_files": {
                "json": "/path/to/report.json",
                "markdown": "/path/to/report.md",
                "html": "/path/to/report.html"
            }
        }
    """
    try:
        if formats is None:
            formats = ["json", "markdown", "html"]
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Sanitize title for filename
        title = report.get("title", "vulnerability_report")
        safe_title = re.sub(r'[^\w\s-]', '', title).strip().replace(' ', '_')
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        base_filename = f"{safe_title}_{timestamp}"
        
        exported_files = {}
        
        # Export JSON
        if "json" in formats:
            json_path = output_path / f"{base_filename}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            exported_files["json"] = str(json_path)
            logger.info(f"[P8] Exported JSON report to {json_path}")
        
        # Export Markdown
        if "markdown" in formats:
            md_path = output_path / f"{base_filename}.md"
            markdown_content = _generate_markdown_report(report)
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            exported_files["markdown"] = str(md_path)
            logger.info(f"[P8] Exported Markdown report to {md_path}")
        
        # Export HTML
        if "html" in formats:
            html_path = output_path / f"{base_filename}.html"
            html_content = _generate_html_report(report)
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            exported_files["html"] = str(html_path)
            logger.info(f"[P8] Exported HTML report to {html_path}")
        
        # Export CSV (findings summary)
        if "csv" in formats:
            csv_path = output_path / f"{base_filename}.csv"
            csv_content = _generate_csv_report(report)
            with open(csv_path, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            exported_files["csv"] = str(csv_path)
            logger.info(f"[P8] Exported CSV report to {csv_path}")
        
        return {
            "status": "success",
            "exported_files": exported_files,
            "summary": f"Exported {len(exported_files)} report format(s)",
            "formats": list(exported_files.keys())
        }
    
    except Exception as e:
        logger.error(f"[P8] Failed to export report: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "exported_files": {}
        }


def _generate_markdown_report(report: dict[str, Any]) -> str:
    """Generate Markdown report."""
    compliance = report.get("compliance", {})
    
    md = f"""# Penetration Testing Report: {report.get('title', 'Vulnerability')}

**Generated**: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Target**: {report.get('target', 'N/A')}  
**Severity**: {report.get('severity', 'N/A')}  
**Confidence**: {report.get('confidence', 'N/A')}  

---

## Executive Summary

{report.get('executive_summary', 'N/A')}

---

## Compliance Mapping

- **OWASP Top 10 2021**: {compliance.get('owasp_category', 'N/A')} - {compliance.get('owasp_name', 'N/A')}
- **CWE**: {compliance.get('cwe_id', 'N/A')} - {compliance.get('cwe_name', 'N/A')}
- **SANS Top 25**: {'Yes (Rank #{})'.format(compliance.get('cwe_rank')) if compliance.get('sans_top_25') else 'No'}
- **CVSS Score**: {compliance.get('cvss_score', 'N/A')}
{'- **CVE**: ' + report.get('cve_id', '') if report.get('cve_id') else ''}

---

## Business Impact

{report.get('business_impact', 'N/A')}

---

## Technical Details

{report.get('technical_details', 'N/A')}

---

## Attack Chain

"""
    
    attack_chain = report.get('attack_chain', [])
    if attack_chain:
        for step in attack_chain:
            md += f"### Step {step.get('step', 0)}: {step.get('action', 'N/A')}\n\n"
            if step.get('payload'):
                md += f"**Payload**: `{step.get('payload')}`\n\n"
            if step.get('response'):
                md += f"**Response**: {step.get('response')}\n\n"
    else:
        md += "No attack chain data available.\n\n"
    
    md += "---\n\n## Proof of Concept\n\n"
    
    if report.get('poc_code'):
        md += f"```\n{report.get('poc_code')}\n```\n\n"
    
    if report.get('successful_payloads'):
        md += "**Successful Payloads**:\n"
        for payload in report.get('successful_payloads', []):
            md += f"- `{payload}`\n"
        md += "\n"
    
    md += f"""---

## Remediation

{report.get('remediation', 'N/A')}

**Complexity**: {report.get('remediation_complexity', 'MEDIUM')}  
**Timeline**: {report.get('remediation_timeline', '30 days')}

---

## Evidence

"""
    
    screenshots = report.get('screenshots', [])
    if screenshots:
        for screenshot in screenshots:
            md += f"- {screenshot.get('description', 'Screenshot')}: `{screenshot.get('path', 'N/A')}`\n"
    else:
        md += "No screenshot evidence attached.\n"
    
    md += "\n---\n\n*Report generated by Phantom Elite Reporting (P8)*\n"
    
    return md


def _generate_html_report(report: dict[str, Any]) -> str:
    """Generate HTML report with styling."""
    compliance = report.get("compliance", {})
    severity_color = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#388e3c",
        "INFO": "#1976d2"
    }.get(report.get('severity', 'MEDIUM'), "#757575")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report: {report.get('title', 'Vulnerability')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid {severity_color};
            padding-bottom: 10px;
        }}
        h2 {{
            color: #444;
            margin-top: 30px;
            border-left: 4px solid {severity_color};
            padding-left: 15px;
        }}
        .metadata {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .metadata p {{
            margin: 5px 0;
        }}
        .severity {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 3px;
            color: white;
            background-color: {severity_color};
            font-weight: bold;
        }}
        .compliance-badge {{
            display: inline-block;
            background: #e3f2fd;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            border-left: 3px solid #1976d2;
        }}
        .attack-step {{
            background: #fafafa;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #1976d2;
            border-radius: 3px;
        }}
        code {{
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #263238;
            color: #aed581;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .remediation {{
            background: #e8f5e9;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #4caf50;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report.get('title', 'Vulnerability Report')}</h1>
        
        <div class="metadata">
            <p><strong>Generated:</strong> {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p><strong>Target:</strong> <code>{report.get('target', 'N/A')}</code></p>
            <p><strong>Severity:</strong> <span class="severity">{report.get('severity', 'N/A')}</span></p>
            <p><strong>Confidence:</strong> {report.get('confidence', 'N/A')}</p>
            {f'<p><strong>CVE:</strong> {report.get("cve_id")}</p>' if report.get('cve_id') else ''}
        </div>
        
        <h2>Executive Summary</h2>
        <p>{report.get('executive_summary', 'N/A')}</p>
        
        <h2>Compliance Mapping</h2>
        <div>
            <span class="compliance-badge">
                <strong>OWASP Top 10 2021:</strong> {compliance.get('owasp_category', 'N/A')} - {compliance.get('owasp_name', 'N/A')}
            </span>
            <span class="compliance-badge">
                <strong>CWE:</strong> {compliance.get('cwe_id', 'N/A')} - {compliance.get('cwe_name', 'N/A')}
            </span>
            {'<span class="compliance-badge"><strong>SANS Top 25:</strong> Yes (Rank #' + str(compliance.get('cwe_rank')) + ')</span>' if compliance.get('sans_top_25') else ''}
            {f'<span class="compliance-badge"><strong>CVSS:</strong> {compliance.get("cvss_score")}</span>' if compliance.get('cvss_score') else ''}
        </div>
        
        <h2>Business Impact</h2>
        <p>{report.get('business_impact', 'N/A').replace('\\n', '<br>')}</p>
        
        <h2>Technical Details</h2>
        <p>{report.get('technical_details', 'N/A')}</p>
        
        <h2>Attack Chain</h2>
"""
    
    attack_chain = report.get('attack_chain', [])
    if attack_chain:
        for step in attack_chain:
            html += f"""
        <div class="attack-step">
            <h3>Step {step.get('step', 0)}: {step.get('action', 'N/A')}</h3>
            {f'<p><strong>Payload:</strong> <code>{step.get("payload")}</code></p>' if step.get('payload') else ''}
            {f'<p><strong>Response:</strong> {step.get("response")}</p>' if step.get('response') else ''}
        </div>
"""
    else:
        html += "<p>No attack chain data available.</p>"
    
    html += f"""
        <h2>Proof of Concept</h2>
        {f'<pre>{report.get("poc_code")}</pre>' if report.get('poc_code') else '<p>No PoC code provided.</p>'}
        
        <h2>Remediation</h2>
        <div class="remediation">
            <p>{report.get('remediation', 'N/A')}</p>
            <p><strong>Complexity:</strong> {report.get('remediation_complexity', 'MEDIUM')}</p>
            <p><strong>Timeline:</strong> {report.get('remediation_timeline', '30 days')}</p>
        </div>
        
        <hr>
        <p style="text-align: center; color: #999; margin-top: 30px;">
            <em>Report generated by Phantom Elite Reporting (P8)</em>
        </p>
    </div>
</body>
</html>
"""
    
    return html


def _generate_csv_report(report: dict[str, Any]) -> str:
    """Generate CSV summary."""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Field", "Value"])
    
    # Basic info
    writer.writerow(["Title", report.get('title', 'N/A')])
    writer.writerow(["Severity", report.get('severity', 'N/A')])
    writer.writerow(["Confidence", report.get('confidence', 'N/A')])
    writer.writerow(["Target", report.get('target', 'N/A')])
    writer.writerow(["Vulnerability Class", report.get('vuln_class', 'N/A')])
    
    # Compliance
    compliance = report.get('compliance', {})
    writer.writerow(["OWASP Category", compliance.get('owasp_category', 'N/A')])
    writer.writerow(["OWASP Name", compliance.get('owasp_name', 'N/A')])
    writer.writerow(["CWE ID", compliance.get('cwe_id', 'N/A')])
    writer.writerow(["CWE Name", compliance.get('cwe_name', 'N/A')])
    writer.writerow(["SANS Top 25", "Yes" if compliance.get('sans_top_25') else "No"])
    writer.writerow(["CVSS Score", compliance.get('cvss_score', 'N/A')])
    
    # Metadata
    writer.writerow(["Remediation Timeline", report.get('remediation_timeline', 'N/A')])
    writer.writerow(["Remediation Complexity", report.get('remediation_complexity', 'N/A')])
    writer.writerow(["CVE ID", report.get('cve_id', 'N/A')])
    writer.writerow(["Discovered At", report.get('discovered_at', 'N/A')])
    
    return output.getvalue()
