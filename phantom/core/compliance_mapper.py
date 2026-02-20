"""
Compliance Mapping Engine

Maps Phantom findings to standard compliance frameworks:
- OWASP Top 10 (2021)
- PCI-DSS v4.0
- NIST 800-53 Rev 5
- ISO 27001:2022 (Annex A)
- CIS Controls v8

Provides gap analysis and compliance posture scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# =========================================================================
# Framework Definitions
# =========================================================================

@dataclass(frozen=True)
class ComplianceRequirement:
    """A single compliance requirement / control."""
    framework: str
    control_id: str
    title: str
    description: str
    severity: str = "medium"        # What failing this implies
    related_cwes: tuple[str, ...] = ()


# -------------------------------------------------------------------------
# OWASP Top 10 (2021)
# -------------------------------------------------------------------------

OWASP_TOP10_2021: list[ComplianceRequirement] = [
    ComplianceRequirement(
        "OWASP-2021", "A01", "Broken Access Control",
        "Restrictions on authenticated users are not properly enforced. "
        "Attackers can exploit flaws to access unauthorized functionality or data.",
        severity="critical",
        related_cwes=("CWE-200", "CWE-284", "CWE-285", "CWE-352", "CWE-639", "CWE-862", "CWE-863"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A02", "Cryptographic Failures",
        "Failures related to cryptography which often lead to sensitive data exposure.",
        severity="critical",
        related_cwes=("CWE-259", "CWE-261", "CWE-310", "CWE-327", "CWE-328", "CWE-330"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A03", "Injection",
        "User-supplied data is not validated, filtered, or sanitized. "
        "SQL, NoSQL, OS command, LDAP injection attacks.",
        severity="critical",
        related_cwes=("CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-917"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A04", "Insecure Design",
        "Risks related to design and architectural flaws. "
        "Missing or ineffective control design.",
        severity="high",
        related_cwes=("CWE-209", "CWE-256", "CWE-501", "CWE-522"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A05", "Security Misconfiguration",
        "Missing security hardening, improperly configured permissions, "
        "unnecessary features enabled, default accounts.",
        severity="high",
        related_cwes=("CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A06", "Vulnerable and Outdated Components",
        "Using components with known vulnerabilities or unsupported software.",
        severity="high",
        related_cwes=("CWE-937", "CWE-1035", "CWE-1104"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A07", "Identification and Authentication Failures",
        "Confirmation of user identity, authentication, and session management "
        "weaknesses.",
        severity="critical",
        related_cwes=("CWE-255", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-384"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A08", "Software and Data Integrity Failures",
        "Code and infrastructure that does not protect against integrity violations. "
        "Insecure CI/CD, deserialization.",
        severity="high",
        related_cwes=("CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A09", "Security Logging and Monitoring Failures",
        "Insufficient logging, detection, monitoring, and active response.",
        severity="medium",
        related_cwes=("CWE-117", "CWE-223", "CWE-532", "CWE-778"),
    ),
    ComplianceRequirement(
        "OWASP-2021", "A10", "Server-Side Request Forgery (SSRF)",
        "Web application fetches a remote resource without validating the "
        "user-supplied URL.",
        severity="high",
        related_cwes=("CWE-918",),
    ),
]

# -------------------------------------------------------------------------
# PCI-DSS v4.0 (selected key requirements)
# -------------------------------------------------------------------------

PCIDSS_V4: list[ComplianceRequirement] = [
    ComplianceRequirement(
        "PCI-DSS-v4", "1.2", "Network Security Controls",
        "Install and maintain network security controls (firewalls).",
        severity="high",
        related_cwes=("CWE-284",),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "2.2", "Secure Configurations",
        "Apply secure configurations to all system components.",
        severity="high",
        related_cwes=("CWE-2", "CWE-16", "CWE-260", "CWE-520", "CWE-526"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "3.4", "Protect Stored Account Data",
        "Protect stored account data with strong cryptography.",
        severity="critical",
        related_cwes=("CWE-311", "CWE-312", "CWE-316", "CWE-327"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "4.2", "Protect Data in Transit",
        "Protect cardholder data with strong cryptography during transmission.",
        severity="critical",
        related_cwes=("CWE-311", "CWE-319", "CWE-326"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "5.2", "Malware Protection",
        "Prevent, detect, and address malware on systems.",
        severity="high",
        related_cwes=("CWE-94", "CWE-506"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "6.2", "Secure Software Development",
        "Develop software in accordance with PCI DSS secure coding guidelines.",
        severity="critical",
        related_cwes=("CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "6.3", "Security Vulnerabilities Identified and Addressed",
        "Identify and manage security vulnerabilities.",
        severity="high",
        related_cwes=("CWE-937", "CWE-1035", "CWE-1104"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "7.2", "Access Control",
        "Access to system components and data restricted to need-to-know.",
        severity="high",
        related_cwes=("CWE-284", "CWE-285", "CWE-862", "CWE-863"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "8.3", "Strong Authentication",
        "Strong authentication for users and administrators.",
        severity="critical",
        related_cwes=("CWE-255", "CWE-287", "CWE-521", "CWE-522"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "10.2", "Audit Logs",
        "Implement automated audit trails for all system components.",
        severity="high",
        related_cwes=("CWE-117", "CWE-223", "CWE-778"),
    ),
    ComplianceRequirement(
        "PCI-DSS-v4", "11.3", "Vulnerability Scanning",
        "Identify and address vulnerabilities through regular scanning.",
        severity="high",
        related_cwes=(),
    ),
]

# -------------------------------------------------------------------------
# NIST 800-53 Rev 5 (selected controls)
# -------------------------------------------------------------------------

NIST_80053: list[ComplianceRequirement] = [
    ComplianceRequirement(
        "NIST-800-53", "AC-3", "Access Enforcement",
        "Enforce approved authorizations for logical access to information.",
        severity="high",
        related_cwes=("CWE-284", "CWE-285", "CWE-862", "CWE-863"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "AC-7", "Unsuccessful Logon Attempts",
        "Enforce a limit of consecutive invalid logon attempts.",
        severity="medium",
        related_cwes=("CWE-307",),
    ),
    ComplianceRequirement(
        "NIST-800-53", "AU-2", "Event Logging",
        "Identify events that the system is capable of logging.",
        severity="medium",
        related_cwes=("CWE-778",),
    ),
    ComplianceRequirement(
        "NIST-800-53", "CA-8", "Penetration Testing",
        "Conduct penetration testing on systems and networks.",
        severity="medium",
        related_cwes=(),
    ),
    ComplianceRequirement(
        "NIST-800-53", "CM-6", "Configuration Settings",
        "Establish and document configuration settings for IT systems.",
        severity="medium",
        related_cwes=("CWE-2", "CWE-16"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "IA-2", "Identification and Authentication",
        "Uniquely identify and authenticate organizational users.",
        severity="high",
        related_cwes=("CWE-287", "CWE-521", "CWE-522"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "IA-5", "Authenticator Management",
        "Manage system authenticators (passwords, keys, tokens).",
        severity="high",
        related_cwes=("CWE-255", "CWE-259", "CWE-521", "CWE-522", "CWE-798"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "RA-5", "Vulnerability Monitoring and Scanning",
        "Monitor and scan for vulnerabilities in the system.",
        severity="high",
        related_cwes=("CWE-937", "CWE-1035"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "SC-8", "Transmission Confidentiality and Integrity",
        "Protect confidentiality and integrity of transmitted information.",
        severity="high",
        related_cwes=("CWE-311", "CWE-319"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "SC-28", "Protection of Information at Rest",
        "Protect confidentiality and integrity of information at rest.",
        severity="high",
        related_cwes=("CWE-311", "CWE-312"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "SI-2", "Flaw Remediation",
        "Identify, report, and correct system flaws in a timely manner.",
        severity="high",
        related_cwes=("CWE-937", "CWE-1035", "CWE-1104"),
    ),
    ComplianceRequirement(
        "NIST-800-53", "SI-10", "Information Input Validation",
        "Check the validity of information inputs.",
        severity="high",
        related_cwes=("CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-89"),
    ),
]

# =========================================================================
# CWE → Requirement Index
# =========================================================================

ALL_REQUIREMENTS: list[ComplianceRequirement] = OWASP_TOP10_2021 + PCIDSS_V4 + NIST_80053

_CWE_INDEX: dict[str, list[ComplianceRequirement]] = {}
for _req in ALL_REQUIREMENTS:
    for _cwe in _req.related_cwes:
        _CWE_INDEX.setdefault(_cwe, []).append(_req)

# Keyword → OWASP mapping for findings without CWEs
_KEYWORD_OWASP_MAP: dict[str, str] = {
    "sql injection": "A03",
    "sqli": "A03",
    "xss": "A03",
    "cross-site scripting": "A03",
    "command injection": "A03",
    "rce": "A03",
    "remote code execution": "A03",
    "code injection": "A03",
    "ldap injection": "A03",
    "nosql injection": "A03",
    "ssti": "A03",
    "template injection": "A03",
    "path traversal": "A01",
    "directory traversal": "A01",
    "idor": "A01",
    "broken access": "A01",
    "privilege escalation": "A01",
    "unauthorized access": "A01",
    "insecure direct object": "A01",
    "csrf": "A01",
    "missing authentication": "A07",
    "broken authentication": "A07",
    "weak password": "A07",
    "session fixation": "A07",
    "brute force": "A07",
    "credential stuffing": "A07",
    "session hijacking": "A07",
    "ssl": "A02",
    "tls": "A02",
    "weak cipher": "A02",
    "cleartext": "A02",
    "plaintext": "A02",
    "encryption": "A02",
    "information disclosure": "A05",
    "misconfiguration": "A05",
    "default credentials": "A05",
    "directory listing": "A05",
    "server-side request forgery": "A10",
    "ssrf": "A10",
    "deserialization": "A08",
    "insecure deserialization": "A08",
    "outdated": "A06",
    "vulnerable component": "A06",
    "known vulnerability": "A06",
    "cve-": "A06",
    "logging": "A09",
    "monitoring": "A09",
}


# =========================================================================
# Compliance Match Result
# =========================================================================

@dataclass
class ComplianceMatch:
    """A finding mapped to a compliance requirement."""
    finding_title: str
    finding_severity: str
    requirement: ComplianceRequirement
    match_source: str  # "cwe", "keyword", "manual"
    cwe: str | None = None


@dataclass
class ComplianceReport:
    """Full compliance posture report."""
    framework: str
    total_controls: int
    controls_tested: int
    controls_passed: int
    controls_failed: int
    controls_untested: int
    pass_rate: float
    failed_controls: list[dict[str, Any]]
    passed_controls: list[str]
    untested_controls: list[str]
    matches: list[ComplianceMatch] = field(default_factory=list)


# =========================================================================
# Compliance Mapper
# =========================================================================

class ComplianceMapper:
    """
    Maps security findings to compliance framework requirements.

    Usage:
        mapper = ComplianceMapper()
        matches = mapper.map_findings(findings)
        report = mapper.generate_report("OWASP-2021", findings)
        gap = mapper.gap_analysis(findings)
    """

    def __init__(
        self,
        frameworks: list[str] | None = None,
    ) -> None:
        """
        Args:
            frameworks: Frameworks to include ("OWASP-2021", "PCI-DSS-v4", "NIST-800-53").
                        None = all frameworks.
        """
        self.frameworks = frameworks or ["OWASP-2021", "PCI-DSS-v4", "NIST-800-53"]
        self._requirements = [
            r for r in ALL_REQUIREMENTS if r.framework in self.frameworks
        ]

    def map_finding(self, finding: dict[str, Any]) -> list[ComplianceMatch]:
        """
        Map a single finding to compliance requirements.

        Args:
            finding: Dict with title, severity, cwe (optional), description (optional)

        Returns:
            List of matched compliance requirements
        """
        matches: list[ComplianceMatch] = []
        seen: set[tuple[str, str]] = set()

        title = finding.get("title", "")
        severity = finding.get("severity", "medium")
        cwe = finding.get("cwe")
        cwes = finding.get("cwes", [])

        # Combine CWE sources
        all_cwes: list[str] = []
        if cwe:
            all_cwes.append(cwe if cwe.startswith("CWE-") else f"CWE-{cwe}")
        for c in cwes:
            all_cwes.append(c if c.startswith("CWE-") else f"CWE-{c}")

        # Match by CWE
        for cwe_id in all_cwes:
            for req in _CWE_INDEX.get(cwe_id, []):
                if req.framework not in self.frameworks:
                    continue
                key = (req.framework, req.control_id)
                if key not in seen:
                    seen.add(key)
                    matches.append(ComplianceMatch(
                        finding_title=title,
                        finding_severity=severity,
                        requirement=req,
                        match_source="cwe",
                        cwe=cwe_id,
                    ))

        # Match by keyword (fallback for findings without CWEs)
        search_text = f"{title} {finding.get('description', '')}".lower()
        for keyword, owasp_id in _KEYWORD_OWASP_MAP.items():
            if keyword in search_text:
                for req in self._requirements:
                    if req.framework == "OWASP-2021" and req.control_id == owasp_id:
                        key = (req.framework, req.control_id)
                        if key not in seen:
                            seen.add(key)
                            matches.append(ComplianceMatch(
                                finding_title=title,
                                finding_severity=severity,
                                requirement=req,
                                match_source="keyword",
                            ))
                        break

        return matches

    def map_findings(self, findings: list[dict[str, Any]]) -> list[ComplianceMatch]:
        """Map all findings to compliance requirements."""
        all_matches: list[ComplianceMatch] = []
        for finding in findings:
            all_matches.extend(self.map_finding(finding))
        return all_matches

    def generate_report(
        self, framework: str, findings: list[dict[str, Any]]
    ) -> ComplianceReport:
        """
        Generate a compliance posture report for a specific framework.

        Args:
            framework: Framework ID ("OWASP-2021", "PCI-DSS-v4", "NIST-800-53")
            findings: List of finding dicts

        Returns:
            ComplianceReport with pass/fail/untested controls
        """
        framework_reqs = [r for r in self._requirements if r.framework == framework]
        matches = self.map_findings(findings)
        framework_matches = [m for m in matches if m.requirement.framework == framework]

        # Controls that have findings mapped = FAILED
        failed_control_ids: set[str] = set()
        for m in framework_matches:
            failed_control_ids.add(m.requirement.control_id)

        # Controls with no explicit failure evidence = UNTESTED
        # We never assume "passed" — only "failed" (with evidence) or "untested"
        passed_ids: set[str] = set()
        untested_ids: set[str] = set()

        for req in framework_reqs:
            if req.control_id not in failed_control_ids:
                # Conservative: mark as untested unless explicitly verified
                untested_ids.add(req.control_id)

        total = len(framework_reqs)
        num_passed = len(passed_ids)
        num_failed = len(failed_control_ids)
        num_untested = len(untested_ids)
        num_tested = num_failed  # Only failed controls are truly "tested"

        pass_rate = (num_passed / num_tested * 100) if num_tested > 0 else 0.0

        # Build failed control details
        failed_details: list[dict[str, Any]] = []
        for req in framework_reqs:
            if req.control_id in failed_control_ids:
                related_findings = [
                    m.finding_title for m in framework_matches
                    if m.requirement.control_id == req.control_id
                ]
                failed_details.append({
                    "control_id": req.control_id,
                    "title": req.title,
                    "severity": req.severity,
                    "findings": related_findings,
                })

        return ComplianceReport(
            framework=framework,
            total_controls=total,
            controls_tested=num_tested,
            controls_passed=num_passed,
            controls_failed=num_failed,
            controls_untested=num_untested,
            pass_rate=round(pass_rate, 1),
            failed_controls=failed_details,
            passed_controls=sorted(passed_ids),
            untested_controls=sorted(untested_ids),
            matches=framework_matches,
        )

    def gap_analysis(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Perform a multi-framework gap analysis.

        Returns a comprehensive report showing compliance posture
        across all configured frameworks.
        """
        reports: dict[str, Any] = {}

        for fw in self.frameworks:
            report = self.generate_report(fw, findings)
            reports[fw] = {
                "total_controls": report.total_controls,
                "controls_tested": report.controls_tested,
                "controls_passed": report.controls_passed,
                "controls_failed": report.controls_failed,
                "controls_untested": report.controls_untested,
                "pass_rate": report.pass_rate,
                "failed_controls": report.failed_controls,
                "risk_level": _assess_risk_level(report),
            }

        # Overall summary
        total_failed = sum(r["controls_failed"] for r in reports.values())
        total_controls = sum(r["total_controls"] for r in reports.values())
        combined_pass_rate = (
            (1 - total_failed / total_controls) * 100 if total_controls > 0 else 0
        )

        return {
            "frameworks": reports,
            "summary": {
                "total_frameworks_assessed": len(reports),
                "total_controls": total_controls,
                "total_failures": total_failed,
                "combined_pass_rate": round(combined_pass_rate, 1),
                "overall_risk": _assess_overall_risk(reports),
                "priority_remediations": _priority_remediations(reports),
            },
        }

    def to_markdown(self, findings: list[dict[str, Any]]) -> str:
        """Generate a Markdown compliance report."""
        gap = self.gap_analysis(findings)
        lines: list[str] = []
        lines.append("# Compliance Posture Report\n")
        lines.append(f"## Summary\n")
        s = gap["summary"]
        lines.append(f"- **Frameworks assessed:** {s['total_frameworks_assessed']}")
        lines.append(f"- **Total controls:** {s['total_controls']}")
        lines.append(f"- **Total failures:** {s['total_failures']}")
        lines.append(f"- **Combined pass rate:** {s['combined_pass_rate']}%")
        lines.append(f"- **Overall risk:** {s['overall_risk']}\n")

        for fw, data in gap["frameworks"].items():
            lines.append(f"## {fw}\n")
            lines.append(f"- Controls: {data['total_controls']}")
            lines.append(f"- Passed: {data['controls_passed']}")
            lines.append(f"- Failed: {data['controls_failed']}")
            lines.append(f"- Untested: {data['controls_untested']}")
            lines.append(f"- Pass rate: {data['pass_rate']}%")
            lines.append(f"- Risk level: {data['risk_level']}\n")

            if data["failed_controls"]:
                lines.append("### Failed Controls\n")
                for fc in data["failed_controls"]:
                    lines.append(f"**{fc['control_id']} - {fc['title']}** (Severity: {fc['severity']})")
                    for f_title in fc["findings"]:
                        lines.append(f"  - {f_title}")
                    lines.append("")

        if s["priority_remediations"]:
            lines.append("## Priority Remediations\n")
            for i, rem in enumerate(s["priority_remediations"], 1):
                lines.append(f"{i}. **[{rem['framework']}] {rem['control_id']}** - {rem['title']} ({rem['severity']})")
            lines.append("")

        return "\n".join(lines)


# =========================================================================
# Helpers
# =========================================================================

def _assess_risk_level(report: ComplianceReport) -> str:
    """Assess risk level based on compliance posture."""
    if report.controls_failed == 0:
        return "low"

    critical_fails = sum(
        1 for fc in report.failed_controls
        if fc.get("severity") == "critical"
    )
    if critical_fails > 0:
        return "critical"
    if report.pass_rate < 50:
        return "high"
    if report.pass_rate < 80:
        return "medium"
    return "low"


def _assess_overall_risk(reports: dict[str, Any]) -> str:
    """Assess overall risk across all frameworks."""
    risk_levels = [r.get("risk_level", "low") for r in reports.values()]
    if "critical" in risk_levels:
        return "critical"
    if "high" in risk_levels:
        return "high"
    if "medium" in risk_levels:
        return "medium"
    return "low"


def _priority_remediations(reports: dict[str, Any]) -> list[dict[str, str]]:
    """Get prioritized remediation list."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    remediations: list[dict[str, str]] = []

    for fw, data in reports.items():
        for fc in data.get("failed_controls", []):
            remediations.append({
                "framework": fw,
                "control_id": fc["control_id"],
                "title": fc["title"],
                "severity": fc["severity"],
            })

    remediations.sort(key=lambda r: severity_order.get(r["severity"], 99))
    return remediations[:20]  # Top 20 priorities
