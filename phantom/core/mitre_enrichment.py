"""
MITRE CWE/CAPEC Enrichment Module

Maps vulnerability findings to MITRE CWE (Common Weakness Enumeration)
and CAPEC (Common Attack Pattern Enumeration and Classification).
Provides standardized vulnerability classification for compliance reporting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CWEEntry:
    """A single CWE weakness entry."""

    cwe_id: int
    name: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    owasp_top10: str = ""  # e.g., "A01:2021"
    capec_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class CAPECEntry:
    """A single CAPEC attack pattern entry."""

    capec_id: int
    name: str
    description: str
    prerequisites: str = ""
    related_cwes: tuple[int, ...] = ()


# ─── CWE Database (most common web/app vulns) ────────────────────────

CWE_DATABASE: dict[int, CWEEntry] = {
    # Injection
    79: CWEEntry(79, "Cross-site Scripting (XSS)", "Improper neutralization of input during web page generation", "high", "A03:2021", (86, 588)),
    89: CWEEntry(89, "SQL Injection", "Improper neutralization of special elements used in an SQL command", "critical", "A03:2021", (66, 7, 108)),
    78: CWEEntry(78, "OS Command Injection", "Improper neutralization of special elements used in an OS command", "critical", "A03:2021", (88,)),
    77: CWEEntry(77, "Command Injection", "Improper neutralization of special elements used in a command", "critical", "A03:2021", (88,)),
    94: CWEEntry(94, "Code Injection", "Improper control of generation of code", "critical", "A03:2021", (242,)),
    90: CWEEntry(90, "LDAP Injection", "Improper neutralization of special elements used in an LDAP query", "high", "A03:2021", (136,)),
    91: CWEEntry(91, "XML Injection", "Improper neutralization of special elements used in XML", "high", "A03:2021", (250,)),
    611: CWEEntry(611, "XML External Entity (XXE)", "Improper restriction of XML external entity reference", "high", "A05:2021", (201,)),
    917: CWEEntry(917, "Server-Side Template Injection (SSTI)", "Improper neutralization of special elements used in an expression language statement", "critical", "A03:2021", ()),

    # Broken Authentication
    287: CWEEntry(287, "Improper Authentication", "Authentication bypass or weakness", "critical", "A07:2021", (114, 151)),
    384: CWEEntry(384, "Session Fixation", "Session identifier not regenerated after authentication", "high", "A07:2021", (61,)),
    613: CWEEntry(613, "Insufficient Session Expiration", "Session does not expire or has excessive timeout", "medium", "A07:2021", (60,)),
    640: CWEEntry(640, "Weak Password Recovery", "Weak password recovery mechanism for forgotten password", "medium", "A07:2021", (50,)),
    798: CWEEntry(798, "Hard-coded Credentials", "Use of hard-coded credentials in source code", "critical", "A07:2021", (70,)),
    307: CWEEntry(307, "Improper Restriction of Excessive Auth Attempts", "No brute force protection", "high", "A07:2021", (49,)),

    # Sensitive Data Exposure
    200: CWEEntry(200, "Information Exposure", "Exposure of sensitive information to unauthorized actor", "medium", "A01:2021", (116,)),
    312: CWEEntry(312, "Cleartext Storage of Sensitive Info", "Storing sensitive information in cleartext", "high", "A02:2021", (37,)),
    319: CWEEntry(319, "Cleartext Transmission", "Cleartext transmission of sensitive information", "medium", "A02:2021", (157,)),
    326: CWEEntry(326, "Inadequate Encryption Strength", "Weak cryptographic algorithm", "high", "A02:2021", ()),
    327: CWEEntry(327, "Use of Broken Crypto Algorithm", "Use of broken or risky cryptographic algorithm", "high", "A02:2021", (20,)),
    759: CWEEntry(759, "Use of One-Way Hash Without Salt", "Password hashing without salt", "medium", "A02:2021", ()),

    # Broken Access Control
    22: CWEEntry(22, "Path Traversal", "Improper limitation of a pathname to a restricted directory", "high", "A01:2021", (126,)),
    284: CWEEntry(284, "Improper Access Control", "Restriction of access to authorized users is not enforced", "high", "A01:2021", ()),
    352: CWEEntry(352, "Cross-Site Request Forgery (CSRF)", "Missing anti-CSRF token validation", "medium", "A01:2021", (62,)),
    639: CWEEntry(639, "Insecure Direct Object Reference (IDOR)", "Authorization bypass through user-controlled key", "high", "A01:2021", (17,)),
    862: CWEEntry(862, "Missing Authorization", "Missing authorization check", "high", "A01:2021", ()),
    863: CWEEntry(863, "Incorrect Authorization", "Authorization check is present but incorrect", "high", "A01:2021", ()),
    918: CWEEntry(918, "Server-Side Request Forgery (SSRF)", "Server makes requests to attacker-controlled destination", "high", "A10:2021", (664,)),

    # Security Misconfiguration
    16: CWEEntry(16, "Configuration", "Security misconfiguration", "medium", "A05:2021", ()),
    209: CWEEntry(209, "Error Message Information Leak", "Generation of error messages containing sensitive information", "low", "A05:2021", (54,)),
    215: CWEEntry(215, "Debug Information Exposure", "Insertion of sensitive information into debug code", "medium", "A05:2021", ()),
    434: CWEEntry(434, "Unrestricted File Upload", "Unrestricted upload of file with dangerous type", "critical", "A04:2021", (1,)),
    1021: CWEEntry(1021, "Improper Restriction of Rendered UI", "Clickjacking / UI redress attack", "medium", "A05:2021", (103,)),

    # Vulnerable Components
    1035: CWEEntry(1035, "Vulnerable Third-Party Component", "Use of component with known vulnerabilities", "high", "A06:2021", ()),
    937: CWEEntry(937, "Using Components with Known Vulns", "Use of a component with known vulnerabilities", "high", "A06:2021", ()),

    # Insufficient Logging
    778: CWEEntry(778, "Insufficient Logging", "Insufficient logging of security events", "low", "A09:2021", ()),
    532: CWEEntry(532, "Log Injection", "Insertion of sensitive information into log file", "medium", "A09:2021", ()),
}


# ─── CAPEC Database (most common attack patterns) ───────────────────

CAPEC_DATABASE: dict[int, CAPECEntry] = {
    7: CAPECEntry(7, "Blind SQL Injection", "Sending crafted SQL queries to extract data without direct error output", "Database access", (89,)),
    66: CAPECEntry(66, "SQL Injection", "Manipulating SQL queries through user input", "Database backend, user input to queries", (89,)),
    86: CAPECEntry(86, "XSS via HTTP Headers", "Injecting script through HTTP headers", "Reflected header values", (79,)),
    88: CAPECEntry(88, "OS Command Injection", "Executing system commands through injection", "User input passed to system commands", (78, 77)),
    108: CAPECEntry(108, "Command Line Execution via SQL Injection", "Using SQL injection to execute commands", "SQL injection + system exec", (89,)),
    126: CAPECEntry(126, "Path Traversal", "Accessing files outside intended directory", "File path in user input", (22,)),
    136: CAPECEntry(136, "LDAP Injection", "Manipulating LDAP queries via user input", "LDAP backend", (90,)),
    242: CAPECEntry(242, "Code Injection", "Injecting code that gets executed", "Dynamic code evaluation", (94,)),
    588: CAPECEntry(588, "DOM-Based XSS", "Manipulating client-side DOM to execute scripts", "Client-side JavaScript processing", (79,)),
    17: CAPECEntry(17, "Using Malicious Files", "Exploiting file handling to access unauthorized objects", "File-based access control", (639,)),
    49: CAPECEntry(49, "Password Brute Forcing", "Systematically trying passwords", "No rate limiting", (307,)),
    50: CAPECEntry(50, "Password Recovery Exploitation", "Exploiting password recovery mechanisms", "Weak recovery process", (640,)),
    54: CAPECEntry(54, "Query System for Information", "Extracting information from error messages", "Verbose error handling", (209,)),
    60: CAPECEntry(60, "Reusing Session IDs", "Exploiting session persistence", "Predictable session management", (613,)),
    61: CAPECEntry(61, "Session Fixation", "Forcing a known session ID", "Session ID in URL or predictable", (384,)),
    62: CAPECEntry(62, "Cross-Site Request Forgery", "Forging requests from authenticated users", "Cookie-based auth, no CSRF token", (352,)),
    70: CAPECEntry(70, "Try Common Credentials", "Using default/common username-password pairs", "Default credentials unchanged", (798,)),
    103: CAPECEntry(103, "Clickjacking", "Tricking users into clicking hidden elements", "Frameable pages without X-Frame-Options", (1021,)),
    114: CAPECEntry(114, "Authentication Abuse", "Exploiting authentication weaknesses", "Weak authentication implementation", (287,)),
    151: CAPECEntry(151, "Identity Spoofing", "Impersonating a legitimate user", "Weak authentication", (287,)),
    157: CAPECEntry(157, "Sniffing Attacks", "Intercepting cleartext network traffic", "Unencrypted communications", (319,)),
    201: CAPECEntry(201, "XML Entity Linking", "Exploiting XML entity processing", "XML input accepted", (611,)),
    250: CAPECEntry(250, "XML Injection", "Manipulating XML input", "XML processing of user input", (91,)),
    664: CAPECEntry(664, "Server Side Request Forgery", "Making server fetch attacker-controlled URLs", "Server-side URL fetching", (918,)),
}


# ─── Keyword→CWE Mapping ────────────────────────────────────────────

_KEYWORD_CWE_MAP: dict[str, list[int]] = {
    # Injection keywords
    "sql injection": [89],
    "sqli": [89],
    "blind sql": [89],
    "xss": [79],
    "cross-site scripting": [79],
    "reflected xss": [79],
    "stored xss": [79],
    "dom xss": [79],
    "command injection": [78, 77],
    "os command": [78],
    "rce": [78, 94],
    "remote code execution": [78, 94],
    "code injection": [94],
    "ssti": [917],
    "template injection": [917],
    "ldap injection": [90],
    "xml injection": [91],
    "xxe": [611],
    "xml external entity": [611],
    "ssrf": [918],
    "server-side request forgery": [918],

    # Auth keywords
    "authentication bypass": [287],
    "auth bypass": [287],
    "broken auth": [287],
    "session fixation": [384],
    "session expiration": [613],
    "weak password": [640],
    "hard-coded credential": [798],
    "hardcoded credential": [798],
    "default credential": [798],
    "brute force": [307],

    # Data exposure
    "information disclosure": [200],
    "information leak": [200],
    "cleartext": [319],
    "unencrypted": [319],
    "weak crypto": [326, 327],
    "weak hash": [759],
    "md5": [327],
    "sha1": [327],

    # Access Control
    "path traversal": [22],
    "directory traversal": [22],
    "lfi": [22],
    "local file inclusion": [22],
    "idor": [639],
    "insecure direct object": [639],
    "csrf": [352],
    "cross-site request forgery": [352],
    "missing authorization": [862],
    "broken access control": [284],
    "access control": [284],
    "privilege escalation": [284],

    # Misconfiguration
    "misconfiguration": [16],
    "debug mode": [215],
    "error message": [209],
    "stack trace": [209],
    "file upload": [434],
    "unrestricted upload": [434],
    "clickjacking": [1021],
    "x-frame-options": [1021],

    # Components
    "known vulnerability": [1035],
    "outdated": [937],
    "cve-": [1035],

    # Logging
    "insufficient logging": [778],
    "log injection": [532],
}


class MITREEnricher:
    """
    Enriches vulnerability findings with MITRE CWE and CAPEC data.

    Usage:
        enricher = MITREEnricher()
        enriched = enricher.enrich_finding({
            "title": "SQL Injection in login",
            "description": "The login endpoint is vulnerable to SQL injection",
            "severity": "critical",
        })
    """

    def __init__(self) -> None:
        self.cwe_db = CWE_DATABASE
        self.capec_db = CAPEC_DATABASE

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enrich a single vulnerability finding with CWE/CAPEC data."""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        search_text = f"{title} {description}"

        # Find matching CWEs
        matched_cwes: list[CWEEntry] = []
        seen_cwe_ids: set[int] = set()

        # Check explicit CWE references (e.g., "CWE-89")
        for match in re.finditer(r"cwe-?(\d+)", search_text):
            cwe_id = int(match.group(1))
            if cwe_id in self.cwe_db and cwe_id not in seen_cwe_ids:
                matched_cwes.append(self.cwe_db[cwe_id])
                seen_cwe_ids.add(cwe_id)

        # Check keyword mapping (use word boundaries to avoid false positives)
        for keyword, cwe_ids in _KEYWORD_CWE_MAP.items():
            if re.search(r'\b' + re.escape(keyword) + r'\b', search_text):
                for cwe_id in cwe_ids:
                    if cwe_id in self.cwe_db and cwe_id not in seen_cwe_ids:
                        matched_cwes.append(self.cwe_db[cwe_id])
                        seen_cwe_ids.add(cwe_id)

        # Find related CAPEC entries
        matched_capecs: list[CAPECEntry] = []
        seen_capec_ids: set[int] = set()

        for cwe in matched_cwes:
            for capec_id in cwe.capec_ids:
                if capec_id in self.capec_db and capec_id not in seen_capec_ids:
                    matched_capecs.append(self.capec_db[capec_id])
                    seen_capec_ids.add(capec_id)

        # Build enrichment
        enrichment: dict[str, Any] = {
            **finding,
            "cwe": [
                {
                    "id": f"CWE-{c.cwe_id}",
                    "name": c.name,
                    "description": c.description,
                    "severity": c.severity,
                    "owasp_top10": c.owasp_top10,
                    "url": f"https://cwe.mitre.org/data/definitions/{c.cwe_id}.html",
                }
                for c in matched_cwes
            ],
            "capec": [
                {
                    "id": f"CAPEC-{c.capec_id}",
                    "name": c.name,
                    "description": c.description,
                    "prerequisites": c.prerequisites,
                    "url": f"https://capec.mitre.org/data/definitions/{c.capec_id}.html",
                }
                for c in matched_capecs
            ],
        }

        # Add primary CWE if found
        if matched_cwes:
            enrichment["primary_cwe"] = f"CWE-{matched_cwes[0].cwe_id}"
            enrichment["primary_cwe_name"] = matched_cwes[0].name

        # Add OWASP Top 10 mapping
        owasp_cats = {c.owasp_top10 for c in matched_cwes if c.owasp_top10}
        if owasp_cats:
            enrichment["owasp_top10"] = sorted(owasp_cats)

        return enrichment

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich multiple findings."""
        return [self.enrich_finding(f) for f in findings]

    def get_cwe(self, cwe_id: int) -> CWEEntry | None:
        """Look up a CWE by ID."""
        return self.cwe_db.get(cwe_id)

    def get_capec(self, capec_id: int) -> CAPECEntry | None:
        """Look up a CAPEC by ID."""
        return self.capec_db.get(capec_id)

    def suggest_cwes(self, text: str) -> list[CWEEntry]:
        """Suggest CWEs based on free text."""
        text_lower = text.lower()
        results: list[CWEEntry] = []
        seen: set[int] = set()

        for keyword, cwe_ids in _KEYWORD_CWE_MAP.items():
            if keyword in text_lower:
                for cwe_id in cwe_ids:
                    if cwe_id in self.cwe_db and cwe_id not in seen:
                        results.append(self.cwe_db[cwe_id])
                        seen.add(cwe_id)

        return results

    def get_attack_patterns_for_cwe(self, cwe_id: int) -> list[CAPECEntry]:
        """Get CAPEC attack patterns related to a CWE."""
        cwe = self.cwe_db.get(cwe_id)
        if not cwe:
            return []
        return [self.capec_db[c] for c in cwe.capec_ids if c in self.capec_db]
