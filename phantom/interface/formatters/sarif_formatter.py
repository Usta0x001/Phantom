"""
SARIF 2.1.0 Formatter

Produces Static Analysis Results Interchange Format (SARIF) v2.1.0 output.
Compatible with GitHub Advanced Security, GitLab SAST, Azure DevOps,
and other CI/CD pipeline integrations.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

# SARIF severity → level mapping
_SEVERITY_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "none",
}


class SARIFFormatter:
    """
    Formats Phantom scan results as SARIF 2.1.0 JSON.

    Usage:
        formatter = SARIFFormatter()
        sarif_json = formatter.format(scan_results)
        # Write sarif_json to file with json.dumps()
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"

    def __init__(self, tool_version: str = "1.0.0") -> None:
        self.tool_version = tool_version

    def format(self, scan_data: dict[str, Any]) -> dict[str, Any]:
        """
        Convert Phantom scan results to SARIF 2.1.0 format.

        Args:
            scan_data: Phantom scan results dict with 'vulnerabilities' key

        Returns:
            Complete SARIF 2.1.0 document as a dict
        """
        vulnerabilities = scan_data.get("vulnerabilities", [])
        rules = self._build_rules(vulnerabilities)
        results = self._build_results(vulnerabilities)

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Phantom",
                            "version": self.tool_version,
                            "informationUri": "https://github.com/0000phantom0000/phantom",
                            "rules": rules,
                            "semanticVersion": self.tool_version,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(UTC).isoformat(),
                            "toolExecutionNotifications": [],
                        }
                    ],
                    "automationDetails": {
                        "id": scan_data.get("scan_id", "phantom-scan"),
                        "guid": str(uuid.uuid5(uuid.NAMESPACE_URL, scan_data.get("scan_id", "phantom-scan"))),
                    },
                }
            ],
        }

    def _build_rules(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build SARIF rule definitions from vulnerabilities."""
        seen_rule_ids: set[str] = set()
        rules: list[dict[str, Any]] = []

        for vuln in vulnerabilities:
            rule_id = self._get_rule_id(vuln)
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)

            severity = vuln.get("severity", "medium").lower()
            cwe_ids = self._extract_cwe_ids(vuln)

            rule: dict[str, Any] = {
                "id": rule_id,
                "name": self._sanitize_name(vuln.get("title", rule_id)),
                "shortDescription": {
                    "text": vuln.get("title", "Unknown vulnerability"),
                },
                "fullDescription": {
                    "text": vuln.get("description", vuln.get("title", "")),
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(severity, "warning"),
                },
                "properties": {
                    "tags": self._get_tags(vuln),
                    "security-severity": self._severity_score(severity),
                },
            }

            # Add CWE references
            if cwe_ids:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": cwe_id,
                            "guid": "",
                            "toolComponent": {"name": "CWE", "guid": ""},
                        },
                        "kinds": ["superset"],
                    }
                    for cwe_id in cwe_ids
                ]

            # Help URI
            if cwe_ids:
                first_cwe = cwe_ids[0].replace("CWE-", "")
                rule["helpUri"] = (
                    f"https://cwe.mitre.org/data/definitions/{first_cwe}.html"
                )

            rules.append(rule)

        return rules

    def _build_results(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build SARIF result entries."""
        results: list[dict[str, Any]] = []

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            rule_id = self._get_rule_id(vuln)

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": _SEVERITY_MAP.get(severity, "warning"),
                "message": {
                    "text": self._build_message(vuln),
                },
                "locations": self._build_locations(vuln),
            }

            # Add fingerprints for deduplication
            fingerprint = vuln.get("fingerprint") or vuln.get("hash")
            if fingerprint:
                result["fingerprints"] = {"phantom/v1": str(fingerprint)}

            # Add fix suggestions
            remediation = vuln.get("remediation") or vuln.get("recommendation")
            if remediation:
                result["fixes"] = [
                    {
                        "description": {"text": remediation},
                    }
                ]

            # Add related locations (evidence URLs, etc.)
            evidence = vuln.get("evidence") or vuln.get("proof")
            if evidence:
                result["relatedLocations"] = [
                    {
                        "id": 0,
                        "message": {"text": f"Evidence: {evidence[:500]}"},
                    }
                ]

            # Timestamp
            detected_at = vuln.get("detected_at") or vuln.get("timestamp")
            if detected_at:
                result["properties"] = {"detected_at": str(detected_at)}

            results.append(result)

        return results

    def _build_locations(self, vuln: dict[str, Any]) -> list[dict[str, Any]]:
        """Build SARIF location entries from a vulnerability."""
        locations: list[dict[str, Any]] = []

        # Try URL-based location
        url = vuln.get("url") or vuln.get("endpoint") or vuln.get("target")
        if url:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(url),
                        "uriBaseId": "WEBROOT",
                    },
                },
            }

            # Add method/parameter info as logical location
            method = vuln.get("method", "")
            parameter = vuln.get("parameter", "")
            if method or parameter:
                location["logicalLocations"] = [
                    {
                        "name": parameter or url,
                        "kind": "parameter" if parameter else "endpoint",
                        "fullyQualifiedName": f"{method} {url}".strip(),
                    }
                ]

            locations.append(location)

        # Try file-based location (for source code findings)
        file_path = vuln.get("file") or vuln.get("source_file")
        if file_path:
            file_location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(file_path),
                    },
                },
            }

            line = vuln.get("line") or vuln.get("line_number")
            if line:
                file_location["physicalLocation"]["region"] = {
                    "startLine": int(line),
                }

            locations.append(file_location)

        # Fallback: at least one location required
        if not locations:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.get("target", "unknown"),
                            "uriBaseId": "WEBROOT",
                        },
                    },
                }
            )

        return locations

    def _build_message(self, vuln: dict[str, Any]) -> str:
        """Build human-readable result message."""
        parts = [vuln.get("title", "Vulnerability detected")]

        description = vuln.get("description", "")
        if description and description != vuln.get("title"):
            parts.append(description)

        url = vuln.get("url") or vuln.get("endpoint")
        if url:
            parts.append(f"Location: {url}")

        parameter = vuln.get("parameter")
        if parameter:
            parts.append(f"Parameter: {parameter}")

        return ". ".join(parts)

    def _get_rule_id(self, vuln: dict[str, Any]) -> str:
        """Generate a stable rule ID for a vulnerability."""
        # Use CWE if available
        cwe_ids = self._extract_cwe_ids(vuln)
        if cwe_ids:
            return cwe_ids[0]

        # Use template ID (from Nuclei)
        template_id = vuln.get("template_id")
        if template_id:
            return f"PHANTOM-{template_id}"

        # Generate from title
        title = vuln.get("title", "unknown")
        slug = title.lower().replace(" ", "-")[:40]
        return f"PHANTOM-{slug}"

    def _extract_cwe_ids(self, vuln: dict[str, Any]) -> list[str]:
        """Extract CWE IDs from a vulnerability."""
        cwe_ids: list[str] = []

        # Direct CWE field
        if "cwe" in vuln:
            cwe = vuln["cwe"]
            if isinstance(cwe, list):
                for item in cwe:
                    if isinstance(item, dict):
                        cwe_ids.append(item.get("id", ""))
                    elif isinstance(item, str):
                        cwe_ids.append(item)
            elif isinstance(cwe, str):
                cwe_ids.append(cwe)

        # Primary CWE
        primary = vuln.get("primary_cwe")
        if primary and primary not in cwe_ids:
            cwe_ids.append(primary)

        return [c for c in cwe_ids if c]

    def _get_tags(self, vuln: dict[str, Any]) -> list[str]:
        """Get tags for a vulnerability."""
        tags = ["security"]

        severity = vuln.get("severity", "").lower()
        if severity:
            tags.append(severity)

        # OWASP mapping
        owasp = vuln.get("owasp_top10")
        if isinstance(owasp, list):
            tags.extend(owasp)
        elif isinstance(owasp, str):
            tags.append(owasp)

        # CWE tags
        for cwe_id in self._extract_cwe_ids(vuln):
            tags.append(cwe_id)

        return tags

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a string for use as a SARIF rule name."""

        return re.sub(r"[^a-zA-Z0-9_\-.]", "", name.replace(" ", "_"))[:100]

    def _severity_score(self, severity: str) -> str:
        """Map severity to CVSS-like score string for GitHub."""
        scores = {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.0",
            "low": "3.0",
            "info": "1.0",
            "informational": "0.0",
        }
        return scores.get(severity, "5.0")
