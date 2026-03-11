"""SARIF 2.1.0 formatter for Phantom vulnerability reports.

Converts Phantom's internal vulnerability JSON into a SARIF 2.1.0 document
suitable for GitHub Code Scanning, Semgrep, and any other SARIF-aware tool.

Usage
-----
    from phantom.interface.formatters.sarif_formatter import SARIFFormatter
    doc = SARIFFormatter().format(report_data)
    # doc is a dict — serialise with json.dumps(doc, indent=2)

SARIF specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub Code Scanning: https://docs.github.com/en/code-security/code-scanning
"""

from __future__ import annotations

import re
import uuid
from typing import Any

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Map Phantom severity strings to SARIF notification levels and security-severity scores.
# "security-severity" is the GitHub Code Scanning extension property (CVSS-ish 0-10 score).
_SEV_MAP: dict[str, tuple[str, float]] = {
    "critical": ("error", 9.5),
    "high":     ("error", 8.0),
    "medium":   ("warning", 5.5),
    "low":      ("note", 3.0),
    "info":     ("note", 1.0),
}


def _safe_str(val: Any, default: str = "") -> str:
    """Return a non-None string."""
    return str(val) if val is not None else default


def _rule_id(vuln: dict[str, Any]) -> str:
    """Generate a stable, slug-safe rule ID from the vulnerability name."""
    name = _safe_str(vuln.get("name") or vuln.get("title"), "Unknown")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()
    return f"PHANTOM-{slug}"[:64]


def _make_rule(vuln: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` from a Phantom vulnerability dict."""
    rid = _rule_id(vuln)
    sev = _safe_str(vuln.get("severity", "info")).lower()
    _, score = _SEV_MAP.get(sev, ("note", 1.0))
    name = _safe_str(vuln.get("name") or vuln.get("title"), "Unknown Finding")
    description = _safe_str(vuln.get("description"), name)
    remediation = vuln.get("remediation")

    rule: dict[str, Any] = {
        "id": rid,
        "name": re.sub(r"[^A-Za-z0-9]", "", name.title()),  # camelCase-ish
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "defaultConfiguration": {
            "level": _SEV_MAP.get(sev, ("note", 1.0))[0],
        },
        "properties": {
            "security-severity": str(score),
            "phantom-severity": sev,
        },
    }

    if remediation:
        rule["help"] = {"text": _safe_str(remediation)}
        rule["helpUri"] = ""

    return rule


def _make_result(vuln: dict[str, Any], run_index: int = 0) -> dict[str, Any]:
    """Build a SARIF ``result`` from a Phantom vulnerability dict."""
    rid = _rule_id(vuln)
    sev = _safe_str(vuln.get("severity", "info")).lower()
    level = _SEV_MAP.get(sev, ("note", 1.0))[0]
    name = _safe_str(vuln.get("name") or vuln.get("title"), "Unknown Finding")
    description = _safe_str(vuln.get("description"), name)
    endpoint = _safe_str(vuln.get("endpoint") or vuln.get("url"), "")
    payload = vuln.get("payload")

    message_text = description
    if endpoint:
        message_text += f"\n\nEndpoint: {endpoint}"
    if payload:
        message_text += f"\n\nPayload: {payload}"

    result: dict[str, Any] = {
        "ruleId": rid,
        "level": level,
        "message": {"text": message_text},
    }

    # Build a physical location if we have an endpoint URL or a file path.
    if endpoint:
        # For HTTP endpoints store the URI as an artifact.
        if re.match(r"https?://", endpoint):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": endpoint, "uriBaseId": "%SRCROOT%"},
                    }
                }
            ]
        else:
            # Could be a file path — use it as-is (relative).
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": endpoint.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ]

    # Attach PoC / evidence as a code flow if present.
    poc = vuln.get("poc_description") or vuln.get("poc")
    if poc:
        result["codeFlows"] = [
            {
                "message": {"text": "Proof of Concept"},
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {"text": _safe_str(poc)[:1000]},
                                }
                            }
                        ]
                    }
                ],
            }
        ]

    # Extra properties (non-standard, surfaced in some UIs).
    extra: dict[str, Any] = {}
    agent_name = vuln.get("agent_name")
    if agent_name:
        extra["phantom-agent"] = agent_name
    cvss = vuln.get("cvss_score")
    if cvss is not None:
        try:
            extra["cvss"] = float(cvss)
        except (TypeError, ValueError):
            pass
    if extra:
        result["properties"] = extra

    return result


class SARIFFormatter:
    """Convert a Phantom scan report dict into a SARIF 2.1.0 document."""

    TOOL_NAME = "phantom"
    TOOL_URI = "https://github.com/Usta0x001/Phantom"

    def format(self, report: dict[str, Any]) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document dict.

        Parameters
        ----------
        report:
            Phantom JSON report dict (the checkpoint ``vulnerability_reports``
            list or a full export JSON).  Keys used:
            ``vulnerabilities`` | ``findings`` | ``vulnerability_reports``
        """
        try:
            from importlib.metadata import version as _v
            tool_version = _v("phantom-agent")
        except Exception:  # noqa: BLE001
            tool_version = "0.0.0"

        # Normalise: Phantom exports may use any of these keys.
        vulns: list[dict[str, Any]] = (
            report.get("vulnerabilities")
            or report.get("findings")
            or report.get("vulnerability_reports")
            or []
        )

        # Collect unique rules (one per distinct vulnerability name/type).
        seen_rule_ids: set[str] = set()
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        for v in vulns:
            rid = _rule_id(v)
            if rid not in seen_rule_ids:
                seen_rule_ids.add(rid)
                rules.append(_make_rule(v))
            results.append(_make_result(v))

        sarif_run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": self.TOOL_NAME,
                    "version": tool_version,
                    "informationUri": self.TOOL_URI,
                    "rules": rules,
                    "properties": {
                        "tags": ["security", "penetration-testing", "phantom"],
                    },
                }
            },
            "results": results,
            # Hint to consumers where sources live.
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": "file:///"},
            },
            # Unique run ID — useful for comparing runs in GitHub Advanced Security.
            "automationDetails": {
                "id": f"phantom/{report.get('run_name', str(uuid.uuid4())[:8])}",
                "description": {
                    "text": (
                        f"Phantom autonomous penetration test against "
                        f"{report.get('target', report.get('targets', ['unknown'])[0] if isinstance(report.get('targets'), list) else 'unknown')}"
                    )
                },
            },
        }

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [sarif_run],
        }
