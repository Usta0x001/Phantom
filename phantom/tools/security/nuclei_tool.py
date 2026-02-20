"""
Nuclei Tool Wrapper

Typed wrapper for Nuclei template-based vulnerability scanning.
Runs inside the sandbox container via terminal_execute.
"""

import json
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool


def _parse_nuclei_jsonl(raw_output: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings."""
    findings: list[dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            finding = json.loads(line)
            findings.append({
                "template_id": finding.get("template-id", ""),
                "template_name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", "unknown"),
                "host": finding.get("host", ""),
                "matched_at": finding.get("matched-at", ""),
                "matcher_name": finding.get("matcher-name", ""),
                "extracted_results": finding.get("extracted-results", []),
                "curl_command": finding.get("curl-command", ""),
                "description": finding.get("info", {}).get("description", ""),
                "reference": finding.get("info", {}).get("reference", []),
                "tags": finding.get("info", {}).get("tags", []),
            })
        except json.JSONDecodeError:
            continue

    return findings


@register_tool(sandbox_execution=True)
def nuclei_scan(
    target: str,
    severity: Literal["info", "low", "medium", "high", "critical", "all"] = "all",
    tags: str | None = None,
    templates: str | None = None,
    exclude_tags: str | None = None,
    rate_limit: int = 150,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Run Nuclei template-based vulnerability scan.

    Args:
        target: Target URL or file containing list of URLs
        severity: Filter by severity level (default: all)
        tags: Comma-separated tags to run (e.g., "cve,sqli,xss,lfi")
        templates: Specific templates to run (e.g., "cves/2023/")
        exclude_tags: Comma-separated tags to exclude (e.g., "dos,fuzz")
        rate_limit: Requests per second (default: 150)
        extra_args: Additional nuclei arguments

    Returns:
        Structured vulnerability findings with severity, POC, and references
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["nuclei", "-u", shlex.quote(target), "-jsonl", "-nc"]  # JSON Lines output, no color

    if severity != "all":
        cmd_parts.extend(["-severity", severity])

    if tags:
        cmd_parts.extend(["-tags", shlex.quote(tags)])

    if templates:
        cmd_parts.extend(["-t", shlex.quote(templates)])

    if exclude_tags:
        cmd_parts.extend(["-exclude-tags", shlex.quote(exclude_tags)])

    cmd_parts.extend(["-rl", str(rate_limit)])

    if extra_args:
        cmd_parts.extend(shlex.split(extra_args))

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    findings = _parse_nuclei_jsonl(raw_output)

    # Group by severity
    severity_groups: dict[str, list[dict[str, Any]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
    }
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_groups:
            severity_groups[sev].append(f)

    return {
        "success": True,
        "command": command,
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
        "by_severity": {k: len(v) for k, v in severity_groups.items()},
        "raw_output": raw_output[:3000] if len(findings) == 0 else "",
    }


@register_tool(sandbox_execution=True)
def nuclei_scan_cves(
    target: str,
    year: str | None = None,
    rate_limit: int = 100,
) -> dict[str, Any]:
    """
    Scan target specifically for known CVEs using Nuclei templates.

    Args:
        target: Target URL to scan
        year: Filter CVEs by year (e.g., "2023", "2024")
        rate_limit: Requests per second (default: 100)

    Returns:
        CVE findings with severity and references
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["nuclei", "-u", shlex.quote(target), "-jsonl", "-nc", "-tags", "cve"]

    if year:
        cmd_parts.extend(["-t", f"http/cves/{year}/"])

    cmd_parts.extend(["-rl", str(rate_limit)])

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    findings = _parse_nuclei_jsonl(raw_output)

    return {
        "success": True,
        "command": command,
        "target": target,
        "cve_findings": len(findings),
        "findings": findings,
        "raw_output": raw_output[:2000] if len(findings) == 0 else "",
    }


@register_tool(sandbox_execution=True)
def nuclei_scan_misconfigs(
    target: str,
    rate_limit: int = 150,
) -> dict[str, Any]:
    """
    Scan for misconfigurations and exposures using Nuclei.

    Args:
        target: Target URL to scan
        rate_limit: Requests per second

    Returns:
        Misconfiguration findings
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = [
        "nuclei", "-u", shlex.quote(target), "-jsonl", "-nc",
        "-tags", "misconfig,exposure,config",
        "-rl", str(rate_limit),
    ]

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    findings = _parse_nuclei_jsonl(raw_output)

    return {
        "success": True,
        "command": command,
        "target": target,
        "misconfig_findings": len(findings),
        "findings": findings,
    }
