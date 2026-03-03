"""
Nuclei Tool Wrapper

Typed wrapper for Nuclei template-based vulnerability scanning.
Runs inside the sandbox container via terminal_execute.
"""

import json
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool
from phantom.tools.security.sanitizer import sanitize_extra_args


def _parse_nuclei_jsonl(raw_output: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings.

    Preserves critical fields the LLM needs to chain exploits:
    - name + description: What the vuln is and how it works
    - reference: URLs linking to exploitation guides/PoCs
    - tags: Quick classification (sqli, xss, cve, etc.)
    - curl_command: Ready-to-use PoC command
    - extracted_results: Data the template captured (versions, tokens, etc.)
    """
    findings: list[dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            finding = json.loads(line)
            info = finding.get("info", {})

            # Build a rich finding dict — every field helps the LLM exploit
            parsed: dict[str, Any] = {
                "template_id": finding.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matched_at": finding.get("matched-at", ""),
                "description": (info.get("description", "") or "")[:500],
                "matcher_name": finding.get("matcher-name", ""),
                "tags": ", ".join(info.get("tags", [])) if info.get("tags") else "",
            }

            # Reference URLs — exploitation guides, CVE details, PoCs
            refs = info.get("reference")
            if refs and isinstance(refs, list):
                parsed["references"] = refs[:5]  # Top 5 refs

            # Curl command — ready-to-use PoC
            curl_cmd = finding.get("curl-command", "")
            if curl_cmd:
                parsed["curl_command"] = curl_cmd[:500]

            # Extracted results — versions, tokens, sensitive data nuclei captured
            extracted = finding.get("extracted-results")
            if extracted:
                if isinstance(extracted, list):
                    parsed["extracted_results"] = extracted[:5]
                else:
                    parsed["extracted_results"] = str(extracted)[:300]

            # Type of detection (http, dns, network, etc.)
            det_type = finding.get("type", "")
            if det_type:
                parsed["type"] = det_type

            findings.append(parsed)
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

    cmd_parts = ["nuclei", "-u", shlex.quote(target), "-jsonl", "-nc", "-stats"]  # JSON Lines output, no color, stats

    if severity != "all":
        cmd_parts.extend(["-severity", severity])

    if tags:
        cmd_parts.extend(["-tags", shlex.quote(tags)])

    if templates:
        cmd_parts.extend(["-t", shlex.quote(templates)])

    if exclude_tags:
        cmd_parts.extend(["-exclude-tags", shlex.quote(exclude_tags)])

    cmd_parts.extend(["-rl", str(int(rate_limit))])

    cmd_parts.extend(sanitize_extra_args(extra_args))

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

    # Cap findings list to avoid huge responses blowing up context
    _MAX_FINDINGS = 40
    truncated = len(findings) > _MAX_FINDINGS
    if truncated:
        # Keep critical/high first, then truncate
        findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            f.get("severity", "info").lower(), 4))
        findings = findings[:_MAX_FINDINGS]

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

    result = {
        "success": True,
        "command": command,
        "target": target,
        "total_findings": len(findings),
        "findings_truncated": truncated,
        "findings": findings,
        "by_severity": {k: len(v) for k, v in severity_groups.items()},
    }
    # Include raw output tail to surface info not captured in JSON parsing
    if len(findings) == 0:
        result["raw_output_tail"] = raw_output[-1000:] if len(raw_output) > 0 else "(no output)"
    elif len(raw_output) > 200:
        # Even with findings, include tail for non-JSON stats/info lines
        non_json_lines = [l for l in raw_output.splitlines()[-30:] if l.strip() and not l.strip().startswith("{")]
        if non_json_lines:
            result["scan_stats"] = "\n".join(non_json_lines[-10:])
    return result


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
