"""
Nmap Tool Wrapper

Typed wrapper for nmap port scanning with structured output parsing.
Runs inside the sandbox container via terminal_execute.
"""

import json
import re
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool


def _parse_nmap_output(raw_output: str) -> dict[str, Any]:
    """Parse nmap text output into structured data."""
    result: dict[str, Any] = {
        "hosts": [],
        "scan_info": {},
        "raw_output": raw_output[:3000],  # Keep first 3000 chars for evidence
    }

    current_host: dict[str, Any] | None = None

    for line in raw_output.splitlines():
        line = line.strip()

        # Host discovery
        if line.startswith("Nmap scan report for"):
            if current_host:
                result["hosts"].append(current_host)
            host_match = re.search(r"for\s+(.+?)(?:\s+\(([^)]+)\))?$", line)
            if host_match:
                hostname = host_match.group(1).strip()
                ip = host_match.group(2) or hostname
                current_host = {"hostname": hostname, "ip": ip, "ports": [], "os": None}

        # Port info
        elif current_host and re.match(r"^\d+/(tcp|udp)", line):
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""

                port_num, proto = port_proto.split("/")
                current_host["ports"].append({
                    "port": int(port_num),
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "version": version.strip(),
                })

        # OS detection
        elif current_host and "OS details:" in line:
            current_host["os"] = line.replace("OS details:", "").strip()

        # Running info
        elif current_host and line.startswith("Running:"):
            current_host["os"] = line.replace("Running:", "").strip()

    if current_host:
        result["hosts"].append(current_host)

    return result


@register_tool(sandbox_execution=True)
def nmap_scan(
    target: str,
    scan_type: Literal["quick", "standard", "comprehensive", "stealth", "udp"] = "standard",
    ports: str | None = None,
    scripts: str | None = None,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Perform a port scan using nmap.

    Args:
        target: IP address, hostname, or CIDR range to scan
        scan_type: Type of scan:
            - quick: Fast scan of top 100 ports (-F)
            - standard: Default nmap scan of top 1000 ports
            - comprehensive: All ports + version + OS detection (-p- -sV -O)
            - stealth: SYN scan (-sS) - requires root
            - udp: UDP scan (-sU) - requires root
        ports: Specific ports to scan (e.g., "22,80,443" or "1-1000")
        scripts: NSE scripts to run (e.g., "vuln" or "http-*")
        extra_args: Additional nmap arguments

    Returns:
        Structured scan results with hosts, ports, services, and versions
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # Build command based on scan type
    cmd_parts = ["nmap", "-oN", "-"]  # Normal output to stdout

    if scan_type == "quick":
        cmd_parts.extend(["-F", "-T4"])
    elif scan_type == "standard":
        cmd_parts.extend(["-sV", "-T4"])  # Service version detection
    elif scan_type == "comprehensive":
        cmd_parts.extend(["-p-", "-sV", "-sC", "-O", "-T4"])
    elif scan_type == "stealth":
        cmd_parts.extend(["-sS", "-T4"])
    elif scan_type == "udp":
        cmd_parts.extend(["-sU", "-T4"])

    if ports:
        cmd_parts.extend(["-p", shlex.quote(ports)])

    if scripts:
        cmd_parts.extend(["--script", shlex.quote(scripts)])

    if extra_args:
        cmd_parts.extend(shlex.split(extra_args))

    cmd_parts.append(shlex.quote(target))

    command = " ".join(cmd_parts)

    # Set timeout based on scan type
    timeout_map = {
        "quick": 120.0,
        "standard": 300.0,
        "comprehensive": 900.0,
        "stealth": 300.0,
        "udp": 600.0,
    }
    timeout = timeout_map.get(scan_type, 300.0)

    result = terminal_execute(command=command, timeout=timeout)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
            "raw_output": result.get("content", ""),
        }

    raw_output = result.get("content", "")
    parsed = _parse_nmap_output(raw_output)

    return {
        "success": True,
        "command": command,
        "target": target,
        "scan_type": scan_type,
        **parsed,
    }


@register_tool(sandbox_execution=True)
def nmap_vuln_scan(
    target: str,
    ports: str | None = None,
) -> dict[str, Any]:
    """
    Run nmap with vulnerability detection scripts.

    Args:
        target: IP address, hostname, or CIDR range to scan
        ports: Specific ports to scan (default: top 1000)

    Returns:
        Vulnerability findings from NSE scripts
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["nmap", "-sV", "--script=vuln", "-T4"]

    if ports:
        cmd_parts.extend(["-p", shlex.quote(ports)])

    cmd_parts.append(shlex.quote(target))

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")

    # Extract vulnerability findings
    vulns: list[dict[str, str]] = []
    current_vuln: dict[str, str] | None = None

    for line in raw_output.splitlines():
        if "VULNERABLE" in line.upper():
            if current_vuln:
                vulns.append(current_vuln)
            current_vuln = {"title": line.strip(), "details": ""}
        elif current_vuln and line.strip():
            current_vuln["details"] += line.strip() + "\n"

    if current_vuln:
        vulns.append(current_vuln)

    return {
        "success": True,
        "command": command,
        "target": target,
        "vulnerabilities": vulns,
        "raw_output": raw_output[:3000],
    }
