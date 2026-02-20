"""
Subfinder Tool Wrapper

Typed wrapper for Subfinder subdomain enumeration.
Runs inside the sandbox container via terminal_execute.
"""

import shlex
from typing import Any

from phantom.tools.registry import register_tool


@register_tool(sandbox_execution=True)
def subfinder_enumerate(
    domain: str,
    recursive: bool = False,
    all_sources: bool = True,
    timeout: int = 30,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Enumerate subdomains using Subfinder.

    Args:
        domain: Target domain (e.g., "example.com")
        recursive: Enable recursive subdomain enumeration
        all_sources: Use all available sources
        timeout: Timeout per source in seconds
        extra_args: Additional subfinder arguments

    Returns:
        List of discovered subdomains
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["subfinder", "-d", shlex.quote(domain), "-silent"]

    if recursive:
        cmd_parts.append("-recursive")

    if all_sources:
        cmd_parts.append("-all")

    cmd_parts.extend(["-timeout", str(timeout)])

    if extra_args:
        cmd_parts.extend(shlex.split(extra_args))

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=300.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    
    # Parse subdomains (one per line)
    subdomains = [
        line.strip()
        for line in raw_output.splitlines()
        if line.strip() and not line.startswith("[")
    ]

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_subdomains: list[str] = []
    for sub in subdomains:
        if sub.lower() not in seen:
            seen.add(sub.lower())
            unique_subdomains.append(sub)

    return {
        "success": True,
        "command": command,
        "domain": domain,
        "total_found": len(unique_subdomains),
        "subdomains": unique_subdomains,
    }


@register_tool(sandbox_execution=True)
def subfinder_with_sources(
    domain: str,
) -> dict[str, Any]:
    """
    Enumerate subdomains and show which sources found each.

    Args:
        domain: Target domain

    Returns:
        Subdomains with their discovery sources
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    command = f'subfinder -d {shlex.quote(domain)} -all -cs'

    result = terminal_execute(command=command, timeout=300.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")

    # Parse output: subdomain,source format
    findings: list[dict[str, str]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if "," in line:
            parts = line.split(",", 1)
            if len(parts) == 2:
                findings.append({
                    "subdomain": parts[0].strip(),
                    "source": parts[1].strip(),
                })

    return {
        "success": True,
        "command": command,
        "domain": domain,
        "total_found": len(findings),
        "findings": findings,
    }
