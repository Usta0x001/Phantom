"""
HTTPx Tool Wrapper

Typed wrapper for HTTPx web probing.
Runs inside the sandbox container via terminal_execute.
"""

import json
import shlex
from typing import Any

from phantom.tools.registry import register_tool


def _parse_httpx_json(raw_output: str) -> list[dict[str, Any]]:
    """Parse HTTPx JSON output into structured results."""
    results: list[dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            results.append({
                "url": data.get("url", ""),
                "status_code": data.get("status_code", 0),
                "title": data.get("title", ""),
                "webserver": data.get("webserver", ""),
                "tech": data.get("tech", []),
                "content_type": data.get("content_type", ""),
                "content_length": data.get("content_length", 0),
                "host": data.get("host", ""),
                "port": data.get("port", ""),
                "scheme": data.get("scheme", ""),
                "method": data.get("method", ""),
                "final_url": data.get("final_url", ""),
                "response_time": data.get("response_time", ""),
            })
        except json.JSONDecodeError:
            continue

    return results


@register_tool(sandbox_execution=True)
def httpx_probe(
    targets: str | list[str],
    ports: str | None = None,
    follow_redirects: bool = True,
    tech_detect: bool = True,
    status_code: bool = True,
    title: bool = True,
    rate_limit: int = 150,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Probe HTTP/HTTPS services using HTTPx.

    Args:
        targets: Single URL/domain or list of targets
        ports: Ports to probe (e.g., "80,443,8080,8443")
        follow_redirects: Follow HTTP redirects
        tech_detect: Detect technologies
        status_code: Include status codes
        title: Include page titles
        rate_limit: Requests per second
        extra_args: Additional httpx arguments

    Returns:
        Probed hosts with status, titles, tech stack
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # Handle list input
    if isinstance(targets, list):
        targets_str = "\n".join(targets)
        # Write to temp file safely
        terminal_execute(
            command=f"cat > /tmp/httpx_targets.txt <<'PHANTOM_EOF'\n{targets_str}\nPHANTOM_EOF",
            timeout=5.0,
        )
        cmd_parts = ["httpx", "-l", "/tmp/httpx_targets.txt"]
    else:
        cmd_parts = ["httpx", "-u", shlex.quote(targets)]

    cmd_parts.extend(["-json", "-nc", "-silent"])

    if ports:
        cmd_parts.extend(["-ports", shlex.quote(ports)])

    if follow_redirects:
        cmd_parts.append("-follow-redirects")

    if tech_detect:
        cmd_parts.append("-td")

    if status_code:
        cmd_parts.append("-sc")

    if title:
        cmd_parts.append("-title")

    cmd_parts.extend(["-rl", str(rate_limit)])

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
    findings = _parse_httpx_json(raw_output)

    return {
        "success": True,
        "command": command,
        "total_alive": len(findings),
        "findings": findings,
    }


@register_tool(sandbox_execution=True)
def httpx_screenshot(
    url: str,
    output_dir: str = "/workspace/screenshots",
) -> dict[str, Any]:
    """
    Take a screenshot of a web page using HTTPx.

    Args:
        url: Target URL
        output_dir: Directory to save screenshots

    Returns:
        Screenshot file path
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # Create output directory
    terminal_execute(command=f"mkdir -p {shlex.quote(output_dir)}", timeout=5.0)

    command = f'httpx -u {shlex.quote(url)} -screenshot -screenshot-path {shlex.quote(output_dir)} -silent'

    result = terminal_execute(command=command, timeout=60.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    # Find screenshot file
    ls_result = terminal_execute(command=f"ls -la {output_dir}/*.png 2>/dev/null | head -5", timeout=5.0)

    return {
        "success": True,
        "command": command,
        "url": url,
        "output_dir": output_dir,
        "files": ls_result.get("content", ""),
    }


@register_tool(sandbox_execution=True)
def httpx_full_analysis(
    targets: str | list[str],
) -> dict[str, Any]:
    """
    Perform full HTTP analysis including headers, tech, status, title.

    Args:
        targets: URL(s) to analyze

    Returns:
        Comprehensive HTTP analysis results
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    if isinstance(targets, list):
        targets_str = "\n".join(targets)
        terminal_execute(
            command=f"cat > /tmp/httpx_targets.txt <<'PHANTOM_EOF'\n{targets_str}\nPHANTOM_EOF",
            timeout=5.0,
        )
        target_parts = ["-l", "/tmp/httpx_targets.txt"]
    else:
        target_parts = ["-u", shlex.quote(targets)]

    cmd_parts = [
        "httpx", *target_parts, "-json", "-nc", "-silent",
        "-sc",  # Status code
        "-title",  # Page title
        "-td",  # Tech detect
        "-server",  # Server header
        "-ct",  # Content type
        "-cl",  # Content length
        "-method",  # HTTP method
        "-location",  # Redirect location
        "-rt",  # Response time
        "-websocket",  # WebSocket check
        "-cname",  # CNAME record
        "-asn",  # ASN info
        "-cdn",  # CDN detection
        "-follow-redirects",
    ]

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=300.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    findings = _parse_httpx_json(raw_output)

    return {
        "success": True,
        "command": command,
        "total_probed": len(findings),
        "findings": findings,
    }
