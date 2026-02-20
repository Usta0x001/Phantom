"""
FFuf Tool Wrapper

Typed wrapper for FFuf web fuzzing.
Runs inside the sandbox container via terminal_execute.
"""

import json
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool


def _parse_ffuf_json(raw_output: str) -> list[dict[str, Any]]:
    """Parse FFuf JSON output into structured results."""
    results: list[dict[str, Any]] = []

    # FFuf outputs JSON when -json flag is used
    try:
        # Find JSON output (may be mixed with other text)
        json_start = raw_output.find('{"commandline"')
        if json_start == -1:
            json_start = raw_output.find('{"results"')
        if json_start == -1:
            return results

        json_data = raw_output[json_start:]
        data = json.loads(json_data)

        for result in data.get("results", []):
            results.append({
                "url": result.get("url", ""),
                "status": result.get("status", 0),
                "length": result.get("length", 0),
                "words": result.get("words", 0),
                "lines": result.get("lines", 0),
                "input": result.get("input", {}),
                "redirect_location": result.get("redirectlocation", ""),
            })
    except (json.JSONDecodeError, KeyError):
        # Fallback: parse text output
        for line in raw_output.splitlines():
            if "[Status:" in line or ":: Status" in line:
                # Try to extract status code and URL from text output
                parts = line.split()
                if len(parts) >= 2:
                    results.append({"raw_line": line.strip()})

    return results


@register_tool(sandbox_execution=True)
def ffuf_directory_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str | None = None,
    filter_status: str | None = None,
    match_status: str = "200,204,301,302,307,401,403,405",
    rate: int = 100,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Discover directories and files using FFuf fuzzing.

    Args:
        url: Target URL with FUZZ keyword (e.g., "http://site.com/FUZZ")
        wordlist: Path to wordlist (default: dirb common.txt)
        extensions: File extensions to try (e.g., "php,html,txt,bak")
        filter_status: Status codes to filter OUT (e.g., "404,403")
        match_status: Status codes to match/include (default: common success codes)
        rate: Requests per second (default: 100)
        extra_args: Additional ffuf arguments

    Returns:
        Discovered paths with status codes and sizes
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # Ensure FUZZ keyword is present
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    cmd_parts = [
        "ffuf",
        "-u", shlex.quote(url),
        "-w", shlex.quote(wordlist),
        "-o", "/tmp/ffuf_out.json",
        "-of", "json",
        "-c",  # Colorized (helps parsing)
        "-rate", str(rate),
    ]

    if extensions:
        cmd_parts.extend(["-e", f".{extensions.replace(',', ',.')}"])

    if filter_status:
        cmd_parts.extend(["-fc", shlex.quote(filter_status)])

    if match_status:
        cmd_parts.extend(["-mc", shlex.quote(match_status)])

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

    # Read JSON output file
    read_result = terminal_execute(command="cat /tmp/ffuf_out.json 2>/dev/null || echo '{}'", timeout=10.0)
    json_output = read_result.get("content", "{}")

    findings = _parse_ffuf_json(json_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        "wordlist": wordlist,
        "total_found": len(findings),
        "findings": findings,
        "raw_output": result.get("content", "")[:2000],
    }


@register_tool(sandbox_execution=True)
def ffuf_parameter_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    method: Literal["GET", "POST"] = "GET",
    data: str | None = None,
    filter_size: str | None = None,
    rate: int = 100,
) -> dict[str, Any]:
    """
    Discover hidden parameters using FFuf.

    Args:
        url: Target URL (FUZZ will be added as parameter name)
        wordlist: Parameter wordlist
        method: HTTP method
        data: POST data with FUZZ keyword (e.g., "FUZZ=test")
        filter_size: Filter responses by size (e.g., "1234")
        rate: Requests per second

    Returns:
        Discovered parameters
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # For GET, add FUZZ as parameter name
    if method == "GET":
        if "?" in url:
            fuzz_url = f"{url}&FUZZ=test"
        else:
            fuzz_url = f"{url}?FUZZ=test"
    else:
        fuzz_url = url

    cmd_parts = [
        "ffuf",
        "-u", shlex.quote(fuzz_url),
        "-w", shlex.quote(wordlist),
        "-o", "/tmp/ffuf_params.json",
        "-of", "json",
        "-rate", str(rate),
    ]

    if method == "POST":
        cmd_parts.extend(["-X", "POST"])
        if data:
            cmd_parts.extend(["-d", shlex.quote(data)])
        else:
            cmd_parts.extend(["-d", "FUZZ=test"])
        cmd_parts.extend(["-H", "Content-Type: application/x-www-form-urlencoded"])

    if filter_size:
        cmd_parts.extend(["-fs", shlex.quote(filter_size)])

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    # Read JSON output
    read_result = terminal_execute(command="cat /tmp/ffuf_params.json 2>/dev/null || echo '{}'", timeout=10.0)
    json_output = read_result.get("content", "{}")

    findings = _parse_ffuf_json(json_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        "method": method,
        "total_found": len(findings),
        "findings": findings,
    }


@register_tool(sandbox_execution=True)
def ffuf_vhost_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    filter_size: str | None = None,
    rate: int = 100,
) -> dict[str, Any]:
    """
    Discover virtual hosts using FFuf.

    Args:
        url: Target URL
        wordlist: Subdomain/vhost wordlist
        filter_size: Filter by response size (to exclude default page)
        rate: Requests per second

    Returns:
        Discovered virtual hosts
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = [
        "ffuf",
        "-u", shlex.quote(url),
        "-w", shlex.quote(wordlist),
        "-H", "Host: FUZZ.target.com",
        "-o", "/tmp/ffuf_vhost.json",
        "-of", "json",
        "-rate", str(rate),
    ]

    if filter_size:
        cmd_parts.extend(["-fs", shlex.quote(filter_size)])

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    read_result = terminal_execute(command="cat /tmp/ffuf_vhost.json 2>/dev/null || echo '{}'", timeout=10.0)
    json_output = read_result.get("content", "{}")

    findings = _parse_ffuf_json(json_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        "total_found": len(findings),
        "findings": findings,
    }
