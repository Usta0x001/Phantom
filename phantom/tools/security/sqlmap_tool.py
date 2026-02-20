"""
SQLMap Tool Wrapper

Typed wrapper for SQLMap SQL injection testing.
Runs inside the sandbox container via terminal_execute.
"""

import re
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool


def _parse_sqlmap_output(raw_output: str) -> dict[str, Any]:
    """Parse SQLMap output into structured findings."""
    result: dict[str, Any] = {
        "vulnerable": False,
        "injection_points": [],
        "dbms": None,
        "databases": [],
        "tables": [],
        "payloads": [],
    }

    # Check for vulnerability confirmation
    if "is vulnerable" in raw_output.lower() or "sqlmap identified the following" in raw_output.lower():
        result["vulnerable"] = True

    # Extract DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+?)(?:\n|$)", raw_output)
    if dbms_match:
        result["dbms"] = dbms_match.group(1).strip()

    # Extract injection points
    for match in re.finditer(r"Parameter:\s*(\S+)\s*\((.+?)\)", raw_output):
        result["injection_points"].append({
            "parameter": match.group(1),
            "type": match.group(2),
        })

    # Extract databases
    for match in re.finditer(r"available databases \[.+\]:\n((?:\[\*\]\s*.+\n?)+)", raw_output):
        dbs = re.findall(r"\[\*\]\s*(.+)", match.group(1))
        result["databases"].extend(dbs)

    # Extract payloads used
    for match in re.finditer(r"Payload:\s*(.+?)(?:\n|$)", raw_output):
        result["payloads"].append(match.group(1).strip())

    return result


@register_tool(sandbox_execution=True)
def sqlmap_test(
    url: str,
    data: str | None = None,
    method: Literal["GET", "POST"] = "GET",
    param: str | None = None,
    level: Literal[1, 2, 3, 4, 5] = 2,
    risk: Literal[1, 2, 3] = 2,
    dbms: str | None = None,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Test for SQL injection vulnerabilities using SQLMap.

    Args:
        url: Target URL with parameter(s) to test (e.g., "http://site.com/page?id=1")
        data: POST data string (e.g., "user=admin&pass=test")
        method: HTTP method (GET or POST)
        param: Specific parameter to test (tests all if not specified)
        level: Test level 1-5 (higher = more tests, default: 2)
        risk: Risk level 1-3 (higher = more dangerous tests, default: 2)
        dbms: Force specific DBMS (e.g., "mysql", "postgresql", "mssql")
        extra_args: Additional SQLMap arguments

    Returns:
        Structured findings with vulnerability status, DBMS, and injection points
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["sqlmap", "-u", shlex.quote(url), "--batch", "--flush-session"]

    if data:
        cmd_parts.extend(["--data", shlex.quote(data)])

    if method == "POST":
        cmd_parts.append("--method=POST")

    if param:
        cmd_parts.extend(["-p", shlex.quote(param)])

    cmd_parts.extend(["--level", str(level), "--risk", str(risk)])

    if dbms:
        cmd_parts.extend(["--dbms", shlex.quote(dbms)])

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
    parsed = _parse_sqlmap_output(raw_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        **parsed,
        "raw_output": raw_output[:3000],
    }


@register_tool(sandbox_execution=True)
def sqlmap_dump_database(
    url: str,
    database: str | None = None,
    table: str | None = None,
    columns: str | None = None,
    dump_all: bool = False,
    data: str | None = None,
) -> dict[str, Any]:
    """
    Dump database contents once SQL injection is confirmed.

    Args:
        url: Target URL known to be vulnerable
        database: Specific database to dump
        table: Specific table to dump
        columns: Specific columns to dump (comma-separated)
        dump_all: Dump all databases (use with caution)
        data: POST data if needed

    Returns:
        Extracted database contents
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = ["sqlmap", "-u", shlex.quote(url), "--batch", "--flush-session"]

    if data:
        cmd_parts.extend(["--data", shlex.quote(data)])

    if dump_all:
        cmd_parts.append("--dump-all")
    elif database and table:
        cmd_parts.extend(["-D", database, "-T", table])
        if columns:
            cmd_parts.extend(["-C", columns])
        cmd_parts.append("--dump")
    elif database:
        cmd_parts.extend(["-D", database, "--tables"])
    else:
        cmd_parts.append("--dbs")  # List databases

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=900.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")

    return {
        "success": True,
        "command": command,
        "url": url,
        "dump_output": raw_output[:5000],
    }


@register_tool(sandbox_execution=True)
def sqlmap_forms(
    url: str,
    crawl_depth: int = 2,
    level: Literal[1, 2, 3, 4, 5] = 2,
) -> dict[str, Any]:
    """
    Automatically find and test forms on a page for SQL injection.

    Args:
        url: Target URL to crawl for forms
        crawl_depth: How deep to crawl for forms (default: 2)
        level: Test level 1-5

    Returns:
        Form-based injection findings
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = [
        "sqlmap", "-u", shlex.quote(url),
        "--forms", "--batch", "--flush-session",
        "--crawl", str(crawl_depth),
        "--level", str(level),
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
    parsed = _parse_sqlmap_output(raw_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        **parsed,
        "raw_output": raw_output[:3000],
    }
