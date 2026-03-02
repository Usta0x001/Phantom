"""
Katana Tool Wrapper

Typed wrapper for Katana web crawler – provides systematic endpoint
and JavaScript-file discovery that the agent needs to build a complete
attack surface map before testing for vulnerabilities.
"""

import json
import shlex
from typing import Any

from phantom.tools.registry import register_tool
from phantom.tools.security.sanitizer import sanitize_extra_args


def _parse_katana_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse Katana output.  Katana with ``-jsonl`` emits one JSON object per
    line.  Without it, plain URLs are emitted."""
    results: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("request", {}).get("endpoint", data.get("url", line)),
                    "method": data.get("request", {}).get("method", "GET"),
                    "status": data.get("response", {}).get("status_code", 0),
                    "content_type": data.get("response", {}).get("headers", {}).get("content_type", ""),
                    "source": data.get("request", {}).get("source", ""),
                    "tag": data.get("request", {}).get("tag", ""),
                })
            except json.JSONDecodeError:
                results.append({"url": line, "method": "GET"})
        else:
            results.append({"url": line, "method": "GET"})
    return results


@register_tool(sandbox_execution=True)
def katana_crawl(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    scope_in_domain: bool = True,
    rate_limit: int = 100,
    max_duration: int = 120,
    extra_args: str | None = None,
) -> dict[str, Any]:
    """
    Crawl and spider a web application using Katana to discover all URLs,
    endpoints, JavaScript files, API routes, and forms.

    Use this BEFORE vulnerability scanning to build a full attack surface
    map. For Single Page Applications (Angular, React, Vue), set headless=True
    to use a headless browser that can render JavaScript.

    Args:
        target: Target URL to crawl (e.g., "http://target.com")
        depth: Crawl depth (default: 3)
        js_crawl: Also parse JavaScript files for endpoints (default: True)
        headless: Use headless browser for JavaScript-heavy/SPA sites (default: False)
        scope_in_domain: Stay within the target domain (default: True)
        rate_limit: Requests per second (default: 100)
        max_duration: Max crawl duration in seconds (default: 120)
        extra_args: Additional katana arguments

    Returns:
        Discovered endpoints, JS files, forms, and API routes
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    cmd_parts = [
        "katana",
        "-u", shlex.quote(target),
        "-jsonl",
        "-nc",          # no colour
        "-silent",
        "-d", str(int(depth)),
        "-rl", str(int(rate_limit)),
        "-timeout", str(int(max_duration)),
    ]

    if headless:
        cmd_parts.extend(["-headless", "-no-sandbox"])  # headless Chrome for SPAs

    if js_crawl:
        cmd_parts.append("-jc")  # JavaScript crawl

    if scope_in_domain:
        cmd_parts.append("-fs")  # field-scope – restrict to same domain

    cmd_parts.extend(sanitize_extra_args(extra_args))

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=float(max_duration) + 30)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    raw_output = result.get("content", "")
    parsed = _parse_katana_output(raw_output)

    # Deduplicate by URL
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in parsed:
        url = item.get("url", "")
        if url and url not in seen:
            seen.add(url)
            unique.append(item)

    # Classify endpoints
    js_files = [u for u in unique if u.get("url", "").endswith((".js", ".mjs"))]
    api_endpoints = [u for u in unique if "/api/" in u.get("url", "") or "/rest/" in u.get("url", "")]
    forms = [u for u in unique if u.get("tag") == "form"]

    # Cap output to prevent context bloat
    _MAX_URLS = 80
    truncated = len(unique) > _MAX_URLS

    return {
        "success": True,
        "command": command,
        "total_urls": len(unique),
        "truncated": truncated,
        "urls": unique[:_MAX_URLS],
        "js_files": js_files[:20],
        "api_endpoints": api_endpoints[:30],
        "forms": forms[:20],
        "summary": {
            "total": len(unique),
            "js_files": len(js_files),
            "api_endpoints": len(api_endpoints),
            "forms": len(forms),
        },
    }
