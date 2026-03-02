"""
FFuf Tool Wrapper

Typed wrapper for FFuf web fuzzing.
Runs inside the sandbox container via terminal_execute.
"""

import json
import shlex
from typing import Any, Literal

from phantom.tools.registry import register_tool
from phantom.tools.security.sanitizer import safe_temp_path, sanitize_extra_args

# Built-in minimal wordlists so we NEVER need to download anything at runtime.
# These cover the most common parameter names for web application testing.
_BUILTIN_PARAM_WORDLIST = [
    "id", "name", "email", "username", "password", "token", "key", "api_key",
    "apikey", "secret", "session", "sessionid", "auth", "access_token",
    "page", "limit", "offset", "sort", "order", "filter", "search", "q",
    "query", "type", "action", "cmd", "command", "exec", "file", "path",
    "dir", "url", "redirect", "next", "return", "callback", "continue",
    "dest", "destination", "redir", "redirect_uri", "return_url",
    "user", "user_id", "uid", "admin", "role", "group", "status",
    "comment", "message", "body", "content", "text", "title", "description",
    "category", "tag", "label", "format", "output", "debug", "test", "mode",
    "lang", "language", "locale", "country", "region", "timezone",
    "from", "to", "start", "end", "date", "time", "year", "month", "day",
    "size", "width", "height", "count", "max", "min", "num", "number",
    "price", "amount", "quantity", "total", "discount", "coupon", "code",
    "product", "item", "sku", "order_id", "invoice", "payment", "method",
    "address", "phone", "zip", "city", "state", "firstname", "lastname",
    "display", "view", "template", "theme", "style", "css", "js",
    "include", "require", "import", "load", "read", "write", "delete",
    "create", "update", "edit", "remove", "add", "set", "get", "list",
    "show", "hide", "enable", "disable", "activate", "deactivate",
    "login", "logout", "register", "signup", "signin", "reset", "forgot",
    "verify", "confirm", "approve", "deny", "accept", "reject",
    "upload", "download", "export", "backup", "restore",
    "config", "setting", "option", "preference", "param", "value", "data",
    "json", "xml", "html", "csv", "pdf", "image", "photo", "avatar",
    "version", "v", "api", "endpoint", "resource", "service", "module",
    "class", "func", "function", "handler", "controller",
    "table", "column", "field", "row", "record", "entry", "index",
    "BasketId", "ProductId", "UserId",  # Juice Shop specific
]

_BUILTIN_VHOST_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "api", "dev", "staging", "test", "beta", "alpha", "demo",
    "app", "portal", "dashboard", "panel", "console", "manage", "m",
    "blog", "shop", "store", "cdn", "static", "assets", "media", "img",
    "docs", "wiki", "help", "support", "status", "monitor", "grafana",
    "git", "gitlab", "jenkins", "ci", "cd", "build", "deploy",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "kibana",
    "vpn", "proxy", "gateway", "auth", "sso", "oauth", "login",
    "internal", "intranet", "private", "secure", "legacy", "old", "new",
    "v1", "v2", "v3", "sandbox", "staging2", "preprod", "uat",
]

# Common directory/file entries for fallback when dirb wordlists are missing
_BUILTIN_DIR_WORDLIST = [
    "admin", "api", "app", "assets", "backup", "bin", "cgi-bin", "config",
    "css", "data", "db", "debug", "docs", "download", "env", "error",
    "files", "fonts", "help", "home", "images", "img", "includes", "js",
    "lib", "log", "login", "logout", "media", "node_modules", "old",
    "panel", "php", "private", "public", "redirect", "rest", "robots.txt",
    "scripts", "search", "server", "sitemap.xml", "static", "status",
    "storage", "swagger", "temp", "test", "tmp", "upload", "uploads",
    "user", "users", "v1", "v2", "vendor", "web", "wp-admin", "wp-login",
    ".env", ".git", ".htaccess", "package.json", "composer.json",
    # Juice Shop / Node.js specific
    "api", "rest", "socket.io", "ftp", "encryptionkeys", "promotion",
    "video", "assets", "i18n", "redirect", "profile", "basket",
    "track-order", "metrics", "security.txt", "main.js", "runtime.js",
    "polyfills.js", "vendor.js", "snippet", "dataerasure", "accounting",
    "b2b", "recycles", "deluxe-membership", "wallet",
]


def _ensure_wordlist(wordlist_path: str, fallback_words: list[str]) -> str:
    """
    Ensure a wordlist file exists. If the requested path doesn't exist,
    generate a minimal built-in wordlist instead of downloading anything.
    Returns the path to the usable wordlist.
    """
    from phantom.tools.terminal.terminal_actions import terminal_execute

    # Check if the requested wordlist exists
    check = terminal_execute(
        command=f"test -f {shlex.quote(wordlist_path)} && echo EXISTS || echo MISSING",
        timeout=5.0,
    )
    if "EXISTS" in check.get("content", ""):
        return wordlist_path

    # Generate a minimal built-in wordlist instead of downloading
    builtin_path = f"/tmp/phantom_wordlist_{abs(hash(wordlist_path)) % 100000}.txt"
    words_content = "\n".join(fallback_words)
    # Use printf to handle newlines properly
    terminal_execute(
        command=f"printf '%s\\n' {' '.join(shlex.quote(w) for w in fallback_words)} > {shlex.quote(builtin_path)}",
        timeout=10.0,
    )
    return builtin_path


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
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",  # Pre-installed in Kali
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

    # Ensure wordlist exists (dirb common.txt should always be there in Kali)
    wordlist = _ensure_wordlist(wordlist, _BUILTIN_DIR_WORDLIST)

    # Ensure FUZZ keyword is present
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    out_file = safe_temp_path("ffuf_out", ".json")

    cmd_parts = [
        "ffuf",
        "-u", shlex.quote(url),
        "-w", shlex.quote(wordlist),
        "-o", out_file,
        "-of", "json",
        "-c",  # Colorized (helps parsing)
        "-rate", str(int(rate)),
    ]

    if extensions:
        cmd_parts.extend(["-e", shlex.quote(f".{extensions.replace(',', ',.')}")])

    if filter_status:
        cmd_parts.extend(["-fc", shlex.quote(filter_status)])

    if match_status:
        cmd_parts.extend(["-mc", shlex.quote(match_status)])

    cmd_parts.extend(sanitize_extra_args(extra_args))

    command = " ".join(cmd_parts)

    result = terminal_execute(command=command, timeout=600.0)

    if result.get("error"):
        return {
            "success": False,
            "error": result.get("error"),
            "command": command,
        }

    # Read JSON output file
    read_result = terminal_execute(command=f"cat {shlex.quote(out_file)} 2>/dev/null || echo '{{}}'", timeout=10.0)
    json_output = read_result.get("content", "{}")

    findings = _parse_ffuf_json(json_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        "wordlist": wordlist,
        "total_found": len(findings),
        "findings": findings,
        "raw_output": result.get("content", "")[:500],  # BUG-04 FIX: reduced from 2000
    }


@register_tool(sandbox_execution=True)
def ffuf_parameter_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",  # Use pre-installed wordlist
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

    # Ensure wordlist exists; fall back to built-in parameter names
    wordlist = _ensure_wordlist(wordlist, _BUILTIN_PARAM_WORDLIST)

    out_file = safe_temp_path("ffuf_params", ".json")

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
        "-o", out_file,
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
    read_result = terminal_execute(command=f"cat {shlex.quote(out_file)} 2>/dev/null || echo '{{}}'", timeout=10.0)
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
    wordlist: str = "/usr/share/wordlists/dirb/small.txt",  # Use pre-installed wordlist
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

    # Ensure wordlist exists; fall back to built-in vhost names
    wordlist = _ensure_wordlist(wordlist, _BUILTIN_VHOST_WORDLIST)

    out_file = safe_temp_path("ffuf_vhost", ".json")

    # Extract the domain from the URL for the Host header
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.hostname or "localhost"

    cmd_parts = [
        "ffuf",
        "-u", shlex.quote(url),
        "-w", shlex.quote(wordlist),
        "-H", f"Host: FUZZ.{domain}",
        "-o", out_file,
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

    read_result = terminal_execute(command=f"cat {shlex.quote(out_file)} 2>/dev/null || echo '{{}}'", timeout=10.0)
    json_output = read_result.get("content", "{}")

    findings = _parse_ffuf_json(json_output)

    return {
        "success": True,
        "command": command,
        "url": url,
        "total_found": len(findings),
        "findings": findings,
    }
