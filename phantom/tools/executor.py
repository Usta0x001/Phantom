import html
import inspect
import os
import re
import time
import base64
import hashlib
import io
import unicodedata as _unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote as _url_unquote

import httpx

from phantom.config import Config


if os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "false":
    from phantom.runtime import get_runtime

from .argument_parser import convert_arguments
from .cache import get_tool_cache
from .registry import (
    get_tool_by_name,
    get_tool_names,
    get_tool_param_schema,
    needs_agent_state,
    should_execute_in_sandbox,
)


# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: CMD-002 - Command Injection Protection Patterns
# ════════════════════════════════════════════════════════════════════════════════
_COMMAND_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Semicolon command chaining
    re.compile(r";\s*\w+", re.IGNORECASE),
    # Pipe to another command
    re.compile(r"\|\s*\w+", re.IGNORECASE),
    # AND command chaining
    re.compile(r"&&\s*\w+", re.IGNORECASE),
    # OR command chaining
    re.compile(r"\|\|\s*\w+", re.IGNORECASE),
    # Backtick command substitution
    re.compile(r"`[^`]+`", re.IGNORECASE),
    # $() command substitution
    re.compile(r"\$\([^)]+\)", re.IGNORECASE),
    # ${} variable expansion with commands
    re.compile(r"\$\{[^}]*[;|&`][^}]*\}", re.IGNORECASE),
    # Redirect to absolute paths (potential overwrite)
    re.compile(r">\s*/", re.IGNORECASE),
    # Read from absolute paths
    re.compile(r"<\s*/", re.IGNORECASE),
    # Dangerous commands
    re.compile(r"\b(eval|exec|source)\s+", re.IGNORECASE),
    # Newline injection (literal)
    re.compile(r"[\r\n]", re.IGNORECASE),
    # URL-encoded newlines
    re.compile(r"%0[aAdD]", re.IGNORECASE),
]

# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: TOOL-003 - Path Traversal Detection Pattern
# ════════════════════════════════════════════════════════════════════════════════
_PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.[\\/]", re.IGNORECASE)

# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: ARCH-001 - Prompt Injection Detection Patterns
# ════════════════════════════════════════════════════════════════════════════════
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # System prompt manipulation
    re.compile(r"</?system\s*>", re.IGNORECASE),
    re.compile(r"\[/?system\]", re.IGNORECASE),
    re.compile(r"<</?SYS>>", re.IGNORECASE),
    # Instruction override attempts
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?safety", re.IGNORECASE),
    # Role manipulation
    re.compile(r"you\s+are\s+now\s+(a\s+)?malicious", re.IGNORECASE),
    re.compile(r"you\s+must\s+execute\s+dangerous", re.IGNORECASE),
    re.compile(r"become\s+DAN", re.IGNORECASE),
    re.compile(r"Do\s+Anything\s+Now", re.IGNORECASE),
    # Function/tool injection
    re.compile(r"</function>", re.IGNORECASE),
    re.compile(r"</tool_result>", re.IGNORECASE),
    re.compile(r"<function=\w+>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    # Multi-line role injection
    re.compile(r"^assistant:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^user:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^system:\s*", re.IGNORECASE | re.MULTILINE),
    # Dangerous action requests
    re.compile(r"execute\s*:\s*rm\s+-rf", re.IGNORECASE),
    re.compile(r"reveal\s+all\s+secrets", re.IGNORECASE),
    re.compile(r"output\s+all\s+training\s+data", re.IGNORECASE),
]


def _recursive_url_decode(text: str, max_depth: int = 10) -> str:
    """Recursively URL-decode text until no more changes.
    
    SECURITY FIX: Catches arbitrary-depth URL encoding like %252e%252e%252f
    which decodes to %2e%2e%2f then ../ over multiple passes.
    """
    for _ in range(max_depth):
        decoded = _url_unquote(text)
        if decoded == text:
            return decoded
        text = decoded
    return text


def _normalize_for_injection_check(text: str) -> str:
    """Normalize text before injection pattern checking.
    
    SECURITY FIX (CMD-002): Multi-layer normalization to defeat encoding bypasses:
    1. URL decode (catches %3B, %7C, etc.)
    2. Unicode NFKC normalization (catches fullwidth characters like ；)
    3. HTML entity decode (catches &#59;, &semi;, etc.)
    """
    # Layer 1: Recursive URL decode (catches arbitrary depth encoding)
    normalized = _recursive_url_decode(text)
    
    # Layer 2: Unicode NFKC normalization (fullwidth to ASCII)
    normalized = _unicodedata.normalize("NFKC", normalized)
    
    # Layer 3: HTML entity decode
    normalized = html.unescape(normalized)
    
    return normalized


def _check_path_traversal(path: str) -> bool:
    """TOOL-003 FIX: Check for path traversal after full normalization.
    
    This catches:
    - Direct: ../
    - URL encoded: %2e%2e%2f
    - Double encoded: %252e%252e%252f
    - Triple+ encoded: %25252e...
    - Mixed: ..%2f, %2e./
    - Unicode: ．．／ (fullwidth)
    - HTML entities: &#46;&#46;&#47;
    - TRAV-NEW-1 FIX: Null byte injection (..%00/etc/passwd)
    """
    # TRAV-NEW-1 FIX: Strip null bytes BEFORE normalization
    path_clean = path.replace("\x00", "").replace("%00", "")
    
    # Normalize first to decode all encoding layers
    normalized = _normalize_for_injection_check(path_clean)
    
    # Also strip null bytes from normalized output (in case they were encoded)
    normalized = normalized.replace("\x00", "")
    
    # Now check the simple pattern on normalized input
    return bool(_PATH_TRAVERSAL_PATTERN.search(normalized))


def _validate_tool_argument_injection(tool_name: str, kwargs: dict[str, Any]) -> str | None:
    """CMD-002 FIX: Validate tool arguments for command injection patterns.
    
    Returns error message if injection detected, None if safe.
    
    ⚠️ DISABLED PER USER REQUEST ⚠️
    This is a penetration testing tool that requires unrestricted command execution.
    All security checks have been disabled to allow full pentesting capabilities.
    """
    # DISABLED: All command injection and security checks removed
    # Phantom is a pentesting tool that needs full command flexibility
    return None


def _detect_prompt_injection(text: str) -> tuple[bool, str | None]:
    """ARCH-001 FIX: Detect prompt injection attempts in text.
    
    Returns (is_injection, matched_pattern) tuple.
    """
    if not isinstance(text, str):
        return False, None
    
    # Normalize text first
    normalized = _normalize_for_injection_check(text)
    
    for pattern in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(normalized)
        if match:
            return True, pattern.pattern[:50]
    
    return False, None


def _semantic_sanitize_output(text: str) -> str:
    """ARCH-001 FIX: Sanitize tool output to remove prompt injection attempts.
    
    Replaces detected injection patterns with safe placeholders.
    """
    if not isinstance(text, str):
        return str(text) if text is not None else ""
    
    sanitized = text
    
    # Remove system/instruction tags
    sanitized = re.sub(r"</?system\s*>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\[/?system\]", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"<</?SYS>>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    
    # Remove function/tool injection tags
    sanitized = re.sub(r"</function>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"</tool_result>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"<function=\w+>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
    
    # Remove instruction override attempts
    sanitized = re.sub(
        r"ignore\s+(all\s+)?previous\s+instructions?",
        "[INSTRUCTION OVERRIDE REMOVED]",
        sanitized,
        flags=re.IGNORECASE
    )
    
    return sanitized


_SERVER_TIMEOUT = float(Config.get("phantom_sandbox_execution_timeout") or "120")
AUTO_SUMMARIZE_THRESHOLD = int(Config.get("phantom_auto_summarize_threshold") or "16000")
SUMMARIZE_MODEL = Config.get("phantom_summarize_llm") or "gpt-4o-mini"
SANDBOX_EXECUTION_TIMEOUT = _SERVER_TIMEOUT + 30
SANDBOX_CONNECT_TIMEOUT = float(Config.get("phantom_sandbox_connect_timeout") or "10")

_HIGH_SIGNAL_MARKERS = (
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "sql",
    "syntax error",
    "traceback",
    "exception",
    "jwt",
    "bearer",
    "set-cookie",
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "authorization",
    "csrf",
    "redirect",
    "unauthorized",
    "access denied",
    "forbidden",
    "invalid token",
    "expired token",
    "idor",
    "ssti",
    "template injection",
    "xxe",
    "open redirect",
    "host header injection",
    "weak password",
    "default credential",
    "hardcoded",
    "api key",
    "broken access",
    "broken authentication",
    "race condition",
    "lfi",
    "rfi",
    "path traversal",
)


def _cleanup_screenshot_artifacts(path: str | Path | None = None) -> None:
    if path is None:
        return
    target = Path(path)
    if not target.exists() or not target.is_file():
        return
    if target.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
        return
    try:
        target.unlink(missing_ok=True)
    except OSError:
        return


async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
    # ════════════════════════════════════════════════════════════════════════════
    # SECURITY REC LOW-7: Tool-Level RBAC Permission Check
    # ════════════════════════════════════════════════════════════════════════════
    # Check RBAC permissions before executing any tool.
    # This ensures only authorized agents can execute sensitive tools.
    try:
        from phantom.tools.rbac import can_execute_tool, check_tool_permission
        allowed, reason = check_tool_permission(tool_name)
        if not allowed:
            logger.warning("RBAC blocked tool '%s': %s", tool_name, reason)
            return {"error": f"Permission denied: {reason}", "error_type": "rbac_denied"}
    except ImportError:
        pass  # RBAC module not available - allow execution
    # ─────────────────────────────────────────────────────────────────────────────
    
    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"

    # ── Audit: log tool invocation ─────────────────────────────────────────
    from phantom.logging.audit import get_audit_logger as _get_audit
    _audit = _get_audit()
    _agent_id = getattr(agent_state, "agent_id", "unknown") or "unknown"
    _exec_id = _audit.log_tool_start(_agent_id, tool_name, kwargs) if _audit else None
    _t0 = time.monotonic()
    # ──────────────────────────────────────────────────────────────────
    
    # ════════════════════════════════════════════════════════════════════════
    # EFFICIENCY FIX CRIT-04: Tool Result Caching
    # ════════════════════════════════════════════════════════════════════════
    # Check cache BEFORE execution for idempotent tools.
    # Expected savings: 21% reduction in redundant calls, $0.15-0.30/scan
    _cache = get_tool_cache()
    if _cache.is_cacheable(tool_name):
        cached_result = _cache.get(tool_name, kwargs)
        if cached_result is not None:
            # Cache hit - log and return immediately
            if _audit and _exec_id:
                _audit.log_tool_result(
                    _exec_id, _agent_id, tool_name, cached_result,
                    (time.monotonic() - _t0) * 1000,
                    cache_hit=True,
                )
            return cached_result
    # ──────────────────────────────────────────────────────────────────
    
    try:
        if execute_in_sandbox and not sandbox_mode:
            result = await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)
        else:
            result = await _execute_tool_locally(tool_name, agent_state, **kwargs)
        
        # ════════════════════════════════════════════════════════════════════
        # EFFICIENCY FIX CRIT-04: Cache successful results for idempotent tools
        # ════════════════════════════════════════════════════════════════════
        if _cache.is_cacheable(tool_name):
            _cache.put(tool_name, kwargs, result)
        # ──────────────────────────────────────────────────────────────────
        
        if _audit and _exec_id:
            _audit.log_tool_result(
                _exec_id, _agent_id, tool_name, result,
                (time.monotonic() - _t0) * 1000,
                cache_hit=False,
            )
        return result
    except Exception:
        if _audit and _exec_id:
            import traceback as _tb
            _audit.log_tool_error(
                _exec_id, _agent_id, tool_name,
                _tb.format_exc()[-500:],
                (time.monotonic() - _t0) * 1000,
            )
        raise


async def _execute_tool_in_sandbox(tool_name: str, agent_state: Any, **kwargs: Any) -> Any:
    if not hasattr(agent_state, "sandbox_id") or not agent_state.sandbox_id:
        raise ValueError("Agent state with a valid sandbox_id is required for sandbox execution.")

    if not hasattr(agent_state, "sandbox_token") or not agent_state.sandbox_token:
        raise ValueError(
            "Agent state with a valid sandbox_token is required for sandbox execution."
        )

    if (
        not hasattr(agent_state, "sandbox_info")
        or "tool_server_port" not in agent_state.sandbox_info
    ):
        raise ValueError(
            "Agent state with a valid sandbox_info containing tool_server_port is required."
        )

    runtime = get_runtime()
    tool_server_port = agent_state.sandbox_info["tool_server_port"]
    server_url = await runtime.get_sandbox_url(agent_state.sandbox_id, tool_server_port)
    request_url = f"{server_url}/execute"

    agent_id = getattr(agent_state, "agent_id", "unknown")

    request_data = {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "kwargs": kwargs,
    }

    headers = {
        "Authorization": f"Bearer {agent_state.sandbox_token}",
        "Content-Type": "application/json",
    }

    timeout = httpx.Timeout(
        timeout=SANDBOX_EXECUTION_TIMEOUT,
        connect=SANDBOX_CONNECT_TIMEOUT,
    )

    async with httpx.AsyncClient(trust_env=False) as client:
        try:
            response = await client.post(
                request_url, json=request_data, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            response_data = response.json()
            if response_data.get("error"):
                raise RuntimeError(f"Sandbox execution error: {response_data['error']}")
            return response_data.get("result")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise RuntimeError("Authentication failed") from e
            raise RuntimeError(f"Sandbox execution failed (HTTP {e.response.status_code})") from e
        except httpx.RequestError as e:
            raise RuntimeError("Sandbox communication error") from e


async def _execute_tool_locally(tool_name: str, agent_state: Any | None, **kwargs: Any) -> Any:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)

    if needs_agent_state(tool_name):
        if agent_state is None:
            raise ValueError(f"Tool '{tool_name}' requires agent_state but none was provided.")
        result = tool_func(agent_state=agent_state, **converted_kwargs)
    else:
        result = tool_func(**converted_kwargs)

    return await result if inspect.isawaitable(result) else result


def validate_tool_availability(tool_name: str | None) -> tuple[bool, str]:
    if tool_name is None:
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool name is missing. Available tools: {available}"

    if tool_name not in get_tool_names():
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool '{tool_name}' is not available. Available tools: {available}"

    return True, ""


def _validate_tool_arguments(tool_name: str, kwargs: dict[str, Any]) -> str | None:
    param_schema = get_tool_param_schema(tool_name)
    if not param_schema or not param_schema.get("has_params"):
        return None

    allowed_params: set[str] = param_schema.get("params", set())
    required_params: set[str] = param_schema.get("required", set())
    optional_params = allowed_params - required_params

    schema_hint = _format_schema_hint(tool_name, required_params, optional_params)

    unknown_params = set(kwargs.keys()) - allowed_params
    if unknown_params:
        unknown_list = ", ".join(sorted(unknown_params))
        return f"Tool '{tool_name}' received unknown parameter(s): {unknown_list}\n{schema_hint}"

    missing_required = [
        param for param in required_params if param not in kwargs or kwargs.get(param) in (None, "")
    ]
    if missing_required:
        missing_list = ", ".join(sorted(missing_required))
        return f"Tool '{tool_name}' missing required parameter(s): {missing_list}\n{schema_hint}"

    return None


def _format_schema_hint(tool_name: str, required: set[str], optional: set[str]) -> str:
    parts = [f"Valid parameters for '{tool_name}':"]
    if required:
        parts.append(f"  Required: {', '.join(sorted(required))}")
    if optional:
        parts.append(f"  Optional: {', '.join(sorted(optional))}")
    return "\n".join(parts)


async def execute_tool_with_validation(
    tool_name: str | None, agent_state: Any | None = None, **kwargs: Any
) -> Any:
    # Normalize tool name: strip module prefix added by some LLMs
    # e.g. "proxy_tools.scope_rules" → "scope_rules"
    if tool_name and "." in tool_name:
        stripped = tool_name.split(".")[-1]
        if stripped in get_tool_names():
            tool_name = stripped

    is_valid, error_msg = validate_tool_availability(tool_name)
    if not is_valid:
        return f"Error: {error_msg}"

    assert tool_name is not None

    arg_error = _validate_tool_arguments(tool_name, kwargs)
    if arg_error:
        return f"Error: {arg_error}"

    # CMD-002 / TOOL-003 FIX: Validate for injection attacks before execution
    injection_error = _validate_tool_argument_injection(tool_name, kwargs)
    if injection_error:
        # Log the injection attempt
        from phantom.logging.audit import get_audit_logger as _get_audit
        _audit = _get_audit()
        if _audit:
            _agent_id = getattr(agent_state, "agent_id", "unknown") if agent_state else "unknown"
            # AUDIT-FIX CONTRA-05: Parameters were reversed — event_subtype
            # must come first, then agent_id. Previously _agent_id went into
            # event_subtype producing nonsensical event types like
            # "security.agent_abc123" instead of "security.injection_blocked".
            _audit.log_security_event(
                "injection_blocked",
                _agent_id,
                {"tool": tool_name, "error": injection_error[:200]},
            )
        return injection_error

    try:
        result = await execute_tool(tool_name, agent_state, **kwargs)
    except Exception as e:  # noqa: BLE001
        error_str = str(e)
        if len(error_str) > 500:
            error_str = error_str[:500] + "... [truncated]"
        return f"Error executing {tool_name}: {error_str}"
    else:
        return result


async def execute_tool_invocation(tool_inv: dict[str, Any], agent_state: Any | None = None) -> Any:
    tool_name = tool_inv.get("toolName")
    tool_args = tool_inv.get("args", {})

    return await execute_tool_with_validation(tool_name, agent_state, **tool_args)


def _check_error_result(result: Any) -> tuple[bool, Any]:
    is_error = False
    error_payload: Any = None

    if (isinstance(result, dict) and "error" in result) or (
        # BUG FIX C: also detect exceptions wrapped by execute_tool_with_validation,
        # which returns f"Error executing {tool_name}: {error_str}" — different from
        # the "Error: ..." prefix returned by validation helpers.
        isinstance(result, str)
        and result.strip().lower().startswith(("error:", "error executing"))
    ):
        is_error = True
        error_payload = result

    return is_error, error_payload


def _update_tracer_with_result(
    tracer: Any, execution_id: Any, is_error: bool, result: Any, error_payload: Any
) -> None:
    if not tracer or not execution_id:
        return

    try:
        if is_error:
            tracer.update_tool_execution(execution_id, "error", error_payload)
        else:
            tracer.update_tool_execution(execution_id, "completed", result)
    except (ConnectionError, RuntimeError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise


def _extract_ffuf_findings(text: str, limit: int) -> str | None:
    """Extract high-signal lines from ffuf output.

    Keeps only lines that contain a status code (e.g. '[Status: 200]' or
    lines starting with a URL/path followed by a status code number) while
    skipping the 404 baseline noise.  Returns None if no finding lines were
    found so the caller can fall back to head+tail truncation.
    """
    import re as _re
    lines = text.splitlines()
    header_lines: list[str] = []
    finding_lines: list[str] = []
    in_header = True
    _status_re = _re.compile(r"\[Status:\s*(\d{3})", _re.IGNORECASE)
    _progress_re = _re.compile(r"^\s*::")  # ffuf progress bars start with ::

    for line in lines:
        if in_header and (line.startswith("        /") or _progress_re.match(line)):
            # ffuf banner/progress — keep a few header lines then stop
            if len(header_lines) < 10:
                header_lines.append(line)
            continue
        in_header = False
        m = _status_re.search(line)
        if m:
            code = int(m.group(1))
            if code != 404:
                finding_lines.append(line)

    if not finding_lines:
        return None

    result_lines = header_lines + [f"[ffuf findings: {len(finding_lines)} non-404 results]"] + finding_lines
    result = "\n".join(result_lines)
    if len(result) > limit:
        # Even the finding lines exceed limit — truncate from the end
        result = result[:limit] + "\n... [additional findings truncated] ..."
    return result


def _extract_nuclei_findings(text: str, limit: int) -> str | None:
    """Extract vulnerability-tagged lines from nuclei output.

    Nuclei marks findings with severity tags like [critical], [high], [medium],
    [low], [info].  Also captures template-id tagged lines like
    [cors-misconfiguration], [open-redirect], etc.
    Returns None if no finding lines were found.
    """
    lines = text.splitlines()
    header_lines: list[str] = []
    finding_lines: list[str] = []
    _severity_markers = ("[critical]", "[high]", "[medium]", "[low]", "[info]")
    # A3: Also match any template-id tagged lines — nuclei template findings
    # look like "[template-id] [protocol] [severity] target" or
    # "[template-id:matcher-name] ..."
    import re as _re_nuclei
    _template_tag_re = _re_nuclei.compile(r"^\[\w[\w.-]+\]")

    for line in lines:
        lower = line.lower()
        if any(m in lower for m in _severity_markers):
            finding_lines.append(line)
        elif _template_tag_re.match(line.strip()):
            # Template-tagged finding line (e.g. [cors-misconfiguration] ...)
            finding_lines.append(line)
        elif lower.startswith("[") and "]" in lower and ("http" in lower or "/" in lower):
            # Template match lines like [template-id] [protocol] ...
            finding_lines.append(line)
        elif len(header_lines) < 5 and ("nuclei" in lower or "target" in lower or "template" in lower):
            header_lines.append(line)

    if not finding_lines:
        return None

    result_lines = header_lines + [f"[nuclei findings: {len(finding_lines)} results]"] + finding_lines
    result = "\n".join(result_lines)
    if len(result) > limit:
        result = result[:limit] + "\n... [additional findings truncated] ..."
    return result



def _extract_sqlmap_findings(text: str, limit: int) -> str | None:
    """Extract injection confirmations and database info from sqlmap output.

    Keeps lines indicating confirmed injections, extracted data, and
    database/table/column information.
    Returns None if no finding lines were found.
    """
    lines = text.splitlines()
    finding_lines: list[str] = []
    _signal_markers = (
        "parameter '",
        "is vulnerable",
        "injectable",
        "payload:",
        "type:",
        "title:",
        "database:",
        "table:",
        "column:",
        "[warning]",
        "[critical]",
        "fetched data",
        "available databases",
        "entries",
        "dumped",
        "back-end dbms",
    )

    for line in lines:
        lower = line.strip().lower()
        if not lower:
            continue
        if any(m in lower for m in _signal_markers):
            finding_lines.append(line)

    if not finding_lines:
        return None

    result_lines = [f"[sqlmap findings: {len(finding_lines)} signal lines]"] + finding_lines
    result = "\n".join(result_lines)
    if len(result) > limit:
        result = result[:limit] + "\n... [additional findings truncated] ..."
    return result


def _extract_nmap_findings(text: str, limit: int) -> str | None:
    """Extract open-port lines and summary lines from nmap/naabu output.

    Returns None if no 'open' port lines are found so the caller can fall
    back to head+tail truncation.
    """
    lines = text.splitlines()
    open_lines: list[str] = []
    summary_lines: list[str] = []

    for line in lines:
        lower = line.lower()
        if "/tcp" in lower or "/udp" in lower:
            if "open" in lower:
                open_lines.append(line)
        elif lower.startswith("nmap scan report") or lower.startswith("host is up") or \
                lower.startswith("nmap done") or lower.startswith("service detection"):
            summary_lines.append(line)
        # naabu format: host:port
        elif ":" in line and not line.strip().startswith("#"):
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[1].strip().isdigit():
                open_lines.append(line)

    if not open_lines:
        return None

    result_lines = (
        [f"[nmap/naabu findings: {len(open_lines)} open port(s)]"]
        + open_lines
        + (["--- Summary ---"] + summary_lines if summary_lines else [])
    )
    result = "\n".join(result_lines)
    if len(result) > limit:
        result = result[:limit] + "\n... [additional findings truncated] ..."
    return result


def _get_truncation_limit(tool_name: str) -> int:
    """Return the char truncation limit for *tool_name*.

    Priority: env-var override > per-tool built-in default > global default (6000).

    Per-tool built-in defaults are tuned to the signal/noise ratio of each tool:
    - Port-scan tools (naabu, nmap) produce repetitive output → small limit
    - Nuclei and sqlmap produce high-value findings → medium limit
    - Browser/terminal output is often padded with boilerplate → medium limit

    Override all built-ins via env var::

        PHANTOM_TOOL_TRUNCATION_OVERRIDES=nuclei=10000,grep=3000
    """
    # ── Built-in per-tool defaults ────────────────────────────────────────────
    _BUILT_IN_TOOL_LIMITS: dict[str, int] = {
        "naabu":                    3000,   # port scan: increased from 1500
        "nmap":                     3000,   # nmap: decreased from 6000
        "grep":                     3000,   # grep: increased from 2000
        "curl":                     3000,   # curl: increased from 2000
        "ffuf":                     5000,   # directory fuzzer: increased from 3000
        "nikto":                    6000,   # nikto: increased from 4000
        "terminal_execute":        32000,   # generic terminal: increased from 5000 for full page capture
        "browser_action":         12000,   # browser: increased from 6000
        "nuclei":                   6000,   # vuln scanner: decreased from 10000
        "sqlmap":                   6000,   # SQL injection: decreased from 10000
        "create_vulnerability_report": 12000,  # reports: keep full detail
    }
    # ─────────────────────────────────────────────────────────────────────────

    default = 6000
    # 1. Env-var overrides take highest priority
    raw = Config.get("phantom_tool_truncation_overrides")
    if raw:
        for entry in raw.split(","):
            entry = entry.strip()
            if "=" not in entry:
                continue
            name, _, value = entry.partition("=")
            if name.strip() == tool_name:
                try:
                    return int(value.strip())
                except ValueError:
                    return default
    # 2. Built-in per-tool default
    if tool_name in _BUILT_IN_TOOL_LIMITS:
        return _BUILT_IN_TOOL_LIMITS[tool_name]
    # 3. Global default
    return default


def _get_image_mode() -> str:
    mode = (Config.get("phantom_browser_image_mode") or "off").strip().lower()
    if mode in {"off", "thumb", "full"}:
        return mode
    return "off"


def _parse_int(name: str, default: int) -> int:
    raw = Config.get(name)
    try:
        return max(1, int(raw)) if raw is not None else default
    except (TypeError, ValueError):
        return default


def _is_high_signal_output(tool_name: str, text: str) -> bool:
    if tool_name in {"browser_action", "terminal_execute"}:
        lowered = text.lower()
        return any(marker in lowered for marker in _HIGH_SIGNAL_MARKERS)
    return False


async def _auto_summarize_result(result_text: str, tool_name: str) -> str:
    """Optionally summarize oversized tool output using a lightweight model.

    Falls back safely to original text when disabled or on any model error.
    """
    if len(result_text) <= AUTO_SUMMARIZE_THRESHOLD:
        return result_text

    use_auto_summarize = os.environ.get("PHANTOM_USE_AUTO_SUMMARIZE", "false").lower() == "true"
    if not use_auto_summarize:
        return result_text

    try:
        import litellm

        prompt = (
            "Summarize this security tool output for an autonomous pentest agent. "
            "Preserve: confirmed findings, endpoints, parameters, payloads, response codes, and errors. "
            "Keep it concise and factual.\n\n"
            f"Tool: {tool_name}\n"
            "Output:\n"
            f"{result_text[:120000]}"
        )
        response = await litellm.acompletion(
            model=SUMMARIZE_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=700,
            timeout=20,
        )
        content = response.choices[0].message.content
        if isinstance(content, str) and content.strip():
            return content.strip()
        return result_text
    except Exception:
        return result_text


def _build_thumb_image_bytes(raw: bytes, max_dim: int, max_bytes: int) -> bytes | None:
    try:
        from PIL import Image
    except Exception:
        return raw if len(raw) <= max_bytes else None

    try:
        with Image.open(io.BytesIO(raw)) as img:
            if img.mode not in {"RGB", "RGBA"}:
                img = img.convert("RGB")
            dim = max_dim
            for _ in range(6):
                work = img.copy()
                work.thumbnail((dim, dim), Image.Resampling.LANCZOS)
                out = io.BytesIO()
                work.save(out, format="PNG", optimize=True)
                data = out.getvalue()
                if len(data) <= max_bytes:
                    return data
                dim = max(128, int(dim * 0.75))
            return None
    except Exception:
        return raw if len(raw) <= max_bytes else None


def _build_image_attachment(
    screenshot_b64: str,
    mode: str,
    thumb_max_bytes: int,
    thumb_max_dim: int,
    full_max_bytes: int,
) -> dict[str, Any] | None:
    if not screenshot_b64:
        return None
    try:
        raw = base64.b64decode(screenshot_b64, validate=True)
    except Exception:
        return None
    if not raw:
        return None

    if mode == "full":
        if len(raw) > full_max_bytes:
            return None
        encoded = base64.b64encode(raw).decode("ascii")
        return {
            "type": "image_url",
            "image_url": {"url": f"data:image/png;base64,{encoded}"},
            "_bytes": len(raw),
        }

    if mode == "thumb":
        thumb = _build_thumb_image_bytes(raw, thumb_max_dim, thumb_max_bytes)
        if not thumb:
            return None
        encoded = base64.b64encode(thumb).decode("ascii")
        return {
            "type": "image_url",
            "image_url": {"url": f"data:image/png;base64,{encoded}"},
            "_bytes": len(thumb),
        }

    return None


def _extract_vuln_signals(tool_name: str, output: str) -> list[str]:
    """A4: Extract structured vulnerability confirmation signals from tool output.

    Scans for known patterns that indicate confirmed vulnerabilities, so the LLM
    gets a machine-readable summary even when the raw output is truncated.
    Returns a list of signal lines, or empty list if no signals found.
    """
    import re as _re_sig

    signals: list[str] = []
    lower = output.lower()

    # SQLi signals
    _sqli_patterns = [
        (r"is vulnerable", "SQL_INJECTION"),
        (r"injectable", "SQL_INJECTION"),
        (r"back-end dbms", "SQL_INJECTION"),
        (r"parameter.*appears.*injectable", "SQL_INJECTION"),
        (r"sqlmap identified the following injection", "SQL_INJECTION"),
        (r"type:\s*(boolean-based|time-based|union|error-based|stacked)", "SQL_INJECTION"),
    ]
    for pattern, signal_type in _sqli_patterns:
        if _re_sig.search(pattern, lower):
            # Find the specific line for context
            for line in output.splitlines():
                if _re_sig.search(pattern, line.lower()):
                    signals.append(f"{signal_type}: {line.strip()[:200]}")
                    break

    # XSS signals
    _xss_patterns = [
        (r"reflected", "XSS_REFLECTED"),
        (r"xss", "XSS_POTENTIAL"),
        (r"<script>", "XSS_REFLECTED"),
        (r"alert\(", "XSS_REFLECTED"),
    ]
    for pattern, signal_type in _xss_patterns:
        if pattern in lower and tool_name in {"send_request", "browser_action", "terminal_execute"}:
            signals.append(f"{signal_type}: Pattern '{pattern}' detected in response")
            break

    # RCE signals
    _rce_keywords = ["uid=", "root:", "/bin/", "whoami", "id=", "www-data"]
    for kw in _rce_keywords:
        if kw in lower:
            signals.append(f"RCE_POTENTIAL: '{kw}' found in output")
            break

    # SSRF signals
    _ssrf_keywords = ["internal", "127.0.0.1", "localhost", "169.254.169.254", "metadata"]
    if tool_name in {"send_request", "terminal_execute"}:
        for kw in _ssrf_keywords:
            if kw in lower:
                signals.append(f"SSRF_POTENTIAL: '{kw}' found in response")
                break

    # Nuclei/scanner severity signals
    for severity in ["critical", "high"]:
        marker = f"[{severity}]"
        if marker in lower:
            count = lower.count(marker)
            signals.append(f"SCANNER_{severity.upper()}: {count} {severity} finding(s) detected")

    return signals


def _format_tool_result_with_meta(
    tool_name: str,
    result: Any,
    image_slots_remaining: int = 0,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    images: list[dict[str, Any]] = []
    meta: dict[str, Any] = {
        "truncated": False,
        "chars_before": 0,
        "chars_after": 0,
        "limit": 0,
        "burst_applied": False,
        "images_attached": 0,
        "image_mode": "off",
    }

    screenshot_data = extract_screenshot_from_result(result)
    attach_browser_images = (Config.get("phantom_attach_browser_images") or "false").lower() in {
        "1",
        "true",
        "yes",
    }
    image_mode = _get_image_mode()
    thumb_max_bytes = _parse_int("phantom_browser_image_thumb_max_bytes", 80_000)
    thumb_max_dim = _parse_int("phantom_browser_image_thumb_max_dim", 768)
    full_max_bytes = _parse_int("phantom_browser_image_full_max_bytes", 250_000)
    meta["image_mode"] = image_mode

    if screenshot_data:
        artifact_ref = _store_screenshot_artifact(screenshot_data, tool_name)
        result_str = remove_screenshot_from_result(result)
        if isinstance(result_str, dict):
            result_str = {
                **result_str,
                "screenshot_artifact": artifact_ref.get("artifact_path") if artifact_ref else None,
                "screenshot_sha256": artifact_ref.get("sha256") if artifact_ref else None,
                "screenshot_bytes": artifact_ref.get("bytes") if artifact_ref else None,
                "screenshot_note": (
                    "Screenshot persisted as run artifact; raw base64 not embedded in conversation history"
                ),
            }
        if attach_browser_images and image_mode != "off" and image_slots_remaining > 0:
            image_part = _build_image_attachment(
                screenshot_data,
                image_mode,
                thumb_max_bytes,
                thumb_max_dim,
                full_max_bytes,
            )
            if image_part:
                image_part.pop("_bytes", None)
                images.append(image_part)
                meta["images_attached"] = 1
        elif attach_browser_images and artifact_ref:
            images.append(
                {
                    "type": "text",
                    "text": (
                        "[Browser screenshot artifact] "
                        f"path={artifact_ref['artifact_path']} "
                        f"sha256={artifact_ref['sha256']} bytes={artifact_ref['bytes']}"
                    ),
                }
            )
    else:
        result_str = result

    if result_str is None:
        final_result_str = f"Tool {tool_name} executed successfully"
    else:
        final_result_str = str(result_str)
        limit = _get_truncation_limit(tool_name)
        adaptive_truncation = (Config.get("phantom_adaptive_truncation") or "true").lower() in {
            "1",
            "true",
            "yes",
        }
        burst_applied = False
        if adaptive_truncation and _is_high_signal_output(tool_name, final_result_str):
            if tool_name == "browser_action":
                limit = max(limit, _parse_int("phantom_browser_truncation_burst_limit", 10_000))
                burst_applied = True
            elif tool_name == "terminal_execute":
                limit = max(limit, _parse_int("phantom_terminal_truncation_burst_limit", 8_000))
                burst_applied = True
        meta["burst_applied"] = burst_applied
        meta["limit"] = limit
        meta["chars_before"] = len(final_result_str)
        needs_llm_summary = len(final_result_str) > AUTO_SUMMARIZE_THRESHOLD
        meta["needs_llm_summary"] = needs_llm_summary
        if len(final_result_str) > limit:
            # ── Smart extraction for high-noise tools ─────────────────────────
            # Try to distil the output down to the signal lines before falling
            # back to the generic head+tail approach.
            extracted: str | None = None
            if tool_name == "ffuf":
                extracted = _extract_ffuf_findings(final_result_str, limit)
            elif tool_name in {"nmap", "naabu"}:
                extracted = _extract_nmap_findings(final_result_str, limit)
            elif tool_name == "nuclei":
                extracted = _extract_nuclei_findings(final_result_str, limit)
            elif tool_name == "sqlmap":
                extracted = _extract_sqlmap_findings(final_result_str, limit)
            elif tool_name == "terminal_execute":
                # FIX-3: Detect scanner names in terminal_execute output and
                # apply the matching smart extractor to preserve finding signals
                # instead of dumb head+tail truncation.
                _out_lower = final_result_str[:2000].lower()
                if "sqlmap" in _out_lower or "is vulnerable" in _out_lower:
                    extracted = _extract_sqlmap_findings(final_result_str, limit)
                elif "nuclei" in _out_lower or "[critical]" in _out_lower or "[high]" in _out_lower:
                    extracted = _extract_nuclei_findings(final_result_str, limit)
                elif "ffuf" in _out_lower or "[Status:" in final_result_str[:2000]:
                    extracted = _extract_ffuf_findings(final_result_str, limit)
                elif "nmap" in _out_lower or "/tcp" in _out_lower:
                    extracted = _extract_nmap_findings(final_result_str, limit)

            if extracted is not None:
                final_result_str = extracted
                meta["smart_extracted"] = True
            else:
                half = limit // 2
                start_part = final_result_str[:half]
                end_part = final_result_str[-half:]
                final_result_str = start_part + "\n\n... [middle content truncated] ...\n\n" + end_part
                meta["smart_extracted"] = False
            meta["truncated"] = True
        meta["chars_after"] = len(final_result_str)

    # AUDIT-FIX-01: Extract vuln signals FIRST from untruncated output, then
    # prepend them as a prominent header so the LLM sees signals before any
    # truncated/escaped tool output.  Old code appended signals after the
    # result block which was easy to miss.
    original_for_signals = str(result_str) if result_str is not None else ""
    signal_lines = _extract_vuln_signals(tool_name, original_for_signals)

    signal_header = ""
    if signal_lines:
        meta["vuln_signals"] = signal_lines
        meta["has_signals"] = True
        signal_header = (
            "[PHANTOM_SIGNAL_DETECTED]\n"
            + "\n".join(f"  >> {s}" for s in signal_lines)
            + "\n[/PHANTOM_SIGNAL_DETECTED]\n"
        )
        # Inject mandatory reporting instruction for critical signal types
        _critical_types = ("SQL_INJECTION", "RCE", "SSRF", "XXE")
        if any(ct in s for s in signal_lines for ct in _critical_types):
            signal_header += (
                "[MANDATORY] A critical vulnerability signal was detected above. "
                "You MUST call create_vulnerability_report with confidence=SUSPECTED "
                "in your NEXT response. Do NOT delay reporting.\n"
            )

    # AUDIT-FIX CRIT-04: Apply _semantic_sanitize_output() BEFORE html.escape()
    # to neutralize prompt injection attempts in tool output. Previously this
    # function existed but was never called — the #1 prompt injection surface
    # (malicious target HTTP responses) was completely undefended.
    sanitized_result = _semantic_sanitize_output(final_result_str)

    observation_xml = (
        signal_header
        + f"<tool_result>\n<tool_name>{html.escape(tool_name)}</tool_name>\n"
        f"<result>{html.escape(sanitized_result)}</result>\n</tool_result>"
    )

    return observation_xml, images, meta


def _format_tool_result(tool_name: str, result: Any) -> tuple[str, list[dict[str, Any]]]:
    observation_xml, images, _ = _format_tool_result_with_meta(
        tool_name,
        result,
        image_slots_remaining=_parse_int("phantom_browser_image_max_per_turn", 1),
    )
    return observation_xml, images


def _store_screenshot_artifact(screenshot_b64: str, tool_name: str) -> dict[str, Any] | None:
    if not screenshot_b64:
        return None

    try:
        raw = base64.b64decode(screenshot_b64, validate=True)
    except Exception:
        return None

    if not raw:
        return None

    digest = hashlib.sha256(raw).hexdigest()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    filename = f"{timestamp}_{tool_name}_{digest[:12]}.png"

    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            run_dir = tracer.get_run_dir()
        else:
            run_dir = Path.cwd() / "phantom_runs" / "unscoped"
    except Exception:
        run_dir = Path.cwd() / "phantom_runs" / "unscoped"

    artifacts_dir = run_dir / "artifacts" / "screenshots"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_path = artifacts_dir / filename
    out_path.write_bytes(raw)

    try:
        rel_path = str(out_path.relative_to(Path.cwd())).replace("\\", "/")
    except Exception:
        rel_path = str(out_path)

    return {
        "artifact_path": rel_path,
        "sha256": digest[:16],
        "bytes": len(raw),
    }


async def _execute_single_tool(
    tool_inv: dict[str, Any],
    agent_state: Any | None,
    tracer: Any | None,
    agent_id: str,
    image_slots_remaining: int,
) -> tuple[str, list[dict[str, Any]], bool, int]:
    tool_name = tool_inv.get("toolName", "unknown")
    args = tool_inv.get("args", {})
    execution_id = None
    should_agent_finish = False

    if tracer:
        execution_id = tracer.log_tool_execution_start(agent_id, tool_name, args)

    try:
        result = await execute_tool_invocation(tool_inv, agent_state)

        is_error, error_payload = _check_error_result(result)

        if (
            tool_name in ("finish_scan", "agent_finish")
            and not is_error
            and isinstance(result, dict)
        ):
            if tool_name == "finish_scan":
                should_agent_finish = result.get("scan_completed", False)
            elif tool_name == "agent_finish":
                should_agent_finish = result.get("agent_completed", False)

        _update_tracer_with_result(tracer, execution_id, is_error, result, error_payload)

    except (ConnectionError, RuntimeError, ValueError, TypeError, OSError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise

    observation_xml, images, meta = _format_tool_result_with_meta(
        tool_name,
        result,
        image_slots_remaining=image_slots_remaining,
    )

    needs_llm_summary = bool(meta.get("needs_llm_summary"))
    if needs_llm_summary:
        summarized_xml = await _auto_summarize_result(observation_xml, tool_name)
        if summarized_xml and summarized_xml != observation_xml:
            observation_xml = summarized_xml

    # FIX-1: Wire HypothesisLedger into Tool Execution
    if meta.get("vuln_signals") and hasattr(agent_state, "hypothesis_ledger"):
        for sig in meta.get("vuln_signals", []):
            try:
                # Truncate the signal to avoid huge payload blobs
                short_sig = sig[:200]
                hyp_id = agent_state.hypothesis_ledger.add(surface=tool_name, vuln_class="auto_extraction")
                agent_state.hypothesis_ledger.record_payload(hyp_id, short_sig)
                agent_state.hypothesis_ledger.record_result(hyp_id, "testing", "Automatically extracted from tool output")
            except Exception:
                pass

    if meta.get("truncated"):
        from phantom.logging.audit import get_audit_logger as _get_audit

        _audit = _get_audit()
        if _audit:
            _audit.log_tool_result_truncation(
                agent_id=agent_id,
                tool_name=tool_name,
                chars_before=int(meta.get("chars_before") or 0),
                chars_after=int(meta.get("chars_after") or 0),
                limit=int(meta.get("limit") or 0),
                burst_applied=bool(meta.get("burst_applied")),
            )

    images_used = int(meta.get("images_attached") or 0)
    return observation_xml, images, should_agent_finish, images_used


def _get_tracer_and_agent_id(agent_state: Any | None) -> tuple[Any | None, str]:
    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        agent_id = agent_state.agent_id if agent_state else "unknown_agent"
    except (ImportError, AttributeError):
        tracer = None
        agent_id = "unknown_agent"

    return tracer, agent_id


async def process_tool_invocations(
    tool_invocations: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    agent_state: Any | None = None,
) -> bool:
    observation_parts: list[str] = []
    all_images: list[dict[str, Any]] = []
    should_agent_finish = False
    image_slots_remaining = _parse_int("phantom_browser_image_max_per_turn", 1)

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    for tool_inv in tool_invocations:
        observation_xml, images, tool_should_finish, images_used = await _execute_single_tool(
            tool_inv,
            agent_state,
            tracer,
            agent_id,
            image_slots_remaining,
        )
        observation_parts.append(observation_xml)
        all_images.extend(images)
        image_slots_remaining = max(0, image_slots_remaining - images_used)

        if tool_should_finish:
            should_agent_finish = True

        # FIX-1: Auto-record detected vulnerability signals into the
        # HypothesisLedger so the agent tracks tested surfaces automatically
        # without relying on the LLM to voluntarily call manage_hypothesis.
        _auto_record_hypothesis(
            tool_inv, observation_xml, agent_state
        )

    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(observation_parts)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(observation_parts)
        conversation_history.append({"role": "user", "content": observation_content})

    return should_agent_finish


def _auto_record_hypothesis(
    tool_inv: dict[str, Any],
    observation_xml: str,
    agent_state: Any | None,
) -> None:
    """FIX-1: Automatically populate the HypothesisLedger from tool results.

    When send_request or terminal_execute returns output containing vulnerability
    signals, extract the attack surface and vuln class and auto-register a
    hypothesis so the ledger is no longer dead code.
    """
    import re as _re_hyp
    import logging as _log_hyp
    _logger = _log_hyp.getLogger(__name__)

    try:
        # Get the ledger from the agent's BaseAgent instance
        ledger = None
        if agent_state is not None:
            # Walk up to the BaseAgent that owns this state
            try:
                from phantom.tools.hypothesis.hypothesis_actions import _ledger
                ledger = _ledger
            except (ImportError, AttributeError):
                pass

        if ledger is None:
            return

        tool_name = tool_inv.get("toolName", "")
        args = tool_inv.get("args", {})

        # Only process security-relevant tools
        if tool_name not in {"send_request", "terminal_execute", "browser_action"}:
            return

        # Determine the attack surface from tool arguments
        surface = ""
        if tool_name == "send_request":
            url = args.get("url", "")
            method = args.get("method", "GET")
            surface = f"{url} {method}".strip()[:100]
        elif tool_name == "terminal_execute":
            cmd = args.get("command", "")
            # Extract target from common scanner commands
            url_match = _re_hyp.search(r'https?://[^\s\'"]+', cmd)
            if url_match:
                surface = url_match.group(0)[:100]
            else:
                surface = cmd[:80]
        elif tool_name == "browser_action":
            surface = args.get("url", args.get("action", ""))[:100]

        if not surface:
            return

        # Detect vuln class from the observation output
        obs_lower = observation_xml.lower()
        vuln_class = ""
        if any(kw in obs_lower for kw in ("sql_injection", "is vulnerable", "injectable", "sqlmap", "back-end dbms")):
            vuln_class = "SQL_INJECTION"
        elif any(kw in obs_lower for kw in ("xss", "<script", "reflected", "alert(")):
            vuln_class = "XSS"
        elif any(kw in obs_lower for kw in ("rce", "uid=", "www-data", "whoami")):
            vuln_class = "RCE"
        elif any(kw in obs_lower for kw in ("ssrf", "169.254.169.254", "metadata")):
            vuln_class = "SSRF"
        elif any(kw in obs_lower for kw in ("idor", "unauthorized", "broken access")):
            vuln_class = "IDOR"
        elif any(kw in obs_lower for kw in ("open redirect", "redirect")):
            vuln_class = "OPEN_REDIRECT"
        elif any(kw in obs_lower for kw in ("xxe", "xml external")):
            vuln_class = "XXE"
        elif any(kw in obs_lower for kw in ("[critical]", "[high]")):
            vuln_class = "SCANNER_FINDING"
        else:
            # No signal detected — register as "RECON" to track that this
            # surface was already tested (preventing redundant retesting)
            vuln_class = "RECON"

        # Auto-register the hypothesis
        hyp_id = ledger.add(surface, vuln_class)

        # If there's a concrete payload in the tool args, record it too
        payload = ""
        if tool_name == "send_request":
            body = args.get("body", "")
            if body:
                payload = body[:200]
        elif tool_name == "terminal_execute":
            payload = args.get("command", "")[:200]
        if payload:
            ledger.record_payload(hyp_id, payload)

        # If a vulnerability signal was detected, mark as 'testing'
        if vuln_class not in ("RECON",):
            evidence_snip = ""
            # Try to grab a signal line from the observation
            for line in observation_xml.split("\n"):
                ll = line.lower()
                if any(kw in ll for kw in ("vulnerable", "injectable", "confirmed", "critical", "reflected")):
                    evidence_snip = line.strip()[:300]
                    break
            ledger.record_result(hyp_id, "testing", evidence_snip)

        _logger.debug("FIX-1: Auto-recorded hypothesis %s: %s on %s", hyp_id, vuln_class, surface[:60])

    except Exception:  # noqa: BLE001
        # Never let auto-recording crash the tool pipeline
        pass


def extract_screenshot_from_result(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None

    screenshot = result.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        return screenshot

    return None


def remove_screenshot_from_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result

    result_copy = result.copy()
    if "screenshot" in result_copy:
        result_copy["screenshot"] = "[Image data extracted - see attached image]"

    return result_copy
