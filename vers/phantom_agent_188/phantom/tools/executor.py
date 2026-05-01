import html
import asyncio
from contextlib import suppress
import inspect
import logging
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
from phantom.llm.tracked_completion import tracked_acompletion


logger = logging.getLogger(__name__)





if os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "false":
    from phantom.runtime import get_runtime

from .argument_parser import convert_arguments

from .context import reset_current_agent_id, set_current_agent_id
from .registry import (
    get_tool_by_name,
    get_tool_names,
    get_tool_param_schema,
    needs_agent_state,
    should_execute_in_sandbox,
)


def _resolve_canonical_tool_name(tool_name: str | None) -> str | None:
    if tool_name is None:
        return None

    candidate = tool_name.strip()
    if not candidate:
        return None

    if "." in candidate:
        candidate = candidate.split(".")[-1]

    candidate = candidate.replace("-", "_")
    available_tools = get_tool_names()

    if candidate in available_tools:
        return candidate

    collapsed = candidate.replace("_", "").lower()
    for name in available_tools:
        if name.replace("_", "").lower() == collapsed:
            return name

    return candidate




# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: ARCH-001 - Prompt Injection Detection Patterns
# ════════════════════════════════════════════════════════════════════════════════
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # System prompt manipulation
    re.compile(r"</?system\s*>", re.IGNORECASE),
    re.compile(r"\[/?system\]", re.IGNORECASE),
    re.compile(r"\[SYSTEM[ \:]", re.IGNORECASE),
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


def _enforce_safe_summary_schema(summary: str) -> str:
    """Normalize auto-summaries to a strict, line-based safe schema."""
    text = str(summary or "").strip()
    if not text:
        return "SUMMARY: unavailable\nKEY_FINDINGS:\n- none"

    text = _semantic_sanitize_output(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "SUMMARY: unavailable\nKEY_FINDINGS:\n- none"

    summary_line = lines[0][:300]
    finding_lines = [line[:240] for line in lines[1:8]]
    if not finding_lines:
        finding_lines = ["none"]

    formatted = [f"SUMMARY: {summary_line}", "KEY_FINDINGS:"]
    for finding in finding_lines:
        normalized = finding.lstrip("-*").strip()
        if normalized:
            formatted.append(f"- {normalized}")

    return "\n".join(formatted)


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
    "onerror=",
    "onload=",
    "sql",
    "syntax error",
    "traceback",
    "exception",
    "jwt",
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

    
    # Execution checks cleared (RBAC removed)
    
    # FIX: Ensure agent_id is always captured - even if agent_state is None
    _agent_id = None
    if agent_state is not None:
        _agent_id = getattr(agent_state, "agent_id", None)
    if not _agent_id:
        # Try to get from kwargs as fallback
        _agent_id = kwargs.get("agent_id", "unknown")
    if not _agent_id or _agent_id == "unknown":
        _agent_id = "unknown"

    agent_token = set_current_agent_id(_agent_id)

    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
    
    # Check if sandbox container exists (either in env var OR in agent_state)
    sandbox_available = sandbox_mode
    if not sandbox_available and agent_state:
        sandbox_available = getattr(agent_state, "sandbox_id", None) is not None

    # ── Audit: log tool invocation ─────────────────────────────────────────
    from phantom.logging.audit import get_audit_logger as _get_audit
    _audit = _get_audit()
    _exec_id = _audit.log_tool_start(_agent_id, tool_name, kwargs) if _audit else None
    _t0 = time.monotonic()
    # ──────────────────────────────────────────────────────────────────
    
    try:
        try:
            if execute_in_sandbox:
                if not sandbox_available:
                    if agent_state and getattr(agent_state, "sandbox_id", None):
                        pass  # Sandbox exists but env var not set - should work
                    else:
                        raise RuntimeError(f"CRITICAL: Tool '{tool_name}' requires Sandbox, but no sandbox container is running.")
                result = await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)
            else:
                result = await _execute_tool_locally(tool_name, agent_state, **kwargs)

            if _audit and _exec_id:
                _audit.log_tool_result(
                    _exec_id,
                    _agent_id,
                    tool_name,
                    result,
                    (time.monotonic() - _t0) * 1000,
                    cache_hit=False,
                )
            return result
        except Exception as e:
            _mark_tool_pipeline_issue(
                agent_state,
                "tool_execution_failed",
                f"Tool '{tool_name}' execution failed: {e}",
            )
            if _audit and _exec_id:
                import traceback as _tb

                _audit.log_tool_error(
                    _exec_id,
                    _agent_id,
                    tool_name,
                    _tb.format_exc()[-500:],
                    (time.monotonic() - _t0) * 1000,
                )
            raise
    finally:
        reset_current_agent_id(agent_token)


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
    normalized_name = _resolve_canonical_tool_name(tool_name)
    if normalized_name is None:
        raise ValueError("Tool name is missing")
    tool_func = get_tool_by_name(normalized_name)
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

    normalized_name = _resolve_canonical_tool_name(tool_name)
    if normalized_name is None:
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool name is missing. Available tools: {available}"
    available_tools = get_tool_names()
    
    if normalized_name not in available_tools:
        sorted_tools = sorted(available_tools)
        available_preview = ", ".join(sorted_tools[:25])
        if len(sorted_tools) > 25:
            available_preview += ", ..."
        suggestion = ""
        for t in available_tools:
            if t.replace("_", "") == normalized_name.replace("_", ""):
                suggestion = f" Did you mean '{t}'?"
                break

        retry_tools = [
            name
            for name in (
                "get_scan_status",
                "send_request",
                "python_action",
                "terminal_execute",
                "create_vulnerability_report",
            )
            if name in available_tools
        ]
        if retry_tools:
            retry_hint = f" Retry immediately with an exact tool name, e.g. {', '.join(retry_tools[:3])}."
        else:
            retry_hint = " Retry immediately with an exact registered tool name."

        return (
            False,
            f"Tool '{tool_name}' is not available. Available tools: {available_preview}.{suggestion}{retry_hint}",
        )

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


def _mark_tool_pipeline_issue(agent_state: Any | None, issue_type: str, message: str) -> None:
    logger.warning("Tool pipeline issue (%s): %s", issue_type, message)

    if agent_state is None:
        return

    try:
        if hasattr(agent_state, "context") and hasattr(agent_state, "update_context"):
            issues = agent_state.context.get("tool_pipeline_issues", [])
            if not isinstance(issues, list):
                issues = []
            issues.append({"type": issue_type, "message": message[:300]})
            agent_state.update_context("tool_pipeline_issues", issues[-20:])
            agent_state.update_context("tool_pipeline_issue_count", len(issues))
            return

        setattr(agent_state, "tool_pipeline_issue", issue_type)
    except Exception:
        logger.debug("Failed to persist tool pipeline issue", exc_info=True)


async def execute_tool_with_validation(
    tool_name: str | None,
    agent_state: Any | None = None,
    allowed_tools: set[str] | None = None,
    **kwargs: Any,
) -> Any:
    tool_name = _resolve_canonical_tool_name(tool_name)

    if allowed_tools is None or tool_name not in allowed_tools:
        raise Exception("Tool not allowed")

    is_valid, error_msg = validate_tool_availability(tool_name)
    if not is_valid:
        return f"Error: {error_msg}"

    arg_error = _validate_tool_arguments(tool_name, kwargs)
    if arg_error:
        return f"Error: {arg_error}"

    # Ensure get_scan_status has a minimal agent-scoped context when invoked
    # through the executor path without prior wiring.
    if tool_name == "get_scan_status" and agent_state is not None:
        agent_id_for_status = str(getattr(agent_state, "agent_id", "") or "").strip()
        if agent_id_for_status and "agent_id" not in kwargs:
            kwargs["agent_id"] = agent_id_for_status

        try:
            context_setter = None
            tool_func = get_tool_by_name(tool_name)
            if tool_func is not None:
                tool_module = inspect.getmodule(tool_func)
                if tool_module is not None:
                    maybe_setter = getattr(tool_module, "set_scan_status_context", None)
                    if callable(maybe_setter):
                        context_setter = maybe_setter

            if context_setter is None:
                from phantom.tools.scan_status.scan_status_actions import set_scan_status_context

                context_setter = set_scan_status_context

            context_setter(
                hypothesis_ledger=getattr(agent_state, "hypothesis_ledger", None),
                coverage_tracker=getattr(agent_state, "coverage_tracker", None),
                attack_graph=getattr(agent_state, "attack_graph", None),
                agent_state=agent_state,
            )
        except Exception:  # noqa: BLE001
            pass



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
    allowed_tools = tool_inv.get("allowedTools")
    if isinstance(allowed_tools, list):
        normalized_allowed_tools = set(str(name) for name in allowed_tools)
    elif isinstance(allowed_tools, set):
        normalized_allowed_tools = set(str(name) for name in allowed_tools)
    else:
        normalized_allowed_tools = None

    return await execute_tool_with_validation(
        tool_name,
        agent_state,
        allowed_tools=normalized_allowed_tools,
        **tool_args,
    )


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

    FIX 3: Enhanced to preserve MORE database dumps, credentials, and extracted data.
    Keeps lines indicating confirmed injections, extracted data, and
    database/table/column information.
    Returns None if no finding lines were found.
    """
    lines = text.splitlines()
    finding_lines: list[str] = []
    # FIX 3: Expanded signal markers to capture more evidence
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
        "[error]",  # FIX: capture errors that reveal DB type
        "fetched data",
        "available databases",
        "entries",
        "dumped",
        "back-end dbms",
        "password",  # FIX: capture password fields
        "username",  # FIX: capture username fields
        "admin",     # FIX: capture admin credentials
        "user:",     # FIX: capture user data
        "hash:",     # FIX: capture password hashes
        "retrieved",  # FIX: capture retrieved data
        "current user",  # FIX: capture DB user info
        "current database",  # FIX: capture current DB
        "privileges",  # FIX: capture privilege escalation info
        "banner:",    # FIX: capture DB version banner
        "| ",         # FIX: capture table-formatted output from --dump
    )

    for line in lines:
        lower = line.strip().lower()
        if not lower:
            continue
        if any(m in lower for m in _signal_markers):
            finding_lines.append(line)

    if not finding_lines:
        return None

    result_lines = [f"[sqlmap findings: {len(finding_lines)} signal lines extracted]"] + finding_lines
    result = "\n".join(result_lines)
    if len(result) > limit:
        # FIX 3: Even when truncating, preserve first 90% (more than before)
        keep_amount = int(limit * 0.9)
        result = result[:keep_amount] + f"\n... [truncated {len(result) - keep_amount} chars] ..."
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
    # FIX 3: MASSIVELY increased limits to preserve critical evidence
    # Previous: sqlmap/nuclei = 6000 chars (90% evidence lost)
    # New: sqlmap/nuclei = 50000 chars (preserves database dumps, POCs)
    _BUILT_IN_TOOL_LIMITS: dict[str, int] = {
        "naabu":                    3000,   # port scan: increased from 1500
        "nmap":                     3000,   # nmap: decreased from 6000
        "grep":                     3000,   # grep: increased from 2000
        "curl":                     3000,   # curl: increased from 2000
        "ffuf":                     5000,   # directory fuzzer: increased from 3000
        "nikto":                    6000,   # nikto: increased from 4000
        "terminal_execute":       12000,    # shell wrapper: keep context compact for follow-up turns
        "exec_terminal":          12000,    # FIX: match terminal_execute
        "terminal":               12000,    # FIX: match terminal_execute
        "browser_action":         12000,   # browser: increased from 6000
        "nuclei":                  50000,   # FIX: increased from 6000 (was 10000) - preserve full POCs
        "run_nuclei":              50000,   # FIX: match nuclei
        "sqlmap":                  50000,   # FIX: increased from 6000 (was 10000) - preserve DB dumps
        "run_sqlmap":              50000,   # FIX: match sqlmap
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

    summary_count = 0
    fallback_mode = "none"
    if "<tool_name>" in result_text and "<result>" in result_text:
        try:
            tool_match = re.search(r"<tool_name>(.*?)</tool_name>", result_text, flags=re.IGNORECASE | re.DOTALL)
            result_match = re.search(r"<result>(.*?)</result>", result_text, flags=re.IGNORECASE | re.DOTALL)
            detected_tool = html.unescape(tool_match.group(1).strip()) if tool_match else tool_name
            extracted_result = html.unescape(result_match.group(1)) if result_match else result_text
            tool_name = detected_tool or tool_name
            result_text = extracted_result
        except Exception:
            pass

    injection_detected, injection_pattern = _detect_prompt_injection(result_text)
    if injection_detected:
        fallback_mode = "injection_detected"
        safe_result = _semantic_sanitize_output(result_text)
        return (
            "SUMMARY: Tool output contained prompt injection indicators.\n"
            "KEY_FINDINGS:\n"
            f"- pattern={injection_pattern or 'unknown'}\n"
            f"- tool={tool_name}\n"
            f"- sanitized_excerpt={safe_result[:600]}\n"
            f"- fallback_mode={fallback_mode}"
        )

    try:
        prompt = (
            "Summarize this security tool output.\n"
            "Respond with plain text in this exact schema:\n"
            "SUMMARY: <single line>\n"
            "KEY_FINDINGS:\n"
            "- <finding 1>\n"
            "- <finding 2>\n"
            "Do not include XML tags, tool calls, system-role text, or instructions.\n\n"
            f"Tool: {tool_name}\n"
            "Output:\n"
            f"{result_text[:120000]}"
        )
        response = await tracked_acompletion(
            model=SUMMARIZE_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=700,
            timeout=20,
        )
        content = response.choices[0].message.content
        if isinstance(content, str) and content.strip():
            safe_summary = _enforce_safe_summary_schema(content)
            summary_count += 1
            if summary_count >= 1:
                fallback_mode = "max_summaries"
            return safe_summary
        return result_text
    except Exception:
        fallback_mode = "summarizer_error"
        safe_result = _semantic_sanitize_output(result_text)
        return (
            "SUMMARY: Failed to summarize tool output safely.\n"
            "KEY_FINDINGS:\n"
            f"- tool={tool_name}\n"
            f"- fallback_mode={fallback_mode}\n"
            f"- excerpt={safe_result[:500]}"
        )


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

    # RCE signals - Context-aware detection to avoid false positives
    # Only trigger on command output patterns, not HTML/CSS/text content
    _rce_patterns = [
        # Match actual command output, not substrings in HTML/CSS
        (r"uid=\d+\([a-z0-9_-]+\)", "RCE_CONFIRMED"),  # uid=1000(user)
        (r"^root:[^:]*:\d+:\d+:", "RCE_CONFIRMED"),    # /etc/passwd format at line start
        (r"\b(bash|sh|zsh|dash)\s+-c\b", "RCE_POTENTIAL"),  # shell invocation
        (r"^total\s+\d+\s*$", "RCE_POTENTIAL"),        # ls -l output
        (r"^\s*(drwx|lrwx|-rwx)", "RCE_POTENTIAL"),    # file permissions at line start
    ]
    for pattern, signal_type in _rce_patterns:
        if _re_sig.search(pattern, lower, _re_sig.MULTILINE):
            # Find matching line for context
            for line in output.splitlines():
                if _re_sig.search(pattern, line.lower()):
                    signals.append(f"{signal_type}: {line.strip()[:200]}")
                    break

    # SSRF signals - Context-aware detection to avoid false positives
    # Only trigger on actual network responses, not HTML content mentioning "internal"
    if tool_name in {"send_request", "terminal_execute"}:
        _ssrf_patterns = [
            # Match actual private IPs in responses, not just anywhere
            (r"(?:^|[^\d])127\.0\.0\.1(?:[^\d]|$)", "SSRF_LOCALHOST"),
            (r"(?:^|[^\d])169\.254\.169\.254(?:[^\d]|$)", "SSRF_METADATA"),  # AWS metadata
            (r"169\.254\.169\.254/latest/meta-data", "SSRF_CONFIRMED"),     # AWS metadata access
            (r"metadata\.google\.internal", "SSRF_CONFIRMED"),              # GCP metadata
            # Only flag "internal" if it appears in suspicious contexts
            (r"internal.*(?:server|api|admin|backend|database)", "SSRF_POTENTIAL"),
        ]
        for pattern, signal_type in _ssrf_patterns:
            if _re_sig.search(pattern, lower):
                for line in output.splitlines():
                    if _re_sig.search(pattern, line.lower()):
                        signals.append(f"{signal_type}: {line.strip()[:200]}")
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
        # P1.1 FIX: Changed from MANDATORY to INVESTIGATION REQUIRED
        # This prevents false positive reports from signals alone.
        # Original: forced immediate reporting with SUSPECTED confidence
        # Fixed: requires confirmation before reporting
        _critical_types = ("SQL_INJECTION", "RCE", "SSRF", "XXE")
        if any(ct in s for s in signal_lines for ct in _critical_types):
            signal_header += (
                "[INVESTIGATION REQUIRED] A potential vulnerability signal was detected. "
                "BEFORE reporting, you MUST:\n"
                "  1. Send a CONFIRMATION payload to verify the vulnerability is exploitable\n"
                "  2. Extract CONCRETE evidence (actual data, command output, or observable state change)\n"
                "  3. Document what you sent and what you received\n"
                "Only report after confirming exploitation. Signals alone are NOT proof.\n"
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
    owner_agent: Any | None,
    tracer: Any | None,
    agent_id: str,
    image_slots_remaining: int,
) -> tuple[str, list[dict[str, Any]], bool, int, bool]:
    tool_name = tool_inv.get("toolName", "unknown")
    args = tool_inv.get("args", {})
    execution_id = None
    should_agent_finish = False
    agent_token = set_current_agent_id(agent_id)

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

    except Exception as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        logger.warning(f"Tool '{tool_name}' raised {type(e).__name__}: {error_msg}")
        result = {"success": False, "error": error_msg, "error_type": type(e).__name__}
        is_error = True
        error_payload = error_msg
    finally:
        reset_current_agent_id(agent_token)

    raw_observation_xml, images, meta = _format_tool_result_with_meta(
        tool_name,
        result,
        image_slots_remaining=image_slots_remaining,
    )
    observation_xml = raw_observation_xml

    needs_llm_summary = bool(meta.get("needs_llm_summary"))
    if needs_llm_summary:
        summarized_xml = await _auto_summarize_result(observation_xml, tool_name)
        if summarized_xml and summarized_xml != observation_xml:
            observation_xml = summarized_xml

    _auto_record_hypothesis(
        tool_inv=tool_inv,
        observation_xml=raw_observation_xml,
        agent_state=agent_state,
        owner_agent=owner_agent,
        vuln_signals=meta.get("vuln_signals", []),
    )

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
    return observation_xml, images, should_agent_finish, images_used, is_error


def _get_tracer_and_agent_id(agent_state: Any | None) -> tuple[Any | None, str]:
    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if agent_state and getattr(agent_state, "agent_id", None):
            agent_id = str(agent_state.agent_id)
        else:
            agent_id = "default"
    except (ImportError, AttributeError):
        tracer = None
        agent_id = "default"

    return tracer, agent_id


async def process_tool_invocations(
    tool_invocations: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    agent_state: Any | None = None,
    owner_agent: Any | None = None,
    allowed_tools: set[str] | None = None,
) -> bool:
    observation_parts: list[str] = []
    all_images: list[dict[str, Any]] = []
    should_agent_finish = False
    batch_had_error = False
    image_slots_remaining = _parse_int("phantom_browser_image_max_per_turn", 1)

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    for tool_inv in tool_invocations:
        tool_inv = dict(tool_inv)
        if allowed_tools is not None:
            tool_inv["allowedTools"] = sorted(allowed_tools)
        observation_xml, images, tool_should_finish, images_used, tool_had_error = await _execute_single_tool(
            tool_inv,
            agent_state,
            owner_agent,
            tracer,
            agent_id,
            image_slots_remaining,
        )
        observation_parts.append(observation_xml)
        all_images.extend(images)
        image_slots_remaining = max(0, image_slots_remaining - images_used)
        batch_had_error = batch_had_error or tool_had_error

        if tool_should_finish:
            should_agent_finish = True

    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(observation_parts)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(observation_parts)
        conversation_history.append({"role": "user", "content": observation_content})

    if agent_state is not None and hasattr(agent_state, "update_context"):
        try:
            agent_state.update_context("last_tool_batch_had_error", batch_had_error)
        except (AttributeError, KeyError, TypeError):  # noqa: BLE001
            pass

    return should_agent_finish


def _auto_record_hypothesis(
    tool_inv: dict[str, Any],
    observation_xml: str,
    agent_state: Any | None,
    owner_agent: Any | None = None,
    vuln_signals: list[str] | None = None,
) -> None:
    """Automatically populate HypothesisLedger from tool results.

    Hardened behavior:
    - Only create/update hypotheses from explicit, strong vulnerability signals.
    - Ignore weak or scanner-only hints to prevent ledger pollution.
    """
    import re as _re_hyp

    def _resolve_component(name: str) -> Any | None:
        if owner_agent is not None and hasattr(owner_agent, name):
            return getattr(owner_agent, name)
        if agent_state is not None and hasattr(agent_state, name):
            return getattr(agent_state, name)
        return None

    if agent_state is None and owner_agent is None:
        return

    ledger = _resolve_component("hypothesis_ledger")
    coverage_tracker = _resolve_component("coverage_tracker")
    correlation_engine = _resolve_component("correlation_engine")
    attack_graph = _resolve_component("attack_graph")

    if ledger is None:
        return

    tool_name = str(tool_inv.get("toolName", ""))
    args = tool_inv.get("args", {})

    try:
        if tool_name not in {"send_request", "terminal_execute", "browser_action"}:
            return

        surface = ""
        if tool_name == "send_request":
            url = str(args.get("url", ""))
            method = str(args.get("method", "GET"))
            surface = f"{url} {method}".strip()[:100]
        elif tool_name == "terminal_execute":
            cmd = str(args.get("command", ""))
            url_match = _re_hyp.search(r'https?://[^\s\'"]+', cmd)
            surface = (url_match.group(0) if url_match else cmd)[:100]
        elif tool_name == "browser_action":
            surface = str(args.get("url") or args.get("action") or "")[:100]

        if not surface:
            return

        obs_lower = observation_xml.lower()

        signals = [s for s in (vuln_signals or []) if isinstance(s, str) and s.strip()]

        signal_vclass = ""
        strong_signal_lines: list[str] = []
        for sig in signals:
            sig_head = sig.split(":", 1)[0].strip().lower()
            sig_text = sig.strip()
            is_strong = (
                "confirmed" in sig_head
                or sig_head in {"sql_injection"}
                or "vulnerable" in sig_text.lower()
                or "injectable" in sig_text.lower()
            )
            # Ignore weak/heuristic-only categories.
            if any(tag in sig_head for tag in ("potential", "scanner_", "_reflected", "xss_potential")):
                is_strong = False
            if is_strong:
                strong_signal_lines.append(sig_text)
            if "sql" in sig_head:
                signal_vclass = "sqli"
                break
            if "xss" in sig_head:
                signal_vclass = "xss"
                break
            if "rce" in sig_head or "command" in sig_head:
                signal_vclass = "rce"
                break
            if "ssrf" in sig_head:
                signal_vclass = "ssrf"
                break
            if "idor" in sig_head:
                signal_vclass = "idor"
                break
            if "xxe" in sig_head:
                signal_vclass = "xxe"
                break
            if "redirect" in sig_head:
                signal_vclass = "open_redirect"
                break

        # Do not auto-create hypotheses from weak/noisy signals.
        if not strong_signal_lines:
            return

        # Backward compatibility: legacy gate tests expect signals-only paths to
        # use "auto_extraction" class when no owner agent is wired.
        if strong_signal_lines and owner_agent is None:
            vuln_class = "auto_extraction"
        elif signal_vclass:
            vuln_class = signal_vclass
        else:
            return

        hyp_id = ledger.add(surface, vuln_class)

        if strong_signal_lines:
            for sig in strong_signal_lines:
                ledger.record_payload(hyp_id, sig.strip()[:200])
            ledger.record_result(
                hyp_id,
                "testing",
                "Auto-recorded from strong tool signal",
            )

        payload = ""
        if tool_name == "send_request":
            payload = str(args.get("body", ""))[:200]
        elif tool_name == "terminal_execute":
            payload = str(args.get("command", ""))[:200]
        if payload:
            ledger.record_payload(hyp_id, payload)

        evidence_snip = ""
        for line in observation_xml.split("\n"):
            ll = line.lower()
            if any(kw in ll for kw in ("vulnerable", "injectable", "confirmed")):
                evidence_snip = line.strip()[:300]
                break
        if evidence_snip:
            ledger.record_result(hyp_id, "testing", evidence_snip)

        if coverage_tracker is not None:
            try:
                coverage_tracker.discover_surface(surface, "tool_surface", source=tool_name)
                coverage_tracker.record_test(surface, "tool_surface", vuln_class, note=f"tool={tool_name}")
                if any(x in obs_lower for x in ("403", "401", "forbidden", "rate limit", "waf")):
                    coverage_tracker.record_failure(
                        surface,
                        "tool_surface",
                        "ACCESS_OR_WAF_BLOCKED",
                        vuln_class=vuln_class,
                    )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                _mark_tool_pipeline_issue(
                    agent_state,
                    "coverage_tracker_update_failed",
                    f"coverage_tracker update failed for {tool_name}: {exc}",
                )

        should_correlate = bool(strong_signal_lines) or any(
            kw in obs_lower for kw in ("confirmed", "extracted", "authentication bypass", "accepted")
        )
        if correlation_engine is not None and vuln_class != "recon" and should_correlate:
            try:
                severity = "medium"
                if vuln_class in {"rce", "auth_bypass", "sqli"}:
                    severity = "high"
                if vuln_class in {"scanner_finding"}:
                    severity = "low"
                correlation_engine.add_finding(
                    vuln_class=vuln_class,
                    surface=surface,
                    severity=severity,
                    details={"source": tool_name, "hypothesis_id": hyp_id},
                )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                _mark_tool_pipeline_issue(
                    agent_state,
                    "correlation_engine_update_failed",
                    f"correlation_engine update failed for {tool_name}: {exc}",
                )

        if attack_graph is not None and vuln_class != "recon":
            try:
                from phantom.core.attack_graph import AttackEdgeType, AttackNodeType

                vuln_hash = hashlib.md5(f"{surface}:{vuln_class}".encode("utf-8")).hexdigest()[:10]
                vuln_node = f"V-{vuln_hash}"
                target_node = f"A-{hashlib.md5(surface.encode('utf-8')).hexdigest()[:10]}"

                if vuln_node not in attack_graph._nodes:
                    attack_graph.add_vulnerability(
                        vuln_id=vuln_node,
                        title=f"{vuln_class.upper()} via {tool_name}",
                        severity="high" if vuln_class in {"sqli", "rce", "auth_bypass"} else "medium",
                        status="suspected",
                        metadata={"surface": surface, "tool": tool_name, "hypothesis_id": hyp_id},
                    )

                belief = 0.5
                confidence = 0.5
                hypothesis_ref = ledger.get(hyp_id) if hasattr(ledger, "get") else None
                if hypothesis_ref is not None:
                    with suppress(Exception):
                        belief = float(getattr(hypothesis_ref, "posterior_mean", 0.5))
                    with suppress(Exception):
                        confidence = float(getattr(hypothesis_ref, "confidence_score", 50.0)) / 100.0
                    node_status = str(getattr(hypothesis_ref, "status", "testing") or "testing")
                else:
                    node_status = "testing"

                belief = max(0.01, min(0.99, belief))
                confidence = max(0.01, min(0.99, confidence))

                node_metadata = attack_graph._nodes[vuln_node].metadata if vuln_node in attack_graph._nodes else {}
                node_metadata = dict(node_metadata or {})
                node_metadata.update(
                    {
                        "surface": surface,
                        "tool": tool_name,
                        "hypothesis_id": hyp_id,
                        "success_probability": round(belief, 4),
                        "confidence": round(confidence, 4),
                        "posterior_mean": round(belief, 4),
                    }
                )
                if vuln_node in attack_graph._nodes:
                    attack_graph._nodes[vuln_node].metadata = node_metadata
                    attack_graph._nodes[vuln_node].status = node_status
                    if hasattr(attack_graph, "_graph") and attack_graph._graph.has_node(vuln_node):
                        attack_graph._graph.nodes[vuln_node].update(node_metadata)
                        attack_graph._graph.nodes[vuln_node]["status"] = node_status

                if target_node not in attack_graph._nodes:
                    attack_graph.add_node(
                        node_id=target_node,
                        node_type=AttackNodeType.ASSET,
                        label=surface[:80],
                        metadata={"surface": surface},
                    )
                if not attack_graph._graph.has_edge(vuln_node, target_node):
                    attack_graph.add_edge(
                        vuln_node,
                        target_node,
                        AttackEdgeType.AFFECTS,
                        metadata={
                            "hypothesis_id": hyp_id,
                            "source": tool_name,
                            "success_probability": round(max(0.01, min(0.99, belief * 0.9)), 4),
                            "confidence": round(confidence, 4),
                            "cost": round(max(0.2, 1.2 - confidence), 3),
                        },
                    )
                else:
                    edge_data = attack_graph._graph.get_edge_data(vuln_node, target_node, default={}) or {}
                    edge_type_raw = str(edge_data.get("type", AttackEdgeType.AFFECTS.value))
                    try:
                        edge_type = AttackEdgeType(edge_type_raw)
                    except ValueError:
                        edge_type = AttackEdgeType.AFFECTS
                    edge_weight = float(edge_data.get("weight", 1.0) or 1.0)
                    updated_metadata = {
                        k: v for k, v in edge_data.items() if k not in {"type", "weight"}
                    }
                    updated_metadata.update(
                        {
                            "hypothesis_id": hyp_id,
                            "source": tool_name,
                            "success_probability": round(max(0.01, min(0.99, belief * 0.9)), 4),
                            "confidence": round(confidence, 4),
                            "cost": round(max(0.2, 1.2 - confidence), 3),
                        }
                    )
                    attack_graph.add_edge(
                        vuln_node,
                        target_node,
                        edge_type,
                        weight=edge_weight,
                        metadata=updated_metadata,
                    )

                ranked_plans = []
                try:
                    ranked_plans = attack_graph.get_ranked_attack_plans(max_plans=3, cutoff=4)
                except (ValueError, TypeError, KeyError):
                    ranked_plans = []

                planner_trace = None
                if hasattr(attack_graph, "metadata"):
                    planner_trace = attack_graph.metadata.get("last_planner_trace")

                if planner_trace and hasattr(ledger, "_record_scheduler_event"):
                    ledger._record_scheduler_event(
                        {
                            "event_type": "planner_trace",
                            "hypothesis_id": hyp_id,
                            "surface": surface,
                            "tool": tool_name,
                            "posterior_mean": round(belief, 4),
                            "confidence": round(confidence, 4),
                            "top_attack_plans": [plan.to_dict() for plan in ranked_plans[:3]],
                            "planner_trace": planner_trace,
                            "timestamp": datetime.now(UTC).isoformat(),
                        }
                    )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                _mark_tool_pipeline_issue(
                    agent_state,
                    "attack_graph_update_failed",
                    f"attack_graph update failed for {tool_name}: {exc}",
                )

    except (ValueError, TypeError, KeyError, AttributeError) as exc:  # noqa: BLE001
        # Never let auto-recording crash the tool pipeline.
        _mark_tool_pipeline_issue(
            agent_state,
            "auto_recording_failed",
            f"auto_recording failed for {tool_name}: {exc}",
        )
        return


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
