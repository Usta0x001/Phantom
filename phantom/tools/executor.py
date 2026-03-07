import inspect
import logging
import os
import time as _time
from html import escape as _xml_escape
from typing import Any

import httpx

from phantom.config import Config
from phantom.core.exceptions import SecurityViolationError, ResourceExhaustedError, ScopeViolationError, ToolError, PhaseViolationError
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState
from phantom.core.tool_firewall import get_global_firewall
from phantom.core.degradation_handler import DegradationHandler
from phantom.core.wal import WriteAheadLog

_logger = logging.getLogger(__name__)

# ── Singletons for degradation and WAL ──
_degradation_handler: DegradationHandler | None = None
_wal: WriteAheadLog | None = None


def get_degradation_handler() -> DegradationHandler:
    """Lazy-init singleton for the degradation handler."""
    global _degradation_handler
    if _degradation_handler is None:
        _degradation_handler = DegradationHandler()
    return _degradation_handler


def get_executor_wal() -> WriteAheadLog:
    """Lazy-init singleton for the executor WAL."""
    global _wal
    if _wal is None:
        _wal = WriteAheadLog("phantom_wal_executor")
    return _wal

# ── T2-01: Use CircuitBreaker class instead of inline dict ────────────
import threading as _cb_threading

_circuit_breaker_lock = _cb_threading.Lock()
_circuit_breakers: dict[str, CircuitBreaker] = {}

# V2-DESIGN-002: Finding provenance tracker for dedup + source attribution
try:
    from phantom.core.finding_provenance import FindingProvenanceTracker, FindingSource
    _finding_tracker = FindingProvenanceTracker()
except ImportError:
    _finding_tracker = None  # type: ignore[assignment]

# L17 FIX: module-level constant instead of per-call recreation
_ENDPOINT_TOOLS_MAP: dict[str, str] = {
    "sqlmap_test": "sqli",
    "sqlmap_forms": "sqli",
    "sqlmap_dump_database": "sqli-dump",
    "nuclei_scan": "nuclei",
    "nuclei_scan_cves": "nuclei-cve",
    "nuclei_scan_misconfigs": "nuclei-misconfig",
    "ffuf_directory_scan": "fuzz",
    "ffuf_parameter_fuzz": "param-fuzz",
    "ffuf_vhost_fuzz": "vhost-fuzz",
    "nmap_scan": "portscan",
    "nmap_vuln_scan": "vuln-scan",
    "httpx_probe": "httpx",
    "httpx_full_analysis": "httpx-full",
    "send_request": "manual",
    "repeat_request": "manual-repeat",
}

# ARC-003 FIX: Minimum scan phase required before a tool can be invoked.
# Tools not listed here are allowed in any phase. Phase ordering:
# recon < enumeration < vulnerability_scanning < exploitation < post_exploitation < reporting
_TOOL_MINIMUM_PHASE: dict[str, str] = {
    # Exploitation tools require at least vulnerability_scanning phase
    "sqlmap_test": "vulnerability_scanning",
    "sqlmap_forms": "vulnerability_scanning",
    "sqlmap_dump_database": "exploitation",
    # Nuclei vuln scanning
    "nuclei_scan_cves": "vulnerability_scanning",
    "nuclei_scan_misconfigs": "enumeration",
    # Fuzzing requires at least enumeration
    "ffuf_parameter_fuzz": "enumeration",
    "ffuf_vhost_fuzz": "enumeration",
    # Terminal/Python execution requires exploitation phase
    "terminal_execute": "exploitation",
    "python_action": "exploitation",
}

_PHASE_ORDER: dict[str, int] = {
    "recon": 0,
    "enumeration": 1,
    "vulnerability_scanning": 2,
    "exploitation": 3,
    "post_exploitation": 4,
    "reporting": 5,
}


if os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "false":
    from phantom.runtime import get_runtime

from .argument_parser import convert_arguments
from .registry import (
    get_tool_by_name,
    get_tool_names,
    get_tool_param_schema,
    needs_agent_state,
    should_execute_in_sandbox,
)


try:
    _SERVER_TIMEOUT = float(Config.get("phantom_sandbox_execution_timeout") or "600")
except (ValueError, TypeError):
    _SERVER_TIMEOUT = 600.0
SANDBOX_EXECUTION_TIMEOUT = _SERVER_TIMEOUT + 30
try:
    SANDBOX_CONNECT_TIMEOUT = float(Config.get("phantom_sandbox_connect_timeout") or "10")
except (ValueError, TypeError):
    SANDBOX_CONNECT_TIMEOUT = 10.0


async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
    # ── HARDENED v0.9.40: Degradation handler — block non-essential tools in MINIMAL mode ──
    dh = get_degradation_handler()
    if not dh.is_tool_allowed(tool_name):
        _logger.warning("DEGRADATION blocked '%s' — system in MINIMAL mode", tool_name)
        return (
            f"⚠️ Tool '{tool_name}' is blocked — system is in degraded (MINIMAL) mode. "
            f"Only essential tools are available."
        )

    # ── Determine current phase ──
    current_phase = "recon"
    if agent_state is not None and hasattr(agent_state, "state_machine") and agent_state.state_machine:
        current_phase = agent_state.state_machine.current_state.value

    # ── HARDENED v0.9.40: Tool Firewall — deterministic pre-execution gate ──
    firewall = get_global_firewall()
    if firewall is not None:
        findings_ledger: list[str] = []
        if agent_state is not None and hasattr(agent_state, "findings_ledger"):
            findings_ledger = agent_state.findings_ledger or []
        verdict = firewall.validate(
            tool_name=tool_name,
            tool_args=kwargs,
            current_phase=current_phase,
            findings_ledger=findings_ledger,
        )
        # validate() raises ToolFirewallViolation on block; returns FirewallVerdict on pass
        if verdict.sanitized_args:
            kwargs = verdict.sanitized_args

    # ── T2-01: Circuit breaker check using CircuitBreaker class ──────
    # V2-BUG-001 FIX: Thread-safe get-or-create with lock
    with _circuit_breaker_lock:
        if tool_name not in _circuit_breakers:
            _circuit_breakers[tool_name] = CircuitBreaker(name=tool_name, failure_threshold=3, recovery_timeout=300.0)
        cb = _circuit_breakers[tool_name]
    if not cb.can_execute():
        _logger.warning(
            "Circuit breaker OPEN for '%s' (state=%s). Try a different tool.",
            tool_name, cb.state.value,
        )
        return (
            f"⚠️ Tool '{tool_name}' is temporarily disabled — circuit breaker "
            f"tripped. Try a different tool or wait for cooldown."
        )

    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"

    # ── HARDENED v0.9.40: WAL-protected tool execution ──
    wal = get_executor_wal()
    txn_id = wal.begin(f"tool:{tool_name}", payload={"tool": tool_name, "phase": current_phase if firewall else "unknown"})

    try:
        if execute_in_sandbox and not sandbox_mode:
            result = await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)
        else:
            result = await _execute_tool_locally(tool_name, agent_state, **kwargs)

        # Success — commit WAL and reset circuit breaker
        wal.commit(txn_id)
        cb.record_success()

        # Track tool failure in degradation handler on success (recovery)
        dh.recover_tool(tool_name)

        return result

    except Exception:
        # Rollback WAL, track failure in circuit breaker and degradation
        wal.rollback(txn_id)
        cb.record_failure()
        dh.handle_tool_failure(tool_name, "execution_error")
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

    # P2-FIX8: Stealth enforcement middleware — enforce rate limiting when
    # stealth profile is active. This is a hard limit, not advisory-only.
    try:
        from phantom.core.scan_profiles import get_active_profile_flags
        flags = get_active_profile_flags()
        delay_ms = flags.get("delay_ms", 0)
        if delay_ms > 0:
            import asyncio as _asyncio
            await _asyncio.sleep(delay_ms / 1000.0)
    except (ImportError, AttributeError):
        pass

    timeout = httpx.Timeout(
        timeout=SANDBOX_EXECUTION_TIMEOUT,
        connect=SANDBOX_CONNECT_TIMEOUT,
    )

    async with httpx.AsyncClient(trust_env=False) as client:
        try:
            # v0.9.39: mTLS support (feature-flagged OFF by default)
            ssl_ctx = _get_tls_context(agent_state)
            if ssl_ctx and request_url.startswith("http://"):
                request_url = "https://" + request_url[7:]
            response = await client.post(
                request_url, json=request_data, headers=headers, timeout=timeout,
                **({"verify": ssl_ctx} if ssl_ctx else {}),
            )
            response.raise_for_status()
            response_data = response.json()
            if response_data.get("error"):
                raise RuntimeError(f"Sandbox execution error: {response_data['error']}")
            return response_data.get("result")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise RuntimeError("Authentication failed: Invalid or missing sandbox token") from e
            raise RuntimeError(f"HTTP error calling tool server: {e.response.status_code}") from e
        except httpx.RequestError as e:
            error_type = type(e).__name__
            raise RuntimeError(f"Request error calling tool server: {error_type}") from e


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
    is_valid, error_msg = validate_tool_availability(tool_name)
    if not is_valid:
        return f"Error: {error_msg}"

    assert tool_name is not None

    arg_error = _validate_tool_arguments(tool_name, kwargs)
    if arg_error:
        return f"Error: {arg_error}"

    try:
        result = await execute_tool(tool_name, agent_state, **kwargs)
    except (SecurityViolationError, ResourceExhaustedError):
        raise  # v0.9.39: NEVER catch security/resource errors
    except Exception as e:  # noqa: BLE001
        # v0.9.39: Check for wrapped security errors
        cause = e.__cause__ or e.__context__
        if isinstance(cause, (SecurityViolationError, ResourceExhaustedError)):
            raise cause from e
        # BUG-021 FIX: Sanitize error strings to prevent stack trace leakage
        # to the LLM. Only expose the final error message, not the traceback.
        error_str = str(e)
        # Strip file paths and line numbers from error messages
        import re as _re_err
        error_str = _re_err.sub(r'File "[^"]+", line \d+', '[internal]', error_str)
        error_str = _re_err.sub(r'Traceback \(most recent call last\):', '', error_str)
        if len(error_str) > 500:
            error_str = error_str[:500] + "... [truncated]"
        return f"Error executing {tool_name}: {error_str}"
    else:
        return result


async def execute_tool_invocation(tool_inv: dict[str, Any], agent_state: Any | None = None) -> Any:
    tool_name = tool_inv.get("toolName")
    tool_args = tool_inv.get("args", {})

    # v0.9.39: Scope enforcement — validate URLs/IPs before execution
    from phantom.core.feature_flags import is_enabled
    if is_enabled("PHANTOM_FF_SCOPE_ENFORCEMENT"):
        scope_validator = _get_scope_validator()
        if scope_validator and tool_name:
            try:
                tool_args = scope_validator.enforce_scope(tool_name, tool_args)
            except ScopeViolationError as e:
                _logger.warning("SCOPE VIOLATION: tool=%s target=%s — %s", tool_name, e.target, e)
                try:
                    from phantom.core.audit_logger import get_global_audit_logger
                    _audit = get_global_audit_logger()
                    if _audit:
                        _audit.log_scope_violation(
                            target=e.target,
                            reason=str(e),
                            tool_name=tool_name or "",
                        )
                except Exception:  # noqa: BLE001
                    pass
                raise  # SecurityViolationError → propagates up

    # v0.9.39: Tool firewall re-enabled with allowlist approach
    if is_enabled("PHANTOM_FF_TOOL_FIREWALL"):
        from phantom.tools.registry import get_tool_names
        if tool_name and tool_name not in get_tool_names():
            return f"Error: Tool '{tool_name}' is not registered."

    # ARC-003 FIX: Phase-gated tool execution — prevent premature exploitation
    if tool_name and tool_name in _TOOL_MINIMUM_PHASE and agent_state is not None:
        required_phase = _TOOL_MINIMUM_PHASE[tool_name]
        current_phase = "recon"
        if hasattr(agent_state, "current_phase"):
            current_phase = getattr(agent_state.current_phase, "value", str(agent_state.current_phase))
        elif hasattr(agent_state, "state_machine"):
            current_phase = getattr(agent_state.state_machine.current_state, "value", "recon")
        required_ord = _PHASE_ORDER.get(required_phase, 0)
        current_ord = _PHASE_ORDER.get(current_phase, 0)
        if current_ord < required_ord:
            _logger.warning(
                "PHASE VIOLATION: tool=%s requires phase '%s' but current is '%s'",
                tool_name, required_phase, current_phase,
            )
            raise PhaseViolationError(
                f"Tool '{tool_name}' requires scan phase '{required_phase}' "
                f"but current phase is '{current_phase}'",
                tool_name=tool_name,
                required_phase=required_phase,
                current_phase=current_phase,
            )

    # Auto-inject auth headers for security tools that support extra_args
    tool_args = _inject_auth_headers(tool_name, tool_args, agent_state)

    # V2-DESIGN-003 FIX: Tool risk classification — enforce evidence gates
    # and per-tier rate limits before executing high-risk tools.
    if tool_name:
        try:
            from phantom.core.tool_risk_classifier import (
                check_evidence_gate,
                get_rate_limit,
                get_risk_tier,
            )

            tier = get_risk_tier(tool_name)
            # Evidence gate: DESTRUCTIVE/UNRESTRICTED tools require verified findings
            findings_count = 0
            if agent_state and hasattr(agent_state, "findings_ledger"):
                findings_count = len(agent_state.findings_ledger or [])
            gate_ok, gate_msg = check_evidence_gate(tool_name, findings_count)
            if not gate_ok:
                _logger.warning("EVIDENCE GATE blocked %s: %s", tool_name, gate_msg)
                return f"⚠️ {gate_msg}"

            # Rate limit check (per-tier)
            rate_limit = get_rate_limit(tool_name)
            if rate_limit is not None:
                _tier_key = f"_risk_rate_{tier.name}"
                _now = _time.monotonic()
                if not hasattr(execute_tool, "_tier_windows"):
                    execute_tool._tier_windows = {}  # type: ignore[attr-defined]
                window = execute_tool._tier_windows.get(_tier_key, [])  # type: ignore[attr-defined]
                window = [t for t in window if _now - t < 60.0]
                if len(window) >= rate_limit:
                    _logger.warning(
                        "RATE LIMIT for tier %s tool %s: %d/%d per minute",
                        tier.name, tool_name, len(window), rate_limit,
                    )
                    return f"⚠️ Rate limit reached for {tier.name}-tier tools ({rate_limit}/min). Wait before retrying."
                window.append(_now)
                execute_tool._tier_windows[_tier_key] = window  # type: ignore[attr-defined]
        except ImportError:
            pass  # tool_risk_classifier not available — skip

    return await execute_tool_with_validation(tool_name, agent_state, **tool_args)


def _get_scope_validator() -> Any:
    """Retrieve ScopeValidator from scan context, if available."""
    try:
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and hasattr(tracer, 'scope_validator'):
            return tracer.scope_validator
    except (ImportError, AttributeError):
        pass
    return None


def _get_tls_context(agent_state: Any) -> Any:
    """Get mTLS SSL context if available (v0.9.39: MTLS feature flag)."""
    try:
        from phantom.core.feature_flags import is_enabled
        if not is_enabled("PHANTOM_FF_MTLS"):
            return None
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and hasattr(tracer, 'tls_manager'):
            return tracer.tls_manager.create_client_ssl_context()
    except (ImportError, AttributeError):
        pass
    return None


# Tools that accept extra_args and support header-style flags
_AUTH_INJECTABLE_TOOLS: dict[str, str] = {
    # tool_name -> header flag format
    "httpx_probe": "-H",
    "httpx_full_analysis": "-H",
    "katana_crawl": "-H",
    "nuclei_scan": "-header",
    "nuclei_scan_cves": "-header",
    "nuclei_scan_misconfigs": "-header",
    "ffuf_directory_scan": "-H",
    "ffuf_parameter_fuzz": "-H",
    "ffuf_vhost_fuzz": "-H",
    "sqlmap_test": "--headers",
    "sqlmap_forms": "--headers",
    "sqlmap_dump_database": "--headers",
}


def _inject_auth_headers(
    tool_name: str | None, tool_args: dict[str, Any], agent_state: Any | None
) -> dict[str, Any]:
    """Auto-inject auth headers into security tools that support extra_args.

    Reads auth_headers from:
    1. Scan config (user-provided at scan start)
    2. Session token store (auto-captured during scanning from login responses)
    Appends appropriate header flags to the tool's extra_args parameter.
    """
    if not tool_name or tool_name not in _AUTH_INJECTABLE_TOOLS:
        return tool_args

    auth_headers: dict[str, str] = {}

    # Source 1: User-provided auth headers from scan config
    try:
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and tracer.scan_config:
            config_headers = tracer.scan_config.get("auth_headers")
            if config_headers:
                auth_headers.update(config_headers)
    except (ImportError, AttributeError):
        pass

    # Source 2: Auto-captured session tokens from proxy_manager
    try:
        from phantom.tools.proxy.proxy_manager import get_auth_token_store
        session_tokens = get_auth_token_store()
        for hdr_name, hdr_value in session_tokens.items():
            if hdr_name not in auth_headers:
                auth_headers[hdr_name] = hdr_value
    except (ImportError, AttributeError):
        pass

    if not auth_headers:
        return tool_args

    flag = _AUTH_INJECTABLE_TOOLS[tool_name]
    header_parts: list[str] = []
    if flag == "--headers":
        # SQLMap: --headers="Header1: val1\nHeader2: val2"
        # V2-BUG-004 FIX: Use allowlist instead of denylist for header values.
        # Only permit safe characters to prevent all injection vectors.
        import re as _re_hdr
        import shlex as _shlex_h
        _SAFE_HDR_RE = _re_hdr.compile(r'^[a-zA-Z0-9_\-=./: ]+$')
        hdr_lines_parts: list[str] = []
        for n, v in auth_headers.items():
            safe_name = str(n).strip()
            safe_value = str(v).strip()
            if not _SAFE_HDR_RE.match(safe_name) or not _SAFE_HDR_RE.match(safe_value):
                _logger.warning("Skipping unsafe auth header: %s", safe_name)
                continue
            hdr_lines_parts.append(f"{safe_name}: {safe_value}")
        if not hdr_lines_parts:
            return tool_args
        hdr_lines = "\\n".join(hdr_lines_parts)
        header_parts.append(f'--headers={_shlex_h.quote(hdr_lines)}')
    else:
    # V2-BUG-004 FIX: Use allowlist validation for header values
        import re as _re_hdr2
        import shlex as _shlex
        _SAFE_HDR_RE2 = _re_hdr2.compile(r'^[a-zA-Z0-9_\-=./: ]+$')
        for name, value in auth_headers.items():
            safe_name = str(name).strip()
            safe_value = str(value).strip()
            if not _SAFE_HDR_RE2.match(safe_name) or not _SAFE_HDR_RE2.match(safe_value):
                _logger.warning("Skipping unsafe auth header: %s", safe_name)
                continue
            header_parts.append(f"{flag} {_shlex.quote(f'{safe_name}: {safe_value}')}")

    header_str = " ".join(header_parts)
    existing = tool_args.get("extra_args", "") or ""
    if existing:
        tool_args["extra_args"] = f"{existing} {header_str}"
    else:
        tool_args["extra_args"] = header_str

    return tool_args


def _check_error_result(result: Any) -> tuple[bool, Any]:
    is_error = False
    error_payload: Any = None

    if (isinstance(result, dict) and "error" in result) or (
        isinstance(result, str) and result.strip().lower().startswith("error:")
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


def _format_tool_result(tool_name: str, result: Any) -> tuple[str, list[dict[str, Any]]]:
    images: list[dict[str, Any]] = []

    screenshot_data = extract_screenshot_from_result(result)
    if screenshot_data:
        images.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{screenshot_data}"},
            }
        )
        result_str = remove_screenshot_from_result(result)
    else:
        result_str = result

    if result_str is None:
        final_result_str = f"Tool {tool_name} executed successfully"
    else:
        final_result_str = str(result_str)
        # BUG-05 FIX: Scanner tools (nuclei, sqlmap, nmap, ffuf) need higher
        # limits — their structured output contains multiple findings that get
        # destroyed by aggressive truncation. 18K for scanners, 8K for others.
        # Increased from 12K/6K — nuclei now returns richer fields (references,
        # curl commands, extracted results) that need more space.
        _scanner_tools = {"nuclei_scan", "sqlmap_test", "sqlmap_forms", "nmap_scan",
                          "ffuf_directory_scan", "katana_crawl", "httpx_probe",
                          "nuclei_scan_cves", "nuclei_scan_misconfigs", "nmap_vuln_scan"}
        _trunc_limit = 18000 if tool_name in _scanner_tools else 8000
        _start_chars = _trunc_limit // 2
        _end_chars = _trunc_limit // 2
        if len(final_result_str) > _trunc_limit:
            start_part = final_result_str[:_start_chars]
            end_part = final_result_str[-_end_chars:]
            # Snap to nearest newline to avoid cutting mid-line/mid-tag
            last_nl = start_part.rfind('\n')
            if last_nl > 2000:
                start_part = start_part[:last_nl]
            first_nl = end_part.find('\n')
            if first_nl != -1 and first_nl < 500:
                end_part = end_part[first_nl + 1:]
            omitted = len(final_result_str) - len(start_part) - len(end_part)
            final_result_str = (
                start_part
                + f"\n\n... [{omitted} characters truncated] ...\n\n"
                + end_part
            )

    # BUG-17 FIX: Use CDATA to avoid double-encoding security payloads
    # (XSS/SQLi payloads in results were being HTML-escaped, hiding reflections)
    # v0.9.39: Sanitize tool output before it enters LLM context
    from phantom.core.feature_flags import is_enabled as _ff_enabled
    if _ff_enabled("PHANTOM_FF_OUTPUT_SANITIZER"):
        from phantom.tools.output_sanitizer import sanitize_tool_output, tag_tool_output
        raw_for_hash = final_result_str
        final_result_str = sanitize_tool_output(final_result_str, tool_name)
        final_result_str = tag_tool_output(tool_name, raw_for_hash, final_result_str)

    observation_xml = (
        f"<tool_result>\n<tool_name>{_xml_escape(tool_name)}</tool_name>\n"
        f"<result><![CDATA[{final_result_str.replace(']]>', ']]]]><![CDATA[>')}]]></result>\n</tool_result>"
    )

    return observation_xml, images


async def _execute_single_tool(
    tool_inv: dict[str, Any],
    agent_state: Any | None,
    tracer: Any | None,
    agent_id: str,
) -> tuple[str, list[dict[str, Any]], bool]:
    tool_name = tool_inv.get("toolName", "unknown")
    args = tool_inv.get("args", {})
    execution_id = None
    should_agent_finish = False

    if tracer:
        execution_id = tracer.log_tool_execution_start(agent_id, tool_name, args)

    _start_ts = _time.monotonic()
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

        # ── Auto-record findings to persistent ledger ──
        _auto_record_findings(tool_name, result, agent_state)

        # ── Track tested endpoints for deduplication ──
        _track_tested_endpoint(tool_name, tool_inv.get("args", {}), agent_state)

        # ── Audit logging ──
        _duration_ms = (_time.monotonic() - _start_ts) * 1000
        try:
            from phantom.core.audit_logger import get_global_audit_logger

            _audit = get_global_audit_logger()
            if _audit:
                _summary = None
                if isinstance(result, dict):
                    _summary = result.get("message", result.get("error", None))
                elif isinstance(result, str):
                    _summary = result[:200] if len(result) > 200 else result
                _audit.log_tool_call(
                    tool_name,
                    args,
                    agent_id=agent_id,
                    result_summary=str(_summary) if _summary else None,
                    success=not is_error,
                    duration_ms=round(_duration_ms, 2),
                )
        except Exception as exc:  # noqa: BLE001
            _logger.debug("Audit log failed for tool %s: %s", tool_name, exc)

    except (ConnectionError, RuntimeError, ValueError, TypeError, OSError) as e:
        _duration_ms = (_time.monotonic() - _start_ts) * 1000
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        # Audit log the failure
        try:
            from phantom.core.audit_logger import get_global_audit_logger

            _audit = get_global_audit_logger()
            if _audit:
                _audit.log_tool_call(
                    tool_name,
                    args,
                    agent_id=agent_id,
                    result_summary=error_msg[:200],
                    success=False,
                    duration_ms=round(_duration_ms, 2),
                )
        except Exception as exc:  # noqa: BLE001
            _logger.debug("Audit log failed for tool error %s: %s", tool_name, exc)
        raise

    observation_xml, images = _format_tool_result(tool_name, result)
    return observation_xml, images, should_agent_finish


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

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    for tool_inv in tool_invocations:
        try:
            observation_xml, images, tool_should_finish = await _execute_single_tool(
                tool_inv, agent_state, tracer, agent_id
            )
        except (SecurityViolationError, ResourceExhaustedError):
            raise  # CRIT-01 FIX: Never swallow security/resource errors
        except Exception as exc:  # noqa: BLE001
            # Capture error as a tool result so results from prior tools are preserved
            tool_name = tool_inv.get("toolName", "unknown")
            error_text = f"Error executing {tool_name}: {str(exc)[:500]}"
            observation_xml = (
                f"<tool_result>\n<tool_name>{_xml_escape(tool_name)}</tool_name>\n"
                f"<result>{_xml_escape(error_text)}</result>\n</tool_result>"
            )
            images = []
            tool_should_finish = False
        observation_parts.append(observation_xml)
        all_images.extend(images)

        if tool_should_finish:
            should_agent_finish = True

    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(observation_parts)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(observation_parts)
        conversation_history.append({"role": "user", "content": observation_content})

    return should_agent_finish


# ── G-01 FIX: Parallel recon batch execution ────────────────────────────
# Independent recon tools (httpx, nmap, nuclei, katana, ffuf) can run
# concurrently inside the sandbox.  This function wraps asyncio.gather()
# with per-tool error isolation so one failure doesn't block the batch.

# Tools that are safe to run concurrently (read-only recon, no shared state)
_PARALLELIZABLE_TOOLS: frozenset[str] = frozenset({
    "nmap_scan", "nmap_vuln_scan",
    "httpx_probe", "httpx_full_analysis",
    "nuclei_scan", "nuclei_scan_cves", "nuclei_scan_misconfigs",
    "ffuf_directory_scan", "ffuf_parameter_fuzz", "ffuf_vhost_fuzz",
    "katana_crawl",
    "subfinder_scan",
})


async def batch_execute_tools(
    tool_invocations: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    agent_state: Any | None = None,
    *,
    max_concurrency: int = 4,
) -> bool:
    """Execute multiple independent tool invocations in parallel.

    Splits *tool_invocations* into parallelizable and sequential buckets.
    Parallelizable tools run via ``asyncio.gather`` (bounded by a semaphore
    to avoid sandbox overload).  Sequential tools (e.g. ``finish_scan``) run
    one-by-one afterwards.

    Returns ``True`` if any tool signals the agent should finish.
    """
    import asyncio as _aio
    from phantom.core.feature_flags import is_enabled

    parallel: list[dict[str, Any]] = []
    sequential: list[dict[str, Any]] = []

    for inv in tool_invocations:
        name = inv.get("toolName", "")
        if name in _PARALLELIZABLE_TOOLS:
            parallel.append(inv)
        else:
            sequential.append(inv)

    # If nothing is parallelizable, fall back to the sequential path
    if not parallel:
        return await process_tool_invocations(tool_invocations, conversation_history, agent_state)

    observation_parts: list[str] = []
    all_images: list[dict[str, Any]] = []
    should_agent_finish = False

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    # ── Run parallel batch ───────────────────────────────────────────
    sem = _aio.Semaphore(max_concurrency)

    async def _guarded(inv: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
        async with sem:
            # v0.9.39: Per-tool timeout + security error propagation
            try:
                return await _aio.wait_for(
                    _execute_single_tool(inv, agent_state, tracer, agent_id),
                    timeout=SANDBOX_EXECUTION_TIMEOUT,
                )
            except _aio.TimeoutError:
                tname = inv.get("toolName", "unknown")
                _logger.warning(
                    "Parallel tool %s timed out after %ds",
                    tname, SANDBOX_EXECUTION_TIMEOUT,
                )
                xml = (
                    f"<tool_result>\n<tool_name>{_xml_escape(tname)}</tool_name>\n"
                    f"<result>Error: Tool execution timed out</result>\n</tool_result>"
                )
                return xml, [], False
            except (SecurityViolationError, ResourceExhaustedError):
                raise  # Propagate security errors — must terminate scan
            except Exception as exc:  # noqa: BLE001
                tname = inv.get("toolName", "unknown")
                err = f"Error executing {tname}: {str(exc)[:500]}"
                xml = (
                    f"<tool_result>\n<tool_name>{_xml_escape(tname)}</tool_name>\n"
                    f"<result>{_xml_escape(err)}</result>\n</tool_result>"
                )
                return xml, [], False

    results = await _aio.gather(*[_guarded(inv) for inv in parallel])
    for obs_xml, imgs, finish in results:
        observation_parts.append(obs_xml)
        all_images.extend(imgs)
        if finish:
            should_agent_finish = True

    # v0.9.39: Cost check between parallel and sequential batches
    # V2-BUG-010 FIX: Use public method instead of accessing private _check_limits
    if is_enabled("PHANTOM_FF_PARALLEL_SAFETY"):
        try:
            from phantom.core.cost_controller import get_cost_controller
            cc = get_cost_controller()
            if cc:
                cc.check_limits()
        except (ImportError, AttributeError):
            pass

    # ── Run sequential remainder ─────────────────────────────────────
    for inv in sequential:
        try:
            obs_xml, imgs, finish = await _execute_single_tool(inv, agent_state, tracer, agent_id)
        except (SecurityViolationError, ResourceExhaustedError):
            raise  # CRIT-02 FIX: Never swallow security/resource errors
        except Exception as exc:  # noqa: BLE001
            tname = inv.get("toolName", "unknown")
            err = f"Error executing {tname}: {str(exc)[:500]}"
            obs_xml = (
                f"<tool_result>\n<tool_name>{_xml_escape(tname)}</tool_name>\n"
                f"<result>{_xml_escape(err)}</result>\n</tool_result>"
            )
            imgs = []
            finish = False
        observation_parts.append(obs_xml)
        all_images.extend(imgs)
        if finish:
            should_agent_finish = True

    # ── Append combined results to conversation ──────────────────────
    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(observation_parts)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(observation_parts)
        conversation_history.append({"role": "user", "content": observation_content})

    _logger.info(
        "G-01: batch_execute_tools — %d parallel + %d sequential tools processed.",
        len(parallel), len(sequential),
    )
    return should_agent_finish


def extract_screenshot_from_result(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None

    screenshot = result.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        return screenshot

    return None


# ── v0.9.33: Auto-report pipeline ──────────────────────────────────────
# The #1 root cause of low vuln count: nuclei/sqlmap find real vulns but
# they are NEVER reported because the LLM must manually call
# create_vulnerability_report with 16 parameters.  This function auto-
# converts scanner findings into proper vulnerability reports.

_SEVERITY_TO_CVSS: dict[str, dict[str, str]] = {
    "critical": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "high":     {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "medium":   {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "low":      {"AV": "N", "AC": "H", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
}


def _auto_report_scanner_findings(scanner: str, findings: list[dict], agent_state: Any) -> None:
    """Auto-create vulnerability reports from scanner findings without LLM involvement.

    This bridges the gap between 'nuclei found 40 findings' and '0 vulnerability reports'.
    Only reports medium+ severity to avoid flooding with info disclosures.
    """
    try:
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if not tracer:
            return

        existing = tracer.get_existing_vulnerabilities()
        existing_titles = {r.get("title", "").lower() for r in existing}
        reported = 0

        for f in findings:
            if scanner == "nuclei":
                sev = f.get("severity", "info").lower()
                if sev not in ("critical", "high", "medium", "low"):
                    continue
                name = f.get("name") or f.get("template_name") or f.get("template_id", "unknown")
                url = f.get("matched_at") or f.get("host", "")
                desc = f.get("description", "") or f"Detected by Nuclei template {f.get('template_id', '')}"
                tags = f.get("tags", "")
                refs = f.get("references", [])
                curl_cmd = f.get("curl_command", "")
                title = f"{name} at {url.split('?')[0]}" if url else name

                # Skip if already reported (simple title dedup)
                if title.lower() in existing_titles:
                    continue

                poc = curl_cmd if curl_cmd else f"Nuclei template: {f.get('template_id', 'N/A')}"
                if refs:
                    poc += "\nReferences: " + ", ".join(refs[:3])

                impact = f"{sev.upper()} severity vulnerability detected by automated scanning."
                remediation = f"Investigate and remediate the {name} finding. Tags: {tags}"
                if refs:
                    remediation += f"\nSee: {refs[0]}"

            elif scanner == "sqlmap":
                sev = "critical"
                url = f.get("url", f.get("target", "?"))
                params = f.get("injection_points", f.get("vulnerable_params", []))
                title = f"SQL Injection at {url.split('?')[0]}"
                if title.lower() in existing_titles:
                    continue
                desc = f"SQLMap confirmed SQL injection at {url} with parameters: {params}"
                poc = f"sqlmap -u '{url}' --batch --level=3 --risk=2"
                impact = "CRITICAL: Full database read/write access via SQL injection."
                remediation = "Use parameterized queries. Implement input validation."
            else:
                continue

            # Map severity to CVSS params
            cvss_map = _SEVERITY_TO_CVSS.get(sev, _SEVERITY_TO_CVSS["medium"])

            try:
                from phantom.tools.reporting.reporting_actions import (
                    calculate_cvss_and_severity,
                )
                cvss_score, severity_str, cvss_vector = calculate_cvss_and_severity(
                    cvss_map["AV"], cvss_map["AC"], cvss_map["PR"], cvss_map["UI"],
                    cvss_map["S"], cvss_map["C"], cvss_map["I"], cvss_map["A"],
                )
            except Exception:
                cvss_score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0}.get(sev, 5.0)
                severity_str = sev
                cvss_vector = ""

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=desc[:500],
                severity=severity_str,
                impact=impact,
                target=url or "unknown",
                technical_analysis=f"Detected by {scanner} automated scanner. {desc[:300]}",
                poc_description=poc[:500],
                poc_script_code="",
                remediation_steps=remediation[:500],
                cvss=cvss_score,
                cvss_breakdown=cvss_map,
                endpoint=url.split("?")[0] if url and "?" in url else url,
                method="GET",
            )

            if report_id:
                existing_titles.add(title.lower())
                reported += 1

            if reported >= 100:  # Safety cap per scanner call
                break

        if reported > 0:
            _logger.info("Auto-reported %d %s findings as vulnerability reports", reported, scanner)

    except Exception as exc:
        _logger.debug("Auto-report failed for %s: %s", scanner, exc)


def _auto_record_findings(tool_name: str, result: Any, agent_state: Any) -> None:
    """Automatically record key findings from security tool results to the
    persistent findings ledger.  This ensures critical discoveries survive
    memory compression even if the agent forgets to call ``record_finding``.

    V2-DESIGN-002: Findings are tracked via FindingProvenanceTracker for
    dedup (O(1) hash lookup) and source attribution (AUTO vs LLM).
    """
    if not isinstance(result, dict):
        return
    # Tools with explicit "success" field: require it to be truthy.
    # Tools WITHOUT "success" (e.g. send_request): allow through.
    if "success" in result and not result.get("success"):
        return
    if not agent_state or not hasattr(agent_state, "add_finding"):
        return

    def _tracked_add_finding(description: str) -> None:
        """Wrapper that deduplicates via provenance tracker before adding."""
        if _finding_tracker is not None:
            added = _finding_tracker.add(description, tool_name, FindingSource.AUTO)
            if added is None:
                return  # Duplicate — skip
        agent_state.add_finding(description)

    try:
        # --- Nuclei ---
        if tool_name in ("nuclei_scan", "nuclei_scan_cves", "nuclei_scan_misconfigs"):
            findings = result.get("findings", [])
            # v0.9.33 FIX: Record ALL severity levels (was medium+ only — lost 40 findings)
            for f in findings[:30]:
                sev = f.get("severity", "unknown").lower()
                name = f.get("template_name") or f.get("name") or f.get("template_id", "unknown")
                url = f.get("matched_at") or f.get("host", "")
                if sev in ("critical", "high", "medium", "low"):
                    verified_tag = "[UNVERIFIED] " if sev in ("critical", "high") else ""
                    _tracked_add_finding(f"[vuln/nuclei] {verified_tag}{sev.upper()} {name} at {url}")
                elif sev in ("unknown", "info") and name:
                    _tracked_add_finding(f"[info/nuclei] {name} at {url}")
                # Queue for verification if EnhancedAgentState supports it
                if sev in ("critical", "high") and hasattr(agent_state, "unverified_findings"):
                    agent_state.unverified_findings.append({
                        "tool": "nuclei", "severity": sev, "name": name, "url": url,
                    })

            # v0.9.33 FIX: AUTO-REPORT nuclei findings as vulnerabilities
            # This is the #1 impact fix — nuclei found 40 findings but 0 were reported.
            _auto_report_scanner_findings("nuclei", findings, agent_state)

        # --- Nmap ---
        elif tool_name == "nmap_scan":
            for host in result.get("hosts", []):
                hostname = host.get("hostname", host.get("ip", "?"))
                ports = host.get("ports", [])
                open_ports = [p for p in ports if p.get("state") == "open"]
                if open_ports:
                    port_list = ", ".join(
                        f"{p['port']}/{p.get('service','?')}" for p in open_ports[:20]
                    )
                    _tracked_add_finding(f"[recon/nmap] {hostname}: {port_list}")

        # --- Katana ---
        elif tool_name == "katana_crawl":
            total = result.get("total_urls", 0)
            api_count = result.get("summary", {}).get("api_endpoints", 0)
            js_count = result.get("summary", {}).get("js_files", 0)
            form_count = result.get("summary", {}).get("forms", 0)
            if total > 0:
                _tracked_add_finding(
                    f"[recon/katana] {total} URLs discovered "
                    f"({api_count} APIs, {js_count} JS, {form_count} forms)"
                )
            for ep in result.get("api_endpoints", [])[:10]:
                url = ep.get("url", "")
                if url:
                    _tracked_add_finding(f"[endpoint] API: {url}")
                    # BUG-07 FIX: Wire add_endpoint for structured tracking
                    if hasattr(agent_state, "add_endpoint"):
                        agent_state.add_endpoint(url)
            # Also register crawled URLs as endpoints
            for url in result.get("urls", [])[:100]:
                if isinstance(url, str) and hasattr(agent_state, "add_endpoint"):
                    agent_state.add_endpoint(url)

        # --- Httpx ---
        elif tool_name in ("httpx_probe", "httpx_full_analysis"):
            for host in result.get("findings", result.get("results", [])):
                url = host.get("url", "")
                tech = host.get("tech", host.get("technologies", []))
                status = host.get("status_code", "")
                if url:
                    parts = [f"[recon/httpx] {url} ({status})"]
                    if tech:
                        parts.append(f"  tech: {', '.join(tech[:5])}")
                    _tracked_add_finding(" ".join(parts))
                    # BUG-07 FIX: Wire add_endpoint for structured tracking
                    if hasattr(agent_state, "add_endpoint"):
                        agent_state.add_endpoint(url)

        # --- Nmap vuln ---
        elif tool_name == "nmap_vuln_scan":
            for vuln in result.get("vulnerabilities", []):
                title = vuln.get("title", "unknown vuln")
                _tracked_add_finding(f"[vuln/nmap] {title}")

        # --- Vulnerability Report ---
        elif tool_name == "create_vulnerability_report":
            title = result.get("message", "")
            severity = result.get("severity", "unknown")
            cvss = result.get("cvss_score", "?")
            report_id = result.get("report_id", "")
            _tracked_add_finding(
                f"[vuln/report] {severity.upper()} (CVSS {cvss}) {title}"
            )
            # Also populate EnhancedAgentState vulnerability tracking
            if hasattr(agent_state, "add_vulnerability") and report_id:
                try:
                    from phantom.telemetry.tracer import get_global_tracer
                    from phantom.tools.finish.finish_actions import _dict_to_vulnerability
                    tracer = get_global_tracer()
                    if tracer:
                        for r in tracer.vulnerability_reports:
                            if r.get("id") == report_id:
                                vuln_model = _dict_to_vulnerability(r)
                                if vuln_model:
                                    agent_state.add_vulnerability(vuln_model)
                                    # Mark as verified — the agent has confirmed this vuln
                                    if hasattr(agent_state, "mark_vuln_verified"):
                                        agent_state.mark_vuln_verified(vuln_model.id)
                                break
                except Exception as exc:  # noqa: BLE001
                    _logger.debug("Auto-record findings failed for %s: %s", tool_name, exc)

        # --- SQLMap ---
        elif tool_name in ("sqlmap_test", "sqlmap_forms", "sqlmap_dump_database"):
            if result.get("vulnerable"):
                url = result.get("url", result.get("target", "?"))
                # BUG-13 FIX: sqlmap returns "injection_points", not "vulnerable_params"
                params = result.get("injection_points", result.get("vulnerable_params", []))
                _tracked_add_finding(
                    f"[vuln/sqlmap] SQLi CONFIRMED at {url} params={params}"
                )
            elif tool_name == "sqlmap_dump_database":
                tables = result.get("tables", [])
                if tables:
                    _tracked_add_finding(
                        f"[data/sqlmap] DB dump: {len(tables)} tables extracted"
                    )

        # --- FFuf ---
        elif tool_name in ("ffuf_directory_scan", "ffuf_parameter_fuzz", "ffuf_vhost_fuzz"):
            findings = result.get("findings", [])
            for f in findings[:15]:
                url = f.get("url", f.get("input", ""))
                status = f.get("status", "")
                size = f.get("length", f.get("words", ""))
                _tracked_add_finding(
                    f"[recon/ffuf] {url} (status={status} size={size})"
                )
                # BUG-07 FIX: Wire add_endpoint for structured tracking
                if url and hasattr(agent_state, "add_endpoint"):
                    agent_state.add_endpoint(url)

        # --- Subfinder ---
        elif tool_name == "subfinder_enumerate":
            subdomains = result.get("subdomains", [])
            if subdomains:
                _tracked_add_finding(
                    f"[recon/subfinder] {len(subdomains)} subdomains: "
                    + ", ".join(subdomains[:10])
                )

        # --- SQLMap auto-report ---
        # v0.9.33: Auto-report confirmed SQLi findings
        if tool_name in ("sqlmap_test", "sqlmap_forms") and result.get("vulnerable"):
            _auto_report_scanner_findings("sqlmap", [result], agent_state)

        # --- Send Request (manual testing) ---
        if tool_name in ("send_request", "repeat_request"):
            status = result.get("status_code", 0)
            url = str(result.get("url", ""))
            body = result.get("body", "")[:2000].lower()
            # Track endpoints
            if url and hasattr(agent_state, "add_endpoint"):
                agent_state.add_endpoint(url)
            # Record interesting HTTP responses
            if status in (200, 201, 301, 302, 403, 500) and url:
                _tracked_add_finding(f"[recon/request] {url} (status={status})")
            # Detect SQLi indicators in response
            if any(kw in body for kw in ("sql", "syntax error", "sqlite", "sequelize",
                                          "unrecognized token", "near \"")):
                _tracked_add_finding(f"[vuln/sqli-indicator] SQL error in response from {url}")
            # Detect XSS reflection
            if "<script" in body or "javascript:" in body or "onerror" in body:
                _tracked_add_finding(f"[vuln/xss-indicator] Script reflection at {url}")
            # Detect sensitive data exposure
            if any(kw in body for kw in ("password", "secret", "api_key", "private_key")):
                _tracked_add_finding(f"[vuln/info-disclosure] Sensitive data at {url}")

    except Exception as exc:  # noqa: BLE001
        _logger.warning("auto-record findings failed for %s: %s", tool_name, exc, exc_info=True)


def remove_screenshot_from_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result

    result_copy = result.copy()
    if "screenshot" in result_copy:
        # H11 FIX: validate the data before passing it along
        raw = result_copy["screenshot"]
        if isinstance(raw, str) and len(raw) > 10_000_000:  # >~7.5 MB decoded
            result_copy["screenshot"] = "[Screenshot too large — removed]"
        else:
            result_copy["screenshot"] = "[Image data extracted - see attached image]"

    return result_copy


def _track_tested_endpoint(tool_name: str, args: dict[str, Any], agent_state: Any) -> None:
    """Track which endpoints have been tested to avoid duplicate testing."""
    if not agent_state or not hasattr(agent_state, "mark_endpoint_tested"):
        return

    try:
        # L17 FIX: use module-level constant instead of recreating per call
        test_type = _ENDPOINT_TOOLS_MAP.get(tool_name)
        if not test_type:
            return

        url = args.get("url") or args.get("target") or args.get("target_url") or ""
        method = args.get("method", "GET").upper()
        parameter = args.get("parameter") or args.get("param") or ""

        if url:
            agent_state.mark_endpoint_tested(url, method, parameter, test_type)
    except Exception as e:  # noqa: BLE001
        _logger.debug("auto-record findings failed: %s", e, exc_info=True)
