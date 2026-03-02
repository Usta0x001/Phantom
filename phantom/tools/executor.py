import inspect
import logging
import os
import time as _time
from html import escape as _xml_escape
from typing import Any

import httpx

from phantom.config import Config

_logger = logging.getLogger(__name__)

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
    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"

    if execute_in_sandbox and not sandbox_mode:
        return await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)

    return await _execute_tool_locally(tool_name, agent_state, **kwargs)


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

    # ---- Tool Firewall check (PHT security controls) ----
    try:
        from phantom.core.tool_firewall import get_tool_firewall
        fw = get_tool_firewall()
        if fw is not None:
            violation = fw.validate(tool_name or "", tool_args)
            if violation is not None:
                import logging as _fw_log
                _fw_log.getLogger("phantom.security.firewall").warning(
                    "Tool call BLOCKED by firewall: %s — %s", tool_name, violation.get("error")
                )
                return violation
    except ImportError:
        import logging as _fw_log
        _fw_log.getLogger("phantom.security.firewall").critical(
            "Tool firewall module UNAVAILABLE — security controls degraded"
        )

    # Auto-inject auth headers for security tools that support extra_args
    tool_args = _inject_auth_headers(tool_name, tool_args, agent_state)

    return await execute_tool_with_validation(tool_name, agent_state, **tool_args)


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
        # SEC-007 FIX: Strip CRLF from header names and values
        hdr_lines = "\\n".join(
            f"{n.replace(chr(13),'').replace(chr(10),'')}: {v.replace(chr(13),'').replace(chr(10),'')}"
            for n, v in auth_headers.items()
        )
        header_parts.append(f'--headers="{hdr_lines}"')
    else:
        # PHT-004 FIX: Use shlex.quote for each header value to prevent
        # shell metacharacter injection via double-quote breakout.
        # SEC-007 FIX: Also strip \r\n (CRLF) to prevent HTTP header injection.
        import shlex as _shlex
        for name, value in auth_headers.items():
            # Validate header name/value don't contain injection chars
            safe_name = str(name).replace('"', '').replace("'", "").replace(";", "").replace("\r", "").replace("\n", "")
            safe_value = str(value).replace('"', '').replace(";", "").replace("`", "").replace("\r", "").replace("\n", "")
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
        if len(final_result_str) > 10000:
            # Reduced from 16K to 10K — saves ~1.5K tokens/call, still
            # preserves critical findings from nuclei/katana/sqlmap.
            start_part = final_result_str[:4500]
            end_part = final_result_str[-4500:]
            # Snap to nearest newline to avoid cutting mid-line/mid-tag
            last_nl = start_part.rfind('\n')
            if last_nl > 3500:
                start_part = start_part[:last_nl]
            first_nl = end_part.find('\n')
            if first_nl != -1 and first_nl < 900:
                end_part = end_part[first_nl + 1:]
            omitted = len(final_result_str) - len(start_part) - len(end_part)
            final_result_str = (
                start_part
                + f"\n\n... [{omitted} characters truncated] ...\n\n"
                + end_part
            )

    observation_xml = (
        f"<tool_result>\n<tool_name>{_xml_escape(tool_name)}</tool_name>\n"
        f"<result>{_xml_escape(final_result_str)}</result>\n</tool_result>"
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


def extract_screenshot_from_result(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None

    screenshot = result.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        return screenshot

    return None


def _auto_record_findings(tool_name: str, result: Any, agent_state: Any) -> None:
    """Automatically record key findings from security tool results to the
    persistent findings ledger.  This ensures critical discoveries survive
    memory compression even if the agent forgets to call ``record_finding``."""
    if not isinstance(result, dict) or not result.get("success"):
        return
    if not agent_state or not hasattr(agent_state, "add_finding"):
        return

    try:
        # --- Nuclei ---
        if tool_name in ("nuclei_scan", "nuclei_scan_cves", "nuclei_scan_misconfigs"):
            findings = result.get("findings", [])
            for f in findings[:15]:
                sev = f.get("severity", "info")
                if sev in ("critical", "high", "medium"):
                    name = f.get("template_name") or f.get("template_id", "unknown")
                    url = f.get("matched_at") or f.get("host", "")
                    # ARCH-003 FIX: Tag HIGH/CRITICAL findings as unverified
                    verified_tag = "[UNVERIFIED] " if sev in ("critical", "high") else ""
                    agent_state.add_finding(f"[vuln/nuclei] {verified_tag}{sev.upper()} {name} at {url}")
                    # Queue for verification if EnhancedAgentState supports it
                    if sev in ("critical", "high") and hasattr(agent_state, "unverified_findings"):
                        agent_state.unverified_findings.append({
                            "tool": "nuclei", "severity": sev, "name": name, "url": url,
                        })

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
                    agent_state.add_finding(f"[recon/nmap] {hostname}: {port_list}")

        # --- Katana ---
        elif tool_name == "katana_crawl":
            total = result.get("total_urls", 0)
            api_count = result.get("summary", {}).get("api_endpoints", 0)
            js_count = result.get("summary", {}).get("js_files", 0)
            form_count = result.get("summary", {}).get("forms", 0)
            if total > 0:
                agent_state.add_finding(
                    f"[recon/katana] {total} URLs discovered "
                    f"({api_count} APIs, {js_count} JS, {form_count} forms)"
                )
            for ep in result.get("api_endpoints", [])[:10]:
                url = ep.get("url", "")
                if url:
                    agent_state.add_finding(f"[endpoint] API: {url}")
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
                    agent_state.add_finding(" ".join(parts))
                    # BUG-07 FIX: Wire add_endpoint for structured tracking
                    if hasattr(agent_state, "add_endpoint"):
                        agent_state.add_endpoint(url)

        # --- Nmap vuln ---
        elif tool_name == "nmap_vuln_scan":
            for vuln in result.get("vulnerabilities", []):
                title = vuln.get("title", "unknown vuln")
                agent_state.add_finding(f"[vuln/nmap] {title}")

        # --- Vulnerability Report ---
        elif tool_name == "create_vulnerability_report":
            title = result.get("message", "")
            severity = result.get("severity", "unknown")
            cvss = result.get("cvss_score", "?")
            report_id = result.get("report_id", "")
            agent_state.add_finding(
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
                params = result.get("vulnerable_params", [])
                agent_state.add_finding(
                    f"[vuln/sqlmap] SQLi CONFIRMED at {url} params={params}"
                )
            elif tool_name == "sqlmap_dump_database":
                tables = result.get("tables", [])
                if tables:
                    agent_state.add_finding(
                        f"[data/sqlmap] DB dump: {len(tables)} tables extracted"
                    )

        # --- FFuf ---
        elif tool_name in ("ffuf_directory_scan", "ffuf_parameter_fuzz", "ffuf_vhost_fuzz"):
            findings = result.get("findings", [])
            for f in findings[:15]:
                url = f.get("url", f.get("input", ""))
                status = f.get("status", "")
                size = f.get("length", f.get("words", ""))
                agent_state.add_finding(
                    f"[recon/ffuf] {url} (status={status} size={size})"
                )
                # BUG-07 FIX: Wire add_endpoint for structured tracking
                if url and hasattr(agent_state, "add_endpoint"):
                    agent_state.add_endpoint(url)

        # --- Subfinder ---
        elif tool_name == "subfinder_enumerate":
            subdomains = result.get("subdomains", [])
            if subdomains:
                agent_state.add_finding(
                    f"[recon/subfinder] {len(subdomains)} subdomains: "
                    + ", ".join(subdomains[:10])
                )

    except Exception as exc:  # noqa: BLE001
        _logger.debug("auto-record findings swallowed: %s", exc, exc_info=True)


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
