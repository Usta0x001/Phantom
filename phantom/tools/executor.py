import html
import inspect
import os
import time
import base64
import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from phantom.config import Config


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


_SERVER_TIMEOUT = float(Config.get("phantom_sandbox_execution_timeout") or "120")
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
)


async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"

    # ── Audit: log tool invocation ─────────────────────────────────────────
    from phantom.logging.audit import get_audit_logger as _get_audit
    _audit = _get_audit()
    _agent_id = getattr(agent_state, "agent_id", "unknown") or "unknown"
    _exec_id = _audit.log_tool_start(_agent_id, tool_name, kwargs) if _audit else None
    _t0 = time.monotonic()
    # ──────────────────────────────────────────────────────────────────
    try:
        if execute_in_sandbox and not sandbox_mode:
            result = await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)
        else:
            result = await _execute_tool_locally(tool_name, agent_state, **kwargs)
        if _audit and _exec_id:
            _audit.log_tool_result(
                _exec_id, _agent_id, tool_name, result,
                (time.monotonic() - _t0) * 1000,
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
        "naabu":                    1500,   # port scan: repetitive IP:port lines
        "nmap":                     3000,   # nmap: structured, compact enough at 3K
        "grep":                     2000,   # grep: line matches, keep tight
        "curl":                     2000,   # curl: HTTP response headers/body snippets
        "ffuf":                     3000,   # directory fuzzer: many short lines
        "nikto":                    4000,   # nikto: medium-density findings
        "terminal_execute":         4000,   # generic terminal: down from 6K
        "browser_action":           3000,   # browser HTML dumps are verbose/boilerplate
        "nuclei":                   5000,   # vuln scanner: high-value, keep more
        "sqlmap":                   5000,   # SQL injection: detailed payloads matter
        "create_vulnerability_report": 12000,  # reports: need full detail
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
        if len(final_result_str) > limit:
            # ── Smart extraction for high-noise tools ─────────────────────────
            # Try to distil the output down to the signal lines before falling
            # back to the generic head+tail approach.
            extracted: str | None = None
            if tool_name == "ffuf":
                extracted = _extract_ffuf_findings(final_result_str, limit)
            elif tool_name in {"nmap", "naabu"}:
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

    observation_xml = (
        f"<tool_result>\n<tool_name>{html.escape(tool_name)}</tool_name>\n"
        f"<result>{html.escape(final_result_str)}</result>\n</tool_result>"
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


def remove_screenshot_from_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result

    result_copy = result.copy()
    if "screenshot" in result_copy:
        result_copy["screenshot"] = "[Image data extracted - see attached image]"

    return result_copy
