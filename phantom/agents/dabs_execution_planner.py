"""Deterministic execution planner driven by DABS-selected hypotheses.

This module converts a kernel-selected hypothesis into one concrete tool
invocation. It must remain deterministic and avoid LLM-based ranking.
"""

from __future__ import annotations

from typing import Any

from phantom.agents.expert_layer import (
    build_structured_hypothesis,
    propose_payload_candidates,
)


def _pick_method(vuln_class: str) -> str:
    vuln = str(vuln_class).strip().lower()
    if vuln in {"sqli", "xss", "idor", "xxe", "ssrf", "open_redirect", "auth_bypass", "lfi", "path_traversal"}:
        return "GET"
    return "POST"


def _base_from_surface(surface: str) -> str:
    value = str(surface or "").strip()
    if not value:
        return "/"
    base = value.split("::", 1)[0].strip()
    if not base.startswith("/") and not base.startswith("http://") and not base.startswith("https://"):
        base = "/" + base
    return base or "/"


def _param_from_surface(surface: str) -> str:
    value = str(surface or "").strip()
    if "::" not in value:
        return "q"
    param = value.split("::", 1)[1].strip().split("#", 1)[0].split("?", 1)[0]
    return param or "q"


def _join_url(base_url: str, path_or_url: str) -> str:
    p = str(path_or_url or "").strip()
    if p.startswith("http://") or p.startswith("https://"):
        return p
    b = str(base_url or "").strip().rstrip("/")
    if not b:
        return p if p.startswith("/") else f"/{p}"
    return f"{b}{p if p.startswith('/') else '/' + p}"


def plan_tool_invocation(
    selected_hypothesis: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build one deterministic tool invocation from selected hypothesis."""

    if not selected_hypothesis:
        return None

    surface = str(selected_hypothesis.get("surface") or "").strip()
    vuln_class = str(selected_hypothesis.get("vuln_class") or "").strip().lower()
    if not surface or not vuln_class:
        return None

    context_obj = dict(context or {})
    target_url = str(context_obj.get("target_url") or "").strip()

    structured = build_structured_hypothesis(
        vuln_class=vuln_class,
        target_surface=surface,
        preconditions=[],
        expected_exploit_path=f"Probe {surface} for {vuln_class}",
        required_signals=["status_change", "error_signal", "response_delta"],
        metadata={"source": "dabs_execution_planner"},
    )

    candidates = propose_payload_candidates(structured)
    payload = candidates[0] if candidates else "baseline_test"
    method = _pick_method(vuln_class)
    base = _base_from_surface(surface)
    param = _param_from_surface(surface)

    if method == "GET":
        connector = "&" if "?" in base else "?"
        path_or_url = f"{base}{connector}{param}={payload}"
        body = ""
    else:
        path_or_url = base
        body = f"{param}={payload}"

    url = _join_url(target_url, path_or_url)

    return {
        "toolName": "send_request",
        "args": {
            "method": method,
            "url": url,
            "headers": {"User-Agent": "Phantom-DABS/strict"},
            "body": body,
            "timeout": 30,
            "follow_redirects": False,
        },
        "dabs_selected_hypothesis_id": selected_hypothesis.get("hypothesis_id"),
        "dabs_selected_vuln_class": vuln_class,
        "dabs_selected_surface": surface,
    }


def plan_bootstrap_invocations(context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Build deterministic bootstrap actions when no hypothesis is selectable.

    Strict-mode bootstrap is deterministic and never sourced from LLM tool calls.
    """

    context_obj = dict(context or {})
    target_url = str(context_obj.get("target_url") or "").strip()

    if target_url:
        return [
            {
                "toolName": "send_request",
                "args": {
                    "method": "GET",
                    "url": target_url,
                    "headers": {"User-Agent": "Phantom-DABS/bootstrap"},
                    "body": "",
                    "timeout": 30,
                    "follow_redirects": False,
                },
                "dabs_bootstrap": True,
            }
        ]

    return [{"toolName": "list_requests", "args": {}, "dabs_bootstrap": True}]
