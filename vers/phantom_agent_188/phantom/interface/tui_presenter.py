from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phantom.interface.tui_design_system import build_agent_tree_label


@dataclass(frozen=True)
class StatusViewModel:
    message: str | None
    keymap_hint: str | None
    should_animate: bool
    mode: str


@dataclass(frozen=True)
class LayoutViewModel:
    hide_sidebar: bool
    full_width_chat: bool


def gather_agent_events(tracer: Any, agent_id: str) -> list[dict[str, Any]]:
    chat_events = [
        {
            "type": "chat",
            "timestamp": msg["timestamp"],
            "id": f"chat_{msg['message_id']}",
            "data": msg,
        }
        for msg in tracer.chat_messages
        if msg.get("agent_id") == agent_id
    ]

    tool_events = [
        {
            "type": "tool",
            "timestamp": tool_data["timestamp"],
            "id": f"tool_{exec_id}",
            "data": tool_data,
        }
        for exec_id, tool_data in list(tracer.tool_executions.items())
        if tool_data.get("agent_id") == agent_id
    ]

    events = chat_events + tool_events
    events.sort(key=lambda event: (event["timestamp"], event["id"]))
    return events


def build_agent_label(agent_data: dict[str, Any], vulnerability_count: int) -> str:
    return build_agent_tree_label(
        agent_name=agent_data.get("name", "Agent"),
        status=agent_data.get("status", "running"),
        vulnerability_count=vulnerability_count,
    )


def should_refresh_chat(
    current_event_ids: list[str],
    displayed_event_ids: list[str],
    current_streaming_len: int,
    last_streaming_len: int,
) -> bool:
    return not (
        current_event_ids == displayed_event_ids and current_streaming_len == last_streaming_len
    )


def compute_layout_view_model(width: int, sidebar_min_width: int) -> LayoutViewModel:
    hide_sidebar = width < sidebar_min_width
    return LayoutViewModel(hide_sidebar=hide_sidebar, full_width_chat=hide_sidebar)


def build_streaming_tool_lines(tool_name: str, args: dict[str, str], is_complete: bool) -> list[str]:
    lines = [f"status={'completed' if is_complete else 'running'}", f"tool={tool_name}"]
    for key, value in list(args.items())[:3]:
        display_value = value if len(value) <= 100 else value[:97] + "..."
        lines.append(f"{key}={display_value}")
    return lines


def get_status_view_model(
    status: str,
    has_real_activity: bool,
    error_message: str | None = None,
) -> StatusViewModel:
    if status in {"stopping", "stopped", "completed"}:
        status_text = {
            "stopping": "Agent stopping...",
            "stopped": "Agent stopped",
            "completed": "Agent completed",
        }[status]
        return StatusViewModel(
            message=status_text,
            keymap_hint=None,
            should_animate=False,
            mode="static",
        )

    if status == "llm_failed":
        return StatusViewModel(
            message=error_message or "LLM request failed",
            keymap_hint="Send message to retry",
            should_animate=False,
            mode="error",
        )

    if status == "waiting":
        return StatusViewModel(
            message=" ",
            keymap_hint="Send message to resume",
            should_animate=False,
            mode="waiting",
        )

    if status == "running":
        if has_real_activity:
            return StatusViewModel(
                message="active",
                keymap_hint="ctrl-q quit",
                should_animate=True,
                mode="active",
            )
        return StatusViewModel(
            message="initializing",
            keymap_hint="ctrl-q quit",
            should_animate=True,
            mode="initializing",
        )

    return StatusViewModel(
        message=None,
        keymap_hint=None,
        should_animate=False,
        mode="hidden",
    )


def enrich_vulnerabilities_with_agents(
    vulnerabilities: list[dict[str, Any]],
    tracer: Any,
    agent_name_resolver: Any,
) -> list[dict[str, Any]]:
    enriched_vulns: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        enriched = dict(vulnerability)
        report_id = vulnerability.get("id", "")
        agent_name = agent_name_resolver(report_id)
        if agent_name:
            enriched["agent_name"] = agent_name
        enriched_vulns.append(enriched)
    return enriched_vulns
