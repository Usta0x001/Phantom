from __future__ import annotations

from typing import Any

from rich.text import Text

from phantom.interface.tui_design_system import TOOL_STATUS_ICONS
from phantom.interface.tool_components.registry import get_tool_renderer


def render_completed_tool_card(tool_data: dict[str, Any]) -> Any:
    tool_name = tool_data.get("tool_name", "Unknown Tool")
    args = tool_data.get("args", {})
    status = tool_data.get("status", "unknown")
    result = tool_data.get("result")

    renderer = get_tool_renderer(tool_name)
    if renderer:
        widget = renderer.render(tool_data)
        return widget.renderable

    if tool_name in ("llm_error_details", "sandbox_error_details"):
        return _render_error_details(tool_name, args)

    text = Text()
    text.append("→ Using tool ")
    text.append(tool_name, style="bold blue")

    icon = TOOL_STATUS_ICONS.get(status, TOOL_STATUS_ICONS["unknown"])
    style = {
        "running": "yellow",
        "completed": "green",
        "failed": "red",
        "error": "red",
    }.get(status, "dim")
    text.append(" ")
    text.append(icon, style=style)

    if args:
        for key, value in list(args.items())[:5]:
            str_value = str(value)
            if len(str_value) > 500:
                str_value = str_value[:497] + "..."
            text.append("\n  ")
            text.append(key, style="dim")
            text.append(": ")
            text.append(str_value)

    if status in ["completed", "failed", "error"] and result:
        result_str = str(result)
        if len(result_str) > 1000:
            result_str = result_str[:997] + "..."
        text.append("\n")
        text.append("Result: ", style="bold")
        text.append(result_str)

    return text


def render_streaming_tool_card(tool_name: str, args: dict[str, str], is_complete: bool) -> Any:
    tool_data = {
        "tool_name": tool_name,
        "args": args,
        "status": "completed" if is_complete else "running",
        "result": None,
    }

    renderer = get_tool_renderer(tool_name)
    if renderer:
        widget = renderer.render(tool_data)
        return widget.renderable

    return render_default_streaming_tool(tool_name, args, is_complete)


def render_default_streaming_tool(tool_name: str, args: dict[str, str], is_complete: bool) -> Text:
    text = Text()

    if is_complete:
        text.append(TOOL_STATUS_ICONS["completed"] + " ", style="green")
    else:
        text.append(TOOL_STATUS_ICONS["running"] + " ", style="yellow")

    text.append("Using tool ", style="dim")
    text.append(tool_name, style="bold blue")

    if args:
        for key, value in list(args.items())[:3]:
            text.append("\n  ")
            text.append(key, style="dim")
            text.append(": ")
            display_value = value if len(value) <= 100 else value[:97] + "..."
            text.append(display_value, style="italic" if not is_complete else None)

    return text


def _render_error_details(tool_name: str, args: dict[str, Any]) -> Text:
    text = Text()
    if tool_name == "llm_error_details":
        text.append("✗ LLM Request Failed", style="red")
    else:
        text.append("✗ Sandbox Initialization Failed", style="red")
        if args.get("error"):
            text.append(f"\n{args['error']}", style="bold red")
    if args.get("details"):
        details = str(args["details"])
        if len(details) > 1000:
            details = details[:997] + "..."
        text.append("\nDetails: ", style="dim")
        text.append(details)
    return text