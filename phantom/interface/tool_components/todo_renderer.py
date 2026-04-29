from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from ..tui_design_system import ACCENT_PURPLE, DANGER_RED, NEUTRAL_STEEL, WARNING_ORANGE
from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


STATUS_MARKERS: dict[str, str] = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "done": "[•]",
}


def _format_todo_lines(text: Text, result: dict[str, Any]) -> None:
    todos = result.get("todos")
    if not isinstance(todos, list) or not todos:
        text.append("\n  ")
        text.append("No todos", style="dim")
        return

    for todo in todos:
        status = todo.get("status", "pending")
        marker = STATUS_MARKERS.get(status, STATUS_MARKERS["pending"])

        title = todo.get("title", "").strip() or "(untitled)"

        text.append("\n  ")
        text.append(marker)
        text.append(" ")

        if status == "done":
            text.append(title, style="dim strike")
        elif status == "in_progress":
            text.append(title, style="italic")
        else:
            text.append(title)
