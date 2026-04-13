from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.util import ClassNotFound
from rich.text import Text
from textual.widgets import Static

from ..tui_design_system import ACCENT_PURPLE, DANGER_RED, SUCCESS_TEAL
from ._colors import get_token_color
from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


def _get_lexer_for_file(path: str) -> Any:
    try:
        return get_lexer_for_filename(path)
    except ClassNotFound:
        return get_lexer_by_name("text")


@register_tool_renderer
class StrReplaceEditorRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "str_replace_editor"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        return get_token_color(token_type)

    @classmethod
    def _highlight_code(cls, code: str, path: str) -> Text:
        lexer = _get_lexer_for_file(path)
        text = Text()

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue
            color = cls._get_token_color(token_type)
            text.append(token_value, style=color)

        return text

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        command = args.get("command", "")
        path = args.get("path", "")
        old_str = args.get("old_str", "")
        new_str = args.get("new_str", "")
        file_text = args.get("file_text", "")

        text = Text()

        icons_and_labels = {
            "view": ("◇ ", "read", SUCCESS_TEAL),
            "str_replace": ("◇ ", "edit", SUCCESS_TEAL),
            "create": ("◇ ", "create", SUCCESS_TEAL),
            "insert": ("◇ ", "insert", SUCCESS_TEAL),
            "undo_edit": ("◇ ", "undo", SUCCESS_TEAL),
        }

        icon, label, color = icons_and_labels.get(command, ("◇ ", "file", SUCCESS_TEAL))
        text.append(icon, style=color)
        text.append(label, style="dim")

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(" ")
            text.append(path_display, style="dim")

        if command == "str_replace" and (old_str or new_str):
            if old_str:
                highlighted_old = cls._highlight_code(old_str, path)
                for line in highlighted_old.plain.split("\n"):
                    text.append("\n")
                    text.append("-", style=DANGER_RED)
                    text.append(" ")
                    text.append(line)

            if new_str:
                highlighted_new = cls._highlight_code(new_str, path)
                for line in highlighted_new.plain.split("\n"):
                    text.append("\n")
                    text.append("+", style=SUCCESS_TEAL)
                    text.append(" ")
                    text.append(line)

        elif command == "create" and file_text:
            text.append("\n")
            text.append_text(cls._highlight_code(file_text, path))

        elif command == "insert" and new_str:
            highlighted_new = cls._highlight_code(new_str, path)
            for line in highlighted_new.plain.split("\n"):
                    text.append("\n")
                    text.append("+", style=SUCCESS_TEAL)
                    text.append(" ")
                    text.append(line)

        elif isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif not (result and isinstance(result, dict) and "content" in result) and not path:
            text.append(" ")
            text.append("Processing...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        path = args.get("path", "")

        text = Text()
        text.append("◇ ", style=SUCCESS_TEAL)
        text.append("list", style="dim")
        text.append(" ")

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(path_display, style="dim")
        else:
            text.append("Current directory", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class SearchFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "search_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        path = args.get("path", "")
        regex = args.get("regex", "")

        text = Text()
        text.append("◇ ", style=ACCENT_PURPLE)
        text.append("search", style="dim")
        text.append("  ")

        if path and regex:
            text.append(path, style="dim")
            text.append(" ", style="dim")
            text.append(regex, style=ACCENT_PURPLE)
        elif path:
            text.append(path, style="dim")
        elif regex:
            text.append(regex, style=ACCENT_PURPLE)
        else:
            text.append("...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)
