from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from ..tui_design_system import WARNING_AMBER
from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer
