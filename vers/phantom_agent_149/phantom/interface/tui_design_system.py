from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class TUITheme:
    bg: str = "#000000"
    fg: str = "#d4d4d4"
    muted: str = "#737373"
    accent: str = "#dc2626"
    warning: str = "#f59e0b"
    border: str = "#333333"


@dataclass(frozen=True)
class TUISpacing:
    xs: int = 0
    sm: int = 1
    md: int = 2
    lg: int = 3


@dataclass(frozen=True)
class TUIKeyboardModel:
    help: str = "F1"
    quit: str = "Ctrl+Q/C"
    stop_selected: str = "ESC"
    pause_all: str = "Ctrl+P"
    send_message: str = "Enter"
    switch_panels: str = "Tab"
    navigate_tree: str = "↑/↓"


@dataclass(frozen=True)
class TUIEmptyStates:
    no_agent_selected: str = "Select an agent from the tree to see its activity."
    no_agent_activity: str = "Starting agent..."


@dataclass(frozen=True)
class TUILoadingStates:
    app_boot: str = "Starting Phantom Agent"
    agent_init: str = "Initializing"


@dataclass(frozen=True)
class TUIErrorStates:
    llm_failed_default: str = "LLM request failed"
    interrupted_by_user: str = "Interrupted by user"


KEYBOARD_MODEL: Final[TUIKeyboardModel] = TUIKeyboardModel()
EMPTY_STATES: Final[TUIEmptyStates] = TUIEmptyStates()
LOADING_STATES: Final[TUILoadingStates] = TUILoadingStates()
ERROR_STATES: Final[TUIErrorStates] = TUIErrorStates()
THEME: Final[TUITheme] = TUITheme()
SPACING: Final[TUISpacing] = TUISpacing()


SEVERITY_COLORS: Final[dict[str, str]] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#2563eb",
}

SEVERITY_SEMANTICS: Final[dict[str, str]] = {
    "critical": "Immediate exploitation risk",
    "high": "Likely exploitable with impact",
    "medium": "Valid issue with constrained impact",
    "low": "Harder to exploit or low impact",
    "info": "Informational finding",
}


AGENT_STATUS_ICONS: Final[dict[str, str]] = {
    "running": "⚪",
    "waiting": "⏸",
    "completed": "🟢",
    "failed": "🔴",
    "stopped": "■",
    "stopping": "○",
    "llm_failed": "🔴",
}

TOOL_STATUS_ICONS: Final[dict[str, str]] = {
    "running": "●",
    "completed": "✓",
    "failed": "✗",
    "error": "✗",
    "unknown": "○",
}


SWEEP_COLORS: Final[list[str]] = [
    "#000000",
    "#031a09",
    "#052e16",
    "#0d4a2a",
    "#15803d",
    "#dc2626",
    "#4ade80",
    "#86efac",
]


def build_agent_tree_label(agent_name: str, status: str, vulnerability_count: int) -> str:
    icon = AGENT_STATUS_ICONS.get(status, "○")
    vuln_suffix = f" ({vulnerability_count})" if vulnerability_count > 0 else ""
    return f"{icon} {agent_name}{vuln_suffix}"
