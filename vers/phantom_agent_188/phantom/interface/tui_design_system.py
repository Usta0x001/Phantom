from __future__ import annotations

from dataclasses import dataclass
from typing import Final


CANVAS_BG: Final[str] = "#050816"
SURFACE_BG: Final[str] = "#0b1220"
SURFACE_ALT_BG: Final[str] = "#0f1a2c"
TEXT_PRIMARY: Final[str] = "#e6eef8"
TEXT_MUTED: Final[str] = "#93a4bf"
TEXT_FAINT: Final[str] = "#a3a3a3"
TEXT_SHADOW: Final[str] = "#525252"
TEXT_SOFT: Final[str] = "#d4d4d4"
PRIMARY_CYAN: Final[str] = "#2dd4ff"
ACTION_CYAN: Final[str] = "#06b6d4"
ACTION_BLUE: Final[str] = "#3b82f6"
INFO_ROYAL: Final[str] = "#2563eb"
SUCCESS_EMERALD: Final[str] = "#2ee59d"
SUCCESS_GREEN: Final[str] = "#22c55e"
SUCCESS_LIME: Final[str] = "#4ade80"
SUCCESS_SOFT: Final[str] = "#86efac"
SUCCESS_TEAL: Final[str] = "#10b981"
WARNING_AMBER: Final[str] = "#f2b84b"
WARNING_YELLOW: Final[str] = "#eab308"
DANGER_RED: Final[str] = "#ef4444"
DANGER_ROSE: Final[str] = "#ff5d73"
DANGER_CRIMSON: Final[str] = "#dc2626"
SECONDARY_VIOLET: Final[str] = "#b58cff"
ACCENT_PURPLE: Final[str] = "#a78bfa"
ACCENT_LILAC: Final[str] = "#c084fc"
BORDER_SLATE: Final[str] = "#223452"
INFO_SKY: Final[str] = "#8ac6ff"
INFO_BLUE: Final[str] = "#60a5fa"
WARNING_GOLD: Final[str] = "#facc15"
WARNING_ORANGE: Final[str] = "#f59e0b"
WARNING_SOFT_ORANGE: Final[str] = "#ff8a5b"
WARNING_BRIGHT_ORANGE: Final[str] = "#f97316"
NEUTRAL_DOT: Final[str] = "#0a3d1f"
NEUTRAL_SLATE: Final[str] = "#6b7280"
NEUTRAL_STEEL: Final[str] = "#94a3b8"
NEUTRAL_DARK: Final[str] = "#475569"


@dataclass(frozen=True)
class TUITheme:
    bg: str = CANVAS_BG
    fg: str = TEXT_PRIMARY
    muted: str = TEXT_MUTED
    accent: str = PRIMARY_CYAN
    warning: str = WARNING_AMBER
    border: str = BORDER_SLATE


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
    "critical": DANGER_ROSE,
    "high": WARNING_SOFT_ORANGE,
    "medium": WARNING_AMBER,
    "low": SUCCESS_EMERALD,
    "info": PRIMARY_CYAN,
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
    CANVAS_BG,
    SURFACE_BG,
    SURFACE_ALT_BG,
    BORDER_SLATE,
    INFO_SKY,
    PRIMARY_CYAN,
    SUCCESS_EMERALD,
    SECONDARY_VIOLET,
    WARNING_AMBER,
    DANGER_ROSE,
]


def build_agent_tree_label(agent_name: str, status: str, vulnerability_count: int) -> str:
    icon = AGENT_STATUS_ICONS.get(status, "○")
    vuln_suffix = f" ({vulnerability_count})" if vulnerability_count > 0 else ""
    return f"{icon} {agent_name}{vuln_suffix}"
