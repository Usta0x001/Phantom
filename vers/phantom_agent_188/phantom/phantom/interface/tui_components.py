from __future__ import annotations

from typing import Any

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import Static, Tree


class CommandBar(Horizontal):
    def __init__(self, chat_input_widget: Any) -> None:
        chat_prompt = Static("> ", id="chat_prompt")
        chat_prompt.ALLOW_SELECT = False
        super().__init__(chat_prompt, chat_input_widget, id="chat_input_container")


class ChatTimelinePane(Vertical):
    def __init__(self, chat_input_widget: Any) -> None:
        chat_display = Static("", id="chat_display")
        chat_history = VerticalScroll(chat_display, id="chat_history")
        chat_history.can_focus = True

        status_text = Static("", id="status_text")
        status_text.ALLOW_SELECT = False
        keymap_indicator = Static("", id="keymap_indicator")
        keymap_indicator.ALLOW_SELECT = False

        agent_status_display = Horizontal(
            status_text, keymap_indicator, id="agent_status_display", classes="hidden"
        )

        command_bar = CommandBar(chat_input_widget)
        super().__init__(chat_history, agent_status_display, command_bar, id="chat_area_container")


class AgentGraphPane(Vertical):
    def __init__(self) -> None:
        self.agents_tree = Tree("Agents", id="agents_tree")
        self.agents_tree.root.expand()
        self.agents_tree.show_root = False
        self.agents_tree.show_guide = True
        self.agents_tree.guide_depth = 3
        self.agents_tree.guide_style = "dashed"
        super().__init__(self.agents_tree)


class VulnerabilityDrawer(Vertical):
    def __init__(self, vulnerabilities_panel_widget: Widget) -> None:
        self.vulnerabilities_panel = vulnerabilities_panel_widget
        super().__init__(self.vulnerabilities_panel)


class ToolCardsPane(Vertical):
    def __init__(self) -> None:
        super().__init__()


class PhantomShell(Vertical):
    def __init__(self, chat_input_widget: Any, vulnerabilities_panel_widget: Widget) -> None:
        main_timeline = ChatTimelinePane(chat_input_widget)

        graph_pane = AgentGraphPane()
        vulnerability_drawer = VulnerabilityDrawer(vulnerabilities_panel_widget)

        stats_display = Static("", id="stats_display")
        stats_scroll = VerticalScroll(stats_display, id="stats_scroll")
        sidebar = Vertical(
            graph_pane,
            vulnerability_drawer,
            stats_scroll,
            id="sidebar",
        )

        content_container = Horizontal(main_timeline, sidebar, id="content_container")
        super().__init__(content_container, id="main_container")


def mount_main_layout(app: Any, chat_input_widget: Any, vulnerabilities_panel_widget: Any) -> None:
    app.mount(PhantomShell(chat_input_widget, vulnerabilities_panel_widget))
