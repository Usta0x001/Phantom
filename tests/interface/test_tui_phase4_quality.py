from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Static, TextArea

from phantom.interface.tui_components import PhantomShell
from phantom.interface.tui_design_system import (
    EMPTY_STATES,
    KEYBOARD_MODEL,
    SEVERITY_COLORS,
    SEVERITY_SEMANTICS,
    TOOL_STATUS_ICONS,
)
from phantom.interface.tui_presenter import (
    build_agent_label,
    compute_layout_view_model,
    gather_agent_events,
    get_status_view_model,
    should_refresh_chat,
)
from phantom.interface.tui_tool_cards import (
    render_default_streaming_tool,
)


def _collect_ids(node):
    found = set()
    node_id = getattr(node, "id", None)
    if node_id:
        found.add(node_id)
    for child in getattr(node, "children", []):
        found.update(_collect_ids(child))
    return found


class _TracerStub:
    def __init__(self) -> None:
        self.chat_messages = [
            {"timestamp": 3, "message_id": "3", "agent_id": "a"},
            {"timestamp": 1, "message_id": "1", "agent_id": "a"},
        ]
        self.tool_executions = {
            "z": {"timestamp": 2, "agent_id": "a"},
            "x": {"timestamp": 1, "agent_id": "a"},
        }


class _HighThroughputTracerStub:
    def __init__(self, n: int) -> None:
        self.chat_messages = [
            {"timestamp": i, "message_id": f"m{i}", "agent_id": "a"}
            for i in range(n)
        ]
        self.tool_executions = {
            f"t{i}": {"timestamp": i, "agent_id": "a"}
            for i in range(n)
        }


class _ShellMountApp(App):
    def compose(self) -> ComposeResult:
        yield PhantomShell(TextArea("", id="chat_input"), Static("", id="vulnerabilities_panel"))


def test_phase0_design_system_contracts_present() -> None:
    assert KEYBOARD_MODEL.help == "F1"
    assert EMPTY_STATES.no_agent_selected
    assert {"critical", "high", "medium", "low", "info"}.issubset(SEVERITY_COLORS.keys())
    assert {"critical", "high", "medium", "low", "info"}.issubset(SEVERITY_SEMANTICS.keys())
    assert {"running", "completed", "failed", "error", "unknown"}.issubset(
        TOOL_STATUS_ICONS.keys()
    )


def test_phase1_presenter_event_order_and_refresh_gate() -> None:
    tracer = _TracerStub()
    events = gather_agent_events(tracer, "a")
    ids = [ev["id"] for ev in events]
    assert ids == ["chat_1", "tool_x", "tool_z", "chat_3"]

    assert should_refresh_chat(["a"], ["a"], 10, 10) is False
    assert should_refresh_chat(["a"], [], 10, 0) is True


def test_phase1_status_vm_attack_unknown_status() -> None:
    status_vm = get_status_view_model("unknown-status", has_real_activity=False)
    assert status_vm.mode == "hidden"

    label = build_agent_label({"name": "agent-X", "status": "weird"}, 2)
    assert label.endswith("agent-X (2)")


@pytest.mark.asyncio
async def test_phase2_component_shell_contains_required_panes() -> None:
    app = _ShellMountApp()
    async with app.run_test():
        ids = {widget.id for widget in app.query("*") if widget.id}
        assert "main_container" in ids
        assert "content_container" in ids
        assert "chat_area_container" in ids
        assert "chat_history" in ids
        assert "chat_input_container" in ids
        assert "agents_tree" in ids
        assert "vulnerabilities_panel" in ids


def test_phase4_resize_stress_layout_logic() -> None:
    for width in range(20, 260):
        vm = compute_layout_view_model(width=width, sidebar_min_width=120)
        if width < 120:
            assert vm.hide_sidebar is True
            assert vm.full_width_chat is True
        else:
            assert vm.hide_sidebar is False
            assert vm.full_width_chat is False


def test_phase4_streaming_tool_snapshot_like_render() -> None:
    render = render_default_streaming_tool(
        "terminal_execute",
        {"command": "echo hello", "cwd": "/tmp"},
        is_complete=False,
    )
    text = str(render)
    assert "Using tool" in text
    assert "terminal_execute" in text
    assert "command" in text


def test_phase4_high_throughput_event_stress() -> None:
    tracer = _HighThroughputTracerStub(2000)
    events = gather_agent_events(tracer, "a")
    assert len(events) == 4000
    assert events[0]["timestamp"] <= events[-1]["timestamp"]
    assert should_refresh_chat([e["id"] for e in events], [], 0, 0) is True
