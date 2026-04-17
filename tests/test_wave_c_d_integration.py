import asyncio
from types import SimpleNamespace

import pytest


def test_wave_c_runtime_allowlist_no_longer_blocks_valid_registered_tool() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import execute_tool_with_validation

    state = AgentState(task="wave-c-allowlist")
    state._runtime_llm = SimpleNamespace(runtime_allowed_tools={"get_scan_status"})

    with pytest.raises(Exception, match="Tool not allowed"):
        asyncio.run(
            execute_tool_with_validation(
                "list_todos",
                state,
                allowed_tools={"get_scan_status"},
            )
        )


def test_wave_c_runtime_allowlist_allows_permitted_tool() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import execute_tool_with_validation
    from phantom.tools.scan_status.scan_status_actions import set_scan_status_context

    state = AgentState(task="wave-c-allowlist-ok")
    state._runtime_llm = SimpleNamespace(runtime_allowed_tools={"get_scan_status"})
    set_scan_status_context(agent_state=state)

    result = asyncio.run(
        execute_tool_with_validation(
            "get_scan_status",
            state,
            allowed_tools={"get_scan_status"},
            include_recommendations=False,
        )
    )
    assert isinstance(result, dict)
    assert "scan_progress" in result


def test_wave_c_runtime_allowlist_missing_fails_closed() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import execute_tool_with_validation

    state = AgentState(task="wave-c-allowlist-missing")

    with pytest.raises(Exception, match="Tool not allowed"):
        asyncio.run(execute_tool_with_validation("get_scan_status", state, include_recommendations=False))


def test_wave_d_local_context_binding_sets_current_agent_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.context import get_current_agent_id
    from phantom.tools.python.python_manager import get_python_session_manager
    from phantom.tools.executor import execute_tool_with_validation

    state = AgentState(task="wave-d-context")
    state.sandbox_id = None
    state.sandbox_token = None
    state.sandbox_info = None
    before = get_current_agent_id()

    manager = get_python_session_manager()

    import phantom.tools.executor as executor_mod

    monkeypatch.setattr(executor_mod, "should_execute_in_sandbox", lambda _tool: False)

    try:
        result = asyncio.run(
            execute_tool_with_validation(
                "python_action",
                state,
                allowed_tools={"python_action"},
                action="list_sessions",
            )
        )
    finally:
        pass

    assert isinstance(result, dict)

    # Ensure context is restored to prior value after execution.
    after = get_current_agent_id()
    assert after == before

    manager.cleanup_agent(state.agent_id)

    # Ensure context is restored to prior value after execution.
    after = get_current_agent_id()
    assert after == before


@pytest.mark.asyncio
async def test_wave_d_base_agent_passes_scan_config_to_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.agents.base_agent import BaseAgent

    captured: dict[str, object] = {}

    class DummyRuntime:
        async def create_sandbox(
            self,
            agent_id: str,
            existing_token: str | None = None,
            local_sources: list[dict[str, str]] | None = None,
            scan_config: dict | None = None,
        ):
            captured["agent_id"] = agent_id
            captured["scan_config"] = scan_config
            return {
                "workspace_id": "ws-1",
                "api_url": "http://127.0.0.1:9999",
                "auth_token": "tok",
                "tool_server_port": 9999,
                "caido_port": 48080,
                "agent_id": agent_id,
            }

    class MinimalAgent:
        _initialize_sandbox_and_state = BaseAgent._initialize_sandbox_and_state
        _restore_sub_agents_from_checkpoint = BaseAgent._restore_sub_agents_from_checkpoint

    agent = MinimalAgent()
    agent.state = SimpleNamespace(
        agent_id="agent-wave-d",
        parent_id=None,
        sandbox_id=None,
        sandbox_token=None,
        sandbox_info=None,
        task="",
        messages=[],
        add_message=lambda role, content, **kwargs: None,
    )
    agent.local_sources = []
    agent.config = {}

    import phantom.runtime as runtime_mod
    from phantom.telemetry.tracer import Tracer, set_global_tracer

    tracer = Tracer("wave-d-runtime")
    tracer.set_scan_config({"targets": [{"type": "web_application", "details": {"target_url": "http://example.com"}}]})
    set_global_tracer(tracer)

    monkeypatch.setenv("PHANTOM_SANDBOX_MODE", "false")

    monkeypatch.setattr(runtime_mod, "get_runtime", lambda: DummyRuntime())
    await agent._initialize_sandbox_and_state("task")

    assert isinstance(captured.get("scan_config"), dict)
    assert "targets" in captured["scan_config"]


def test_wave_d_checkpoint_build_captures_active_sub_agents() -> None:
    from phantom.agents.state import AgentState
    from phantom.checkpoint.checkpoint import CheckpointManager

    root_state = AgentState(task="root-task", agent_name="Root", parent_id=None)
    child_state = AgentState(task="child-task", agent_name="Child", parent_id=root_state.agent_id)

    cp = CheckpointManager.build(
        run_name="wave-d-checkpoint",
        state=root_state,
        tracer=None,
        scan_config={"run_name": "wave-d-checkpoint"},
        active_sub_agents={
            child_state.agent_id: {
                "state": child_state,
                "status": "running",
                "parent_id": root_state.agent_id,
            }
        },
    )

    assert child_state.agent_id in cp.sub_agent_states
    sub = cp.sub_agent_states[child_state.agent_id]
    assert sub["status"] == "running"
    assert sub["parent_id"] == root_state.agent_id
    assert sub["state"]["task"] == "child-task"
