import asyncio
import time
from argparse import Namespace

import pytest


def test_r1_tool_bypass_blocked() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import execute_tool_with_validation

    state = AgentState(task="r1")

    with pytest.raises(Exception, match="Tool not allowed"):
        asyncio.run(
            execute_tool_with_validation(
                "think",
                state,
                allowed_tools={"get_scan_status"},
                thought="blocked",
            )
        )


def test_r2_circuit_breaker_counts_exhausted_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, LLMRequestFailedError, _CIRCUIT_BREAKER

    class Boom(Exception):
        pass

    async def fake_stream(self, _messages):  # type: ignore[no-untyped-def]
        err = Boom("boom")
        err.status_code = 400
        raise err
        if False:
            yield None

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini", scan_mode="deep"), agent_name="PhantomAgent")
    llm._fallback_llm_name = None
    monkeypatch.setattr(llm, "_stream", fake_stream.__get__(llm, type(llm)))

    _CIRCUIT_BREAKER.reset()
    before = _CIRCUIT_BREAKER._failure_count

    with pytest.raises(LLMRequestFailedError):
        asyncio.run(_consume_generate(llm))

    after = _CIRCUIT_BREAKER._failure_count
    assert after == before + 1


async def _consume_generate(llm):  # type: ignore[no-untyped-def]
    async for _ in llm.generate([{"role": "user", "content": "x"}]):
        pass


def test_r3_resume_path_is_sanitized_and_confined(monkeypatch: pytest.MonkeyPatch) -> None:
    import os
    if os.name == "nt":
        pytest.skip("Windows path normalization differs from Unix")

    from phantom.interface import cli
    
    captured: dict[str, object] = {}

    class StopRun(Exception):
        pass

    class DummyCheckpointManager:
        def __init__(self, run_dir, interval=5):  # type: ignore[no-untyped-def]
            captured["run_dir"] = run_dir

        def load(self):  # type: ignore[no-untyped-def]
            raise StopRun()

    args = Namespace(resume_run="/tmp/evil", run_name="demo", targets_info=[])

    import phantom.checkpoint.checkpoint as cp_mod

    monkeypatch.setattr(cp_mod, "CheckpointManager", DummyCheckpointManager)

    with pytest.raises(StopRun):
        asyncio.run(cli.run_cli(args))

    assert str(captured["run_dir"]).startswith("phantom_runs")


def test_r4_wait_for_agents_async_non_blocking() -> None:
    import os
    if os.name == "nt":
        pytest.skip("timing test not reliable on Windows")

    from phantom.tools.executor import execute_tool_with_validation
    from phantom.tools.agents_graph import agents_graph_actions as aga

    class State:
        agent_id = "agent-r4"

    aga._agent_graph["nodes"]["child-r4"] = {"status": "running"}

    marks: dict[str, float] = {}
    t0 = time.monotonic()

    async def waiter() -> None:
        marks["wait_start"] = time.monotonic() - t0
        await execute_tool_with_validation(
            "wait_for_agents",
            State(),
            allowed_tools={"wait_for_agents"},
            agent_ids=["child-r4"],
            timeout_seconds=1,
        )
        marks["wait_done"] = time.monotonic() - t0

    async def ticker() -> None:
        marks["tick_start"] = time.monotonic() - t0
        await asyncio.sleep(0.1)
        marks["tick_done"] = time.monotonic() - t0

    async def _run_both() -> None:
        await asyncio.gather(waiter(), ticker())

    asyncio.run(_run_both())

    assert marks["tick_start"] < marks["wait_done"]
    assert marks["tick_done"] < marks["wait_done"]


def test_r5_scan_mode_rate_limit_is_per_agent() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import _apply_stealth_rate_limit

    stealth = AgentState(task="stealth")
    stealth.scan_mode = "stealth"
    deep = AgentState(task="deep")
    deep.scan_mode = "deep"

    asyncio.run(_apply_stealth_rate_limit("terminal_execute", stealth))

    start = time.monotonic()
    asyncio.run(_apply_stealth_rate_limit("terminal_execute", deep))
    deep_elapsed = time.monotonic() - start
    assert deep_elapsed < 0.2

    start = time.monotonic()
    asyncio.run(_apply_stealth_rate_limit("terminal_execute", stealth))
    stealth_elapsed = time.monotonic() - start
    assert stealth_elapsed >= 1.8


def test_r2_circuit_breaker_budget_failure_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, LLMRequestFailedError, _CIRCUIT_BREAKER

    monkeypatch.setenv("PHANTOM_MAX_COST", "0.0001")
    monkeypatch.setenv("PHANTOM_COST_ABORT_ON_LIMIT", "true")

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini", scan_mode="deep"), agent_name="PhantomAgent")
    _CIRCUIT_BREAKER.reset()
    llm._total_stats.cost = 1.0

    with pytest.raises(LLMRequestFailedError, match="Budget exceeded"):
        llm._check_budget()

    assert _CIRCUIT_BREAKER._failure_count == 1


def test_r6_scope_firewall_fail_closed() -> None:
    import os
    if os.name == "nt":
        pytest.skip("iptables not available on Windows")

    from types import SimpleNamespace
    from phantom.runtime.docker_runtime import DockerRuntime

    class FakeContainer:
        attrs = {"NetworkSettings": {"Gateway": "172.17.0.1"}}

        def reload(self) -> None:
            pass

        def exec_run(self, _cmd, user="root"):
            return SimpleNamespace(exit_code=1)

    with pytest.raises(RuntimeError, match="Scope firewall enforcement failed"):
        DockerRuntime._configure_scope_firewall(None, FakeContainer(), "1.1.1.1")


def test_r7_agent_graph_reset_on_new_root() -> None:
    from phantom.agents.PhantomAgent import PhantomAgent
    from phantom.llm.config import LLMConfig
    from phantom.tools.agents_graph import agents_graph_actions as aga

    a1 = PhantomAgent({"llm_config": LLMConfig(model_name="openai/gpt-4o-mini", scan_mode="deep")})
    first_root = a1.state.agent_id

    a2 = PhantomAgent({"llm_config": LLMConfig(model_name="openai/gpt-4o-mini", scan_mode="deep")})
    second_root = a2.state.agent_id

    assert aga._root_agent_id == second_root
    assert aga._root_agent_id != first_root
    assert len(aga._agent_graph["nodes"]) == 1
    assert second_root in aga._agent_graph["nodes"]


def test_r5_modes_do_not_cross_contaminate_concurrent() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.executor import _apply_stealth_rate_limit

    stealth = AgentState(task="stealth-concurrent")
    stealth.scan_mode = "stealth"
    deep = AgentState(task="deep-concurrent")
    deep.scan_mode = "deep"

    async def _run() -> tuple[float, float]:
        await _apply_stealth_rate_limit("terminal_execute", stealth)

        start_deep = time.monotonic()
        start_stealth = time.monotonic()

        async def _deep_call() -> float:
            await _apply_stealth_rate_limit("terminal_execute", deep)
            return time.monotonic() - start_deep

        async def _stealth_call() -> float:
            await _apply_stealth_rate_limit("terminal_execute", stealth)
            return time.monotonic() - start_stealth

        deep_elapsed, stealth_elapsed = await asyncio.gather(_deep_call(), _stealth_call())
        return deep_elapsed, stealth_elapsed

    deep_elapsed, stealth_elapsed = asyncio.run(_run())

    assert deep_elapsed < 0.2
    assert stealth_elapsed >= 1.8
