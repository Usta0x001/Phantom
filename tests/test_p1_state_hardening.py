from phantom.tools.scan_status.scan_status_actions import (
    clear_scan_status_context,
    get_scan_status,
    set_scan_status_context,
)


class _State:
    def __init__(self, agent_id: str, iteration: int, max_iterations: int = 100) -> None:
        self.agent_id = agent_id
        self.iteration = iteration
        self.max_iterations = max_iterations


def test_scan_status_context_is_agent_scoped() -> None:
    s1 = _State("agent-a", 5)
    s2 = _State("agent-b", 77)

    set_scan_status_context(agent_state=s1)
    set_scan_status_context(agent_state=s2)

    status_a = get_scan_status(include_recommendations=False, agent_id="agent-a")
    status_b = get_scan_status(include_recommendations=False, agent_id="agent-b")

    assert status_a["scan_progress"]["iteration"] == 5
    assert status_b["scan_progress"]["iteration"] == 77


def test_scan_status_context_can_be_cleared() -> None:
    s = _State("agent-clear", 12)
    set_scan_status_context(agent_state=s)
    clear_scan_status_context()

    status = get_scan_status(include_recommendations=False, agent_id="agent-clear")
    assert status["scan_progress"]["iteration"] == 0


def test_tracer_cleanup_clears_global_tracer() -> None:
    from phantom.telemetry import get_global_tracer
    from phantom.telemetry.tracer import Tracer, clear_global_tracer
    from phantom.tools.cache import get_tool_cache
    from phantom.tools.context import reset_current_agent_id, set_current_agent_id
    from phantom.tools.hypothesis.hypothesis_actions import get_ledger, set_ledger
    from phantom.agents.hypothesis_ledger import HypothesisLedger

    clear_global_tracer()
    tracer = Tracer("cleanup-test")
    assert get_global_tracer() is None or get_global_tracer() is tracer
    token = set_current_agent_id("agent-cleanup")
    try:
        set_ledger(HypothesisLedger())
        assert get_ledger() is not None
    finally:
        reset_current_agent_id(token)
    cache = get_tool_cache()
    cache.put("read_file", {"path": "/tmp/test"}, "content")
    tracer.cleanup()
    assert get_global_tracer() is None
    assert get_tool_cache().get("read_file", {"path": "/tmp/test"}) is None
    token2 = set_current_agent_id("agent-cleanup")
    try:
        assert get_ledger() is None
    finally:
        reset_current_agent_id(token2)
