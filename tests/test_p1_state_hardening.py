from phantom.tools.scan_status.scan_status_actions import get_scan_status, set_scan_status_context


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
