from phantom.agents.dabs_execution_planner import plan_bootstrap_invocations


def test_strict_mode_uses_deterministic_bootstrap_with_target_url() -> None:
    actions = plan_bootstrap_invocations({"target_url": "http://example.local"})
    assert actions
    assert actions[0]["toolName"] == "send_request"
    assert actions[0]["args"]["url"].startswith("http://example.local")


def test_strict_mode_uses_deterministic_bootstrap_without_target_url() -> None:
    actions = plan_bootstrap_invocations({})
    assert actions
    assert actions[0]["toolName"] == "list_requests"
