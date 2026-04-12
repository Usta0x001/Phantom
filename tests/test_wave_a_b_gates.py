from types import SimpleNamespace

import pytest


def test_wave_a_scan_status_recommendation_handles_discovered_surface() -> None:
    from phantom.agents.coverage_tracker import CoverageTracker
    from phantom.tools.scan_status.scan_status_actions import _compute_recommendation

    tracker = CoverageTracker()
    tracker.discover_surface(
        surface="/api/users/{id}",
        surface_type="endpoint",
        source="unit_test",
    )

    recommendation = _compute_recommendation(
        hyp_ledger=None,
        cov_tracker=tracker,
        corr_engine=None,
        phase="TESTING",
    )

    assert recommendation.startswith("Test untested surface:")
    assert "/api/users/{id}" in recommendation


def test_wave_a_auto_hypothesis_uses_agent_ledger_not_legacy_global() -> None:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.tools.executor import _auto_record_hypothesis

    ledger = HypothesisLedger()
    agent_state = SimpleNamespace(hypothesis_ledger=ledger)

    tool_inv = {
        "toolName": "send_request",
        "args": {
            "url": "http://example.com/api/login",
            "method": "POST",
            "body": "username=admin&password=' OR 1=1--",
        },
    }

    _auto_record_hypothesis(
        tool_inv=tool_inv,
        observation_xml="vulnerable injectable sqlmap back-end dbms",
        agent_state=agent_state,
        vuln_signals=["sql_injection signal found"],
    )

    all_hypotheses = ledger.get_all()
    assert len(all_hypotheses) == 1
    hyp = next(iter(all_hypotheses.values()))
    assert hyp.vuln_class == "auto_extraction"
    assert hyp.status == "testing"
    assert any("sql_injection" in payload for payload in hyp.payloads_tested)


@pytest.mark.asyncio
async def test_wave_a_status_injection_failure_emits_structured_event() -> None:
    from phantom.agents.base_agent import BaseAgent
    from phantom.telemetry.tracer import Tracer

    class MinimalAgent:
        _process_iteration = BaseAgent._process_iteration

    agent = MinimalAgent()
    agent.state = SimpleNamespace(
        iteration=10,
        max_iterations=100,
        agent_id="agent-wave-a",
        parent_id=None,
        get_conversation_history=lambda: [{"role": "user", "content": "x"}] * 60,
        add_message=lambda role, content, **kwargs: None,
    )
    class _LenZero:
        def __len__(self) -> int:
            return 0

    agent.hypothesis_ledger = _LenZero()
    agent.coverage_tracker = _LenZero()
    agent.correlation_engine = _LenZero()
    agent._last_iteration_action_count = 0

    async def _raise_generate(_history):
        if False:
            yield None
        raise RuntimeError("llm-stop")

    agent.llm = SimpleNamespace(generate=_raise_generate)

    tracer = Tracer("wave-a-status-event")
    captured: list[dict[str, object]] = []

    original_record_runtime_event = tracer.record_runtime_event

    def _wrapped_record_runtime_event(*args, **kwargs):
        event_type = kwargs.get("event_type")
        if event_type is None and args:
            event_type = args[0]
        payload = kwargs.get("payload")
        status = kwargs.get("status")
        actor = kwargs.get("actor")
        error = kwargs.get("error")
        source = kwargs.get("source")
        captured.append(
            {
                "event_type": event_type,
                "payload": payload,
                "status": status,
                "actor": actor,
                "error": error,
                "source": source,
            }
        )
        return original_record_runtime_event(*args, **kwargs)

    tracer.record_runtime_event = _wrapped_record_runtime_event

    try:
        # Force status injection failure inside the local import block.
        from phantom.tools.scan_status import scan_status_actions

        original_fn = scan_status_actions.get_scan_status

        def _boom(*args, **kwargs):
            raise ValueError("forced status failure")

        scan_status_actions.get_scan_status = _boom

        with pytest.raises(Exception):
            await agent._process_iteration(tracer)
    finally:
        scan_status_actions.get_scan_status = original_fn

    matching = [e for e in captured if e["event_type"] == "scan_status.injection.failed"]
    assert matching, "Expected structured status injection failure event"
    event = matching[0]
    assert event["status"] == "error"
    payload = event["payload"]
    assert isinstance(payload, dict)
    assert payload.get("error_type") == "ValueError"


def test_wave_b_hardened_injection_guard_blocks_semicolon_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.executor import _validate_tool_argument_injection

    monkeypatch.setenv("PHANTOM_SECURITY_MODE", "hardened")

    err = _validate_tool_argument_injection(
        "terminal_execute",
        {"command": "nmap 127.0.0.1; rm -rf /tmp/x"},
    )
    assert err is not None
    assert "blocked" in err.lower()


def test_wave_b_hardened_python_safety_blocks_os_system(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.python.python_instance import _validate_code_safety

    monkeypatch.setenv("PHANTOM_SECURITY_MODE", "hardened")

    err = _validate_code_safety("import os\nos.system('id')")
    assert err is not None
    assert "blocked" in err.lower()


@pytest.mark.asyncio
async def test_wave_b_hardened_rbac_denies_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.executor import execute_tool

    monkeypatch.setenv("PHANTOM_SECURITY_MODE", "hardened")
    monkeypatch.setenv("PHANTOM_RBAC_ENABLED", "false")

    result = await execute_tool("list_todos")
    assert isinstance(result, dict)
    assert result.get("error_type") == "rbac_misconfigured"


def test_wave_b_circuit_breaker_toggle_controls_generate_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, LLMRequestFailedError, _CIRCUIT_BREAKER

    monkeypatch.setenv("PHANTOM_LLM", "openai/gpt-4o-mini")
    monkeypatch.setenv("PHANTOM_CIRCUIT_BREAKER_ENABLED", "false")
    monkeypatch.setenv("PHANTOM_LLM_MAX_RETRIES", "0")
    monkeypatch.setenv("PHANTOM_LLM_RATELIMIT_MAX_RETRIES", "0")

    llm = LLM(LLMConfig(scan_mode="quick"), agent_name="Test")
    _CIRCUIT_BREAKER.reset()
    _CIRCUIT_BREAKER.record_failure()
    _CIRCUIT_BREAKER.record_failure()
    _CIRCUIT_BREAKER.record_failure()
    _CIRCUIT_BREAKER.record_failure()
    _CIRCUIT_BREAKER.record_failure()

    async def _fake_stream(_messages):
        if False:
            yield None
        raise RuntimeError("downstream-call-attempted")

    llm._stream = _fake_stream  # type: ignore[assignment]

    async def _run() -> None:
        async for _ in llm.generate([{"role": "user", "content": "hello"}]):
            pass

    try:
        with pytest.raises(LLMRequestFailedError) as exc_info:
            asyncio.run(_run())

        # Toggle=false should bypass early OPEN-gate error and reach downstream path.
        assert "circuit breaker is OPEN" not in str(exc_info.value)
    finally:
        _CIRCUIT_BREAKER.reset()


def test_wave_b_circuit_breaker_toggle_disables_open_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.llm.llm import _CIRCUIT_BREAKER, CircuitState, _is_circuit_breaker_enabled

    _CIRCUIT_BREAKER.reset()

    try:
        # Simulate an open breaker from prior failures.
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        assert _CIRCUIT_BREAKER.get_state() == CircuitState.OPEN

        monkeypatch.setenv("PHANTOM_CIRCUIT_BREAKER_ENABLED", "false")
        assert _is_circuit_breaker_enabled() is False

        # Open breaker must not deny when toggle is disabled.
        assert _CIRCUIT_BREAKER.allow_request() is False
    finally:
        _CIRCUIT_BREAKER.reset()


def test_wave_b_circuit_breaker_toggle_enables_open_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, LLMRequestFailedError, _CIRCUIT_BREAKER, CircuitState, _is_circuit_breaker_enabled

    _CIRCUIT_BREAKER.reset()
    try:
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        _CIRCUIT_BREAKER.record_failure()
        assert _CIRCUIT_BREAKER.get_state() == CircuitState.OPEN

        monkeypatch.setenv("PHANTOM_CIRCUIT_BREAKER_ENABLED", "true")
        assert _is_circuit_breaker_enabled() is True

        # Open breaker must deny when toggle is enabled.
        assert _CIRCUIT_BREAKER.allow_request() is False

        monkeypatch.setenv("PHANTOM_LLM", "openai/gpt-4o-mini")
        llm = LLM(LLMConfig(scan_mode="quick"), agent_name="TestEnabled")

        async def _run() -> None:
            async for _ in llm.generate([{"role": "user", "content": "hello"}]):
                pass

        with pytest.raises(LLMRequestFailedError) as exc_info:
            asyncio.run(_run())

        assert "circuit breaker is OPEN" in str(exc_info.value)
    finally:
        _CIRCUIT_BREAKER.reset()
