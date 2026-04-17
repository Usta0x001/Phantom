import asyncio
from types import SimpleNamespace


def test_hypothesis_tools_execute_locally_not_in_sandbox() -> None:
    from phantom.tools.registry import should_execute_in_sandbox

    assert should_execute_in_sandbox("add_hypothesis") is False
    assert should_execute_in_sandbox("record_payload_test") is False
    assert should_execute_in_sandbox("confirm_hypothesis") is False
    assert should_execute_in_sandbox("reject_hypothesis") is False


def test_elite_reporting_tools_execute_locally_not_in_sandbox() -> None:
    from phantom.tools.registry import should_execute_in_sandbox

    assert should_execute_in_sandbox("create_elite_report") is False
    assert should_execute_in_sandbox("export_elite_report") is False


def test_detection_and_cve_auto_tools_execute_locally_not_in_sandbox() -> None:
    # Import modules explicitly so the tools are registered even when subset mode
    # does not preload extended modules.
    import phantom.tools.detection.detector  # noqa: F401
    import phantom.tools.vuln_intel.cve_auto_integration  # noqa: F401

    from phantom.tools.registry import should_execute_in_sandbox

    assert should_execute_in_sandbox("detect_pattern") is False
    assert should_execute_in_sandbox("detect_error_based") is False
    assert should_execute_in_sandbox("detect_timing_based") is False
    assert should_execute_in_sandbox("detect_differential") is False
    assert should_execute_in_sandbox("auto_queue_cve_exploits") is False
    assert should_execute_in_sandbox("enrich_hypothesis_with_cve") is False
    assert should_execute_in_sandbox("get_cve_exploitation_status") is False


def test_browser_tool_executes_locally_not_in_sandbox() -> None:
    from phantom.tools.registry import should_execute_in_sandbox

    assert should_execute_in_sandbox("browser_action") is False


def test_sandbox_tool_server_registers_browser_tool(monkeypatch) -> None:
    import importlib
    import sys

    monkeypatch.setenv("PHANTOM_SANDBOX_MODE", "true")

    for module_name in list(sys.modules):
        if module_name == "phantom.tools" or module_name.startswith("phantom.tools."):
            sys.modules.pop(module_name, None)

    importlib.import_module("phantom.tools")

    from phantom.tools.registry import get_tool_names

    assert "browser_action" in get_tool_names()


def test_prepare_messages_preserves_archive_then_live_order() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")

    captured = {}

    def _capture(messages, agent_state=None):  # type: ignore[no-untyped-def]
        captured["messages"] = list(messages)
        return messages

    llm.memory_compressor.compress_history = _capture  # type: ignore[method-assign]

    state = SimpleNamespace(
        get_archived_messages=lambda: [{"role": "user", "content": "archived-older"}],
        clear_archived_messages=lambda: None,
        finding_anchors=[],
    )
    llm.set_agent_state(state)

    history = [{"role": "user", "content": "live-newer"}]
    asyncio.run(llm._prepare_messages(history))

    seen = captured["messages"]
    assert seen[0]["content"] == "archived-older"
    assert seen[1]["content"] == "live-newer"


def test_auto_record_hypothesis_ignores_weak_scanner_signals() -> None:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.tools.executor import _auto_record_hypothesis

    ledger = HypothesisLedger()
    owner = SimpleNamespace(
        hypothesis_ledger=ledger,
        coverage_tracker=None,
        correlation_engine=None,
        attack_graph=None,
    )

    _auto_record_hypothesis(
        tool_inv={"toolName": "send_request", "args": {"url": "https://x", "method": "GET"}},
        observation_xml="<tool_result><result>signal only</result></tool_result>",
        agent_state=None,
        owner_agent=owner,
        vuln_signals=["SCANNER_HIGH: 2 high findings detected", "XSS_POTENTIAL: reflected pattern"],
    )

    assert len(ledger.get_all()) == 0


def test_html_and_headers_do_not_trigger_burst_truncation() -> None:
    from phantom.config.config import Config
    from phantom.tools.executor import _format_tool_result_with_meta, _get_truncation_limit

    body_prefix = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Security-Policy: default-src 'self'",
            "Set-Cookie: session=abc; HttpOnly; Secure",
            "X-Frame-Options: DENY",
            "<html>",
            "  <head>",
            "    <script>console.log('hello')</script>",
            "  </head>",
            "  <body>",
        ]
    ) + "\n"

    burst_limit = int(Config.get("phantom_terminal_truncation_burst_limit") or "8000")

    for tool_name in ("terminal_execute", "browser_action"):
        base_limit = _get_truncation_limit(tool_name)
        assert burst_limit > base_limit, "burst limit must exceed the base truncation limit"

        target_len = base_limit + min(1500, burst_limit - base_limit - 1)
        filler = "lorem ipsum dolor sit amet " * 600
        result = (body_prefix + filler)[:target_len]

        _, images, meta = _format_tool_result_with_meta(tool_name, result, image_slots_remaining=0)

        assert images == []
        assert meta["burst_applied"] is False
        assert meta["truncated"] is True
        assert meta["limit"] == base_limit
