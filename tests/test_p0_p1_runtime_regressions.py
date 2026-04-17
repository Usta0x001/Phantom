import asyncio
import sys
import types
from types import SimpleNamespace

import pytest


def test_create_vulnerability_report_returns_structured_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    class _TracerStub:
        def get_existing_vulnerabilities(self) -> list[dict]:
            return []

        def add_vulnerability_report(self, **kwargs):  # noqa: ANN003
            return "vuln-0001"

    tracer = _TracerStub()
    monkeypatch.setattr("phantom.telemetry.tracer.get_global_tracer", lambda: tracer)
    monkeypatch.setattr(
        "phantom.llm.dedupe.check_duplicate",
        lambda candidate, existing: {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": "",
        },
    )

    result = create_vulnerability_report(
        title="SQL Injection in login",
        description="SQL injection vulnerability in login endpoint",
        impact="Authentication bypass",
        target="https://example.com",
        technical_analysis=(
            "Sent payload ' OR '1'='1 and observed status code: 500 with SQL syntax error in response."
        ),
        poc_description="Replay with crafted username field",
        poc_script_code="print('poc')",
        cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        endpoint="/api/login",
        method="POST",
        parameter="username",
        confidence="LIKELY",
    )

    assert result["success"] is True
    assert result["report_id"] == "vuln-0001"
    assert result["cvss_vector"].startswith("CVSS:3.1/")
    assert result["replay_status"] in {"SKIPPED", "PENDING"}


def test_create_vulnerability_report_rejects_vague_likely_proof() -> None:
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    result = create_vulnerability_report(
        title="Possible SQLi",
        description="Potential SQL injection",
        impact="Potential data exposure",
        target="https://example.com",
        technical_analysis="This might be vulnerable and could be exploitable.",
        poc_description="Could be exploitable with SQL payloads",
        poc_script_code="print('test')",
        cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        confidence="LIKELY",
    )

    assert result["success"] is False
    assert result["message"] == "Proof validation failed"


def test_create_vulnerability_report_skips_replay_without_active_agent_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    class _TracerStub:
        def get_existing_vulnerabilities(self) -> list[dict]:
            return []

        def add_vulnerability_report(self, **kwargs):  # noqa: ANN003
            return "vuln-0002"

    tracer = _TracerStub()
    monkeypatch.setattr("phantom.telemetry.tracer.get_global_tracer", lambda: tracer)
    monkeypatch.setattr(
        "phantom.llm.dedupe.check_duplicate",
        lambda candidate, existing: {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": "",
        },
    )

    result = create_vulnerability_report(
        title="SQL Injection replay state gating",
        description="SQL injection vulnerability in login endpoint",
        impact="Authentication bypass",
        target="https://example.com",
        technical_analysis=(
            "Sent payload ' OR '1'='1 and observed status code: 500 with SQL syntax error in response."
        ),
        poc_description="Replay with crafted username field",
        poc_script_code="print('poc')",
        cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        endpoint="/api/login",
        method="POST",
        parameter="username",
        confidence="LIKELY",
    )

    assert result["success"] is True
    assert result["replay_status"] == "SKIPPED"


def test_generate_ai_payloads_parses_llm_json(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.payload_gen.payload_gen_actions import generate_ai_payloads

    class _FakeLLM:
        def __init__(self, _config):
            pass

        async def generate(self, _messages):
            yield SimpleNamespace(
                content='[{"payload":"<script>alert(1)</script>","context":"html","bypasses":["case"],"technique":"xss"}]'
            )

    monkeypatch.setattr("phantom.llm.llm.LLM", _FakeLLM)

    result = asyncio.run(generate_ai_payloads("xss", {"injection_context": "html"}, count=1))

    assert len(result) == 1
    assert result[0]["payload"] == "<script>alert(1)</script>"
    assert result[0]["category"] == "ai_generated"


def test_generate_ai_payloads_raises_on_invalid_llm_output(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.payload_gen.payload_gen_actions import generate_ai_payloads

    class _FakeLLM:
        def __init__(self, _config):
            pass

        async def generate(self, _messages):
            yield SimpleNamespace(content="not-json")

    monkeypatch.setattr("phantom.llm.llm.LLM", _FakeLLM)

    with pytest.raises(RuntimeError, match="AI payload generation failed"):
        asyncio.run(generate_ai_payloads("xss", {"injection_context": "html"}, count=1))


def test_prepare_messages_strips_thinking_blocks_before_compression() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    captured = {}

    def _capture(messages, agent_state=None):  # type: ignore[no-untyped-def]
        captured["messages"] = list(messages)
        return messages

    llm.memory_compressor.compress_history = _capture  # type: ignore[method-assign]

    history = [
        {
            "role": "assistant",
            "content": "<thinking><function=bad><parameter=x>1</parameter></function></thinking><function=good><parameter=y>2</parameter></function>",
        }
    ]

    import asyncio as _asyncio

    _asyncio.run(llm._prepare_messages(history))

    seen = captured["messages"]
    assert "<thinking>" not in seen[0]["content"]
    assert "<function=good>" in seen[0]["content"]


def test_proxy_manager_blocks_direct_fallback_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from requests.exceptions import ProxyError

    from phantom.tools.proxy.proxy_manager import ProxyManager

    calls: list[dict] = []

    def _fake_request(*_args, **kwargs):
        calls.append(kwargs)
        raise ProxyError("proxy unavailable")

    monkeypatch.delenv("PHANTOM_PROXY_DIRECT_FALLBACK", raising=False)
    import phantom.tools.proxy.proxy_manager as proxy_manager_module
    monkeypatch.setattr(proxy_manager_module.requests, "request", _fake_request)

    manager = ProxyManager()
    result = manager.send_simple_request("GET", "https://example.com", timeout=1)

    assert "error" in result
    assert "fallback is disabled" in result["error"].lower()
    assert result.get("transport") == "proxy_only"
    assert len(calls) == 1


def test_proxy_manager_uses_direct_fallback_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from requests.exceptions import ProxyError

    from phantom.tools.proxy.proxy_manager import ProxyManager

    class _Response:
        status_code = 200
        headers = {"content-type": "text/plain"}
        text = "ok"
        url = "https://example.com"

    calls: list[dict] = []

    def _fake_request(*_args, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise ProxyError("proxy unavailable")
        return _Response()

    monkeypatch.setenv("PHANTOM_PROXY_DIRECT_FALLBACK", "true")
    import phantom.tools.proxy.proxy_manager as proxy_manager_module
    monkeypatch.setattr(proxy_manager_module.requests, "request", _fake_request)

    manager = ProxyManager()
    result = manager.send_simple_request("GET", "https://example.com", timeout=1)

    assert result.get("status_code") == 200
    assert result.get("used_fallback") is True
    assert result.get("transport") == "direct_fallback"
    assert len(calls) == 2
    assert calls[1].get("proxies") is None


def test_fuzzer_routes_requests_through_proxy_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.fuzzer.fuzzer_actions import execute_fuzz_batch

    seen: list[dict] = []

    class _ProxyStub:
        def send_simple_request(self, method, url, headers=None, body="", timeout=30, follow_redirects=False):
            seen.append(
                {
                    "method": method,
                    "url": url,
                    "headers": headers or {},
                    "body": body,
                    "timeout": timeout,
                    "follow_redirects": follow_redirects,
                }
            )
            return {"status_code": 200, "body": "ok"}

    import phantom.tools.fuzzer.fuzzer_manager as fuzzer_manager_module
    monkeypatch.setattr(fuzzer_manager_module, "get_proxy_manager", lambda: _ProxyStub())

    result = execute_fuzz_batch(
        base_url="https://example.com/api/search",
        method="GET",
        payloads=["test"],
        injection_point="param",
        param_name="q",
    )

    assert result["total_requests"] == 1
    assert len(seen) == 1
    assert "q=test" in seen[0]["url"]


def test_terminal_manager_forwards_trusted_command_flag() -> None:
    if "libtmux" not in sys.modules:
        sys.modules["libtmux"] = types.SimpleNamespace(Server=object)
    from phantom.tools.terminal.terminal_manager import TerminalManager

    class _SessionStub:
        def __init__(self):
            self.trusted_values: list[bool] = []

        def execute(self, command, is_input, timeout, no_enter, trusted_command=False):
            self.trusted_values.append(bool(trusted_command))
            return {
                "content": command,
                "status": "completed",
                "exit_code": 0,
                "working_dir": "/workspace",
            }

    manager = TerminalManager()
    session = _SessionStub()
    manager._get_or_create_session = lambda _terminal_id: session  # type: ignore[method-assign]

    out = manager.execute_command("echo hi", trusted_command=True)
    assert out["status"] == "completed"
    assert session.trusted_values == [True]


def test_terminal_session_allows_metacharacters_for_trusted_command() -> None:
    if "libtmux" not in sys.modules:
        sys.modules["libtmux"] = types.SimpleNamespace(Server=object)
    from phantom.tools.terminal.terminal_session import TerminalSession

    session = TerminalSession.__new__(TerminalSession)
    session._initialized = True
    session.quarantine = True
    session._cwd = "/workspace"
    session.PS1_END = "]$ "
    session._get_pane_content = lambda: "]$ "  # type: ignore[method-assign]
    session._matches_ps1_metadata = lambda _content: []  # type: ignore[method-assign]
    session._is_special_key = lambda _command: False  # type: ignore[method-assign]
    session._execute_new_command = lambda command, no_enter, timeout: {  # type: ignore[method-assign]
        "content": command,
        "status": "completed",
        "exit_code": 0,
        "working_dir": session._cwd,
    }

    trusted = session.execute("echo hi; whoami", trusted_command=True)
    untrusted = session.execute("echo hi; whoami", trusted_command=False)

    assert trusted["status"] == "completed"
    assert untrusted["status"] == "error"
    assert "[QUARANTINE]" in untrusted["content"]


def test_memory_compressor_returns_image_evictions_in_output() -> None:
    from phantom.llm.memory_compressor import MemoryCompressor

    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "first"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64," + ("A" * 800)}},
            ],
        },
        {
            "role": "assistant",
            "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64," + ("B" * 800)}},
            ],
        },
    ]

    compressor = MemoryCompressor(max_images=1, max_total_image_bytes=5000, model_name="openai/gpt-4o-mini")
    compressed = compressor.compress_history(messages)

    replaced_texts: list[str] = []
    for msg in compressed:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                replaced_texts.append(str(item.get("text") or ""))

    assert any("Previously attached image removed" in text for text in replaced_texts)


@pytest.mark.asyncio
async def test_execute_actions_keeps_recent_results_trimmed_on_success() -> None:
    from phantom.agents.base_agent import BaseAgent

    class _StateStub:
        def __init__(self) -> None:
            self._messages = []
            self.actions = []

        def add_action(self, action):
            self.actions.append(action)

        def get_conversation_history(self):
            return list(self._messages)

    agent = BaseAgent.__new__(BaseAgent)
    agent.state = _StateStub()
    agent._current_task = None
    agent._recent_action_batches = []
    agent._recent_action_results = [(f"old-{i}", True) for i in range(8)]

    actions = [{"toolName": "terminal_execute", "args": {"command": "pwd"}}]

    from unittest.mock import AsyncMock, patch

    with patch("phantom.agents.base_agent.process_tool_invocations", new=AsyncMock(return_value=False)):
        should_finish = await BaseAgent._execute_actions(agent, actions, tracer=None)

    assert should_finish is False
    assert len(agent._recent_action_results) == 8
    assert agent._recent_action_results[0][0] == "old-1"


@pytest.mark.asyncio
async def test_process_tool_invocations_marks_batch_error_in_agent_context() -> None:
    from phantom.tools.executor import process_tool_invocations

    class _StateStub:
        def __init__(self) -> None:
            self.agent_id = "agent-test"
            self.context: dict[str, object] = {}

        def update_context(self, key, value):  # noqa: ANN001
            self.context[key] = value

    state = _StateStub()
    history: list[dict[str, object]] = []

    from unittest.mock import patch

    with patch(
        "phantom.tools.executor.execute_tool_invocation",
        side_effect=["Error executing send_request: boom"],
    ):
        should_finish = await process_tool_invocations(
            [{"toolName": "send_request", "args": {"method": "GET", "url": "https://example.com"}}],
            history,
            state,
            None,
            allowed_tools={"send_request"},
        )

    assert should_finish is False
    assert state.context.get("last_tool_batch_had_error") is True


@pytest.mark.asyncio
async def test_execute_actions_records_failed_batch_signature() -> None:
    from phantom.agents.base_agent import BaseAgent

    class _StateStub:
        def __init__(self) -> None:
            self._messages = []
            self.actions = []
            self.context: dict[str, object] = {}

        def add_action(self, action):
            self.actions.append(action)

        def get_conversation_history(self):
            return list(self._messages)

    agent = BaseAgent.__new__(BaseAgent)
    agent.state = _StateStub()
    agent._current_task = None
    agent._recent_action_batches = []
    agent._recent_action_results = []

    actions = [{"toolName": "terminal_execute", "args": {"command": "pwd"}}]

    async def _fake_process(*_args, **_kwargs):  # noqa: ANN002, ANN003
        agent.state.context["last_tool_batch_had_error"] = True
        return False

    from unittest.mock import patch

    with patch("phantom.agents.base_agent.process_tool_invocations", side_effect=_fake_process):
        should_finish = await BaseAgent._execute_actions(agent, actions, tracer=None)

    assert should_finish is False
    assert agent._recent_action_results
    assert agent._recent_action_results[-1][1] is False


def test_send_user_message_to_agent_updates_live_state_immediately() -> None:
    from phantom.agents.state import AgentState
    from phantom.tools.agents_graph import agents_graph_actions as actions

    class _AgentStub:
        def __init__(self, agent_id: str) -> None:
            self.state = AgentState(agent_name="Stub Agent", agent_id=agent_id)

    agent_id = "agent-live-message"
    stub = _AgentStub(agent_id)

    with actions._GRAPH_LOCK:
        actions._agent_graph["nodes"][agent_id] = {
            "id": agent_id,
            "name": "Stub Agent",
            "status": "running",
        }
        actions._agent_messages[agent_id] = []
        actions._agent_instances[agent_id] = stub

    try:
        result = actions.send_user_message_to_agent(agent_id, "hello from tui")

        assert result["success"] is True
        assert actions._agent_messages[agent_id]
        assert stub.state.messages[-1]["content"] == "hello from tui"
    finally:
        with actions._GRAPH_LOCK:
            actions._agent_graph["nodes"].pop(agent_id, None)
            actions._agent_messages.pop(agent_id, None)
            actions._agent_instances.pop(agent_id, None)
