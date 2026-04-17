import json
from types import SimpleNamespace


def test_extract_scope_targets_includes_web_application_details_target_url() -> None:
    from phantom.runtime.docker_runtime import DockerRuntime

    runtime = DockerRuntime.__new__(DockerRuntime)
    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {
                    "target_url": "https://app.example.org/#/login",
                },
            }
        ]
    }

    result = runtime._extract_scope_targets(scan_config)
    assert "app.example.org" in result.split(",")


def test_browser_action_promotes_click_with_selector() -> None:
    from phantom.tools.browser import browser_actions

    assert browser_actions._resolve_action_name("click", selector="#login-btn") == "click_selector"
    assert browser_actions._resolve_action_name("'fill'", selector="input[name=q]") == "fill_selector"


def test_update_usage_stats_estimates_input_tokens_without_usage() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)

    response = SimpleNamespace(
        usage=None,
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
    )
    messages = [{"role": "user", "content": "hello world"}]

    before_in = llm._total_stats.input_tokens
    before_out = llm._total_stats.output_tokens
    llm._update_usage_stats(response, messages)

    assert llm._total_stats.input_tokens > before_in
    assert llm._total_stats.output_tokens >= before_out


def test_update_usage_stats_separates_cached_tokens_from_input() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)

    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=100,
            completion_tokens=25,
            prompt_tokens_details=SimpleNamespace(cached_tokens=40),
        ),
    )

    before_in = llm._total_stats.input_tokens
    before_cached = llm._total_stats.cached_tokens
    llm._update_usage_stats(response, messages=[])

    assert llm._total_stats.input_tokens - before_in == 60
    assert llm._total_stats.cached_tokens - before_cached == 40


def test_parse_tool_invocations_recovers_incomplete_parameter() -> None:
    from phantom.llm.utils import parse_tool_invocations

    parsed = parse_tool_invocations("<function=send_request>\n<parameter=url>https://example.com")

    assert parsed == [{"toolName": "send_request", "args": {"url": "https://example.com"}}]


def test_per_model_stats_use_net_input_tokens_after_cache() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, reset_global_llm_stats

    reset_global_llm_stats()
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)

    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=100,
            completion_tokens=25,
            prompt_tokens_details=SimpleNamespace(cached_tokens=40),
        ),
    )

    usage_delta = llm._update_usage_stats(response, messages=[])
    llm._update_per_model_stats(usage_delta)

    model_key = llm.config.litellm_model
    stats = llm._per_model_stats[model_key]
    assert stats.input_tokens == 60
    assert stats.cached_tokens == 40
    assert stats.output_tokens == 25


def test_update_usage_stats_returns_deltas_with_estimated_usage() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)
    response = SimpleNamespace(
        usage=None,
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
    )

    deltas = llm._update_usage_stats(response, messages=[{"role": "user", "content": "hello"}])
    assert int(deltas["input_tokens"]) > 0
    assert int(deltas["output_tokens"]) >= 0


def test_audit_tool_result_redacts_inline_base64(monkeypatch, tmp_path) -> None:
    from phantom.logging.audit import AuditLogger

    monkeypatch.setenv("PHANTOM_AUDIT_LOG", "true")
    audit = AuditLogger(run_id="test-runtime-hardening", run_dir=tmp_path)

    audit.log_tool_result(
        exec_id="e-1",
        agent_id="a-1",
        tool_name="browser_action",
        result={
            "screenshot": "A" * 120,
            "result_preview": "prefix data:image/png;base64," + ("A" * 80) + " suffix",
        },
        duration_ms=12.0,
    )

    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    tool_result = next(r for r in records if r.get("event_type") == "tool.result")
    preview = str(tool_result["payload"]["result_preview"])

    assert "data:image/[omitted-base64]" in preview
    assert "AAAA" not in preview


def test_malformed_tool_notice_uses_real_tool_names_not_placeholders() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")

    accumulated = "<function=tool_name><parameter=param_name>value</parameter></function>"
    from phantom.llm.utils import normalize_tool_format, strip_thinking_blocks, fix_incomplete_tool_call, _truncate_to_first_function, parse_tool_invocations

    accumulated = normalize_tool_format(accumulated)
    accumulated = strip_thinking_blocks(accumulated)
    accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
    parsed = parse_tool_invocations(accumulated)
    assert parsed is not None
    assert parsed[0]["toolName"] == "tool_name"

    # Mirror llm.generate malformed-notice condition + message body expectation.
    xml_markers = ["<function=", "<invoke ", "</function>"]
    looks_like_tool = any(m in accumulated for m in xml_markers)
    assert looks_like_tool is True

    # Validate prompt/tool docs no longer teach placeholder tool names.
    assert "<function=tool_name>" not in llm.system_prompt
    assert "<function=get_scan_status></function>" in llm.system_prompt
