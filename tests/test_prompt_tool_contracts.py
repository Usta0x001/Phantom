import os
import re
import asyncio
from types import SimpleNamespace

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM
from phantom.tools.registry import RICH_TOOL_NAMES, tools
from phantom.tools.executor import execute_tool_with_validation, validate_tool_availability
from phantom.tools.dynamic_tools import get_compact_tools_prompt


def test_hypothesis_tools_have_real_xml_schema() -> None:
    hypothesis_tools = {
        "add_hypothesis",
        "record_payload_test",
        "confirm_hypothesis",
        "reject_hypothesis",
        "query_hypotheses",
        "has_tested_payload",
    }

    by_name = {entry.get("name"): entry for entry in tools}
    for tool_name in hypothesis_tools:
        entry = by_name.get(tool_name)
        assert entry is not None, f"Missing tool registration for {tool_name}"
        schema = str(entry.get("xml_schema", ""))
        assert "Schema not found for tool" not in schema, f"Missing XML schema for {tool_name}"


def test_system_prompt_does_not_reference_unregistered_generate_ai_payloads() -> None:
    cfg = LLMConfig(model_name="openai/gpt-4o-mini")
    llm = LLM(cfg, agent_name="PhantomAgent")
    prompt = llm.system_prompt
    assert "generate_ai_payloads(" not in prompt


def test_minimal_subset_intentionally_excludes_hypothesis_tools(monkeypatch) -> None:
    monkeypatch.setenv("PHANTOM_TOOL_SUBSET", "minimal")
    cfg = LLMConfig(model_name="openai/gpt-4o-mini")
    llm = LLM(cfg, agent_name="PhantomAgent")
    allowed = set(llm.runtime_allowed_tools or set())

    assert "confirm_hypothesis" not in allowed
    assert "get_scan_status" not in allowed


def test_compact_schema_keeps_only_rich_tool_explanations() -> None:
    by_name = {entry.get("name"): entry for entry in tools}

    rich_schema = str(by_name["create_vulnerability_report"].get("xml_schema", ""))
    plain_schema = str(by_name["send_request"].get("xml_schema", ""))
    agent_finish_schema = str(by_name["agent_finish"].get("xml_schema", ""))

    assert "<parameters>" in rich_schema
    assert "<description>" in rich_schema
    assert "<description>" in agent_finish_schema
    assert "<details>" in agent_finish_schema

    browser_schema = str(by_name["browser_action"].get("xml_schema", ""))
    assert "click_selector" in browser_schema
    assert "fill_selector" in browser_schema

    prompt = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent").system_prompt
    if "browser_action" in prompt:
        assert "click_selector" in prompt
        assert "fill_selector" in prompt

    assert "<parameters>" in plain_schema
    assert "<description>" in plain_schema
    assert "<details>" not in plain_schema
    assert "<notes>" not in plain_schema
    assert RICH_TOOL_NAMES


def test_system_prompt_stays_compact() -> None:
    cfg = LLMConfig(model_name="openai/gpt-4o-mini")
    llm = LLM(cfg, agent_name="PhantomAgent")
    prompt = llm.system_prompt

    assert len(prompt) < 120000
    assert "<tool_catalog_note>" in prompt
    assert "Example: <function=" in prompt


def test_default_prompt_is_strictly_smaller_than_full_tools_prompt() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    assert len(llm.system_prompt) < len(get_compact_tools_prompt()) + 50000


def test_runtime_allowed_tools_match_prompt() -> None:
    cfg = LLMConfig(model_name="openai/gpt-4o-mini")
    llm = LLM(cfg, agent_name="PhantomAgent")
    prompt = llm.system_prompt
    prompt_tool_names = set(re.findall(r'<tool name="([^"]+)"', prompt))

    assert prompt_tool_names
    assert prompt_tool_names.issubset(set(llm.runtime_allowed_tools or set()))


def test_lazy_expansion_updates_next_turn_tool_set() -> None:
    state = SimpleNamespace(_runtime_llm=SimpleNamespace(runtime_allowed_tools={"send_request"}, _extra_tool_names=set()))
    result = asyncio.run(
        execute_tool_with_validation(
            "create_vulnerability_report",
            agent_state=state,
            allowed_tools={"create_vulnerability_report"},
        )
    )

    assert isinstance(result, str)
    assert "missing required parameter(s)" in result


def test_create_agent_context_summary_contract_matches_prompt() -> None:
    from phantom.tools.registry import tools

    by_name = {entry.get("name"): entry for entry in tools}
    schema = str(by_name["create_agent"].get("xml_schema", ""))
    assert "context_summary" in schema

    prompt = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent").system_prompt
    assert "context_summary: REQUIRED - Must be 200+ characters" in prompt
    assert "Multiple tool calls per message are ALLOWED" not in prompt


def test_system_prompt_falls_back_when_template_loading_fails(monkeypatch) -> None:
    import phantom.llm.llm as llm_module

    def _raise_template_error(self, _name):  # type: ignore[no-untyped-def]
        raise RuntimeError("template load failed")

    monkeypatch.setattr(llm_module.Environment, "get_template", _raise_template_error)

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    prompt = llm.system_prompt

    assert prompt.strip()
    assert "<tool name=\"" in prompt
    assert "Schema not found for tool" not in prompt


def test_validate_tool_availability_accepts_underscoreless_alias() -> None:
    ok, msg = validate_tool_availability("getscanstatus")
    assert ok is True
    assert msg == ""


def test_execute_tool_with_validation_accepts_underscoreless_alias() -> None:
    state = SimpleNamespace(agent_id="agent-alias")
    result = asyncio.run(
        execute_tool_with_validation(
            "getscanstatus",
            state,
            allowed_tools={"get_scan_status"},
            include_recommendations=False,
        )
    )
    assert isinstance(result, dict)
    assert "scan_progress" in result


def test_validate_tool_availability_unknown_tool_message_is_actionable() -> None:
    ok, msg = validate_tool_availability("definitely_not_a_tool")

    assert ok is False
    assert "is not available" in msg
    assert "Retry immediately with an exact tool name" in msg
