from pathlib import Path
import re

import os

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM
from phantom.tools.dynamic_tools import get_tools_for_subset_mode
from phantom.tools.registry import get_tool_names, tools
from audit_report import generate_audit_report


def test_prompt_contains_core_memory_contracts() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    prompt = llm.system_prompt

    assert "get_scan_status" in prompt
    assert "add_hypothesis" in prompt
    assert "has_tested_payload" in prompt
    assert "confirm_hypothesis" in prompt
    assert "reject_hypothesis" in prompt


def test_task_aware_prompt_selection_uses_state_task() -> None:
    from phantom.agents.state import AgentState

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    state = AgentState(agent_name="Phantom Agent", task="Investigate SQL injection and report findings")
    llm.set_agent_state(state)

    prompt = llm.system_prompt
    assert "create_vulnerability_report" in prompt
    assert (
        "generate_smart_payloads" in prompt
        or "terminal_execute" in prompt
    )


def test_set_agent_state_keeps_prompt_and_tool_set_in_sync() -> None:
    from phantom.agents.state import AgentState

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    state = AgentState(agent_name="Phantom Agent", task="Review findings")

    llm.set_agent_state(state)

    assert "<tool name=" in llm.system_prompt
    assert llm.runtime_allowed_tools
    prompt_tool_names = set(re.findall(r'<tool name="([^"]+)"', llm.system_prompt))
    assert prompt_tool_names.issubset(set(llm.runtime_allowed_tools))


def test_prompt_runtime_tool_parity_across_subset_modes() -> None:
    original_subset = os.environ.get("PHANTOM_TOOL_SUBSET")
    try:
        for mode in ("minimal", "core", "core-fast", "web", "full"):
            os.environ["PHANTOM_TOOL_SUBSET"] = mode
            llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
            prompt_tool_names = set(re.findall(r'<tool name="([^"]+)"', llm.system_prompt))
            runtime_tool_names = set(llm.runtime_allowed_tools or set())
            assert prompt_tool_names
            assert prompt_tool_names.issubset(runtime_tool_names)
    finally:
        if original_subset is None:
            os.environ.pop("PHANTOM_TOOL_SUBSET", None)
        else:
            os.environ["PHANTOM_TOOL_SUBSET"] = original_subset


def test_subset_mode_tools_are_registered() -> None:
    for mode in ("minimal", "core", "core-fast", "web"):
        subset = set(get_tools_for_subset_mode(mode))
        assert subset or mode == "minimal"
        assert subset.issubset(set(get_tool_names()))


def test_browser_tool_is_not_offered_when_playwright_missing() -> None:
    from phantom.tools.registry import get_tool_names

    tools = get_tool_names()
    assert tools


def test_core_fast_subset_includes_wait_for_agents() -> None:
    subset = set(get_tools_for_subset_mode("core-fast"))
    assert subset


def test_unknown_extra_tool_is_not_exposed_in_runtime_or_prompt() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    llm._extra_tool_names = {"nonexistent_tool_name"}
    llm.refresh_tool_prompt()

    assert "nonexistent_tool_name" not in set(llm.runtime_allowed_tools or set())
    assert "<tool name=\"nonexistent_tool_name\"" not in llm.system_prompt


def test_hypothesis_tools_have_schemas() -> None:
    by_name = {tool.get("name"): tool for tool in tools}
    for name in ("add_hypothesis", "confirm_hypothesis", "reject_hypothesis", "query_hypotheses", "has_tested_payload", "get_scan_status"):
        schema = str(by_name[name].get("xml_schema", ""))
        assert "Schema not found for tool" not in schema


def test_full_tool_subset_injects_entire_registry() -> None:
    original_subset = os.environ.get("PHANTOM_TOOL_SUBSET")
    try:
        os.environ["PHANTOM_TOOL_SUBSET"] = "full"
        llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
        prompt_tool_names = set(re.findall(r'<tool name="([^"]+)"', llm.system_prompt))
        registered_tool_names = set(get_tool_names())

        assert prompt_tool_names == registered_tool_names
    finally:
        if original_subset is None:
            os.environ.pop("PHANTOM_TOOL_SUBSET", None)
        else:
            os.environ["PHANTOM_TOOL_SUBSET"] = original_subset


def test_send_request_schema_is_not_compacted_in_prompt() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    prompt = llm.system_prompt

    assert '<tool name="send_request">' in prompt
    assert 'Params: method*' in prompt
    assert 'Example: <function=send_request>' in prompt
    assert '<function=send_request>' in prompt
    assert '<function=python_action>' in prompt


def test_audit_report_includes_top_risks_field() -> None:
    report = generate_audit_report(run_dir=Path("phantom_runs/does-not-exist"))
    assert "top_risks" in report
