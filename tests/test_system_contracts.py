from pathlib import Path

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


def test_subset_mode_tools_are_registered() -> None:
    for mode in ("minimal", "core", "core-fast", "web"):
        subset = set(get_tools_for_subset_mode(mode))
        assert subset
        assert subset.issubset(set(get_tool_names()))


def test_hypothesis_tools_have_schemas() -> None:
    by_name = {tool.get("name"): tool for tool in tools}
    for name in ("add_hypothesis", "confirm_hypothesis", "reject_hypothesis", "query_hypotheses", "has_tested_payload", "get_scan_status"):
        schema = str(by_name[name].get("xml_schema", ""))
        assert "Schema not found for tool" not in schema


def test_audit_report_includes_top_risks_field() -> None:
    report = generate_audit_report(run_dir=Path("phantom_runs/does-not-exist"))
    assert "top_risks" in report
