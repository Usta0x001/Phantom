import os
import re

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM
from phantom.tools.registry import tools


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


def test_minimal_subset_intentionally_excludes_hypothesis_tools() -> None:
    os.environ["PHANTOM_TOOL_SUBSET"] = "minimal"
    cfg = LLMConfig(model_name="openai/gpt-4o-mini")
    llm = LLM(cfg, agent_name="PhantomAgent")
    allowed = set(llm.runtime_allowed_tools or set())

    assert "create_vulnerability_report" in allowed
    assert "confirm_hypothesis" not in allowed
    assert "get_scan_status" not in allowed
