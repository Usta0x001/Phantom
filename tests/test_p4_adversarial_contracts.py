import re

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM
from phantom.tools.registry import get_tool_names, tools


def test_schema_drift_detector_reports_no_missing_tool_schemas_for_core_memory_tools() -> None:
    required = {
        "add_hypothesis",
        "record_payload_test",
        "confirm_hypothesis",
        "reject_hypothesis",
        "query_hypotheses",
        "has_tested_payload",
        "get_scan_status",
    }
    by_name = {entry.get("name"): entry for entry in tools}

    missing = []
    for name in required:
        entry = by_name.get(name)
        if not entry:
            missing.append(f"missing_registration:{name}")
            continue
        schema = str(entry.get("xml_schema", ""))
        if "Schema not found for tool" in schema:
            missing.append(f"missing_schema:{name}")

    assert not missing, f"Schema drift detected: {missing}"


def test_prompt_tool_names_are_registered_when_invoked_as_functions() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    prompt = llm.system_prompt

    # only function-like references, excluding jinja helper placeholders
    names = set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", prompt))
    ignore = {
        "get_tools_prompt",
        "get_skill",
    }
    function_like = {n for n in names if n not in ignore}

    registered = set(get_tool_names())
    # Allow common prose words that appear in sentences but can match regex.
    prose_noise = {
        "if",
        "for",
        "max",
        "min",
        "int",
        "str",
    }
    unresolved = sorted([n for n in function_like if n not in registered and n not in prose_noise])

    assert "generate_ai_payloads" not in unresolved
