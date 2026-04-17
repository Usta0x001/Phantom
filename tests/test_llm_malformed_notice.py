from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM


def test_system_prompt_does_not_contain_placeholder_tool_name() -> None:
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    prompt = llm.system_prompt

    assert "<function=tool_name>" not in prompt
    assert "tool_name / param_name" in prompt
    assert "<function=get_scan_status></function>" in prompt
    assert "new_session, execute, close, list_sessions" in prompt
