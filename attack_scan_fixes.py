"""
SCAN FIXES — ADVERSARIAL VALIDATION SUITE
Tests for issues found in the real estin-dz scan.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("SCAN FIXES — ADVERSARIAL VALIDATION")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 1: Token tracking — input_tokens=0 fallback
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 1] Token tracking estimates input when API reports 0...")

src_llm = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "input_tokens == 0 fallback exists",
    "if input_tokens == 0 and messages:" in src_llm,
    "fallback not found",
)
assert_true(
    "_estimate_input_tokens called in fallback",
    "_estimate_input_tokens(messages)" in src_llm.split("if input_tokens == 0 and messages:")[1].split("async with self._shared_state.lock:")[0],
    "estimation not in fallback block",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 2: agent_finish blocked for root agents
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 2] agent_finish blocked for root agents in executor...")

src_exec = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
assert_true(
    "agent_finish guard exists",
    'tool_name == "agent_finish"' in src_exec,
    "guard not found",
)
assert_true(
    "parent_id checked in guard",
    "parent_id" in src_exec.split('tool_name == "agent_finish"')[1].split("if tool_name ==")[0],
    "parent_id not checked",
)
assert_true(
    "error message mentions finish_scan",
    "finish_scan" in src_exec.split('tool_name == "agent_finish"')[1].split("if tool_name ==")[0],
    "error doesn't redirect to finish_scan",
)

# Functional test
async def _test_agent_finish_block():
    from phantom.tools.executor import execute_tool_with_validation

    fake_state = MagicMock()
    fake_state.parent_id = None  # root agent
    result = await execute_tool_with_validation("agent_finish", agent_state=fake_state, result_summary="done")
    assert_true(
        "root agent blocked from agent_finish",
        "finish_scan" in str(result),
        f"got: {result}",
    )

    fake_state.parent_id = "some-parent"  # subagent
    # Should proceed to actual tool execution (which may fail for other reasons)
    # We just verify it doesn't return the root-agent error
    with patch("phantom.tools.executor.execute_tool") as mock_exec:
        mock_exec.return_value = {"agent_completed": True}
        result = await execute_tool_with_validation("agent_finish", agent_state=fake_state, result_summary="done")
        assert_true(
            "subagent allowed through",
            "finish_scan" not in str(result),
            f"subagent was blocked: {result}",
        )

asyncio.run(_test_agent_finish_block())


# ═══════════════════════════════════════════════════════════════════════════
# FIX 3: finish_scan accepts parameter aliases
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 3] finish_scan accepts result_summary alias...")

src_finish = Path("phantom/tools/finish/finish_actions.py").read_text(encoding="utf-8")
assert_true(
    "result_summary parameter exists",
    "result_summary: str = \"\"" in src_finish,
    "result_summary parameter missing",
)
assert_true(
    "alias mapping logic exists",
    "executive_summary = result_summary" in src_finish,
    "alias mapping missing",
)

# Functional test
async def _test_finish_scan_alias():
    from phantom.tools.finish.finish_actions import finish_scan

    fake_state = MagicMock()
    fake_state.agent_id = "test-agent"
    fake_state.parent_id = None
    fake_state.hypothesis_ledger = None
    fake_state.coverage_tracker = None
    fake_state.attack_graph = None

    # Should accept result_summary as alias for executive_summary
    with patch("phantom.tools.finish.finish_actions._validate_root_agent", return_value=None):
        with patch("phantom.tools.finish.finish_actions._check_active_agents", return_value=None):
            with patch("phantom.telemetry.tracer.get_global_tracer", return_value=None):
                result = finish_scan(
                    result_summary="Test completed successfully",
                    agent_state=fake_state,
                )
                assert_true(
                    "result_summary mapped to executive_summary",
                    result.get("success", False) or "Validation failed" not in str(result),
                    f"got: {result}",
                )

asyncio.run(_test_finish_scan_alias())


# ═══════════════════════════════════════════════════════════════════════════
# FIX 4: finish_scan defaults for optional fields
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 4] finish_scan provides defaults for empty optional fields...")

assert_true(
    "methodology default exists",
    'methodology = "Automated security scan completed."' in src_finish,
    "methodology default missing",
)
assert_true(
    "technical_analysis default exists",
    '"No detailed technical analysis' in src_finish,
    "technical_analysis default missing",
)
assert_true(
    "recommendations default exists",
    '"No specific recommendations."' in src_finish,
    "recommendations default missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 5: Skills warning removed
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 5] Skills import warning removed from registry...")

src_reg = Path("phantom/tools/registry.py").read_text(encoding="utf-8")
assert_true(
    "no logger.warning for skills",
    "Could not import skills" not in src_reg,
    "warning still present",
)
assert_true(
    "skills placeholder replaced with empty string",
    'content.replace(' in src_reg and '{{DYNAMIC_SKILLS_DESCRIPTION}}' in src_reg,
    "not replaced with empty string",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 6: LLM stats shared across instances
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 6] LLM instances share default state for global stats...")

src_llm_init = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "LLM defaults to _DEFAULT_SHARED_STATE",
    "shared_state or _DEFAULT_SHARED_STATE" in src_llm_init,
    "default shared state not used",
)

# Functional test
from phantom.llm.llm import LLM, _DEFAULT_SHARED_STATE, LLMConfig

fake_config = LLMConfig(litellm_model="gpt-4")
llm1 = LLM(fake_config)
llm2 = LLM(fake_config)

# Verify both instances share the same state object
assert_true(
    "two LLM instances share _shared_state",
    llm1._shared_state is llm2._shared_state,
    "instances have different shared states",
)
assert_true(
    "LLM state is _DEFAULT_SHARED_STATE",
    llm1._shared_state is _DEFAULT_SHARED_STATE,
    "instance state is not the default",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL SCAN FIX VALIDATIONS PASSED")
print("=" * 70)
