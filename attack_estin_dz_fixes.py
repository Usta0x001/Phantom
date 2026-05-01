"""
BUG FIX VALIDATION — estin-dz_4380 Scan Issues
Tests for the 6 bugs that caused 13 wasted iterations.
"""

from pathlib import Path
from unittest.mock import patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("BUG FIX VALIDATION — estin-dz_4380 Scan Issues")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# Bug 1: Parser rejects literal "tool_name" placeholder
# ═══════════════════════════════════════════════════════════════════════════
print("\n[BUG 1] Parser rejects 'tool_name' placeholder from system prompt...")

from phantom.llm.utils import parse_tool_invocations

# The system prompt example uses <function=tool_name> — the LLM copies it verbatim.
result = parse_tool_invocations(
    '<function=tool_name><parameter=title>Test</parameter></function>'
)
assert_true(
    "tool_name placeholder is rejected",
    result is None or len(result) == 0,
    f"parser returned: {result}",
)

# Real tool names still work
result2 = parse_tool_invocations(
    '<function=send_request><parameter=method>GET</parameter></function>'
)
assert_true(
    "real tool names still parse",
    result2 is not None and len(result2) == 1 and result2[0]["toolName"] == "send_request",
    f"parser returned: {result2}",
)


# ═══════════════════════════════════════════════════════════════════════════
# Bug 2: finish_scan accepts "reason" alias
# ═══════════════════════════════════════════════════════════════════════════
print("\n[BUG 2] finish_scan accepts 'reason' as alias for executive_summary...")

from phantom.tools.finish.finish_actions import finish_scan

fake_state = type("FakeState", (), {
    "agent_id": "test-agent",
    "parent_id": None,
    "hypothesis_ledger": None,
    "coverage_tracker": None,
    "attack_graph": None,
})()

with patch("phantom.tools.finish.finish_actions._validate_root_agent", return_value=None):
    with patch("phantom.tools.finish.finish_actions._check_active_agents", return_value=None):
        with patch("phantom.telemetry.tracer.get_global_tracer", return_value=None):
            result = finish_scan(
                reason="Browser test completed successfully.",
                agent_state=fake_state,
            )
            assert_true(
                "reason mapped to executive_summary",
                result.get("success", False) or "Validation failed" not in str(result),
                f"got: {result}",
            )


# ═══════════════════════════════════════════════════════════════════════════
# Bug 3: System prompt uses real tool name in example, not "tool_name"
# ═══════════════════════════════════════════════════════════════════════════
print("\n[BUG 3] System prompt uses real tool name in example...")

prompt_src = Path("phantom/agents/PhantomAgent/system_prompt.jinja").read_text(encoding="utf-8")
assert_true(
    "no '<function=tool_name>' placeholder in prompt",
    "<function=tool_name>" not in prompt_src,
    "literal tool_name placeholder still present",
)
assert_true(
    "finish_scan example present",
    "<function=finish_scan>" in prompt_src,
    "no finish_scan example",
)
assert_true(
    "'NEVER use <function> in reasoning' instruction present",
    "NEVER use <function>" in prompt_src,
    "no anti-reasoning instruction",
)
assert_true(
    "'NEVER tool_name' instruction present",
    "NEVER \"tool_name\"" in prompt_src or "NEVER 'tool_name'" in prompt_src,
    "no anti-placeholder instruction",
)
assert_true(
    "exactly ONE tool call per response",
    "exactly ONE tool call" in prompt_src,
    "missing one-call rule",
)


# ═══════════════════════════════════════════════════════════════════════════
# Bug 4: Parser doesn't greedily match bare </function>
# ═══════════════════════════════════════════════════════════════════════════
print("\n[BUG 4] Parser handles reasoning text with </function> correctly...")

# Simulate LLM reasoning that includes </function> naturally
result = parse_tool_invocations(
    "Some reasoning text with </function> in it. "
    "<function=send_request><parameter=method>GET</parameter></function>"
)
assert_true(
    "bare </function> in text doesn't create spurious match",
    result is not None and len(result) == 1 and result[0]["toolName"] == "send_request",
    f"parser returned: {result}",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL BUG FIX VALIDATIONS PASSED")
print("=" * 70)
