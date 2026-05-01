"""
REAL SCAN SIMULATION — estin-dz_4380
Feeds the exact LLM outputs from the scan log into the parser
and agent loop to verify no wasted iterations would occur.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("REAL SCAN SIMULATION — estin-dz_4380")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# Iteration 4-7: Natural language conclusions (Events 19, 21, 23, 25)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST] Iteration 4-7: Natural language conclusions -> NO phantom tool calls...")

from phantom.llm.utils import parse_tool_invocations

iter4_text = (
    "The browser closed successfully. We have verified that the browser_action tool works: "
    "we launched, navigated to target, captured screenshot, and closed. "
    "We can now provide a summary to the user."
)
iter5_text = (
    "The browser test is complete. The user only wanted to test browser_action tool, "
    "and we have confirmed it works. We can now conclude the interaction."
)
iter6_text = (
    "The browser_action tool is functional and accessible. I successfully launched a headless browser, "
    "navigated to https://estin.dz, captured a screenshot (saved as a run artifact), "
    "and closed the session. The browser test is complete."
)
iter7_text = (
    "The user's request was only to test the browser_action tool, not to perform a full penetration test. "
    "We have done that and provided confirmation. We can now stop."
)

for i, text in enumerate([iter4_text, iter5_text, iter6_text, iter7_text], 4):
    result = parse_tool_invocations(text)
    assert_true(
        f"Iter {i}: natural language returns None",
        result is None,
        f"parser returned: {result}",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Iteration 10-11: </function> in reasoning text (Event 36)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST] Iteration 10-11: </function> in reasoning -> NO phantom match...")

iter10_text = (
    'It seems we incorrectly output a raw function tag? We output "'
)
iter11_text = (
    "We ended our message with </function>. That caused the system to parse it as XML. "
    "We should not include </function> in reasoning text."
)

for i, text in enumerate([iter10_text, iter11_text], 10):
    result = parse_tool_invocations(text)
    assert_true(
        f"Iter {i}: </function> in text returns None",
        result is None,
        f"parser returned: {result}",
    )


# ═══════════════════════════════════════════════════════════════════════════
# fix_incomplete_tool_call must NOT corrupt reasoning mentioning <function=
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST] fix_incomplete_tool_call must not corrupt reasoning...")

from phantom.llm.utils import fix_incomplete_tool_call

reasoning_with_function_mention = (
    "Let me analyze the previous output. The system uses <function=send_request> "
    "for tool calls. I need to make sure my next call is well-formed."
)

fixed = fix_incomplete_tool_call(reasoning_with_function_mention)
assert_true(
    "reasoning text with <function= mention is NOT modified",
    fixed == reasoning_with_function_mention,
    f"was corrupted to: {fixed}",
)

# But it SHOULD fix a real incomplete call
incomplete_call = '<function=send_request><parameter=method>GET</parameter>'
fixed_real = fix_incomplete_tool_call(incomplete_call)
assert_true(
    "real incomplete call IS fixed",
    "</function>" in fixed_real,
    f"not fixed: {fixed_real}",
)


# ═══════════════════════════════════════════════════════════════════════════
# System prompt must NOT contain tool_name placeholder
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST] System prompt has no tool_name placeholder...")

prompt_src = Path("phantom/agents/PhantomAgent/system_prompt.jinja").read_text(encoding="utf-8")
assert_true(
    "no '<function=tool_name>' in prompt",
    "<function=tool_name>" not in prompt_src,
    "literal placeholder still present",
)
assert_true(
    "MANDATORY: EVERY response must contain exactly ONE tool call",
    "EVERY response must contain exactly ONE tool call" in prompt_src,
    "missing mandatory tool call rule",
)
assert_true(
    "Natural language without tool calls is NEVER allowed",
    "Natural language without tool calls is NEVER allowed" in prompt_src,
    "missing natural language ban",
)
assert_true(
    "To end the scan, call finish_scan",
    "To end the scan, call finish_scan" in prompt_src,
    "missing finish_scan instruction",
)
assert_true(
    "Output exactly ONE tool call per response",
    "Output exactly ONE tool call per response" in prompt_src,
    "missing one-call-per-response rule",
)
assert_true(
    "PUT THE TOOL CALL FIRST",
    "PUT THE TOOL CALL FIRST" in prompt_src,
    "missing tool-call-first rule",
)


# ═══════════════════════════════════════════════════════════════════════════
# Agent loop messages must suggest finish_scan, not recon
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST] Agent loop corrective messages suggest finish_scan...")

agent_src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
assert_true(
    "empty response message suggests finish_scan",
    "call finish_scan to end" in agent_src,
    "empty response message still suggests terminal_execute",
)
assert_true(
    "no-action streak message suggests finish_scan",
    "If the scan is complete, call finish_scan" in agent_src,
    "no-action streak message still says pivot to new exploit path",
)
assert_true(
    "no-action streak message bans natural language",
    "Do NOT output natural language without a tool call" in agent_src,
    "missing natural language ban in no-action message",
)


print("\n" + "=" * 70)
print("ALL REAL SCAN SIMULATIONS PASSED")
print("=" * 70)
