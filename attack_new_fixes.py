"""
NEW FIXES — ADVERSARIAL VALIDATION SUITE
Tests for XML/tools/efficiency fixes applied in the comprehensive round.
"""

from pathlib import Path
from unittest.mock import MagicMock


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("NEW FIXES — ADVERSARIAL VALIDATION")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 1: System prompt requires exactly one call per response
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 1] System prompt requires exactly one call per response...")

prompt_src = Path("phantom/agents/PhantomAgent/system_prompt.jinja").read_text(encoding="utf-8")
assert_true(
    "exactly ONE tool call rule exists",
    "exactly ONE tool call" in prompt_src,
    "no one-call rule found",
)
assert_true(
    "tool call first rule exists",
    "PUT THE TOOL CALL FIRST" in prompt_src,
    "no tool-call-first rule",
)
assert_true(
    "anti-batching rule present",
    "Do NOT attempt to batch" in prompt_src,
    "anti-batching rule missing",
)
assert_true(
    "signal_rules block exists",
    "<signal_rules>" in prompt_src and "</signal_rules>" in prompt_src,
    "signal_rules block missing",
)
assert_true(
    "signal_rules mention SQL_INJECTION",
    "SIGNAL:SQL_INJECTION" in prompt_src,
    "SQL_INJECTION signal rule missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 2: Registry preserves examples
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 2] Registry preserves up to 1 example per tool...")

reg_src = Path("phantom/tools/registry.py").read_text(encoding="utf-8")
assert_true(
    "_truncate_examples function exists",
    "def _truncate_examples" in reg_src,
    "function missing",
)
assert_true(
    "max_examples parameter exists",
    "max_examples: int = 1" in reg_src,
    "max_examples param missing",
)
assert_true(
    "_truncate_examples called in _load_xml_schema",
    "_truncate_examples(content, max_examples=1)" in reg_src,
    "not called in loader",
)
assert_true(
    "old blanket stripper removed",
    '_EXAMPLE_BLOCK_RE.sub("", content)' not in reg_src,
    "old stripper still present",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 3: Signal headers compact + CDATA
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 3] Signal headers are compact, results use CDATA...")

exec_src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
assert_true(
    "compact signal tag emitted",
    '<signal type=\\"' in exec_src or '<signal type="' in exec_src,
    "no compact signal tag",
)
assert_true(
    "bloated investigation paragraph removed",
    "[INVESTIGATION REQUIRED] A potential vulnerability signal was detected." not in exec_src,
    "bloated paragraph still present",
)
assert_true(
    "CDATA wrapping used",
    "<![CDATA[" in exec_src,
    "CDATA not used",
)
assert_true(
    "html.escape removed from result body",
    # The old line was: f"<result>{html.escape(final_result_str)}</result>"
    '<result>{html.escape(final_result_str)}</result>' not in exec_src,
    "old html.escape still in result body",
)
assert_true(
    "truncation attributes added",
    'truncated="true"' in exec_src or 'truncated=\\"true\\"' in exec_src,
    "truncation attrs missing",
)
assert_true(
    "chars_before attribute",
    'chars_before="' in exec_src or 'chars_before=\\"' in exec_src,
    "chars_before attr missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 4: Hypothesis broad buffer
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 4] Hypothesis context retains broad buffer...")

base_src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
assert_true(
    "broad_buffer created",
    "broad_buffer = history[-15:]" in base_src,
    "broad_buffer not created",
)
assert_true(
    "broad_ids dedup set",
    "broad_ids = {id(m) for m in broad_buffer}" in base_src,
    "dedup set missing",
)
assert_true(
    "broad_buffer returned",
    "return [hypothesis_block, *supporting, *broad_buffer[-55:]]" in base_src,
    "broad_buffer not returned",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 5: Cleanup frequency reduced
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 5] Message cleanup frequency reduced...")

assert_true(
    "cleanup_multiplier increased",
    "cleanup_multiplier = 6 if scan_mode" in base_src,
    "multiplier not increased",
)
assert_true(
    "min interval between cleanups",
    "self.state.iteration - last_cleanup_iter < 10" in base_src,
    "interval guard missing",
)
assert_true(
    "_last_cleanup_iteration tracked",
    "self._last_cleanup_iteration = self.state.iteration" in base_src,
    "tracking missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 6: XML parser for tool invocations
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 6] XML parser used for tool invocation parameter extraction...")

utils_src = Path("phantom/llm/utils.py").read_text(encoding="utf-8")
assert_true(
    "_extract_params_xml exists",
    "def _extract_params_xml" in utils_src,
    "function missing",
)
assert_true(
    "ElementTree import",
    "from xml.etree import ElementTree" in utils_src,
    "ElementTree import missing",
)
assert_true(
    "_extract_params_xml called in parse_tool_invocations",
    "args = _extract_params_xml(fn_body)" in utils_src,
    "not called in parser",
)

# Functional test
from phantom.llm.utils import parse_tool_invocations

# Test 1: normal parsing
result = parse_tool_invocations(
    '<function=send_request><parameter name="method">GET</parameter><parameter name="url">https://example.com</parameter></function>'
)
assert_true(
    "XML parser extracts params correctly",
    result is not None and len(result) == 1 and result[0]["args"]["method"] == "GET",
    f"got {result}",
)

# Test 2: payload with > inside parameter (previously broken with regex)
result = parse_tool_invocations(
    '<function=terminal_execute><parameter name="command">python -c "print(1>0)"</parameter></function>'
)
assert_true(
    "XML parser handles > in parameter values",
    result is not None and 'print(1>0)' in result[0]["args"].get("command", ""),
    f"got {result}",
)

# Test 3: multiple tool calls (batching)
result = parse_tool_invocations(
    '<function=send_request><parameter name="method">GET</parameter></function>'
    '<function=send_request><parameter name="method">POST</parameter></function>'
)
assert_true(
    "XML parser handles batched tool calls",
    result is not None and len(result) == 2,
    f"got {result}",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 7: Merge consecutive user messages
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 7] Consecutive user messages are merged...")

llm_src = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "_merge_consecutive_same_role exists",
    "def _merge_consecutive_same_role" in llm_src,
    "function missing",
)
assert_true(
    "called in _prepare_messages",
    "messages = self._merge_consecutive_same_role(messages)" in llm_src,
    "not called in _prepare_messages",
)

# Functional test
from phantom.llm.llm import LLM

fake_config = MagicMock()
fake_config.litellm_model = "gpt-4"
fake_config.canonical_model = "gpt-4"
fake_config.enable_prompt_caching = False
llm = LLM(fake_config)

merged = llm._merge_consecutive_same_role([
    {"role": "user", "content": "Message 1"},
    {"role": "user", "content": "Message 2"},
    {"role": "assistant", "content": "Response"},
    {"role": "user", "content": "Message 3"},
])
assert_true(
    "consecutive users merged into one",
    len(merged) == 3 and "Message 1" in merged[0]["content"] and "Message 2" in merged[0]["content"],
    f"got {merged}",
)
assert_true(
    "assistant preserved between merged users",
    merged[1]["role"] == "assistant",
    f"got {merged}",
)
assert_true(
    "final user message preserved",
    merged[2]["role"] == "user" and merged[2]["content"] == "Message 3",
    f"got {merged}",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL NEW FIX VALIDATIONS PASSED")
print("=" * 70)
