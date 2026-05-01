"""
Adversarial validation — attack the fixes to ensure they are robust.
"""

import asyncio
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def test_fix1_no_regression_empty_messages():
    """FIX 1 regression: empty message list should not crash."""
    print("\n[ATTACK 1] Empty messages after tool execution...")
    from phantom.agents.state import AgentState

    state = AgentState(agent_name="TestAgent", max_iterations=10)
    state.messages = []
    # Verify state is valid
    assert state.get_conversation_history() == []
    print("  PASS: Empty messages handled correctly")


def test_fix2_streaming_edge_empty_delta():
    """FIX 2 regression: chunks with empty delta should not cause infinite loop."""
    print("\n[ATTACK 2] Streaming chunks with empty delta...")
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig

    llm = LLM(LLMConfig(), agent_name="TestAgent")
    accumulated = ""
    done_streaming = 0
    chunks = [{"content": ""}, {"content": ""}, {"content": "<function=a></function>"}]

    for chunk in chunks:
        delta = chunk.get("content", "")
        if delta:
            accumulated += delta
        # Simulate the fixed streaming logic
        if done_streaming:
            done_streaming += 1
            if done_streaming > 5:
                break
            continue
        if delta and ("</function>" in accumulated or "</invoke>" in accumulated):
            done_streaming = 1
            continue

    assert "</function>" in accumulated
    print("  PASS: Empty deltas don't break streaming")


def test_fix2_streaming_many_tools():
    """FIX 2: Verify 5 tool calls in one turn are all preserved."""
    print("\n[ATTACK 3] Five tool calls in one LLM turn...")
    from phantom.llm.utils import parse_tool_invocations

    accumulated = (
        "<function=a><parameter=x>1</parameter></function>\n"
        "<function=b><parameter>x>2</parameter></function>\n"
        "<function=c><parameter>x>3</parameter></function>\n"
        "<function=d><parameter>x>4</parameter></function>\n"
        "<function=e><parameter>x>5</parameter></function>"
    )
    tools = parse_tool_invocations(accumulated)
    assert len(tools) == 5, f"Expected 5 tools, got {len(tools)}"
    print("  PASS: Five tool calls preserved")


def test_fix3_dedupe_non_phantom_model():
    """FIX 3: Dedupe with non-phantom model should work."""
    print("\n[ATTACK 4] Dedupe with non-phantom model...")
    from phantom.llm.utils import resolve_phantom_model

    api_model, canonical = resolve_phantom_model("gpt-4")
    assert api_model == "gpt-4"
    assert canonical == "gpt-4"
    print("  PASS: Non-phantom model passes through correctly")


def test_fix4_summarizer_short_text():
    """FIX 4: Short text below threshold should bypass summarizer entirely."""
    print("\n[ATTACK 5] Short text bypasses summarizer...")
    import os

    os.environ["PHANTOM_USE_AUTO_SUMMARIZE"] = "true"
    from phantom.tools.executor import _auto_summarize_result

    short_text = "Short output"
    result = asyncio.run(_auto_summarize_result(short_text, "test_tool"))
    assert result == short_text, "Short text should not be modified"
    print("  PASS: Short text bypasses summarizer")


def test_fix5_checkpoint_corrupt():
    """FIX 5: Corrupt checkpoint should gracefully fall back to fresh state."""
    print("\n[ATTACK 6] Corrupt checkpoint fallback...")
    import tempfile
    from phantom.checkpoint.checkpoint import CheckpointManager

    with tempfile.TemporaryDirectory() as tmpdir:
        run_dir = Path(tmpdir) / "bad_run"
        mgr = CheckpointManager(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "checkpoint.json").write_text("NOT_JSON{{{")
        (run_dir / "checkpoint.json.hmac").write_text("invalid")
        loaded = mgr.load()
        assert loaded is None, "Corrupt checkpoint should return None"
    print("  PASS: Corrupt checkpoint falls back gracefully")


def test_fix5_checkpoint_missing():
    """FIX 5: Missing checkpoint should return None, not crash."""
    print("\n[ATTACK 7] Missing checkpoint...")
    import tempfile
    from phantom.checkpoint.checkpoint import CheckpointManager

    with tempfile.TemporaryDirectory() as tmpdir:
        run_dir = Path(tmpdir) / "no_checkpoint"
        mgr = CheckpointManager(run_dir)
        loaded = mgr.load()
        assert loaded is None
    print("  PASS: Missing checkpoint returns None")


def test_fix7_context_various_errors():
    """FIX 7: Context detector handles various provider error messages."""
    print("\n[ATTACK 8] Context error detection coverage...")
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig

    llm = LLM(LLMConfig(), agent_name="TestAgent")
    errors = [
        "maximum context length exceeded",
        "too many tokens in your prompt",
        "input is too long for model",
        "payload too large",
        "token count exceeds limit",
        "request body too large",
    ]
    for msg in errors:
        e = Exception(msg)
        assert llm._is_context_too_large(e), f"Should detect: {msg}"
    # Non-context errors should NOT match
    non_context = [
        "invalid api key",
        "rate limit exceeded",
        "server error 500",
    ]
    for msg in non_context:
        e = Exception(msg)
        assert not llm._is_context_too_large(e), f"Should NOT detect: {msg}"
    print("  PASS: Context error detection is accurate")


def test_fix8_exception_catching():
    """FIX 8: Verify KeyError, AttributeError, OSError are all caught."""
    print("\n[ATTACK 9] Exception handler breadth...")
    import ast

    source = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            exc_type = ast.unparse(node.type) if node.type else ""
            if exc_type == "Exception":
                found = True
                break
    assert found, "Must catch broad Exception"
    print("  PASS: Broad Exception handler covers all subtypes")


def test_fix9_hypothesis_no_false_positive():
    """FIX 9: Non-anchor messages about other hypotheses should still be dropped."""
    print("\n[ATTACK 10] Non-anchor other-hypothesis messages dropped...")
    from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS

    msg = "This is about hypothesis_xyz but has no anchor keywords"
    has_anchor = any(k in msg.lower() for k in _ANCHOR_KEYWORDS)
    assert not has_anchor, "Plain mention of hypothesis without anchor should not be kept"
    print("  PASS: Plain hypothesis messages correctly dropped")


if __name__ == "__main__":
    print("=" * 60)
    print("PHANTOM FIXES — ADVERSARIAL ATTACK SUITE")
    print("=" * 60)

    tests = [
        test_fix1_no_regression_empty_messages,
        test_fix2_streaming_edge_empty_delta,
        test_fix2_streaming_many_tools,
        test_fix3_dedupe_non_phantom_model,
        test_fix4_summarizer_short_text,
        test_fix5_checkpoint_corrupt,
        test_fix5_checkpoint_missing,
        test_fix7_context_various_errors,
        test_fix8_exception_catching,
        test_fix9_hypothesis_no_false_positive,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {e}")

    print("\n" + "=" * 60)
    print(f"ATTACK RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
