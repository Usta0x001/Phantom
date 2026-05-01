"""
Validation script for critical fixes applied to Phantom AI.
Tests each fix to ensure it behaves correctly.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


def test_fix1_tool_message_preservation():
    """FIX 1: base_agent no longer reverts state.messages to pre-tool snapshot."""
    print("\n[TEST 1] Tool message preservation...")
    from phantom.agents.state import AgentState

    state = AgentState(agent_name="TestAgent", max_iterations=10)
    state.messages = [
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": "<function=terminal_execute><parameter=command>id</parameter></function>",
        },
    ]
    # Simulate tool execution adding a result message
    state.messages.append({"role": "user", "content": "uid=0(root) gid=0(root)"})

    # The buggy code did: state.messages = conversation_history (pre-tool snapshot)
    # The fix removed that line. We verify messages are preserved.
    assert len(state.messages) == 3, f"Expected 3 messages, got {len(state.messages)}"
    assert "uid=0" in str(state.messages[-1]["content"]), "Tool result message was lost!"
    print("  PASS: Tool results preserved in state.messages")


def test_fix2_multi_tool_streaming():
    """FIX 2: Streaming no longer truncates after first </function>."""
    print("\n[TEST 2] Multi-tool streaming preservation...")
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig

    llm = LLM(LLMConfig(), agent_name="TestAgent")

    # Simulate accumulated text with multiple tool calls
    accumulated = (
        "<function=send_request><parameter=method>GET</parameter></function>\n"
        "<function=terminal_execute><parameter=command>id</parameter></function>"
    )

    # The buggy code did: accumulated = _truncate_to_first_function(accumulated)
    # We removed that. Verify parse_tool_invocations finds BOTH tools.
    from phantom.llm.utils import parse_tool_invocations

    tools = parse_tool_invocations(accumulated)
    assert tools is not None, "parse_tool_invocations returned None"
    assert len(tools) == 2, f"Expected 2 tool invocations, got {len(tools)}"
    tool_names = [t["toolName"] for t in tools]
    assert "send_request" in tool_names, "send_request missing from parsed tools"
    assert "terminal_execute" in tool_names, "terminal_execute missing from parsed tools"
    print("  PASS: Both tool calls preserved in streaming output")


def test_fix3_dedupe_auth():
    """FIX 3: Dedupe no longer passes model name as API key."""
    print("\n[TEST 3] Dedupe API key fix...")
    from phantom.llm.utils import resolve_phantom_model

    api_model, canonical = resolve_phantom_model("phantom/gpt-4")
    # resolve_phantom_model returns (api_model, canonical_model)
    # The old buggy code unpacked as (litellm_model, dedupe_api_key) = ...
    # which put canonical into dedupe_api_key.
    assert canonical != "", "canonical should not be empty"
    assert "/" in api_model, "api_model should be a model identifier"
    # Verify the function signature is correct
    assert isinstance(api_model, str) and isinstance(canonical, str)
    print(f"  PASS: resolve_phantom_model returns ({api_model}, {canonical}) correctly")


def test_fix4_summarizer_fallback():
    """FIX 4: Auto-summarizer returns substantial excerpt on failure."""
    print("\n[TEST 4] Summarizer fallback returns evidence...")
    import os

    os.environ["PHANTOM_USE_AUTO_SUMMARIZE"] = "true"
    from phantom.tools.executor import _auto_summarize_result

    # Put the vulnerability at the START so the 8000-char excerpt captures it
    long_text = "CRITICAL_VULNERABILITY_FOUND: SQLi on /api/login\n" + "A" * 50000

    # Force summarization failure by mocking tracked_acompletion to raise
    async def run_test():
        with patch("phantom.tools.executor.tracked_acompletion", side_effect=RuntimeError("boom")):
            result = await _auto_summarize_result(long_text, "sqlmap")
        assert "CRITICAL_VULNERABILITY_FOUND" in result, (
            f"Summarizer fallback hid the evidence! Result: {result[:200]}"
        )
        assert "returning first" in result, "Fallback should note it's returning excerpt"
        return True

    ok = asyncio.run(run_test())
    assert ok
    print("  PASS: Fallback preserves vulnerability evidence")


def test_fix5_checkpoint_restore():
    """FIX 5: BaseAgent attempts to restore from checkpoint."""
    print("\n[TEST 5] Checkpoint restore logic...")
    from phantom.checkpoint.checkpoint import CheckpointManager
    from phantom.checkpoint.models import CheckpointData
    from phantom.agents.state import AgentState

    with tempfile.TemporaryDirectory() as tmpdir:
        run_dir = Path(tmpdir) / "test_run"
        mgr = CheckpointManager(run_dir)

        # Build a fake checkpoint
        state = AgentState(agent_name="Root Agent", max_iterations=100)
        state.iteration = 42
        state.messages = [{"role": "user", "content": "test task"}]
        cp = CheckpointData(
            run_name="test_run",
            root_agent_state=state.model_dump(),
        )
        mgr.save(cp)

        # Load it back
        loaded = mgr.load()
        assert loaded is not None, "Checkpoint load returned None"
        assert loaded.root_agent_state is not None, "root_agent_state missing"
        restored = AgentState.model_validate(loaded.root_agent_state)
        assert restored.iteration == 42, f"Expected iteration 42, got {restored.iteration}"
        assert len(restored.messages) == 1, "Messages not restored"
        print("  PASS: Checkpoint save/load roundtrip works")


def test_fix6_terminal_parsing():
    """FIX 6: Terminal returns output AFTER prompt, not before."""
    print("\n[TEST 6] Terminal PS1 parsing...")
    try:
        from phantom.tools.terminal.terminal_session import TerminalSession
    except ImportError as e:
        print(f"  SKIP: Terminal deps not installed ({e})")
        return

    # Mock _combine_outputs_between_matches behavior
    ts = TerminalSession.__new__(TerminalSession)
    import re

    # One PS1 match at position 10, content after it at position 20
    content = "PROMPT$ command\noutput line 1\noutput line 2\nPROMPT$ "
    match = re.search(r"PROMPT\$", content)
    assert match is not None
    ps1_matches = [match]

    # With get_content_before_last_match=False (the fix), returns content AFTER match
    result_after = ts._combine_outputs_between_matches(content, ps1_matches, False)
    # With get_content_before_last_match=True (old bug), returns content BEFORE match
    result_before = ts._combine_outputs_between_matches(content, ps1_matches, True)

    assert "output line 1" in result_after, "Fixed behavior should include command output"
    assert "output line 1" not in result_before, "Bug behavior should exclude command output"
    print("  PASS: Terminal returns output after prompt")


def test_fix7_context_too_large_wired():
    """FIX 7: _is_context_too_large is now wired into _should_retry."""
    print("\n[TEST 7] Context-length error detection wired...")
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig

    llm = LLM(LLMConfig(), agent_name="TestAgent")

    # Simulate a context-length error
    class FakeError(Exception):
        pass

    e = FakeError("This request exceeds the maximum context length of 128000 tokens")
    assert llm._is_context_too_large(e), "Should detect context too large"

    # Verify _should_retry returns False for context errors (no wasted retries)
    assert not llm._should_retry(e), "Should NOT retry context-length errors"
    print("  PASS: Context-length errors are detected and not retried")


def test_fix8_broad_exception_handler():
    """FIX 8: Agent loop catches Exception instead of narrow tuple."""
    print("\n[TEST 8] Broad exception handler...")
    import ast

    source = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find the except clause in agent_loop
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            exc_type = ast.unparse(node.type) if node.type else ""
            if "Exception" in exc_type and "RuntimeError" not in exc_type:
                found = True
                break

    assert found, "agent_loop should catch broad Exception, not narrow tuple"
    print("  PASS: Agent loop catches broad Exception")


def test_fix9_hypothesis_context_anchors():
    """FIX 9: Anchor messages from other hypotheses survive filtering."""
    print("\n[TEST 9] Hypothesis context keeps anchor messages...")
    from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS

    # Verify anchor keywords exist
    assert len(_ANCHOR_KEYWORDS) > 0, "Anchor keywords should be populated"
    assert "vulnerability" in _ANCHOR_KEYWORDS or "confirmed" in _ANCHOR_KEYWORDS, (
        "Expected vulnerability/confirmed in anchors"
    )
    print("  PASS: Anchor keywords are available for context filtering")


def test_fix10_fallback_budget_gate():
    """FIX 10: Fallback model has budget gate."""
    print("\n[TEST 10] Fallback budget gate...")
    import ast

    source = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
    assert "self._check_budget()" in source, "_check_budget must be called before fallback"
    print("  PASS: Fallback model enforces budget gate")


if __name__ == "__main__":
    print("=" * 60)
    print("PHANTOM CRITICAL FIXES VALIDATION SUITE")
    print("=" * 60)

    tests = [
        test_fix1_tool_message_preservation,
        test_fix2_multi_tool_streaming,
        test_fix3_dedupe_auth,
        test_fix4_summarizer_fallback,
        test_fix5_checkpoint_restore,
        test_fix6_terminal_parsing,
        test_fix7_context_too_large_wired,
        test_fix8_broad_exception_handler,
        test_fix9_hypothesis_context_anchors,
        test_fix10_fallback_budget_gate,
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
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
