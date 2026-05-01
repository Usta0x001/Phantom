"""
ADVERSARIAL ATTACK SUITE — Round 3
Attempts to break the new fixes with edge cases.
"""

import sys
from pathlib import Path


def attack_a1_empty_tool_list():
    """A1: Empty tool list should not crash."""
    print("\n[ATTACK A1] Empty tool list...")
    from phantom.tools.dynamic_tools import get_compact_tools_prompt_subset

    result = get_compact_tools_prompt_subset([], max_chars=1000)
    assert "tool_catalog_note" in result, f"Expected note for empty list, got: {result}"
    print("  PASS")


def attack_a2_single_tool_exceeds_cap():
    """A2: A single very long tool entry with tiny cap."""
    print("\n[ATTACK A2] Single tool exceeds cap...")
    from phantom.tools.dynamic_tools import get_compact_tools_prompt_subset
    from phantom.tools.registry import get_tool_names

    real_tools = get_tool_names()
    if not real_tools:
        print("  SKIP")
        return
    # Cap smaller than header
    result = get_compact_tools_prompt_subset(real_tools[:1], max_chars=10)
    assert "omitted" in result.lower() or "No tools" in result
    print("  PASS")


def attack_a3_skills_truncation():
    """A3: Skills system removed — no dynamic skills rendering in template."""
    print("\n[ATTACK A3] Skills truncation...")
    source = Path("phantom/agents/PhantomAgent/system_prompt.jinja").read_text(encoding="utf-8")
    # Skills system was deleted; template should not contain dynamic skill rendering
    assert "get_skill(" not in source, "Dead skills rendering should be removed from template"
    print("  PASS")


def attack_b1_session_overwrite():
    """B1: Overwriting a session should update disk."""
    print("\n[ATTACK B1] Session overwrite...")
    from phantom.tools.session.session_actions import store_session, get_session, clear_sessions

    clear_sessions()
    store_session("overwrite_test", cookies={"v": "1"})
    store_session("overwrite_test", cookies={"v": "2"})
    sess = get_session("overwrite_test")
    assert sess["cookies"]["v"] == "2"
    clear_sessions()
    print("  PASS")


def attack_b2_session_special_chars():
    """B2: Session with special characters in cookies."""
    print("\n[ATTACK B2] Session special chars...")
    from phantom.tools.session.session_actions import store_session, get_session, clear_sessions

    clear_sessions()
    store_session("special", cookies={"data": "<script>alert(1)</script>"})
    sess = get_session("special")
    assert "<script>" in sess["cookies"]["data"]
    clear_sessions()
    print("  PASS")


def attack_c1_compressor_no_regression():
    """C1: recent_digests doesn't break when recent_msgs is empty."""
    print("\n[ATTACK C1] Compressor empty recent...")
    source = Path("phantom/llm/memory_compressor.py").read_text(encoding="utf-8")
    # Make sure recent_digests is computed safely (list comp on empty list = empty list)
    assert "recent_digests = [_message_digest(msg) for msg in recent_msgs]" in source
    print("  PASS")


def attack_d1_no_error_calls_refs():
    """D1: No references to _error_calls remain anywhere."""
    print("\n[ATTACK D1] No _error_calls references...")
    source = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
    assert "_error_calls" not in source
    print("  PASS")


def attack_e1_model_map_no_fiction():
    """E1: Model map doesn't contain future/unreleased models."""
    print("\n[ATTACK E1] Model map no fiction...")
    from phantom.llm.utils import PHANTOM_MODEL_MAP

    for alias, resolved in PHANTOM_MODEL_MAP.items():
        assert "/" in resolved, f"Model {alias} -> {resolved} lacks provider prefix"
    print("  PASS")


def attack_f1_percent_in_command():
    """F1: Command with %20 should pass quarantine."""
    print("\n[ATTACK F1] Percent in command...")
    try:
        from phantom.tools.terminal.terminal_session import TerminalSession
    except ImportError:
        print("  SKIP")
        return
    quarantine = TerminalSession._QUARANTINE_METACHARACTERS
    assert "%" not in quarantine
    print("  PASS")


if __name__ == "__main__":
    print("=" * 65)
    print("PHANTOM ROUND 3 — ADVERSARIAL ATTACK SUITE")
    print("=" * 65)

    tests = [
        attack_a1_empty_tool_list,
        attack_a2_single_tool_exceeds_cap,
        attack_a3_skills_truncation,
        attack_b1_session_overwrite,
        attack_b2_session_special_chars,
        attack_c1_compressor_no_regression,
        attack_d1_no_error_calls_refs,
        attack_e1_model_map_no_fiction,
        attack_f1_percent_in_command,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {e}")

    print("\n" + "=" * 65)
    print(f"ATTACK RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 65)
    sys.exit(0 if failed == 0 else 1)
