"""
COMPREHENSIVE VALIDATION — Round 3 Fixes
Tests all new fixes: system prompt compactness, tool catalog capping,
session persistence, memory compressor dedup, model map cleanup,
WAF quarantine fix, dead code removal.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


def test_a1_system_prompt_compact():
    """A1: System prompt no longer has static tool list duplication."""
    print("\n[TEST A1] System prompt compactness...")
    source = Path("phantom/agents/PhantomAgent/system_prompt.jinja").read_text(encoding="utf-8")
    assert "PHANTOM TOOLS:" not in source, "Static tool list should be removed"
    assert "{{ get_tools_prompt() | safe }}" in source, "Dynamic catalog must remain"
    # Tool catalog should be LAST so truncation hits skills first
    tools_pos = source.find("{{ get_tools_prompt() | safe }}")
    skills_pos = source.find("{% if loaded_skill_names %}")
    assert tools_pos > skills_pos, "Tool catalog should come AFTER skills"
    print("  PASS")


def test_a2_tool_catalog_capped():
    """A2: Compact tool catalog has a hard size cap."""
    print("\n[TEST A2] Tool catalog size cap...")
    from phantom.tools.dynamic_tools import get_compact_tools_prompt_subset
    from phantom.tools.registry import get_tool_names

    real_tools = get_tool_names()
    if len(real_tools) < 5:
        print("  SKIP: not enough registered tools")
        return

    # Use real tools but force a very small cap so truncation fires
    result = get_compact_tools_prompt_subset(real_tools, max_chars=500)
    assert len(result) <= 600, f"Catalog exceeded cap: {len(result)} chars"
    assert "omitted" in result.lower(), f"Should note omitted tools: {result[:200]}"
    print("  PASS")


def test_a3_malformed_notice_compact():
    """A3: Malformed tool notice is ultra-compact."""
    print("\n[TEST A3] Malformed notice compactness...")
    source = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
    # The old notice had ~5 lines; the new one is a single line
    idx = source.find("malformed_notice")
    block = source[idx : idx + 800]
    line_count = block.count("\\n")
    assert line_count < 3, f"Malformed notice too verbose ({line_count} newlines)"
    assert "Valid names include" in block, "Should mention valid names briefly"
    print("  PASS")


def test_b1_session_persistence():
    """B1: Sessions persist to disk and reload."""
    print("\n[TEST B1] Session persistence...")
    from phantom.tools.session.session_actions import (
        store_session,
        get_session,
        clear_sessions,
        _SESSION_FILE,
    )

    clear_sessions()
    store_session("test_sess", cookies={"session": "abc123"}, headers={"X-Auth": "token"})
    assert _SESSION_FILE.exists(), "Session file should be created"
    data = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
    assert "test_sess" in data, "Session should be in file"
    loaded = get_session("test_sess")
    assert loaded is not None
    assert loaded["cookies"]["session"] == "abc123"
    clear_sessions()
    print("  PASS")


def test_c1_compressor_digest_tracking():
    """C1: Memory compressor stores digests of all messages, not just recent."""
    print("\n[TEST C1] Compressor digest tracking...")
    source = Path("phantom/llm/memory_compressor.py").read_text(encoding="utf-8")
    # Verify recent_digests is computed
    assert "recent_digests = [_message_digest(msg) for msg in recent_msgs]" in source
    # Verify it's stored alongside current_digest
    assert "current_digest + recent_digests" in source
    print("  PASS")


def test_d1_error_calls_removed():
    """D1: _error_calls dead code removed."""
    print("\n[TEST D1] _error_calls dead code removal...")
    source = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
    assert "self._error_calls" not in source, "_error_calls should be completely removed"
    print("  PASS")


def test_e1_model_map_realistic():
    """E1: Phantom model map contains only verified models."""
    print("\n[TEST E1] Model map realism...")
    from phantom.llm.utils import PHANTOM_MODEL_MAP

    fictional = {
        "gpt-5.2",
        "gpt-5.1",
        "gpt-5",
        "glm-5",
        "glm-4.7",
        "gemini-3-pro-preview",
        "gemini-3-flash-preview",
    }
    for alias in fictional:
        assert alias not in PHANTOM_MODEL_MAP, f"Fictional model {alias} still in map"
    # Verify known-good models exist
    assert "gpt-4o" in PHANTOM_MODEL_MAP or "claude-sonnet-4" in PHANTOM_MODEL_MAP
    print("  PASS")


def test_f1_waf_quarantine_allows_percent():
    """F1: WAF quarantine no longer blocks '%' character."""
    print("\n[TEST F1] WAF quarantine allows %...")
    try:
        from phantom.tools.terminal.terminal_session import TerminalSession
    except ImportError as e:
        print(f"  SKIP: Terminal deps not installed ({e})")
        return
    quarantine_chars = TerminalSession._QUARANTINE_METACHARACTERS
    assert "%" not in quarantine_chars, "% should NOT be in quarantine set"
    assert ";" in quarantine_chars, "; should still be blocked"
    print("  PASS")


def test_a4_default_subset_consistent():
    """A4: Default tool subset is consistent between config and llm.py."""
    print("\n[TEST A4] Default subset consistency...")
    from phantom.config import Config

    config_default = Config.get("phantom_tool_subset")
    assert config_default == "core", f"Config default should be 'core', got {config_default}"
    source = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
    assert 'or "core"' in source, "llm.py fallback should match config default"
    print("  PASS")


def test_b2_session_mgmt_persistence():
    """B2: Session mgmt module also persists to disk."""
    print("\n[TEST B2] Session mgmt persistence...")
    from phantom.tools.session_mgmt.session_mgmt_actions import (
        _SESSIONS,
        _SESSION_FILE,
        _save_sessions,
    )

    _SESSIONS["mgmt_test"] = {"cookies": {"a": "b"}, "headers": {}}
    _save_sessions(_SESSIONS)
    assert _SESSION_FILE.exists(), "Session mgmt file should be created"
    data = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
    assert "mgmt_test" in data
    del _SESSIONS["mgmt_test"]
    _save_sessions(_SESSIONS)
    print("  PASS")


if __name__ == "__main__":
    print("=" * 65)
    print("PHANTOM ROUND 3 FIXES — COMPREHENSIVE VALIDATION")
    print("=" * 65)

    tests = [
        test_a1_system_prompt_compact,
        test_a2_tool_catalog_capped,
        test_a3_malformed_notice_compact,
        test_a4_default_subset_consistent,
        test_b1_session_persistence,
        test_b2_session_mgmt_persistence,
        test_c1_compressor_digest_tracking,
        test_d1_error_calls_removed,
        test_e1_model_map_realistic,
        test_f1_waf_quarantine_allows_percent,
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
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 65)
    sys.exit(0 if failed == 0 else 1)
