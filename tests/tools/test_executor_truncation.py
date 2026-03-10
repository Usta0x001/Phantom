"""Pytest tests for executor.py — truncation and per-tool overrides."""

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phantom.tools.executor import _format_tool_result, _get_truncation_limit


# ── _get_truncation_limit ──────────────────────────────────────────────────────

class TestGetTruncationLimit:
    def test_default_is_6000(self):
        assert _get_truncation_limit("unknown_tool") == 6000

    def test_override_single_tool(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        assert _get_truncation_limit("nuclei") == 10000

    def test_override_multiple_tools(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000,grep=3000")
        assert _get_truncation_limit("nuclei") == 10000
        assert _get_truncation_limit("grep") == 3000

    def test_unspecified_tool_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        assert _get_truncation_limit("nmap") == 6000

    def test_env_not_set_returns_default(self):
        assert "PHANTOM_TOOL_TRUNCATION_OVERRIDES" not in os.environ
        assert _get_truncation_limit("nuclei") == 6000

    def test_invalid_value_returns_default(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=not-a-number")
        assert _get_truncation_limit("nuclei") == 6000

    def test_whitespace_trimmed(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", " nuclei = 8000 , grep = 2000 ")
        assert _get_truncation_limit("nuclei") == 8000
        assert _get_truncation_limit("grep") == 2000

    def test_malformed_entry_without_equals_is_skipped(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "malformed,nuclei=5000")
        assert _get_truncation_limit("nuclei") == 5000
        assert _get_truncation_limit("malformed") == 6000


# ── _format_tool_result — default truncation ───────────────────────────────────

class TestFormatToolResultDefaultTruncation:
    def test_truncates_at_6001_chars(self):
        result, _ = _format_tool_result("sometool", "A" * 6001)
        assert "truncated" in result.lower()

    def test_no_truncation_at_5999_chars(self):
        result, _ = _format_tool_result("sometool", "B" * 5999)
        assert "truncated" not in result.lower()

    def test_head_and_tail_preserved(self):
        result, _ = _format_tool_result("sometool", "HEAD" + "X" * 7990 + "TAIL")
        assert "HEAD" in result
        assert "TAIL" in result

    def test_output_fits_in_context_after_truncation(self):
        result, _ = _format_tool_result("sometool", "Z" * 20000)
        # 2500 head + 2500 tail + small markup overhead
        assert len(result) < 7000

    def test_none_result_becomes_success_message(self):
        result, _ = _format_tool_result("sometool", None)
        assert "executed successfully" in result

    def test_returns_xml_wrapper(self):
        result, _ = _format_tool_result("sometool", "data")
        assert "<tool_result>" in result
        assert "<tool_name>sometool</tool_name>" in result


# ── _format_tool_result — per-tool override ────────────────────────────────────

class TestFormatToolResultWithOverride:
    def test_nuclei_uses_10000_limit(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        # 9000 chars — should NOT be truncated under nuclei's 10k limit
        result, _ = _format_tool_result("nuclei", "N" * 9000)
        assert "truncated" not in result.lower()

    def test_nuclei_truncates_above_override(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        result, _ = _format_tool_result("nuclei", "N" * 10001)
        assert "truncated" in result.lower()

    def test_grep_uses_smaller_limit(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "grep=3000")
        # 4000 chars — over 3000, so it should be truncated
        result, _ = _format_tool_result("grep", "G" * 4000)
        assert "truncated" in result.lower()

    def test_grep_not_truncated_under_limit(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "grep=3000")
        result, _ = _format_tool_result("grep", "G" * 2999)
        assert "truncated" not in result.lower()

    def test_other_tools_unaffected_by_nuclei_override(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        # nmap uses default 6000
        result, _ = _format_tool_result("nmap", "M" * 6001)
        assert "truncated" in result.lower()
