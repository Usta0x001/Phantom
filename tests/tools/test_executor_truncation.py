"""Pytest tests for executor.py — truncation and per-tool overrides."""

import base64
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

    def test_built_in_terminal_execute(self):
        """terminal_execute has a built-in default of 4000."""
        assert _get_truncation_limit("terminal_execute") == 4000

    def test_built_in_browser_action(self):
        """browser_action has a built-in default of 3000."""
        assert _get_truncation_limit("browser_action") == 3000

    def test_built_in_naabu(self):
        """naabu (port scanner) has a tight built-in default of 1500."""
        assert _get_truncation_limit("naabu") == 1500

    def test_built_in_nmap(self):
        """nmap has a built-in default of 3000."""
        assert _get_truncation_limit("nmap") == 3000

    def test_built_in_nuclei(self):
        """nuclei (vuln scanner) has a built-in default of 5000."""
        assert _get_truncation_limit("nuclei") == 5000

    def test_env_override_beats_builtin(self, monkeypatch):
        """Env-var overrides take priority over built-in defaults."""
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        assert _get_truncation_limit("nuclei") == 10000

    def test_override_single_tool(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        assert _get_truncation_limit("nuclei") == 10000

    def test_override_multiple_tools(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000,grep=3000")
        assert _get_truncation_limit("nuclei") == 10000
        assert _get_truncation_limit("grep") == 3000

    def test_unspecified_tool_falls_back_to_default(self, monkeypatch):
        """Tools not in built-in table and not in env fall back to global default 6000."""
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        assert _get_truncation_limit("whatevs_unknown_tool") == 6000

    def test_builtin_without_env_override(self):
        """nuclei built-in default is 5000 when no env override is set."""
        assert "PHANTOM_TOOL_TRUNCATION_OVERRIDES" not in os.environ
        assert _get_truncation_limit("nuclei") == 5000

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
        # 9000 chars — should NOT be truncated under nuclei's 10k override
        result, _ = _format_tool_result("nuclei", "N" * 9000)
        assert "truncated" not in result.lower()

    def test_nuclei_truncates_above_override(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TOOL_TRUNCATION_OVERRIDES", "nuclei=10000")
        result, _ = _format_tool_result("nuclei", "N" * 10001)
        assert "truncated" in result.lower()

    def test_nuclei_uses_builtin_5000_without_override(self):
        # nuclei built-in = 5000; 5001 chars → truncated
        result, _ = _format_tool_result("nuclei", "N" * 5001)
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

    def test_other_tools_use_builtin_limits(self):
        # nmap built-in = 3000; 6001 chars → truncated
        result, _ = _format_tool_result("nmap", "M" * 6001)
        assert "truncated" in result.lower()

    def test_terminal_execute_builtin_limit(self):
        # terminal_execute built-in = 4000; 4001 → truncated
        result, _ = _format_tool_result("terminal_execute", "T" * 4001)
        assert "truncated" in result.lower()

    def test_terminal_execute_not_truncated_under_limit(self):
        result, _ = _format_tool_result("terminal_execute", "T" * 3999)
        assert "truncated" not in result.lower()


class TestAdaptiveTruncationAndVisionModes:
    def test_browser_high_signal_gets_burst_limit(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_ADAPTIVE_TRUNCATION", "true")
        monkeypatch.setenv("PHANTOM_BROWSER_TRUNCATION_BURST_LIMIT", "10000")
        payload = "SQL syntax error near SELECT " + ("X" * 9000)
        result, _ = _format_tool_result("browser_action", payload)
        assert "truncated" not in result.lower()

    def test_browser_non_signal_still_truncated(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_ADAPTIVE_TRUNCATION", "true")
        payload = "X" * 3500
        result, _ = _format_tool_result("browser_action", payload)
        assert "truncated" in result.lower()

    def test_browser_thumb_mode_attaches_image_url(self, monkeypatch):
        one_px_png = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
            "/w8AAusB9Y9Y6mQAAAAASUVORK5CYII="
        )
        monkeypatch.setenv("PHANTOM_ATTACH_BROWSER_IMAGES", "true")
        monkeypatch.setenv("PHANTOM_BROWSER_IMAGE_MODE", "thumb")
        monkeypatch.setenv("PHANTOM_BROWSER_IMAGE_MAX_PER_TURN", "1")

        xml, images = _format_tool_result("browser_action", {"screenshot": one_px_png, "ok": True})

        assert "data:image" not in xml
        assert images and images[0].get("type") == "image_url"

    def test_browser_full_mode_respects_byte_cap(self, monkeypatch):
        raw = b"Z" * 2048
        screenshot = base64.b64encode(raw).decode("ascii")
        monkeypatch.setenv("PHANTOM_ATTACH_BROWSER_IMAGES", "true")
        monkeypatch.setenv("PHANTOM_BROWSER_IMAGE_MODE", "full")
        monkeypatch.setenv("PHANTOM_BROWSER_IMAGE_FULL_MAX_BYTES", "1000")

        _, images = _format_tool_result("browser_action", {"screenshot": screenshot, "ok": True})
        # Over cap, so image_url should not be attached in full mode fallback path here.
        # In _format_tool_result compatibility wrapper, this yields no attached images.
        assert not images or all(i.get("type") != "image_url" for i in images)
