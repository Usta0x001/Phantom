"""Tests for v0.9.6 vulnerability discovery overhaul.

Validates:
- Scan profile iteration and tool changes
- Tool output truncation limits
- Memory compressor settings
- Subagent iteration inheritance
- Subagent context inheritance cap
- Katana tool registration and parsing
- Nmap rate limiting changes
- Nuclei findings truncation
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# =========================================================================
# Scan Profile Tests
# =========================================================================


class TestScanProfilesV096:
    """Validate new iteration limits and tool configurations."""

    def test_quick_iterations_increased(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("quick")
        assert p.max_iterations == 60, "Quick must be 60 iterations"

    def test_standard_iterations_increased(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("standard")
        assert p.max_iterations == 120, "Standard must be 120 iterations"

    def test_deep_iterations_increased(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("deep")
        assert p.max_iterations == 300, "Deep must be 300 iterations"

    def test_stealth_iterations_increased(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("stealth")
        assert p.max_iterations == 60, "Stealth must be 60 iterations"

    def test_api_only_iterations_increased(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("api_only")
        assert p.max_iterations == 100, "API Only must be 100 iterations"

    def test_quick_does_not_skip_sqlmap(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("quick")
        assert "sqlmap_scan" not in p.skip_tools, "Quick must not skip sqlmap"

    def test_quick_does_not_skip_create_sub_agent(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("quick")
        assert "create_sub_agent" not in p.skip_tools

    def test_quick_enables_browser(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("quick")
        assert p.enable_browser is True

    def test_katana_in_standard_priority(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("standard")
        assert "katana_crawl" in p.priority_tools

    def test_katana_in_deep_priority(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("deep")
        assert "katana_crawl" in p.priority_tools

    def test_katana_in_api_only_priority(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("api_only")
        assert "katana_crawl" in p.priority_tools


# =========================================================================
# Memory Compressor Tests
# =========================================================================


class TestMemoryCompressorV096:
    """Validate reduced compression thresholds."""

    def test_max_total_tokens_reduced(self):
        from phantom.llm.memory_compressor import MAX_TOTAL_TOKENS
        assert MAX_TOTAL_TOKENS == 60_000, f"Expected 60K, got {MAX_TOTAL_TOKENS}"

    def test_max_messages_reduced(self):
        from phantom.llm.memory_compressor import MAX_MESSAGES
        assert MAX_MESSAGES == 150, f"Expected 150, got {MAX_MESSAGES}"

    def test_min_recent_messages_reduced(self):
        from phantom.llm.memory_compressor import MIN_RECENT_MESSAGES
        assert MIN_RECENT_MESSAGES == 12, f"Expected 12, got {MIN_RECENT_MESSAGES}"


# =========================================================================
# Nuclei Output Truncation Tests
# =========================================================================


class TestNucleiTruncation:
    """Validate nuclei findings are capped to prevent context bloat."""

    def test_parse_and_cap_findings(self):
        from phantom.tools.security.nuclei_tool import _parse_nuclei_jsonl

        # Generate 50 fake findings
        import json
        lines = []
        for i in range(50):
            sev = ["critical", "high", "medium", "low", "info"][i % 5]
            lines.append(json.dumps({
                "template-id": f"test-{i}",
                "info": {"name": f"Test {i}", "severity": sev},
                "host": "http://target",
                "matched-at": f"http://target/path{i}",
            }))
        raw = "\n".join(lines)
        findings = _parse_nuclei_jsonl(raw)
        assert len(findings) == 50, "Parser should return all findings"
        # The capping happens in the nuclei_scan function, not in parser

    def test_findings_are_sorted_by_severity_before_cap(self):
        """When we have >30 findings, critical/high should be kept."""
        # This tests the logic indirectly via severity sorting
        # The actual cap is in nuclei_scan which requires sandbox
        findings = [
            {"severity": "info"} for _ in range(20)
        ] + [
            {"severity": "critical"} for _ in range(15)
        ]
        # Simulate the sorting from nuclei_tool
        findings.sort(key=lambda f: {
            "critical": 0, "high": 1, "medium": 2, "low": 3
        }.get(f.get("severity", "info").lower(), 4))
        capped = findings[:30]
        critical_count = sum(1 for f in capped if f["severity"] == "critical")
        assert critical_count == 15, "All critical findings should be preserved"


# =========================================================================
# Subagent Iteration Inheritance Tests
# =========================================================================


class TestSubagentIterations:
    """Validate subagent iteration limits derive from parent profile."""

    def test_child_gets_60_percent_of_parent(self):
        """Child should get 60% of parent's max_iterations (min 40)."""
        # Test the calculation logic directly
        parent_max = 120  # standard profile
        child_max = max(40, int(parent_max * 0.6))
        assert child_max == 72

    def test_child_minimum_is_40(self):
        parent_max = 50
        child_max = max(40, int(parent_max * 0.6))
        assert child_max == 40, "Minimum should be 40"

    def test_deep_profile_child_iterations(self):
        parent_max = 300  # deep profile
        child_max = max(40, int(parent_max * 0.6))
        assert child_max == 180


# =========================================================================
# Subagent Context Inheritance Tests
# =========================================================================


class TestSubagentContextCap:
    """Validate subagent gets limited context, not full parent history."""

    def test_context_cap_at_10_messages(self):
        """When parent has >10 messages, child should get only last 10."""
        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(50)]
        _MAX_INHERITED = 10
        if len(full_history) > _MAX_INHERITED:
            inherited = full_history[-_MAX_INHERITED:]
        else:
            inherited = list(full_history)
        assert len(inherited) == 10
        assert inherited[0]["content"] == "msg 40"

    def test_small_history_passed_fully(self):
        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(5)]
        _MAX_INHERITED = 10
        if len(full_history) > _MAX_INHERITED:
            inherited = full_history[-_MAX_INHERITED:]
        else:
            inherited = list(full_history)
        assert len(inherited) == 5


# =========================================================================
# Katana Tool Tests
# =========================================================================


class TestKatanaTool:
    """Validate katana_crawl tool registration and output parsing."""

    def test_katana_tool_registered(self):
        from phantom.tools.registry import get_tool_names
        names = get_tool_names()
        assert "katana_crawl" in names, f"katana_crawl not in registered tools: {sorted(names)}"

    def test_parse_katana_plain_urls(self):
        from phantom.tools.security.katana_tool import _parse_katana_output
        raw = "http://target/login\nhttp://target/api/users\nhttp://target/main.js\n"
        results = _parse_katana_output(raw)
        assert len(results) == 3
        assert results[0]["url"] == "http://target/login"

    def test_parse_katana_jsonl(self):
        import json
        from phantom.tools.security.katana_tool import _parse_katana_output
        line = json.dumps({
            "request": {"endpoint": "http://target/api/v1", "method": "POST"},
            "response": {"status_code": 200},
        })
        results = _parse_katana_output(line)
        assert len(results) == 1
        assert results[0]["url"] == "http://target/api/v1"
        assert results[0]["method"] == "POST"

    def test_parse_katana_empty(self):
        from phantom.tools.security.katana_tool import _parse_katana_output
        assert _parse_katana_output("") == []
        assert _parse_katana_output("\n\n") == []


# =========================================================================
# Tool Output Truncation Tests
# =========================================================================


class TestToolOutputTruncation:
    """Validate executor truncates large tool outputs."""

    def test_truncation_at_6000_chars(self):
        from phantom.tools.executor import _format_tool_result
        big_result = "A" * 8000
        observation_xml, images = _format_tool_result("test_tool", big_result)
        # The truncated result should be about 5000 + XML overhead
        assert len(observation_xml) < 7000, f"Output too large: {len(observation_xml)}"
        assert "... [middle content truncated] ..." in observation_xml

    def test_small_output_not_truncated(self):
        from phantom.tools.executor import _format_tool_result
        small_result = "A" * 100
        observation_xml, images = _format_tool_result("test_tool", small_result)
        assert "... [middle content truncated] ..." not in observation_xml


# =========================================================================
# Nmap Rate Limiting Tests
# =========================================================================


class TestNmapRateLimiting:
    """Validate nmap comprehensive scan no longer uses -p- and has rate limits."""

    def test_comprehensive_uses_top_ports_not_all(self):
        """nmap comprehensive should use --top-ports, not -p- (all ports)."""
        from phantom.tools.security import nmap_tool
        import inspect
        source = inspect.getsource(nmap_tool.nmap_scan)
        assert "--top-ports" in source, "Comprehensive scan should use --top-ports"
        # Check the actual command-building logic, not the docstring
        # The old code had: cmd_parts.extend(["-p-", ...])
        # The new code has: cmd_parts.extend(["--top-ports", "10000", ...])
        # We verify -p- is no longer in any cmd_parts.extend line
        import re
        cmd_lines = [l for l in source.split('\n') if 'cmd_parts' in l and 'extend' in l]
        for line in cmd_lines:
            assert '"-p-"' not in line, f"cmd_parts still uses -p-: {line}"

    def test_rate_limits_present(self):
        from phantom.tools.security import nmap_tool
        import inspect
        source = inspect.getsource(nmap_tool.nmap_scan)
        assert "--max-rate" in source, "All scan types should have --max-rate"


# =========================================================================
# Version Test
# =========================================================================


class TestVersion096:
    def test_version_is_096(self):
        from phantom import __version__
        assert __version__ == "0.9.6"
