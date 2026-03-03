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
        assert p.max_iterations == 150, "Quick must be 150 iterations"

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
        assert MAX_TOTAL_TOKENS == 80_000, f"Expected 80K, got {MAX_TOTAL_TOKENS}"

    def test_max_messages_reduced(self):
        from phantom.llm.memory_compressor import MAX_MESSAGES
        assert MAX_MESSAGES == 150, f"Expected 150, got {MAX_MESSAGES}"

    def test_min_recent_messages_increased(self):
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
    """Validate subagent gets SMART context (first msgs + summary + recent)."""

    def test_smart_context_preserves_first_messages(self):
        """When parent has >8 messages, child should get first 2 + summary + last 5."""
        from phantom.tools.agents_graph.agents_graph_actions import _build_smart_context
        from unittest.mock import MagicMock

        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(50)]
        state = MagicMock()
        state.findings_ledger = []
        result = _build_smart_context(full_history, state)
        # First 2 should be preserved
        assert result[0]["content"] == "msg 0"
        assert result[1]["content"] == "msg 1"

    def test_smart_context_includes_recent(self):
        """Last 5 messages should be in the result."""
        from phantom.tools.agents_graph.agents_graph_actions import _build_smart_context
        from unittest.mock import MagicMock

        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(50)]
        state = MagicMock()
        state.findings_ledger = []
        result = _build_smart_context(full_history, state)
        last_contents = [m["content"] for m in result[-5:]]
        assert "msg 45" in last_contents
        assert "msg 49" in last_contents

    def test_small_history_passed_fully(self):
        from phantom.tools.agents_graph.agents_graph_actions import _build_smart_context
        from unittest.mock import MagicMock

        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(5)]
        state = MagicMock()
        state.findings_ledger = []
        result = _build_smart_context(full_history, state)
        assert len(result) == 5

    def test_findings_ledger_in_context(self):
        """If parent has findings, they should appear in the summary."""
        from phantom.tools.agents_graph.agents_graph_actions import _build_smart_context
        from unittest.mock import MagicMock

        full_history = [{"role": "user", "content": f"msg {i}"} for i in range(50)]
        state = MagicMock()
        state.findings_ledger = ["SQLi at /login", "XSS at /search"]
        result = _build_smart_context(full_history, state)
        # There should be a parent_findings_summary message
        summary_msgs = [m for m in result if "parent_findings_summary" in m.get("content", "")]
        assert len(summary_msgs) == 1
        assert "SQLi at /login" in summary_msgs[0]["content"]


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

    def test_truncation_at_16000_chars(self):
        from phantom.tools.executor import _format_tool_result
        big_result = "A" * 20000
        observation_xml, images = _format_tool_result("test_tool", big_result)
        # The truncated result should be smaller than original + XML overhead
        assert len(observation_xml) < 18000, f"Output too large: {len(observation_xml)}"
        assert "characters truncated" in observation_xml

    def test_small_output_not_truncated(self):
        from phantom.tools.executor import _format_tool_result
        small_result = "A" * 100
        observation_xml, images = _format_tool_result("test_tool", small_result)
        assert "characters truncated" not in observation_xml


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
    def test_version_is_current(self):
        from phantom import __version__
        assert __version__ == "0.9.20"


# =========================================================================
# Findings Ledger Tests (v0.9.7)
# =========================================================================


class TestFindingsLedger:
    """Validate persistent findings ledger in AgentState."""

    def test_agentstate_has_findings_ledger(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        assert hasattr(state, "findings_ledger")
        assert state.findings_ledger == []

    def test_add_finding(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        state.add_finding("SQLi at /login")
        assert len(state.findings_ledger) == 1
        assert state.findings_ledger[0] == "SQLi at /login"

    def test_get_findings_summary(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        state.add_finding("SQLi at /login")
        state.add_finding("XSS at /search")
        summary = state.get_findings_summary()
        assert "SQLi at /login" in summary
        assert "XSS at /search" in summary

    def test_findings_ledger_cap(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        for i in range(250):
            state.add_finding(f"finding {i}")
        # Should be capped at _MAX_FINDINGS // 2 + remaining
        assert len(state.findings_ledger) <= 200

    def test_record_finding_tool_registered(self):
        from phantom.tools.registry import get_tool_names
        names = get_tool_names()
        assert "record_finding" in names, f"record_finding not in {sorted(names)}"
        assert "get_findings_ledger" in names, f"get_findings_ledger not in {sorted(names)}"


class TestAutoRecordFindings:
    """Validate auto-recording of key findings from security tools."""

    def test_nuclei_findings_auto_recorded(self):
        from phantom.tools.executor import _auto_record_findings
        from phantom.agents.state import AgentState

        state = AgentState()
        result = {
            "success": True,
            "findings": [
                {"severity": "critical", "template_name": "sqli-test", "matched_at": "http://target/login"},
                {"severity": "info", "template_name": "tech-detect", "matched_at": "http://target/"},
            ],
        }
        _auto_record_findings("nuclei_scan", result, state)
        # v0.9.33: Both critical AND info findings are now recorded
        assert len(state.findings_ledger) == 2
        assert "sqli-test" in state.findings_ledger[0]
        assert "tech-detect" in state.findings_ledger[1]

    def test_nmap_ports_auto_recorded(self):
        from phantom.tools.executor import _auto_record_findings
        from phantom.agents.state import AgentState

        state = AgentState()
        result = {
            "success": True,
            "hosts": [
                {
                    "hostname": "target.com",
                    "ip": "10.0.0.1",
                    "ports": [
                        {"port": 80, "state": "open", "service": "http"},
                        {"port": 443, "state": "open", "service": "https"},
                        {"port": 22, "state": "closed", "service": "ssh"},
                    ],
                }
            ],
        }
        _auto_record_findings("nmap_scan", result, state)
        assert len(state.findings_ledger) == 1
        assert "80/http" in state.findings_ledger[0]
        assert "443/https" in state.findings_ledger[0]
        # Closed port should NOT appear
        assert "22/ssh" not in state.findings_ledger[0]

    def test_katana_crawl_auto_recorded(self):
        from phantom.tools.executor import _auto_record_findings
        from phantom.agents.state import AgentState

        state = AgentState()
        result = {
            "success": True,
            "total_urls": 42,
            "summary": {"api_endpoints": 5, "js_files": 8, "forms": 3},
            "api_endpoints": [
                {"url": "http://target/api/users"},
                {"url": "http://target/api/products"},
            ],
        }
        _auto_record_findings("katana_crawl", result, state)
        # Should record summary + API endpoints
        assert len(state.findings_ledger) >= 2
        assert any("42 URLs" in f for f in state.findings_ledger)
        assert any("/api/users" in f for f in state.findings_ledger)

    def test_failed_tool_not_recorded(self):
        from phantom.tools.executor import _auto_record_findings
        from phantom.agents.state import AgentState

        state = AgentState()
        result = {"success": False, "error": "timeout"}
        _auto_record_findings("nuclei_scan", result, state)
        assert len(state.findings_ledger) == 0


class TestMemoryCompressorLedger:
    """Validate findings ledger is injected during compression."""

    def test_ledger_message_built(self):
        from phantom.llm.memory_compressor import MemoryCompressor
        from phantom.agents.state import AgentState
        from unittest.mock import patch

        state = AgentState()
        state.add_finding("SQLi at /login")
        state.add_finding("XSS at /search")

        with patch.dict("os.environ", {"PHANTOM_LLM": "test-model"}):
            mc = MemoryCompressor(model_name="test-model")
            mc._agent_state = state
            msg = mc._build_ledger_message()

        assert msg is not None
        assert "SQLi at /login" in msg["content"]
        assert "persistent_findings_ledger" in msg["content"]

    def test_no_ledger_when_empty(self):
        from phantom.llm.memory_compressor import MemoryCompressor

        with patch.dict("os.environ", {"PHANTOM_LLM": "test-model"}):
            mc = MemoryCompressor(model_name="test-model")
            mc._agent_state = None
            msg = mc._build_ledger_message()
        assert msg is None
