"""
Tests for the Strategic Planner (BUG-001 FIX).

Validates:
- Phase-aware tool recommendations
- Stagnation detection
- Coverage tracking
- Recommendation generation
"""

from unittest.mock import MagicMock

import pytest

from phantom.core.strategic_planner import StrategicPlanner


# ── Fixtures ──


def _make_state(**overrides):
    state = MagicMock()
    state.hosts = overrides.get("hosts", {})
    state.subdomains = overrides.get("subdomains", [])
    state.endpoints = overrides.get("endpoints", [])
    state.vuln_stats = overrides.get("vuln_stats", {"total": 0})
    state.verified_vulns = overrides.get("verified_vulns", [])
    state.findings_ledger = overrides.get("findings_ledger", [])
    return state


def _make_phase(value: str):
    phase = MagicMock()
    phase.value = value
    return phase


# ── Phase Guidance ──


class TestPhaseGuidance:
    def test_recon_guidance(self):
        planner = StrategicPlanner()
        state = _make_state()
        phase = _make_phase("reconnaissance")
        guidance = planner.generate_phase_guidance(state, phase)
        assert "RECONNAISSANCE" in guidance
        assert "nmap_scan" in guidance or "Recommended tools" in guidance

    def test_exploitation_guidance(self):
        planner = StrategicPlanner()
        state = _make_state(vuln_stats={"total": 3})
        phase = _make_phase("exploitation")
        guidance = planner.generate_phase_guidance(state, phase)
        assert "EXPLOITATION" in guidance
        assert "sqlmap" in guidance.lower() or "send_request" in guidance.lower()

    def test_coverage_in_guidance(self):
        planner = StrategicPlanner()
        planner._coverage["hosts_scanned"] = {"10.0.0.1", "10.0.0.2"}
        state = _make_state()
        phase = _make_phase("enumeration")
        guidance = planner.generate_phase_guidance(state, phase)
        assert "2 hosts scanned" in guidance


# ── Stagnation Detection ──


class TestStagnationDetection:
    def test_no_stagnation_initially(self):
        planner = StrategicPlanner()
        state = _make_state()
        phase = _make_phase("reconnaissance")
        rec = planner.get_next_recommendation(state, phase)
        assert rec is None  # Not enough history

    def test_stagnation_detected_after_repeated_tool(self):
        planner = StrategicPlanner()
        state = _make_state()
        # Simulate 10 calls to the same tool with no findings
        for _ in range(10):
            planner.record_tool_call("nmap_scan", {"target": "10.0.0.1"}, {}, state)

        stagnation = planner._detect_stagnation()
        assert stagnation is not None
        assert "nmap_scan" in stagnation

    def test_no_stagnation_with_diverse_tools(self):
        planner = StrategicPlanner()
        state = _make_state()
        tools = ["nmap_scan", "ffuf_directory_scan", "nuclei_scan", "httpx_probe",
                 "katana_crawl", "subfinder_scan", "dns_lookup", "httpx_full_analysis",
                 "nmap_vuln_scan", "sqlmap_test"]
        for tool in tools:
            planner.record_tool_call(tool, {}, {}, state)

        stagnation = planner._detect_stagnation()
        assert stagnation is None

    def test_no_stagnation_when_findings_present(self):
        planner = StrategicPlanner()
        state = _make_state()
        # Same tool but with findings each time
        for _ in range(10):
            result = {"vulnerabilities": [{"id": "v1"}]}
            planner.record_tool_call("nuclei_scan", {}, result, state)

        stagnation = planner._detect_stagnation()
        assert stagnation is None


# ── Recommendation ──


class TestRecommendation:
    def test_recommendation_when_stagnating(self):
        planner = StrategicPlanner()
        state = _make_state()
        phase = _make_phase("reconnaissance")

        # Stagnate on one tool
        for _ in range(10):
            planner.record_tool_call("nmap_scan", {}, {}, state)

        rec = planner.get_next_recommendation(state, phase)
        assert rec is not None
        assert "stagnating" in rec.lower()


# ── Coverage Tracking ──


class TestCoverageTracking:
    def test_tool_usage_tracked(self):
        planner = StrategicPlanner()
        state = _make_state()
        planner.record_tool_call("nmap_scan", {"target": "10.0.0.1"}, {}, state)
        assert "nmap_scan" in planner._coverage["tools_used"]

    def test_host_coverage_tracked(self):
        planner = StrategicPlanner()
        state = _make_state()
        planner.record_tool_call("nmap_scan", {"target": "10.0.0.1"}, {}, state)
        assert "10.0.0.1" in planner._coverage["hosts_scanned"]

    def test_endpoint_coverage_tracked(self):
        planner = StrategicPlanner()
        state = _make_state()
        planner.record_tool_call(
            "ffuf_directory_scan", {"target": "http://10.0.0.1"}, {}, state,
        )
        assert "http://10.0.0.1" in planner._coverage["endpoints_tested"]


# ── Attack Graph Integration ──


class TestGraphIntegration:
    def test_guidance_includes_graph_stats(self):
        from phantom.core.attack_graph import AttackGraph
        graph = AttackGraph()
        graph.add_host("10.0.0.1", ports=[80])
        graph.add_vulnerability("v1", "SQLi", severity="critical", host="10.0.0.1", port=80)

        planner = StrategicPlanner(attack_graph=graph)
        state = _make_state()
        phase = _make_phase("vulnerability_scanning")
        guidance = planner.generate_phase_guidance(state, phase)
        assert "Attack surface" in guidance
