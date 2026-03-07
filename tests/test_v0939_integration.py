"""
Integration tests for v0.9.39 audit fixes.

Tests the full pipeline:
  LLM proposes → graph validates → executor runs → validator verifies →
  critic reviews → confidence updates

Validates cross-module integration between:
- ScanStateMachine
- StrategicPlanner
- AdversarialCritic
- ConfidenceEngine
- EvidenceRegistry
- HypothesisTracker
- AttackGraph
"""

from unittest.mock import MagicMock

import pytest

from phantom.core.attack_graph import AttackGraph, NodeType
from phantom.core.scan_state_machine import ScanState, ScanStateMachine
from phantom.core.strategic_planner import StrategicPlanner
from phantom.core.adversarial_critic import AdversarialCritic
from phantom.core.confidence_engine import ConfidenceEngine
from phantom.core.evidence_registry import EvidenceRegistry, EvidenceType, EvidenceQuality
from phantom.core.hypothesis_tracker import HypothesisTracker, HypothesisStatus


# ── Fixtures ──


def _make_state(**overrides):
    """Create a mock EnhancedAgentState."""
    state = MagicMock()
    state.sandbox_id = "sandbox-1"
    state.hosts = overrides.get("hosts", {})
    state.subdomains = overrides.get("subdomains", [])
    state.endpoints = overrides.get("endpoints", [])
    state.vulnerabilities = overrides.get("vulnerabilities", {})
    state.vuln_stats = overrides.get("vuln_stats", {"total": 0})
    state.pending_verification = overrides.get("pending_verification", [])
    state.verified_vulns = overrides.get("verified_vulns", [])
    state.false_positives = overrides.get("false_positives", [])
    state.findings_ledger = overrides.get("findings_ledger", [])
    state.tested_endpoints = overrides.get("tested_endpoints", {})
    return state


def _make_phase(value: str):
    phase = MagicMock()
    phase.value = value
    return phase


def _make_vuln(vid: str, severity: str = "high"):
    v = MagicMock()
    v.id = vid
    v.severity.value = severity
    return v


# ── Full Scan Simulation ──


class TestFullScanPipeline:
    """Simulate a complete scan lifecycle through all intelligence components."""

    def test_recon_through_reporting(self):
        # Initialize all components
        graph = AttackGraph()
        fsm = ScanStateMachine()
        planner = StrategicPlanner(graph)
        critic = AdversarialCritic()
        confidence = ConfidenceEngine()
        evidence_reg = EvidenceRegistry()
        hypothesis = HypothesisTracker()

        mock_host = MagicMock()
        mock_host.ports = [MagicMock()]

        # Phase 1: INIT → RECON
        state = _make_state()
        state.attack_graph = graph
        state.state_machine = fsm
        fsm.transition(ScanState.RECONNAISSANCE, state)
        assert fsm.current_state == ScanState.RECONNAISSANCE

        # Planner gives recon guidance
        guidance = planner.generate_phase_guidance(state, fsm.current_state)
        assert "RECONNAISSANCE" in guidance

        # Critic allows nmap during recon
        verdict = critic.review_action("nmap_scan", {"target": "10.0.0.1"}, state, fsm.current_state)
        assert verdict.allowed
        assert len(verdict.issues) == 0

        # Critic should warn about sqlmap during recon
        verdict2 = critic.review_action("sqlmap_test", {}, state, fsm.current_state)
        assert len(verdict2.issues) > 0

        # Record tool usage
        planner.record_tool_call("nmap_scan", {"target": "10.0.0.1"},
                                 {"ports": [80, 443]}, state)

        # Add discovered host to graph
        graph.add_host("10.0.0.1", ports=[80, 443])

        # Phase 2: RECON → ENUM
        state.hosts = {"10.0.0.1": mock_host}
        fsm.transition(ScanState.ENUMERATION, state)

        # Phase 3: ENUM → VULN_SCANNING
        state.endpoints = ["/api/login", "/api/search"]
        fsm.transition(ScanState.VULNERABILITY_SCANNING, state)

        # Propose hypothesis
        hyp_id = hypothesis.propose(
            claim="POST /api/login is SQL injectable",
            target="http://10.0.0.1/api/login",
            category="sqli",
            test_plan="Run nuclei SQL templates",
        )

        # Record nuclei findings
        graph.add_vulnerability(
            "v1", "SQL Injection", severity="critical",
            host="10.0.0.1", port=80, endpoint="/api/login",
        )
        evidence_reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "SQL injection template match",
            "[critical] sqli-time-based at /api/login",
            vuln_ids=["v1"], host="10.0.0.1",
        )
        confidence.add_evidence("v1", "nuclei_scan", "Nuclei found SQL injection")

        # Phase 4: VULN_SCANNING → EXPLOITATION
        state.vuln_stats = {"total": 1}
        state.vulnerabilities = {"v1": _make_vuln("v1", "critical")}
        fsm.transition(ScanState.EXPLOITATION, state)

        # Start testing hypothesis
        hypothesis.start_testing(hyp_id)
        assert hypothesis.get_active()[0].id == hyp_id

        # Critic should allow sqlmap with evidence in findings ledger
        state.findings_ledger = ["Found sql injection error at http://10.0.0.1/api/login"]
        verdict3 = critic.review_action(
            "sqlmap_test", {"url": "http://10.0.0.1/api/login"},
            state, fsm.current_state,
        )
        evidence_issues = [i for i in verdict3.issues if "requires prior evidence" in i]
        assert len(evidence_issues) == 0

        # Record sqlmap evidence
        confidence.add_evidence("v1", "sqlmap_test", "SQLmap confirmed injection")
        evidence_reg.add(
            EvidenceType.EXPLOITATION, EvidenceQuality.DEFINITIVE,
            "sqlmap_test", "Confirmed SQL injection, database dumped",
            "Parameter: id\nType: time-based blind\n...",
            vuln_ids=["v1"], host="10.0.0.1",
        )

        # Confirm hypothesis
        hypothesis.confirm(hyp_id, 0.95, "SQLmap confirmed")

        # Phase 5: EXPLOITATION → VERIFICATION
        state.pending_verification = ["v1"]
        fsm.transition(ScanState.VERIFICATION, state)

        # Phase 6: VERIFICATION → REPORTING
        state.verified_vulns = ["v1"]
        fsm.transition(ScanState.REPORTING, state)

        # Finish scan should pass critic check (all verified)
        verdict4 = critic.review_action("finish_scan", {}, state, fsm.current_state)
        verification_issues = [i for i in verdict4.issues if "unverified" in i.lower()]
        assert len(verification_issues) == 0

        # Phase 7: REPORTING → COMPLETED
        fsm.transition(ScanState.COMPLETED, state)
        assert fsm.current_state == ScanState.COMPLETED

        # Final assertions
        # Bayesian model with decay: two evidence pieces produce a lower score
        # than the old additive model (nuclei + sqlmap → Bayesian posterior)
        assert confidence.get_confidence("v1") > 0.0
        assert evidence_reg.count >= 2
        assert len(hypothesis.get_confirmed()) == 1
        assert graph.node_count >= 4  # host, 2 services, 1 vuln

        report = graph.validate_graph()
        assert report["node_count"] >= 4


class TestCriticPlannerInteraction:
    """Test that planner recommendations align with critic approvals."""

    def test_planner_recommends_critic_allows(self):
        planner = StrategicPlanner()
        critic = AdversarialCritic()
        state = _make_state()

        # Planner recommendations for recon should all pass critic
        phase = _make_phase("reconnaissance")
        # nmap_scan is recommended for recon
        verdict = critic.review_action("nmap_scan", {}, state, phase)
        assert len(verdict.issues) == 0


class TestConfidenceGraphPropagation:
    """Test that confidence engine propagates to attack graph."""

    def test_propagation(self):
        graph = AttackGraph()
        graph.add_host("10.0.0.1", ports=[80])
        graph.add_vulnerability("v1", "SQLi", severity="critical",
                                host="10.0.0.1", port=80)

        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Scanner found")
        engine.add_evidence("v1", "sqlmap_test", "Confirmed")

        engine.propagate_to_graph(graph)

        node = graph._nodes.get("vuln:v1")
        assert node is not None
        assert node.properties.get("confidence", 0) > 0
        assert node.properties.get("evidence_count", 0) == 2


class TestEvidenceHypothesisLink:
    """Test evidence and hypothesis tracking together."""

    def test_evidence_ids_on_hypothesis(self):
        evidence_reg = EvidenceRegistry()
        tracker = HypothesisTracker()

        hid = tracker.propose("XSS at /search", "http://t/search", "xss")
        tracker.start_testing(hid)

        eid1 = evidence_reg.add(
            EvidenceType.HTTP_RESPONSE, EvidenceQuality.STRONG,
            "send_request", "Reflected input",
            "<script>alert(1)</script>",
            vuln_ids=["v1"],
        )
        eid2 = evidence_reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "XSS template match",
            "nuclei output...",
            vuln_ids=["v1"],
        )

        tracker.confirm(hid, 0.8, "XSS confirmed", evidence_ids=[eid1, eid2])

        confirmed = tracker.get_confirmed()
        assert len(confirmed) == 1
        assert len(confirmed[0].evidence_ids) == 2

        # Evidence should be retrievable by vuln
        v1_evidence = evidence_reg.get_for_vuln("v1")
        assert len(v1_evidence) == 2


class TestStagnationTriggersPlannerRecommendation:
    """Test that stagnation detection generates useful recommendations."""

    def test_stagnation_recommends_unused_tool(self):
        planner = StrategicPlanner()
        state = _make_state()
        phase = _make_phase("reconnaissance")

        # Stagnate on nmap
        for _ in range(10):
            planner.record_tool_call("nmap_scan", {"target": "10.0.0.1"}, {}, state)

        rec = planner.get_next_recommendation(state, phase)
        assert rec is not None
        assert "stagnating" in rec.lower()
        # Should recommend an unused recon tool
        assert any(tool in rec for tool in [
            "subfinder_scan", "dns_lookup", "httpx_probe", "httpx_full_analysis",
        ])
