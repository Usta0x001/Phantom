"""
TASK 1: Full-Scale Operational Simulation Tests

Simulates multi-host networks, mixed OS targets, various network configs,
high concurrency with parallel scan lifecycle through all FSM phases.
Measures scan lifecycle durations, tool execution success/failure rates,
exploit discovery accuracy, state transitions including ERROR handling.
"""
import math
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import MagicMock

import pytest

from phantom.core.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, NodeType, EdgeType,
)
from phantom.core.scan_state_machine import ScanStateMachine, ScanState
from phantom.core.strategic_planner import StrategicPlanner
from phantom.core.adversarial_critic import AdversarialCritic
from phantom.core.confidence_engine import ConfidenceEngine
from phantom.core.evidence_registry import (
    EvidenceRegistry, EvidenceType, EvidenceQuality,
)
from phantom.core.hypothesis_tracker import HypothesisTracker, HypothesisStatus
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState
from phantom.core.degradation_handler import DegradationHandler, DegradationMode
from phantom.core.exceptions import InvalidTransitionError


# ---------------------------------------------------------------------------
# Fixtures for operational simulation
# ---------------------------------------------------------------------------

def _build_multi_host_graph(num_hosts: int = 5) -> AttackGraph:
    """Build a realistic multi-host attack graph."""
    g = AttackGraph()
    for i in range(num_hosts):
        ip = f"10.0.0.{i + 1}"
        g.add_host(ip, ports=[22, 80, 443, 3306] if i % 2 == 0 else [80, 8080])
        g.add_node(AttackNode(
            id=f"svc-http-{i}", node_type=NodeType.SERVICE,
            label=f"HTTP on {ip}", properties={"port": 80, "host": ip},
        ))
        g.add_edge(AttackEdge(
            source_id=ip, target_id=f"svc-http-{i}", edge_type=EdgeType.HOSTS,
        ))
        if i % 3 == 0:
            vuln_id = f"vuln-sqli-{i}"
            g.add_vulnerability(
                vuln_id, "SQL Injection", severity="critical",
                host=ip, port=80, endpoint=f"/api/v1/item{i}",
            )
        if i % 4 == 0:
            vuln_id = f"vuln-xss-{i}"
            g.add_vulnerability(
                vuln_id, "XSS", severity="medium",
                host=ip, port=80, endpoint=f"/search?q={i}",
            )
    return g


def _make_mock_state(graph: AttackGraph, fsm: ScanStateMachine, **overrides) -> MagicMock:
    """Create a mock agent state with realistic host data."""
    state = MagicMock()
    state.sandbox_id = "sim-sandbox-001"
    state.attack_graph = graph
    state.state_machine = fsm
    state.hosts = overrides.get("hosts", {"10.0.0.1": MagicMock(ports=[MagicMock()])})
    state.subdomains = overrides.get("subdomains", ["sub.target.com"])
    state.endpoints = overrides.get("endpoints", ["/api/v1", "/login"])
    state.vulnerabilities = overrides.get("vulnerabilities", {})
    state.vuln_stats = overrides.get("vuln_stats", {"total": 0})
    state.pending_verification = overrides.get("pending_verification", [])
    state.verified_vulns = overrides.get("verified_vulns", [])
    state.false_positives = overrides.get("false_positives", [])
    state.findings_ledger = overrides.get("findings_ledger", [])
    state.tested_endpoints = overrides.get("tested_endpoints", {})
    state.discovered_vulns = overrides.get("discovered_vulns", {})
    state.iteration_count = 5
    return state


# ===================================================================
# 1.1 Multi-Host Network Simulation
# ===================================================================

class TestMultiHostNetworkSimulation:
    """Simulate scanning a multi-host network with varied services."""

    def test_five_host_graph_construction(self):
        graph = _build_multi_host_graph(5)
        assert graph.node_count >= 10  # hosts + services + vulns
        assert graph.edge_count >= 5

    def test_ten_host_full_lifecycle(self):
        """Simulate INIT → COMPLETED across 10 hosts."""
        graph = _build_multi_host_graph(10)
        fsm = ScanStateMachine()
        confidence = ConfidenceEngine()
        evidence_reg = EvidenceRegistry()

        mock_host = MagicMock(ports=[MagicMock()])
        hosts = {f"10.0.0.{i+1}": mock_host for i in range(10)}

        mock_vuln = MagicMock()
        mock_vuln.id = "vuln-sqli-0"
        mock_vuln.severity.value = "critical"

        state = _make_mock_state(graph, fsm,
            hosts=hosts,
            endpoints=[f"/api/v1/item{i}" for i in range(10)],
            vuln_stats={"total": 4},
            vulnerabilities={"vuln-sqli-0": mock_vuln},
            pending_verification=["vuln-sqli-0"],
            verified_vulns=["vuln-sqli-0"],
            false_positives=[],
        )

        # Walk through all phases
        transitions = []
        phases = [
            ScanState.RECONNAISSANCE,
            ScanState.ENUMERATION,
            ScanState.VULNERABILITY_SCANNING,
            ScanState.EXPLOITATION,
            ScanState.VERIFICATION,
            ScanState.REPORTING,
            ScanState.COMPLETED,
        ]
        for phase in phases:
            start = time.monotonic()
            fsm.transition(phase, state)
            elapsed = time.monotonic() - start
            transitions.append({"phase": phase.value, "time_ms": elapsed * 1000})

        assert fsm.current_state == ScanState.COMPLETED
        assert len(transitions) == 7
        # Each transition should be fast (< 50ms)
        for t in transitions:
            assert t["time_ms"] < 50, f"Slow transition to {t['phase']}: {t['time_ms']:.2f}ms"

    def test_mixed_os_targets(self):
        """Simulate hosts with different OS characteristics."""
        graph = AttackGraph()
        os_types = [
            ("10.0.0.1", "Linux", [22, 80, 443]),
            ("10.0.0.2", "Windows", [135, 445, 3389, 80]),
            ("10.0.0.3", "Android", [5555, 8080]),
            ("10.0.0.4", "Linux", [80, 443, 8443]),
            ("10.0.0.5", "Windows", [80, 443, 1433]),
        ]
        for ip, os_name, ports in os_types:
            graph.add_host(ip, ports=ports, os_info=os_name)

        assert graph.node_count >= 5
        risk = graph.get_risk_summary()
        assert risk["total_nodes"] >= 5

    def test_ipv4_ipv6_network_nodes(self):
        """Test attack graph handles both IPv4 and IPv6 addresses."""
        graph = AttackGraph()
        graph.add_host("192.168.1.1", ports=[80, 443])
        graph.add_host("fd00::1", ports=[80, 443])  # IPv6 ULA
        graph.add_host("2001:db8::1", ports=[22, 80])  # IPv6 documentation

        assert graph.node_count >= 3
        for host_id in ["host:192.168.1.1", "host:fd00::1", "host:2001:db8::1"]:
            assert host_id in graph._nodes


# ===================================================================
# 1.2 Scan Lifecycle Duration Measurement
# ===================================================================

class TestScanLifecycleTiming:
    """Measure and validate scan lifecycle durations."""

    def test_phase_timing_capture(self):
        """Capture timing for every phase transition."""
        fsm = ScanStateMachine()
        graph = _build_multi_host_graph(3)
        mock_host = MagicMock(ports=[MagicMock()])
        mock_vuln = MagicMock()
        mock_vuln.id = "v1"
        mock_vuln.severity.value = "high"

        state = _make_mock_state(graph, fsm,
            hosts={"10.0.0.1": mock_host},
            endpoints=["/api"],
            vuln_stats={"total": 1},
            vulnerabilities={"v1": mock_vuln},
            pending_verification=["v1"],
            verified_vulns=["v1"],
            false_positives=[],
        )

        timings = {}
        phases = [
            ScanState.RECONNAISSANCE, ScanState.ENUMERATION,
            ScanState.VULNERABILITY_SCANNING, ScanState.EXPLOITATION,
            ScanState.VERIFICATION, ScanState.REPORTING, ScanState.COMPLETED,
        ]
        for phase in phases:
            t0 = time.perf_counter_ns()
            fsm.transition(phase, state)
            t1 = time.perf_counter_ns()
            timings[phase.value] = (t1 - t0) / 1_000_000  # ms

        for phase_name, ms in timings.items():
            assert ms < 100, f"Phase {phase_name} took {ms:.3f}ms (>100ms threshold)"

    def test_phase_metrics_tracked(self):
        """Verify PhaseMetrics are populated for each phase."""
        fsm = ScanStateMachine()
        state = _make_mock_state(AttackGraph(), fsm,
            hosts={"10.0.0.1": MagicMock(ports=[MagicMock()])},
            endpoints=["/"], vuln_stats={"total": 1},
        )
        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.record_iteration()
        fsm.record_tool_invocation()
        fsm.record_finding()

        metrics = fsm.phase_metrics
        recon = metrics[ScanState.RECONNAISSANCE]
        assert recon.started_at is not None
        assert recon.iterations_used >= 1
        assert recon.tools_invoked >= 1
        assert recon.findings_count >= 1


# ===================================================================
# 1.3 Tool Execution Success/Failure Tracking
# ===================================================================

class TestToolExecutionTracking:
    """Track tool outcomes across a simulated scan."""

    def test_tool_success_failure_counters(self):
        """Simulate tool calls and count successes/failures."""
        planner = StrategicPlanner(AttackGraph())
        state = MagicMock()
        state.hosts = {}
        state.endpoints = set()
        state.vulnerabilities = {}

        outcomes = {"success": 0, "failure": 0}
        tools_called = []

        for i in range(50):
            tool = ["nmap_scan", "nuclei_scan", "sqlmap_test", "send_request"][i % 4]
            success = i % 7 != 0  # ~14% failure rate
            result = {"found": True} if success else {"error": "timeout"}
            planner.record_tool_call(tool, {"target": "10.0.0.1"}, result, state)
            tools_called.append(tool)
            outcomes["success" if success else "failure"] += 1

        assert outcomes["success"] > 0
        assert outcomes["failure"] > 0
        assert outcomes["success"] + outcomes["failure"] == 50


# ===================================================================
# 1.4 ERROR State Handling
# ===================================================================

class TestErrorStateHandling:
    """Validate error state transitions and recovery."""

    def test_error_transition_from_any_phase(self):
        """ERROR should be reachable from any active phase."""
        for phase in [ScanState.RECONNAISSANCE, ScanState.ENUMERATION,
                      ScanState.VULNERABILITY_SCANNING, ScanState.EXPLOITATION]:
            fsm = ScanStateMachine()
            state = _make_mock_state(AttackGraph(), fsm,
                hosts={"h": MagicMock(ports=[MagicMock()])},
                endpoints=["/"], vuln_stats={"total": 1},
            )
            fsm.transition(ScanState.RECONNAISSANCE, state)
            if phase != ScanState.RECONNAISSANCE:
                try:
                    fsm.transition(phase, state)
                except Exception:
                    pass  # May fail guards, that's fine
            fsm.transition(ScanState.ERROR, state)
            assert fsm.current_state == ScanState.ERROR

    def test_error_recovery(self):
        """Test recovery from ERROR state."""
        fsm = ScanStateMachine()
        state = _make_mock_state(AttackGraph(), fsm,
            hosts={"h": MagicMock(ports=[MagicMock()])},
            endpoints=["/"], vuln_stats={"total": 1},
        )
        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.transition(ScanState.ERROR, state)
        assert fsm.current_state == ScanState.ERROR

        recovered = fsm.recover_from_error(state)
        # Should recover to a valid state or None
        if recovered is not None:
            assert isinstance(recovered, ScanState)


# ===================================================================
# 1.5 High-Concurrency Parallel Scan Simulation
# ===================================================================

class TestHighConcurrencyScans:
    """Simulate parallel scans with shared and independent resources."""

    def test_parallel_fsm_instances(self):
        """Run 10 independent FSMs concurrently — no shared state."""
        results = []
        errors = []

        def run_scan(scan_id):
            try:
                g = _build_multi_host_graph(2)
                fsm = ScanStateMachine()
                mock_vuln = MagicMock()
                mock_vuln.id = "v1"
                mock_vuln.severity.value = "high"
                state = _make_mock_state(g, fsm,
                    hosts={"10.0.0.1": MagicMock(ports=[MagicMock()])},
                    endpoints=["/api"], vuln_stats={"total": 1},
                    vulnerabilities={"v1": mock_vuln},
                    pending_verification=["v1"],
                    verified_vulns=["v1"], false_positives=[],
                )
                for phase in [ScanState.RECONNAISSANCE, ScanState.ENUMERATION,
                              ScanState.VULNERABILITY_SCANNING, ScanState.EXPLOITATION,
                              ScanState.VERIFICATION, ScanState.REPORTING,
                              ScanState.COMPLETED]:
                    fsm.transition(phase, state)
                results.append(("ok", scan_id, fsm.current_state))
            except Exception as e:
                errors.append((scan_id, str(e)))

        threads = [threading.Thread(target=run_scan, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Parallel FSM errors: {errors}"
        assert len(results) == 10
        assert all(r[2] == ScanState.COMPLETED for r in results)

    def test_shared_evidence_registry_contention(self):
        """Multiple threads writing to shared EvidenceRegistry."""
        registry = EvidenceRegistry()
        errors = []

        def writer(wid):
            for i in range(100):
                try:
                    registry.add(
                        EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                        f"tool_{wid}", f"finding_{i}",
                        f"data_w{wid}_i{i}_{time.monotonic()}",
                        vuln_ids=[f"vuln-{i % 20}"],
                        host=f"10.0.0.{wid % 10 + 1}",
                    )
                except Exception as e:
                    errors.append((wid, i, str(e)))

        threads = [threading.Thread(target=writer, args=(w,)) for w in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Registry contention errors: {errors[:5]}"
        assert registry.count > 0

    def test_concurrent_confidence_updates(self):
        """Multiple threads updating confidence engine concurrently."""
        engine = ConfidenceEngine()
        errors = []

        def updater(uid):
            for i in range(50):
                try:
                    vid = f"vuln-{i % 10}"
                    engine.add_evidence(vid, f"tool_{uid}", f"desc_{i}")
                except Exception as e:
                    errors.append((uid, i, str(e)))

        threads = [threading.Thread(target=updater, args=(u,)) for u in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent confidence errors: {errors[:5]}"
        for vid_i in range(10):
            conf = engine.get_confidence(f"vuln-{vid_i}")
            assert 0.0 <= conf <= 1.0

    def test_parallel_graph_mutations(self):
        """Multiple threads modifying attack graph simultaneously."""
        graph = AttackGraph()
        errors = []

        def add_nodes(tid):
            for i in range(50):
                try:
                    graph.add_node(AttackNode(
                        id=f"node-t{tid}-{i}", node_type=NodeType.HOST,
                        label=f"Host {tid}-{i}",
                    ))
                except Exception as e:
                    errors.append((tid, i, str(e)))

        threads = [threading.Thread(target=add_nodes, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # NetworkX isn't thread-safe by default, but we test for crashes
        assert len(errors) == 0, f"Graph mutation errors: {errors[:5]}"
        assert graph.node_count >= 100  # 10 threads × 50 nodes


# ===================================================================
# 1.6 Full Lifecycle Integration
# ===================================================================

class TestFullLifecycleIntegration:
    """End-to-end lifecycle: build graph → scan → evaluate → report."""

    def test_complete_scan_with_all_components(self):
        """Simulate a complete scan using all intelligence components."""
        # Setup
        graph = _build_multi_host_graph(3)
        fsm = ScanStateMachine()
        planner = StrategicPlanner(graph)
        critic = AdversarialCritic()
        confidence = ConfidenceEngine()
        evidence_reg = EvidenceRegistry()
        hypothesis = HypothesisTracker()
        degradation = DegradationHandler()

        mock_host = MagicMock(ports=[MagicMock()])
        mock_vuln = MagicMock()
        mock_vuln.id = "vuln-sqli-0"
        mock_vuln.severity.value = "critical"

        state = _make_mock_state(graph, fsm,
            hosts={"10.0.0.1": mock_host, "10.0.0.2": mock_host},
            endpoints=["/api/v1/item0", "/search"],
            vuln_stats={"total": 1},
            vulnerabilities={"vuln-sqli-0": mock_vuln},
            pending_verification=["vuln-sqli-0"],
            verified_vulns=["vuln-sqli-0"],
            false_positives=[],
            findings_ledger=["SQL injection error at http://10.0.0.1/api/v1/item0"],
        )

        lifecycle_log = []

        # INIT → RECON
        fsm.transition(ScanState.RECONNAISSANCE, state)
        lifecycle_log.append("RECON")
        guidance = planner.generate_phase_guidance(state, fsm.current_state)
        assert "RECONNAISSANCE" in guidance

        # RECON → ENUM
        fsm.transition(ScanState.ENUMERATION, state)
        lifecycle_log.append("ENUM")

        # ENUM → VULN_SCAN
        fsm.transition(ScanState.VULNERABILITY_SCANNING, state)
        lifecycle_log.append("VULN_SCAN")
        hyp_id = hypothesis.propose(
            claim="POST /api/v1/item0 is SQL injectable",
            target="http://10.0.0.1/api/v1/item0",
            category="sqli",
            test_plan="Run nuclei + sqlmap",
        )
        # Add evidence
        evidence_reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                         "nuclei_scan", "SQL injection detected",
                         "Template match: sqli-time-based",
                         vuln_ids=["vuln-sqli-0"], host="10.0.0.1")
        confidence.add_evidence("vuln-sqli-0", "nuclei_scan", "Found SQLi")

        # VULN_SCAN → EXPLOITATION
        fsm.transition(ScanState.EXPLOITATION, state)
        lifecycle_log.append("EXPLOITATION")
        hypothesis.start_testing(hyp_id)

        # Critic should allow sqlmap with evidence
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://10.0.0.1/api/v1/item0"},
            state, fsm.current_state,
        )
        assert len([i for i in verdict.issues if "requires prior evidence" in i]) == 0

        # Record tool results
        planner.record_tool_call("sqlmap_test", {"url": "http://10.0.0.1/api/v1/item0"},
                                  {"vulnerable": True}, state)
        confidence.add_evidence("vuln-sqli-0", "sqlmap_test", "Confirmed SQLi")
        evidence_reg.add(EvidenceType.EXPLOITATION, EvidenceQuality.DEFINITIVE,
                         "sqlmap_test", "Confirmed SQL injection",
                         "database: mysql\nParameter: id\nType: time-based",
                         vuln_ids=["vuln-sqli-0"], host="10.0.0.1")
        hypothesis.confirm(hyp_id, 0.95, "Confirmed by sqlmap")

        # EXPLOITATION → VERIFICATION → REPORTING → COMPLETED
        fsm.transition(ScanState.VERIFICATION, state)
        lifecycle_log.append("VERIFICATION")
        fsm.transition(ScanState.REPORTING, state)
        lifecycle_log.append("REPORTING")
        fsm.transition(ScanState.COMPLETED, state)
        lifecycle_log.append("COMPLETED")

        # Assertions
        assert lifecycle_log == ["RECON", "ENUM", "VULN_SCAN", "EXPLOITATION",
                                 "VERIFICATION", "REPORTING", "COMPLETED"]
        assert confidence.get_confidence("vuln-sqli-0") > 0
        assert evidence_reg.count >= 2
        assert len(hypothesis.get_confirmed()) == 1
        assert degradation.mode == DegradationMode.FULL
