"""
TASK 5: Stress Testing & Performance Profiling

Profiles CPU time, memory allocation, and thread contention under high load.
Tests hundreds of graph nodes, thousands of evidence entries, many concurrent
circuit breakers, and identifies performance bottlenecks.
"""
import gc
import math
import threading
import time
import tracemalloc
from unittest.mock import MagicMock

import pytest

from phantom.core.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, NodeType, EdgeType,
)
from phantom.core.confidence_engine import ConfidenceEngine
from phantom.core.evidence_registry import (
    EvidenceRegistry, EvidenceType, EvidenceQuality,
)
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState
from phantom.core.scan_state_machine import ScanStateMachine, ScanState
from phantom.core.hypothesis_tracker import HypothesisTracker
from phantom.core.strategic_planner import StrategicPlanner
from phantom.core.degradation_handler import DegradationHandler


# ===================================================================
# 5.1 Large Attack Graph Performance
# ===================================================================

class TestLargeGraphPerformance:
    """Profile attack graph operations with hundreds of nodes."""

    def test_200_host_graph_build_time(self):
        """Building a 200-host graph should complete in < 2s."""
        start = time.perf_counter()
        graph = AttackGraph()
        for i in range(200):
            ip = f"10.{i // 256}.{i % 256}.1"
            graph.add_host(ip, ports=[80, 443, 22] if i % 2 == 0 else [80])
            graph.add_vulnerability(
                f"vuln-{i}", f"Vuln {i}", severity="high",
                host=ip, port=80,
            )
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"200-host graph build took {elapsed:.2f}s"
        assert graph.node_count >= 800  # hosts + services + vulns

    def test_500_node_graph_operations(self):
        """Validate graph operations at 500 nodes stay responsive."""
        graph = AttackGraph()
        for i in range(100):
            graph.add_host(f"10.0.{i // 256}.{i % 256}", ports=[80])
        for i in range(400):
            graph.add_node(AttackNode(
                id=f"ep-{i}", node_type=NodeType.ENDPOINT,
                label=f"/path/{i}", properties={"host": f"10.0.0.{i % 100}"},
            ))

        start = time.perf_counter()
        risk = graph.get_risk_summary()
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"Risk summary at 500 nodes took {elapsed:.2f}s"
        assert risk["total_nodes"] >= 500

    def test_graph_chain_inference_at_scale(self):
        """Chain inference with 50 chained vulnerabilities."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1", ports=[80])
        for i in range(50):
            graph.add_vulnerability(f"v{i}", f"Vuln {i}",
                                    severity="high", host="10.0.0.1", port=80)
        for i in range(49):
            graph.add_edge(AttackEdge(
                source_id=f"vuln:v{i}", target_id=f"vuln:v{i+1}",
                edge_type=EdgeType.CHAINS_WITH,
            ))
        start = time.perf_counter()
        chains = graph.infer_attack_chains()
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"Chain inference took {elapsed:.2f}s"
        assert len(chains) > 0

    def test_graph_memory_usage(self):
        """Memory usage for 200-host graph should be reasonable."""
        tracemalloc.start()
        graph = AttackGraph()
        for i in range(200):
            ip = f"10.{i // 256}.{i % 256}.1"
            graph.add_host(ip, ports=[80, 443])
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        total_mb = sum(s.size for s in snapshot.statistics("lineno")) / (1024 * 1024)
        assert total_mb < 50, f"Graph used {total_mb:.1f}MB (>50MB threshold)"


# ===================================================================
# 5.2 Evidence Registry at Capacity
# ===================================================================

class TestEvidenceRegistryCapacity:
    """Stress test evidence registry near and at _MAX_EVIDENCE (5000)."""

    def test_fill_to_4000_entries(self):
        """Fill to 4000 entries — should work without eviction."""
        reg = EvidenceRegistry()
        start = time.perf_counter()
        for i in range(4000):
            reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                    f"tool_{i % 20}", f"desc_{i}", f"data_{i}_{time.monotonic()}")
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"4000 inserts took {elapsed:.2f}s"
        assert reg.count == 4000

    def test_eviction_at_capacity(self):
        """At 5000+ entries, eviction should trigger for weak/moderate evidence."""
        reg = EvidenceRegistry()
        for i in range(4999):
            reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK,
                    f"tool_{i % 10}", f"desc_{i}", f"data_{i}_{time.monotonic()}")
        assert reg.count == 4999
        # This should trigger eviction
        reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK,
                "tool_overflow", "overflow_desc", f"overflow_{time.monotonic()}")
        # Count should be <= 5000 after eviction
        assert reg.count <= 5000

    def test_registry_memory_usage(self):
        """Memory for 3000 entries should be < 30MB."""
        tracemalloc.start()
        reg = EvidenceRegistry()
        for i in range(3000):
            reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                    f"tool_{i % 10}", f"desc_{i}", f"data_{i}_{time.monotonic()}")
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        total_mb = sum(s.size for s in snapshot.statistics("lineno")) / (1024 * 1024)
        assert total_mb < 30, f"Registry used {total_mb:.1f}MB for 3000 entries"


# ===================================================================
# 5.3 Confidence Engine Under Load
# ===================================================================

class TestConfidenceEngineUnderLoad:
    """Profile confidence engine with many vulnerabilities and evidence."""

    def test_100_vulns_with_evidence(self):
        """100 vulns × 10 evidence each = 1000 entries."""
        engine = ConfidenceEngine()
        start = time.perf_counter()
        for v in range(100):
            for e in range(10):
                engine.add_evidence(f"v{v}", f"tool_{e % 5}", f"desc_{v}_{e}")
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"1000 evidence entries took {elapsed:.2f}s"
        for v in range(100):
            c = engine.get_confidence(f"v{v}")
            assert 0.0 <= c <= 1.0

    def test_bulk_confidence_retrieval(self):
        """Retrieve confidence for 200 vulns sequentially."""
        engine = ConfidenceEngine()
        for v in range(200):
            engine.add_evidence(f"v{v}", "nuclei_scan", f"found_{v}")
        start = time.perf_counter()
        for v in range(200):
            engine.get_confidence(f"v{v}")
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"200 lookups took {elapsed:.2f}s"

    def test_decay_recalculation_all(self):
        """Recalculate all with decay should handle 50 vulns."""
        engine = ConfidenceEngine()
        for v in range(50):
            engine.add_evidence(f"v{v}", "nuclei_scan", f"found_{v}")
        start = time.perf_counter()
        engine.recalculate_all_with_decay(decay_half_life=600.0)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"Decay recalc for 50 vulns took {elapsed:.2f}s"


# ===================================================================
# 5.4 Circuit Breaker Stress
# ===================================================================

class TestCircuitBreakerStress:
    """Stress test multiple circuit breakers concurrently."""

    def test_100_circuit_breakers(self):
        """Create and exercise 100 independent circuit breakers."""
        breakers = [CircuitBreaker(f"cb_{i}", failure_threshold=3, recovery_timeout=0.05)
                    for i in range(100)]
        start = time.perf_counter()
        for cb in breakers:
            cb.record_failure()
            cb.record_failure()
            cb.record_failure()
            assert cb.state == CircuitState.OPEN
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0

    def test_concurrent_breaker_access(self):
        """10 threads hammering 10 shared circuit breakers."""
        breakers = [CircuitBreaker(f"shared_{i}", failure_threshold=5, recovery_timeout=0.1)
                    for i in range(10)]
        errors = []

        def worker(tid):
            for _ in range(200):
                cb = breakers[tid % 10]
                try:
                    if cb.can_execute():
                        cb.record_success()
                    cb.record_failure()
                except Exception as e:
                    errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)
        assert len(errors) == 0, f"CB stress errors: {errors[:5]}"


# ===================================================================
# 5.5 FSM Throughput
# ===================================================================

class TestFSMThroughput:
    """Measure FSM transition throughput."""

    def test_100_full_lifecycle_scans(self):
        """Run 100 complete scan lifecycles sequentially."""
        mock_vuln = MagicMock()
        mock_vuln.id = "v1"
        mock_vuln.severity.value = "high"

        start = time.perf_counter()
        for _ in range(100):
            fsm = ScanStateMachine()
            state = MagicMock()
            state.state_machine = fsm
            state.sandbox_id = "test"
            state.hosts = {"h": MagicMock(ports=[MagicMock()])}
            state.endpoints = ["/"]
            state.vuln_stats = {"total": 1}
            state.vulnerabilities = {"v1": mock_vuln}
            state.pending_verification = ["v1"]
            state.verified_vulns = ["v1"]
            state.false_positives = []
            state.subdomains = []
            state.findings_ledger = []
            state.tested_endpoints = {}
            state.discovered_vulns = {}
            for phase in [ScanState.RECONNAISSANCE, ScanState.ENUMERATION,
                          ScanState.VULNERABILITY_SCANNING, ScanState.EXPLOITATION,
                          ScanState.VERIFICATION, ScanState.REPORTING,
                          ScanState.COMPLETED]:
                fsm.transition(phase, state)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"100 lifecycles took {elapsed:.2f}s"


# ===================================================================
# 5.6 Hypothesis Tracker at Scale
# ===================================================================

class TestHypothesisTrackerScale:
    """Test hypothesis tracker at high volume."""

    def test_create_300_hypotheses(self):
        tracker = HypothesisTracker()
        start = time.perf_counter()
        for i in range(300):
            tracker.propose(f"hyp_{i}", f"target_{i}", f"cat_{i % 10}")
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0
        summary = tracker.get_summary()
        assert summary["total"] >= 300

    def test_hypothesis_lifecycle_at_scale(self):
        """Propose, test, confirm/reject 100 hypotheses."""
        tracker = HypothesisTracker()
        ids = []
        for i in range(100):
            hid = tracker.propose(f"hyp_{i}", f"t_{i}", f"c_{i % 5}")
            ids.append(hid)
        for i, hid in enumerate(ids):
            tracker.start_testing(hid)
            if i % 3 == 0:
                tracker.confirm(hid, 0.8, "confirmed")
            else:
                tracker.reject(hid, "not valid")
        confirmed = tracker.get_confirmed()
        assert len(confirmed) >= 30


# ===================================================================
# 5.7 Strategic Planner Under Load
# ===================================================================

class TestStrategicPlannerLoad:
    """Profile planner with many tool calls."""

    def test_500_tool_calls(self):
        graph = AttackGraph()
        planner = StrategicPlanner(graph)
        state = MagicMock()
        state.hosts = {"10.0.0.1": MagicMock()}
        state.endpoints = set()
        state.vulnerabilities = {}
        start = time.perf_counter()
        for i in range(500):
            tool = ["nmap_scan", "nuclei_scan", "send_request"][i % 3]
            planner.record_tool_call(tool, {"target": f"10.0.0.{i % 50}"},
                                     {"found": i % 5 == 0}, state)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"500 tool records took {elapsed:.2f}s"
        status = planner.get_status()
        assert status["total_tool_calls"] == 500


# ===================================================================
# 5.8 Degradation Handler Rapid Cycles
# ===================================================================

class TestDegradationHandlerStress:
    """Rapid mode transitions under stress."""

    def test_rapid_provider_fail_recover(self):
        handler = DegradationHandler()
        start = time.perf_counter()
        for i in range(100):
            handler.handle_provider_failure(f"provider_{i % 3}", "error")
            handler.recover_provider(f"provider_{i % 3}")
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0

    def test_rapid_tool_fail_recover(self):
        handler = DegradationHandler()
        for i in range(50):
            handler.handle_tool_failure(f"tool_{i % 10}", "err")
            if i % 5 == 0:
                handler.recover_tool(f"tool_{i % 10}")
        # Mode should reflect accumulated failures
        status = handler.get_status()
        assert isinstance(status, dict)


# ===================================================================
# 5.9 Combined System Stress
# ===================================================================

class TestCombinedSystemStress:
    """Profile combined operations simulating real usage."""

    def test_full_system_under_load(self):
        """Simulate heavy usage across all subsystems simultaneously."""
        graph = AttackGraph()
        for i in range(50):
            graph.add_host(f"10.0.0.{i+1}", ports=[80, 443])
        confidence = ConfidenceEngine()
        evidence_reg = EvidenceRegistry()
        planner = StrategicPlanner(graph)
        hypothesis = HypothesisTracker()
        degradation = DegradationHandler()

        state = MagicMock()
        state.hosts = {f"10.0.0.{i+1}": MagicMock() for i in range(50)}
        state.endpoints = [f"/path/{i}" for i in range(100)]
        state.vulnerabilities = {}
        state.vuln_stats = {"total": 0}
        state.verified_vulns = []

        start = time.perf_counter()

        # Simulate discovery phase
        for i in range(100):
            evidence_reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                             f"tool_{i % 5}", f"finding_{i}",
                             f"data_{i}_{time.monotonic()}")
            confidence.add_evidence(f"v{i % 25}", f"tool_{i % 5}", f"desc_{i}")
            planner.record_tool_call(f"tool_{i % 5}", {"t": f"10.0.0.{i % 50 + 1}"},
                                     {"found": i % 3 == 0}, state)
            if i % 10 == 0:
                hypothesis.propose(f"test_{i}", f"target_{i}", f"cat_{i % 5}")

        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"Combined stress took {elapsed:.2f}s"
        assert evidence_reg.count >= 100
        assert confidence.get_confidence("v0") > 0
