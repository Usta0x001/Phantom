"""
Tests for Attack Graph Engine fixes.

Validates:
- BUG-024: Node merge instead of overwrite
- BUG-008: Configurable propagation decay/iterations
- BUG-009: Additive aggregation capped at 10.0
- BUG-023: Geometric mean for critical path scoring
- Cycle detection
- Graph validation
- Highest-risk path finding
"""

import math
import pytest

from phantom.core.attack_graph import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    EdgeType,
    NodeType,
    SEVERITY_SCORES,
)


# ── Fixtures ──


@pytest.fixture
def graph():
    return AttackGraph()


@pytest.fixture
def populated_graph():
    """Graph with a host → service → endpoint → vuln chain."""
    g = AttackGraph()
    g.add_host("10.0.0.1", ports=[80, 443])
    g.add_endpoint("10.0.0.1", 80, "/api/login", method="POST")
    g.add_vulnerability(
        "vuln-001", "SQL Injection",
        severity="critical", host="10.0.0.1", port=80, endpoint="/api/login",
    )
    return g


# ── BUG-024: Node Merge ──


class TestNodeMerge:
    def test_add_duplicate_node_merges_properties(self, graph):
        node1 = AttackNode(
            id="host:10.0.0.1",
            node_type=NodeType.HOST,
            label="10.0.0.1",
            risk_score=3.0,
            properties={"os": "Linux"},
        )
        node2 = AttackNode(
            id="host:10.0.0.1",
            node_type=NodeType.HOST,
            label="10.0.0.1",
            risk_score=5.0,
            properties={"os": "Linux", "banner": "Apache"},
        )
        graph.add_node(node1)
        graph.add_node(node2)

        stored = graph._nodes["host:10.0.0.1"]
        assert stored.risk_score == 5.0  # max(3.0, 5.0)
        assert stored.properties["banner"] == "Apache"  # merged
        assert graph.node_count == 1  # not duplicated

    def test_merge_keeps_higher_risk(self, graph):
        node1 = AttackNode(
            id="test-node", node_type=NodeType.HOST, label="test",
            risk_score=8.0,
        )
        node2 = AttackNode(
            id="test-node", node_type=NodeType.HOST, label="test",
            risk_score=3.0,
        )
        graph.add_node(node1)
        graph.add_node(node2)
        assert graph._nodes["test-node"].risk_score == 8.0


# ── BUG-008: Configurable Propagation ──


class TestRiskPropagation:
    def test_default_propagation(self, populated_graph):
        risk = populated_graph.propagate_risk()
        # Vuln node should have risk = 10.0 (critical)
        assert risk.get("vuln:vuln-001", 0) >= 10.0

    def test_custom_decay(self, populated_graph):
        risk_low = populated_graph.propagate_risk(decay=0.1)
        risk_high = populated_graph.propagate_risk(decay=0.9)
        # Higher decay = more risk inherited by upstream nodes
        host_key = "host:10.0.0.1"
        assert risk_high.get(host_key, 0) >= risk_low.get(host_key, 0)

    def test_custom_iterations(self, populated_graph):
        risk_1 = populated_graph.propagate_risk(iterations=1)
        risk_10 = populated_graph.propagate_risk(iterations=10)
        # More iterations = more propagation
        host_key = "host:10.0.0.1"
        assert risk_10.get(host_key, 0) >= risk_1.get(host_key, 0)


# ── BUG-009: Additive Aggregation Capped at 10 ──


class TestAdditiveAggregation:
    def test_risk_capped_at_10(self, graph):
        """Multiple high-severity vulns shouldn't push risk above 10.0."""
        graph.add_host("10.0.0.1", ports=[80])
        for i in range(5):
            graph.add_vulnerability(
                f"vuln-{i}", f"Critical Vuln {i}",
                severity="critical", host="10.0.0.1", port=80,
            )
        risk = graph.propagate_risk()
        for score in risk.values():
            assert score <= 10.0


# ── BUG-023: Geometric Mean ──


class TestCriticalPaths:
    def test_geometric_mean_scoring(self, populated_graph):
        paths = populated_graph.find_critical_paths(min_severity=5.0)
        if paths:
            for p in paths:
                # Geometric mean should be ≤ max node risk
                assert p["risk_score"] <= p["max_node_risk"] + 0.01

    def test_no_paths_for_high_threshold(self, graph):
        graph.add_host("10.0.0.1")
        graph.add_vulnerability("v1", "Low", severity="low", host="10.0.0.1")
        paths = graph.find_critical_paths(min_severity=9.0)
        assert paths == []


# ── Highest-Risk Path ──


class TestHighestRiskPath:
    def test_finds_path(self, populated_graph):
        path = populated_graph.find_highest_risk_path(
            "host:10.0.0.1", "vuln:vuln-001"
        )
        assert path is not None
        assert path[0] == "host:10.0.0.1"
        assert path[-1] == "vuln:vuln-001"

    def test_no_path_returns_none(self, graph):
        graph.add_host("10.0.0.1")
        graph.add_host("10.0.0.2")
        path = graph.find_highest_risk_path("host:10.0.0.1", "host:10.0.0.2")
        assert path is None


# ── Cycle Detection ──


class TestCycleDetection:
    def test_no_cycles_in_normal_graph(self, populated_graph):
        cycles = populated_graph.detect_cycles()
        assert cycles == []

    def test_detects_cycle(self, graph):
        graph.add_node(AttackNode(id="a", node_type=NodeType.HOST, label="a"))
        graph.add_node(AttackNode(id="b", node_type=NodeType.HOST, label="b"))
        graph.add_edge(AttackEdge(source_id="a", target_id="b", edge_type=EdgeType.HOSTS))
        graph.add_edge(AttackEdge(source_id="b", target_id="a", edge_type=EdgeType.HOSTS))
        cycles = graph.detect_cycles()
        assert len(cycles) > 0


# ── Graph Validation ──


class TestGraphValidation:
    def test_healthy_graph(self, populated_graph):
        report = populated_graph.validate_graph()
        # A populated graph with proper edges should be relatively healthy
        assert "node_count" in report
        assert "edge_count" in report
        assert report["node_count"] > 0

    def test_orphan_detection(self, graph):
        graph.add_node(AttackNode(id="orphan", node_type=NodeType.HOST, label="orphan"))
        report = graph.validate_graph()
        assert report["orphan_count"] == 1

    def test_empty_graph(self, graph):
        report = graph.validate_graph()
        assert report["healthy"] is True
        assert report["node_count"] == 0


# ── Basic Graph Operations ──


class TestBasicOperations:
    def test_add_host(self, graph):
        host_id = graph.add_host("10.0.0.1", ports=[80, 443])
        assert host_id == "host:10.0.0.1"
        assert graph.node_count >= 3  # host + 2 services

    def test_add_vulnerability(self, graph):
        graph.add_host("10.0.0.1", ports=[80])
        vid = graph.add_vulnerability(
            "v1", "XSS", severity="high", host="10.0.0.1", port=80,
        )
        assert vid == "vuln:v1"

    def test_chain_vulnerabilities(self, graph):
        graph.add_vulnerability("v1", "SQLi", severity="critical")
        graph.add_vulnerability("v2", "Priv Esc", severity="high")
        graph.chain_vulnerabilities("v1", "v2", description="SQLi → Priv Esc")
        assert graph.edge_count >= 1

    def test_get_nodes_by_type(self, populated_graph):
        hosts = populated_graph.get_nodes_by_type(NodeType.HOST)
        assert len(hosts) == 1
        vulns = populated_graph.get_nodes_by_type(NodeType.VULNERABILITY)
        assert len(vulns) == 1

    def test_get_vulnerabilities_for_host(self, populated_graph):
        vulns = populated_graph.get_vulnerabilities_for_host("10.0.0.1")
        assert len(vulns) == 1
        assert vulns[0].id == "vuln:vuln-001"

    def test_risk_summary(self, populated_graph):
        summary = populated_graph.get_risk_summary()
        assert summary["total_vulnerabilities"] == 1
        assert summary["max_risk"] > 0
