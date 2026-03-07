"""Test Suite 2: Attack Chain Inference (T3-05, Section 7)."""
import pytest
from phantom.core.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, NodeType, EdgeType,
)


class TestChainInferenceBasic:
    def test_linear_chain(self, attack_graph):
        chains = attack_graph.infer_attack_chains()
        found = any(
            "vuln-sqli" in chain and "vuln-xss" in chain
            for chain in chains
        )
        assert found, f"Expected chain with vuln-sqli→vuln-xss, got {chains}"

    def test_no_chains_without_vuln_edges(self):
        g = AttackGraph()
        g.add_node(AttackNode(id="h1", node_type=NodeType.HOST, label="H1"))
        g.add_node(AttackNode(id="s1", node_type=NodeType.SERVICE, label="S1"))
        g.add_edge(AttackEdge(source_id="h1", target_id="s1", edge_type=EdgeType.HOSTS))
        chains = g.infer_attack_chains()
        assert chains == [] or all(len(c) <= 1 for c in chains)

    def test_empty_graph(self):
        g = AttackGraph()
        assert g.infer_attack_chains() == []


class TestChainCycleDetection:
    def test_cycle_does_not_infinite_loop(self):
        g = AttackGraph()
        g.add_node(AttackNode(id="v1", node_type=NodeType.VULNERABILITY, label="V1", risk_score=8.0))
        g.add_node(AttackNode(id="v2", node_type=NodeType.VULNERABILITY, label="V2", risk_score=7.0))
        g.add_node(AttackNode(id="v3", node_type=NodeType.VULNERABILITY, label="V3", risk_score=5.0))
        g.add_edge(AttackEdge(source_id="v1", target_id="v2", edge_type=EdgeType.CHAINS_WITH))
        g.add_edge(AttackEdge(source_id="v2", target_id="v3", edge_type=EdgeType.CHAINS_WITH))
        g.add_edge(AttackEdge(source_id="v3", target_id="v1", edge_type=EdgeType.CHAINS_WITH))
        chains = g.infer_attack_chains()
        assert isinstance(chains, list)

    def test_self_referencing_edge(self):
        g = AttackGraph()
        g.add_node(AttackNode(id="v1", node_type=NodeType.VULNERABILITY, label="V1", risk_score=8.0))
        g.add_edge(AttackEdge(source_id="v1", target_id="v1", edge_type=EdgeType.CHAINS_WITH))
        chains = g.infer_attack_chains()
        assert isinstance(chains, list)
        for chain in chains:
            assert chain.count("v1") <= 1, f"Self-ref caused duplication: {chain}"

    def test_depth_limit_enforced(self):
        g = AttackGraph()
        for i in range(15):
            g.add_node(AttackNode(id=f"v{i}", node_type=NodeType.VULNERABILITY, label=f"V{i}", risk_score=5.0))
        for i in range(14):
            g.add_edge(AttackEdge(source_id=f"v{i}", target_id=f"v{i+1}", edge_type=EdgeType.CHAINS_WITH))
        chains = g.infer_attack_chains()
        for chain in chains:
            assert len(chain) <= 8, f"Chain exceeded depth limit: len={len(chain)}"


class TestChainDisconnectedComponents:
    def test_disconnected_vulns_separate_chains(self):
        g = AttackGraph()
        g.add_node(AttackNode(id="v1", node_type=NodeType.VULNERABILITY, label="V1", risk_score=8.0))
        g.add_node(AttackNode(id="v2", node_type=NodeType.VULNERABILITY, label="V2", risk_score=5.0))
        g.add_edge(AttackEdge(source_id="v1", target_id="v2", edge_type=EdgeType.CHAINS_WITH))
        g.add_node(AttackNode(id="v3", node_type=NodeType.VULNERABILITY, label="V3", risk_score=9.0))
        g.add_node(AttackNode(id="v4", node_type=NodeType.VULNERABILITY, label="V4", risk_score=3.0))
        g.add_edge(AttackEdge(source_id="v3", target_id="v4", edge_type=EdgeType.LEADS_TO))
        chains = g.infer_attack_chains()
        has_c1 = any("v1" in c for c in chains)
        has_c2 = any("v3" in c for c in chains)
        assert has_c1 and has_c2, f"Missing disconnected chains: {chains}"


class TestPageRankTargets:
    @pytest.mark.xfail(reason="numpy not installed in CI environment", strict=False)
    def test_pagerank_returns_scored_nodes(self, attack_graph):
        targets = attack_graph.get_priority_targets()
        assert isinstance(targets, list)
        if targets:
            assert "combined_priority" in targets[0]

    @pytest.mark.xfail(reason="numpy not installed in CI environment", strict=False)
    def test_hub_node_ranks_higher(self):
        g = AttackGraph()
        g.add_node(AttackNode(id="hub", node_type=NodeType.VULNERABILITY, label="Hub", risk_score=9.0))
        for i in range(5):
            g.add_node(AttackNode(id=f"leaf-{i}", node_type=NodeType.VULNERABILITY, label=f"Leaf{i}", risk_score=3.0))
            g.add_edge(AttackEdge(source_id=f"leaf-{i}", target_id="hub", edge_type=EdgeType.LEADS_TO))
        targets = g.get_priority_targets()
        if targets:
            top_ids = [t["id"] for t in targets[:3]]
            assert "hub" in top_ids
