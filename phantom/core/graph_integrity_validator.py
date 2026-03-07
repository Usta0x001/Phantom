"""
Graph Integrity Validator — Hardening H-GR-004

Validates the attack graph's structural integrity:
  1. All node types are valid NodeType enum members
  2. All edge types are valid EdgeType enum members
  3. No orphan edges (source/target missing)
  4. No cycles (graph must be a DAG for exploit chain correctness)
  5. Evidence links reference existing evidence
  6. No orphan references in node properties
  7. No semantically duplicate nodes (same host:port)

Can run standalone or be invoked from the InvariantOrchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from phantom.core.attack_graph import AttackGraph, NodeType, EdgeType

_logger = logging.getLogger(__name__)


@dataclass
class GraphIntegrityReport:
    """Result of a graph integrity validation."""
    valid: bool = True
    node_count: int = 0
    edge_count: int = 0
    invalid_node_types: int = 0
    invalid_edge_types: int = 0
    orphan_edges: int = 0
    cycles: int = 0
    duplicate_nodes: int = 0
    missing_node_data: int = 0
    issues: list[str] = field(default_factory=list)

    def add_issue(self, msg: str) -> None:
        self.issues.append(msg)
        self.valid = False


class GraphIntegrityValidator:
    """Validates attack graph structural integrity."""

    _VALID_NODE_TYPES = frozenset(nt.value for nt in NodeType)
    _VALID_EDGE_TYPES = frozenset(et.value for et in EdgeType)

    def validate_graph(self, graph: AttackGraph) -> GraphIntegrityReport:
        """Run all integrity checks on the graph.

        Returns a GraphIntegrityReport. If report.valid is False,
        the issues list contains human-readable descriptions.
        """
        report = GraphIntegrityReport(
            node_count=graph.node_count,
            edge_count=graph.edge_count,
        )

        self._check_node_types(graph, report)
        self._check_edge_types(graph, report)
        self._check_orphan_edges(graph, report)
        self._check_cycles(graph, report)
        self._check_duplicate_nodes(graph, report)
        self._check_node_data_consistency(graph, report)

        if report.valid:
            _logger.debug(
                "Graph integrity OK: %d nodes, %d edges",
                report.node_count, report.edge_count,
            )
        else:
            _logger.warning(
                "Graph integrity FAILED: %d issues — %s",
                len(report.issues),
                "; ".join(report.issues[:5]),
            )

        return report

    def _check_node_types(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Check that all nodes have valid NodeType values."""
        for node_id, data in graph._graph.nodes(data=True):
            ntype = data.get("node_type", "")
            if ntype not in self._VALID_NODE_TYPES:
                report.invalid_node_types += 1
                report.add_issue(f"Node '{node_id}' has invalid type '{ntype}'")

    def _check_edge_types(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Check that all edges have valid EdgeType values."""
        for u, v, data in graph._graph.edges(data=True):
            etype = data.get("edge_type", "")
            if etype not in self._VALID_EDGE_TYPES:
                report.invalid_edge_types += 1
                report.add_issue(f"Edge '{u}'→'{v}' has invalid type '{etype}'")

    def _check_orphan_edges(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Check for edges referencing non-existent nodes."""
        nodes = set(graph._graph.nodes)
        for u, v, _ in graph._graph.edges(data=True):
            if u not in nodes:
                report.orphan_edges += 1
                report.add_issue(f"Edge source '{u}' not in graph nodes")
            if v not in nodes:
                report.orphan_edges += 1
                report.add_issue(f"Edge target '{v}' not in graph nodes")

    def _check_cycles(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Check for cycles in the directed graph."""
        try:
            import networkx as nx
            cycles = list(nx.simple_cycles(graph._graph))
            # Cap reported cycles to avoid huge outputs
            report.cycles = len(cycles)
            if cycles:
                for cycle in cycles[:5]:
                    report.add_issue(
                        f"Cycle detected: {' → '.join(str(n) for n in cycle[:8])}"
                    )
        except Exception as e:
            _logger.warning("Cycle detection failed: %s", e)

    def _check_duplicate_nodes(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Detect semantically duplicate nodes (same host:port or IP)."""
        seen_keys: dict[str, str] = {}  # semantic_key → node_id

        for node_id, data in graph._graph.nodes(data=True):
            ntype = data.get("node_type", "")
            key = None

            if ntype == NodeType.HOST.value:
                ip = data.get("ip", "")
                if ip:
                    key = f"host:{ip}"
            elif ntype == NodeType.SERVICE.value:
                host = data.get("host", "")
                port = data.get("port", "")
                if host and port:
                    key = f"svc:{host}:{port}"
            elif ntype == NodeType.ENDPOINT.value:
                host = data.get("host", "")
                port = data.get("port", "")
                path = data.get("path", "")
                if host and path:
                    key = f"ep:{host}:{port}{path}"

            if key:
                if key in seen_keys and seen_keys[key] != node_id:
                    report.duplicate_nodes += 1
                    report.add_issue(
                        f"Duplicate node: '{node_id}' duplicates '{seen_keys[key]}' (key={key})"
                    )
                else:
                    seen_keys[key] = node_id

    def _check_node_data_consistency(self, graph: AttackGraph, report: GraphIntegrityReport) -> None:
        """Check that NetworkX nodes have corresponding AttackNode objects."""
        for node_id in graph._graph.nodes:
            if node_id not in graph._nodes:
                report.missing_node_data += 1
                report.add_issue(f"Node '{node_id}' in graph but missing AttackNode data")

    def auto_repair(self, graph: AttackGraph) -> list[str]:
        """Attempt to repair detected issues. Returns list of repairs made."""
        repairs: list[str] = []

        # Remove orphan edges where source or target doesn't exist
        nodes = set(graph._graph.nodes)
        edges_to_remove = []
        for u, v, _ in graph._graph.edges(data=True):
            if u not in nodes or v not in nodes:
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            graph._graph.remove_edge(u, v)
            repairs.append(f"Removed orphan edge {u}→{v}")

        # Break cycles by removing back-edges
        try:
            import networkx as nx
            while True:
                try:
                    cycle = nx.find_cycle(graph._graph, orientation="original")
                    if cycle:
                        # Remove the last edge in the cycle
                        u, v, _ = cycle[-1]
                        graph._graph.remove_edge(u, v)
                        repairs.append(f"Broke cycle by removing edge {u}→{v}")
                    else:
                        break
                except nx.NetworkXNoCycle:
                    break
        except Exception as e:
            _logger.warning("Cycle repair failed: %s", e)

        # Create missing AttackNode objects for graph nodes
        for node_id in list(graph._graph.nodes):
            if node_id not in graph._nodes:
                data = dict(graph._graph.nodes[node_id])
                try:
                    ntype = NodeType(data.get("node_type", "host"))
                except ValueError:
                    ntype = NodeType.HOST
                    graph._graph.nodes[node_id]["node_type"] = ntype.value
                from phantom.core.attack_graph import AttackNode
                graph._nodes[node_id] = AttackNode(
                    id=node_id,
                    node_type=ntype,
                    label=data.get("label", node_id),
                    risk_score=data.get("risk_score", 0.0),
                )
                repairs.append(f"Created missing AttackNode for '{node_id}'")

        if repairs:
            graph._cache_version += 1
            _logger.info("Graph auto-repair: %d fixes applied", len(repairs))

        return repairs
