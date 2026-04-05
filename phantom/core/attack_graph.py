"""
Attack Graph Builder - P2.1

Builds a directed graph showing how vulnerabilities can be chained together
to achieve attack objectives. Helps identify:
- Multi-step attack paths (e.g., XSS -> Session Hijack -> Privilege Escalation)
- Critical nodes that enable multiple attack paths
- Attack surface visualization
- Vulnerability prioritization based on graph centrality

Uses NetworkX for graph operations and analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import networkx as nx
except ImportError:
    nx = None  # type: ignore


class AttackNodeType(str, Enum):
    """Types of nodes in the attack graph."""
    VULNERABILITY = "vulnerability"
    ASSET = "asset"
    OBJECTIVE = "objective"
    TECHNIQUE = "technique"


class AttackEdgeType(str, Enum):
    """Types of edges (relationships) in the attack graph."""
    ENABLES = "enables"  # Vuln A enables exploiting Vuln B
    AFFECTS = "affects"  # Vuln affects an asset
    ACHIEVES = "achieves"  # Attack chain achieves objective
    USES = "uses"  # Objective uses technique


@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    type: AttackNodeType
    label: str
    severity: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "severity": self.severity,
            "status": self.status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackNode":
        d = d.copy()
        d["type"] = AttackNodeType(d["type"])
        return cls(**d)


@dataclass
class AttackEdge:
    """An edge (relationship) in the attack graph."""
    source: str
    target: str
    type: AttackEdgeType
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "weight": self.weight,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackEdge":
        d = d.copy()
        d["type"] = AttackEdgeType(d["type"])
        return cls(**d)


class AttackGraph:
    """
    Directed graph representing attack paths and vulnerability chains.
    
    Features:
    - Add vulnerabilities, assets, objectives, techniques
    - Define relationships between nodes
    - Find attack paths between two nodes
    - Identify critical vulnerabilities (high centrality)
    - Export to various formats (JSON, GraphML, DOT)
    """

    def __init__(self) -> None:
        if nx is None:
            raise ImportError(
                "NetworkX is required for AttackGraph. Install with: pip install networkx"
            )
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []
        self.metadata: dict[str, Any] = {
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
        }

    # ── Node Management ────────────────────────────────────────────────────

    def add_node(
        self,
        node_id: str,
        node_type: AttackNodeType,
        label: str,
        severity: str | None = None,
        status: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a node to the attack graph."""
        node = AttackNode(
            id=node_id,
            type=node_type,
            label=label,
            severity=severity,
            status=status,
            metadata=metadata or {},
        )
        self._nodes[node_id] = node
        self._graph.add_node(
            node_id,
            type=node_type.value,
            label=label,
            severity=severity,
            status=status,
            **node.metadata,
        )
        self.metadata["updated_at"] = datetime.now(UTC).isoformat()

    def add_vulnerability(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        status: str = "suspected",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a vulnerability node."""
        self.add_node(
            node_id=vuln_id,
            node_type=AttackNodeType.VULNERABILITY,
            label=title,
            severity=severity,
            status=status,
            metadata=metadata,
        )

    def add_asset(
        self,
        asset_id: str,
        label: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add an asset node (e.g., database, admin panel, user data)."""
        self.add_node(
            node_id=asset_id,
            node_type=AttackNodeType.ASSET,
            label=label,
            metadata=metadata,
        )

    def add_objective(
        self,
        objective_id: str,
        label: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add an attack objective node (e.g., privilege escalation, data exfiltration)."""
        self.add_node(
            node_id=objective_id,
            node_type=AttackNodeType.OBJECTIVE,
            label=label,
            metadata=metadata,
        )

    # ── Edge Management ────────────────────────────────────────────────────

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: AttackEdgeType,
        weight: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed edge between two nodes."""
        if source not in self._nodes:
            raise ValueError(f"Source node '{source}' not found in graph")
        if target not in self._nodes:
            raise ValueError(f"Target node '{target}' not found in graph")

        edge = AttackEdge(
            source=source,
            target=target,
            type=edge_type,
            weight=weight,
            metadata=metadata or {},
        )
        self._edges.append(edge)
        self._graph.add_edge(
            source,
            target,
            type=edge_type.value,
            weight=weight,
            **edge.metadata,
        )
        self.metadata["updated_at"] = datetime.now(UTC).isoformat()

    def add_chain(
        self,
        vuln_id_chain: list[str],
        edge_type: AttackEdgeType = AttackEdgeType.ENABLES,
    ) -> None:
        """Add a chain of vulnerabilities where each enables the next."""
        for i in range(len(vuln_id_chain) - 1):
            self.add_edge(vuln_id_chain[i], vuln_id_chain[i + 1], edge_type)

    # ── Analysis ───────────────────────────────────────────────────────────

    def find_paths(self, source: str, target: str, cutoff: int | None = None) -> list[list[str]]:
        """Find all simple paths from source to target."""
        if source not in self._graph or target not in self._graph:
            return []
        try:
            paths = list(nx.all_simple_paths(self._graph, source, target, cutoff=cutoff))
            return paths
        except nx.NetworkXNoPath:
            return []

    def get_critical_vulnerabilities(self, top_n: int = 10) -> list[tuple[str, float]]:
        """
        Identify critical vulnerabilities using betweenness centrality.
        
        Returns list of (vuln_id, centrality_score) tuples, sorted by score.
        High centrality means the vulnerability appears in many attack paths.
        """
        if not self._graph.nodes():
            return []
        
        centrality = nx.betweenness_centrality(self._graph, weight="weight")
        
        # Filter to only vulnerabilities
        vuln_centrality = [
            (node_id, score)
            for node_id, score in centrality.items()
            if self._nodes.get(node_id) and self._nodes[node_id].type == AttackNodeType.VULNERABILITY
        ]
        
        # Sort by centrality (descending)
        vuln_centrality.sort(key=lambda x: x[1], reverse=True)
        
        return vuln_centrality[:top_n]

    def get_attack_surface(self) -> dict[str, Any]:
        """
        Calculate attack surface metrics.
        
        Returns:
            - total_vulnerabilities: Count of vulnerability nodes
            - total_assets: Count of asset nodes
            - total_objectives: Count of objective nodes
            - avg_path_length: Average shortest path length
            - connected_components: Number of disconnected graph components
            - density: Graph density (0-1, higher = more connected)
        """
        vuln_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.VULNERABILITY)
        asset_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.ASSET)
        objective_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.OBJECTIVE)
        
        metrics = {
            "total_vulnerabilities": vuln_count,
            "total_assets": asset_count,
            "total_objectives": objective_count,
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "connected_components": nx.number_weakly_connected_components(self._graph),
            "density": nx.density(self._graph),
        }
        
        # Calculate average path length if graph is connected
        if nx.is_weakly_connected(self._graph):
            metrics["avg_path_length"] = nx.average_shortest_path_length(self._graph)
        else:
            metrics["avg_path_length"] = None
        
        return metrics

    def get_vulnerability_chains(self, min_length: int = 2) -> list[list[str]]:
        """
        Find all chains of vulnerabilities (multi-step attack paths).
        
        Args:
            min_length: Minimum chain length to return
            
        Returns:
            List of vulnerability chains (each chain is a list of vuln IDs)
        """
        chains = []
        vuln_nodes = [n for n in self._nodes.values() if n.type == AttackNodeType.VULNERABILITY]
        
        # Find paths between all pairs of vulnerabilities
        for source in vuln_nodes:
            for target in vuln_nodes:
                if source.id != target.id:
                    paths = self.find_paths(source.id, target.id)
                    for path in paths:
                        # Filter path to only vulnerability nodes
                        vuln_path = [
                            node_id for node_id in path
                            if self._nodes.get(node_id) and
                            self._nodes[node_id].type == AttackNodeType.VULNERABILITY
                        ]
                        if len(vuln_path) >= min_length and vuln_path not in chains:
                            chains.append(vuln_path)
        
        return chains

    # ── Export ─────────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Export graph to dictionary format."""
        return {
            "metadata": self.metadata,
            "nodes": [node.to_dict() for node in self._nodes.values()],
            "edges": [edge.to_dict() for edge in self._edges],
        }

    def to_json(self, filepath: str | Path | None = None, indent: int = 2) -> str:
        """Export graph to JSON format."""
        data = self.to_dict()
        json_str = json.dumps(data, indent=indent)
        
        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")
        
        return json_str

    def to_networkx(self) -> nx.DiGraph:
        """Export as NetworkX DiGraph for advanced analysis."""
        return self._graph.copy()

    def to_graphml(self, filepath: str | Path) -> None:
        """Export graph to GraphML format (readable by graph visualization tools)."""
        nx.write_graphml(self._graph, str(filepath))

    def to_dot(self, filepath: str | Path | None = None) -> str:
        """
        Export graph to DOT format (Graphviz).
        
        Returns DOT string. If filepath provided, also writes to file.
        """
        try:
            from networkx.drawing.nx_pydot import to_pydot
            pydot_graph = to_pydot(self._graph)
            dot_str = pydot_graph.to_string()
            
            if filepath:
                Path(filepath).write_text(dot_str, encoding="utf-8")
            
            return dot_str
        except ImportError:
            raise ImportError(
                "pydot is required for DOT export. Install with: pip install pydot"
            )

    # ── Import ─────────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackGraph":
        """Load graph from dictionary format."""
        graph = cls()
        graph.metadata = data.get("metadata", {})
        
        # Add nodes
        for node_data in data.get("nodes", []):
            node = AttackNode.from_dict(node_data)
            graph._nodes[node.id] = node
            graph._graph.add_node(
                node.id,
                type=node.type.value,
                label=node.label,
                severity=node.severity,
                status=node.status,
                **node.metadata,
            )
        
        # Add edges
        for edge_data in data.get("edges", []):
            edge = AttackEdge.from_dict(edge_data)
            graph._edges.append(edge)
            graph._graph.add_edge(
                edge.source,
                edge.target,
                type=edge.type.value,
                weight=edge.weight,
                **edge.metadata,
            )
        
        return graph

    @classmethod
    def from_json(cls, filepath: str | Path) -> "AttackGraph":
        """Load graph from JSON file."""
        data = json.loads(Path(filepath).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    # ── Visualization Helpers ──────────────────────────────────────────────

    def generate_summary_report(self) -> str:
        """Generate a text summary of the attack graph."""
        lines = ["=== Attack Graph Summary ===\n"]
        
        surface = self.get_attack_surface()
        lines.append(f"Nodes: {surface['total_nodes']}")
        lines.append(f"  - Vulnerabilities: {surface['total_vulnerabilities']}")
        lines.append(f"  - Assets: {surface['total_assets']}")
        lines.append(f"  - Objectives: {surface['total_objectives']}")
        lines.append(f"Edges: {surface['total_edges']}")
        lines.append(f"Density: {surface['density']:.3f}")
        lines.append(f"Connected Components: {surface['connected_components']}")
        
        if surface['avg_path_length'] is not None:
            lines.append(f"Avg Path Length: {surface['avg_path_length']:.2f}")
        
        lines.append("\n=== Critical Vulnerabilities (by Centrality) ===\n")
        critical = self.get_critical_vulnerabilities(top_n=5)
        for vuln_id, score in critical:
            node = self._nodes.get(vuln_id)
            if node:
                lines.append(f"  {vuln_id}: {node.label} (centrality={score:.4f})")
        
        lines.append("\n=== Vulnerability Chains (Multi-step Attacks) ===\n")
        chains = self.get_vulnerability_chains(min_length=2)
        if chains:
            for i, chain in enumerate(chains[:10], 1):  # Show top 10 chains
                chain_labels = []
                for vuln_id in chain:
                    node = self._nodes.get(vuln_id)
                    if node:
                        chain_labels.append(f"{vuln_id}({node.label})")
                lines.append(f"  Chain {i}: {' -> '.join(chain_labels)}")
        else:
            lines.append("  No multi-step attack chains detected.")
        
        return "\n".join(lines)


def build_attack_graph_from_vulnerabilities(
    vulnerabilities: list[Any],
    hypothesis_ledger: Any | None = None,
) -> AttackGraph:
    """
    Build an attack graph from a list of vulnerability objects.
    
    Args:
        vulnerabilities: List of Vulnerability objects
        hypothesis_ledger: Optional HypothesisLedger to extract relationships
        
    Returns:
        AttackGraph instance
    """
    graph = AttackGraph()
    
    # Add vulnerability nodes
    for vuln in vulnerabilities:
        graph.add_vulnerability(
            vuln_id=vuln.id,
            title=vuln.title,
            severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
            status=vuln.status.value if hasattr(vuln.status, 'value') else str(vuln.status),
            metadata={
                "description": getattr(vuln, 'description', None),
                "evidence": getattr(vuln, 'evidence', []),
                "remediation": getattr(vuln, 'remediation', None),
                "discovered_at": getattr(vuln, 'discovered_at', None),
            },
        )
    
    # TODO: Add logic to infer relationships between vulnerabilities
    # This could be based on:
    # 1. Hypothesis ledger data (which hypotheses enabled others)
    # 2. Vulnerability metadata (e.g., "requires authentication" -> auth bypass vuln)
    # 3. Attack surface analysis (same endpoint, related parameters)
    
    return graph
