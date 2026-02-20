"""
Attack Graph Engine (NetworkX-based)

Pure Python attack surface modeling using NetworkX.
No external infrastructure required (no Neo4j).

Builds directed graphs of:
- Hosts, services, endpoints, vulnerabilities
- Relationships: EXPOSES, RUNS_ON, LEADS_TO, CHAINS_WITH
- Attack paths from entry points to high-value targets
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
    nx = None  # Graceful degradation if networkx not installed

# ---------------------------------------------------------------------------
# Node & Edge Types
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    DATA_ASSET = "data_asset"


class EdgeType(str, Enum):
    HOSTS = "HOSTS"             # host -> service
    EXPOSES = "EXPOSES"         # service -> endpoint
    HAS_VULN = "HAS_VULN"      # endpoint/service -> vulnerability
    LEADS_TO = "LEADS_TO"       # vulnerability -> endpoint/host (lateral)
    CHAINS_WITH = "CHAINS_WITH" # vulnerability -> vulnerability
    ACCESSES = "ACCESSES"       # credential -> service/host
    PROTECTS = "PROTECTS"       # service -> data_asset


# ---------------------------------------------------------------------------
# Node Data
# ---------------------------------------------------------------------------

@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    node_type: NodeType
    label: str
    risk_score: float = 0.0
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class AttackEdge:
    """An edge in the attack graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Severity Helpers
# ---------------------------------------------------------------------------

SEVERITY_SCORES = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}


def _severity_to_score(severity: str) -> float:
    return SEVERITY_SCORES.get(severity.lower(), 1.0)


# ---------------------------------------------------------------------------
# Attack Graph
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    NetworkX-based attack graph for modeling attack surfaces.

    Provides:
    - Node/edge management (hosts, services, endpoints, vulns)
    - Attack path discovery (shortest, all, critical)
    - Risk scoring and propagation
    - Export to JSON / DOT / GEXF

    Usage:
        graph = AttackGraph()
        graph.add_host("192.168.1.1", ports=[80, 443, 22])
        graph.add_vulnerability("vuln-001", "SQL Injection",
                                severity="critical", endpoint="/api/login")
        paths = graph.find_attack_paths("192.168.1.1", target_type=NodeType.DATA_ASSET)
    """

    def __init__(self) -> None:
        if nx is None:
            raise ImportError(
                "networkx is required for attack graph analysis. "
                "Install it with: pip install networkx"
            )
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, AttackNode] = {}

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    # --- Node Management ---

    def add_node(self, node: AttackNode) -> None:
        """Add or update a node in the graph."""
        self._nodes[node.id] = node
        self._graph.add_node(
            node.id,
            node_type=node.node_type.value,
            label=node.label,
            risk_score=node.risk_score,
            **node.properties,
        )

    def add_edge(self, edge: AttackEdge) -> None:
        """Add an edge between two nodes."""
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type.value,
            weight=edge.weight,
            **edge.properties,
        )

    def add_host(
        self,
        host: str,
        *,
        ports: list[int] | None = None,
        os_info: str | None = None,
        risk_score: float = 0.0,
    ) -> str:
        """Add a host and optionally its services."""
        host_id = f"host:{host}"
        self.add_node(AttackNode(
            id=host_id,
            node_type=NodeType.HOST,
            label=host,
            risk_score=risk_score,
            properties={"ip": host, "os": os_info},
        ))

        for port in (ports or []):
            svc_id = self.add_service(host, port)
            self.add_edge(AttackEdge(
                source_id=host_id,
                target_id=svc_id,
                edge_type=EdgeType.HOSTS,
            ))
        return host_id

    def add_service(
        self,
        host: str,
        port: int,
        *,
        name: str | None = None,
        version: str | None = None,
    ) -> str:
        """Add a service node."""
        svc_id = f"svc:{host}:{port}"
        self.add_node(AttackNode(
            id=svc_id,
            node_type=NodeType.SERVICE,
            label=name or f"port-{port}",
            properties={"host": host, "port": port, "service_name": name, "version": version},
        ))
        return svc_id

    def add_endpoint(
        self,
        host: str,
        port: int,
        path: str,
        *,
        method: str = "GET",
        status_code: int | None = None,
    ) -> str:
        """Add an endpoint node, linked to its service."""
        ep_id = f"ep:{host}:{port}{path}"
        self.add_node(AttackNode(
            id=ep_id,
            node_type=NodeType.ENDPOINT,
            label=f"{method} {path}",
            properties={"host": host, "port": port, "path": path, "method": method, "status_code": status_code},
        ))

        svc_id = f"svc:{host}:{port}"
        if svc_id in self._graph:
            self.add_edge(AttackEdge(
                source_id=svc_id,
                target_id=ep_id,
                edge_type=EdgeType.EXPOSES,
            ))
        return ep_id

    def add_vulnerability(
        self,
        vuln_id: str,
        title: str,
        *,
        severity: str = "medium",
        cwe: str | None = None,
        cvss: float | None = None,
        host: str | None = None,
        port: int | None = None,
        endpoint: str | None = None,
        verified: bool = False,
    ) -> str:
        """Add a vulnerability and link it to the affected node."""
        node_id = f"vuln:{vuln_id}"
        score = cvss if cvss is not None else _severity_to_score(severity)
        self.add_node(AttackNode(
            id=node_id,
            node_type=NodeType.VULNERABILITY,
            label=title,
            risk_score=score,
            properties={
                "severity": severity,
                "cwe": cwe,
                "cvss": cvss,
                "verified": verified,
            },
        ))

        # Link to affected node
        if endpoint and host and port:
            target = f"ep:{host}:{port}{endpoint}"
        elif host and port:
            target = f"svc:{host}:{port}"
        elif host:
            target = f"host:{host}"
        else:
            target = None

        if target and target in self._graph:
            self.add_edge(AttackEdge(
                source_id=target,
                target_id=node_id,
                edge_type=EdgeType.HAS_VULN,
                weight=score,
            ))
        return node_id

    def add_data_asset(
        self, asset_id: str, label: str, *, sensitivity: str = "high"
    ) -> str:
        """Add a data asset (database, file store, etc.)."""
        node_id = f"data:{asset_id}"
        self.add_node(AttackNode(
            id=node_id,
            node_type=NodeType.DATA_ASSET,
            label=label,
            risk_score=SEVERITY_SCORES.get(sensitivity, 5.0),
            properties={"sensitivity": sensitivity},
        ))
        return node_id

    def chain_vulnerabilities(
        self, vuln_a: str, vuln_b: str, *, description: str = ""
    ) -> None:
        """Record that vuln_a can be chained with vuln_b."""
        a_id = f"vuln:{vuln_a}" if not vuln_a.startswith("vuln:") else vuln_a
        b_id = f"vuln:{vuln_b}" if not vuln_b.startswith("vuln:") else vuln_b
        self.add_edge(AttackEdge(
            source_id=a_id,
            target_id=b_id,
            edge_type=EdgeType.CHAINS_WITH,
            properties={"description": description},
        ))

    def add_lateral_movement(
        self, vuln_id: str, target_id: str, *, description: str = ""
    ) -> None:
        """Record that exploiting a vuln leads to access to another node."""
        v_id = f"vuln:{vuln_id}" if not vuln_id.startswith("vuln:") else vuln_id
        self.add_edge(AttackEdge(
            source_id=v_id,
            target_id=target_id,
            edge_type=EdgeType.LEADS_TO,
            properties={"description": description},
        ))

    # --- Query Methods ---

    def get_nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        """Get all nodes of a specific type."""
        return [
            self._nodes[nid]
            for nid, data in self._graph.nodes(data=True)
            if data.get("node_type") == node_type.value and nid in self._nodes
        ]

    def get_neighbors(self, node_id: str) -> list[str]:
        """Get direct successors of a node."""
        if node_id not in self._graph:
            return []
        return list(self._graph.successors(node_id))

    def get_vulnerabilities_for_host(self, host: str) -> list[AttackNode]:
        """Get all vulnerabilities connected to a host (directly or via services)."""
        host_id = f"host:{host}"
        vulns: list[AttackNode] = []

        if host_id not in self._graph:
            return vulns

        # BFS from host to find all connected vuln nodes
        visited: set[str] = set()
        queue = [host_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            node_data = self._graph.nodes.get(current, {})
            if node_data.get("node_type") == NodeType.VULNERABILITY.value:
                if current in self._nodes:
                    vulns.append(self._nodes[current])
            else:
                queue.extend(self._graph.successors(current))

        return vulns

    # --- Attack Path Analysis ---

    def find_attack_paths(
        self,
        source: str,
        target: str | None = None,
        *,
        target_type: NodeType | None = None,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """
        Find attack paths from source to target(s).

        Args:
            source: Source node ID
            target: Specific target node ID
            target_type: Find paths to all nodes of this type
            max_depth: Maximum path length

        Returns:
            List of paths (each path is a list of node IDs)
        """
        if source not in self._graph:
            return []

        paths: list[list[str]] = []

        if target and target in self._graph:
            try:
                for path in nx.all_simple_paths(self._graph, source, target, cutoff=max_depth):
                    paths.append(list(path))
            except nx.NetworkXNoPath:
                pass
        elif target_type:
            targets = [
                nid for nid, d in self._graph.nodes(data=True)
                if d.get("node_type") == target_type.value
            ]
            for t in targets:
                try:
                    for path in nx.all_simple_paths(self._graph, source, t, cutoff=max_depth):
                        paths.append(list(path))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        return paths

    def find_critical_paths(self, min_severity: float = 7.0) -> list[dict[str, Any]]:
        """
        Find paths that traverse high-severity vulnerabilities.

        Returns paths annotated with cumulative risk scores.
        """
        hosts = self.get_nodes_by_type(NodeType.HOST)
        vulns = [
            n for n in self.get_nodes_by_type(NodeType.VULNERABILITY)
            if n.risk_score >= min_severity
        ]

        critical_paths: list[dict[str, Any]] = []

        for host_node in hosts:
            for vuln_node in vulns:
                try:
                    for path in nx.all_simple_paths(
                        self._graph, host_node.id, vuln_node.id, cutoff=8
                    ):
                        risk = sum(
                            self._nodes[n].risk_score
                            for n in path
                            if n in self._nodes
                        )
                        critical_paths.append({
                            "path": path,
                            "risk_score": risk,
                            "entry_point": host_node.label,
                            "target_vuln": vuln_node.label,
                            "length": len(path),
                        })
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        # Sort by risk score descending
        critical_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return critical_paths

    def find_shortest_attack_path(self, source: str, target: str) -> list[str] | None:
        """Find the shortest path between two nodes."""
        try:
            return list(nx.shortest_path(self._graph, source, target))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    # --- Risk Analysis ---

    def propagate_risk(self) -> dict[str, float]:
        """
        Propagate risk scores through the graph.

        Nodes inherit risk from their connected vulnerabilities,
        weighted by edge proximity.
        """
        risk_map: dict[str, float] = {}

        for node_id in self._graph.nodes:
            if node_id in self._nodes:
                risk_map[node_id] = self._nodes[node_id].risk_score

        # Propagate risk backward from vulns to hosts (3 iterations)
        for _ in range(3):
            new_risk = dict(risk_map)
            for u, v in self._graph.edges:
                # Propagate some risk from target to source
                child_risk = risk_map.get(v, 0)
                if child_risk > 0:
                    inherited = child_risk * 0.5
                    new_risk[u] = max(new_risk.get(u, 0), inherited)
            risk_map = new_risk

        return risk_map

    def get_risk_summary(self) -> dict[str, Any]:
        """Get an overall risk summary of the attack surface."""
        risk_map = self.propagate_risk()
        vulns = self.get_nodes_by_type(NodeType.VULNERABILITY)
        hosts = self.get_nodes_by_type(NodeType.HOST)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = v.properties.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

        host_risks = []
        for h in hosts:
            host_risk = risk_map.get(h.id, 0)
            host_vulns = self.get_vulnerabilities_for_host(h.label)
            host_risks.append({
                "host": h.label,
                "risk_score": round(host_risk, 2),
                "vuln_count": len(host_vulns),
            })

        host_risks.sort(key=lambda h: h["risk_score"], reverse=True)

        return {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "total_vulnerabilities": len(vulns),
            "severity_distribution": severity_counts,
            "host_risk_ranking": host_risks,
            "max_risk": max(risk_map.values()) if risk_map else 0,
        }

    # --- Import from Scan Data ---

    def ingest_scan_findings(self, findings: list[dict[str, Any]]) -> int:
        """
        Import findings from a Phantom scan into the graph.

        Expects dicts with: title, severity, host, port, endpoint, cwe, cvss, verified

        Returns number of nodes added.
        """
        added = 0
        for i, finding in enumerate(findings):
            host = finding.get("host") or finding.get("target", "unknown")
            port = finding.get("port")
            endpoint = finding.get("endpoint") or finding.get("url", "")

            # Parse host from URL if needed
            if "://" in host:
                from urllib.parse import urlparse
                parsed = urlparse(host)
                host = parsed.hostname or host
                if not port and parsed.port:
                    port = parsed.port

            # Add host
            host_id = f"host:{host}"
            if host_id not in self._graph:
                self.add_host(host)
                added += 1

            # Add service if port known
            if port:
                svc_id = f"svc:{host}:{port}"
                if svc_id not in self._graph:
                    self.add_service(host, port)
                    self.add_edge(AttackEdge(
                        source_id=host_id, target_id=svc_id,
                        edge_type=EdgeType.HOSTS,
                    ))
                    added += 1

            # Add endpoint
            if endpoint:
                ep_path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
                ep_port = port or 80
                self.add_endpoint(host, ep_port, ep_path)
                added += 1

            # Add vulnerability
            vuln_id = finding.get("id", f"finding-{i}")
            self.add_vulnerability(
                vuln_id,
                finding.get("title", "Unknown Vulnerability"),
                severity=finding.get("severity", "medium"),
                cwe=finding.get("cwe"),
                cvss=finding.get("cvss"),
                host=host,
                port=port,
                endpoint=endpoint,
                verified=finding.get("verified", False),
            )
            added += 1

        return added

    # --- Export ---

    def to_dict(self) -> dict[str, Any]:
        """Export graph as a JSON-serializable dict."""
        nodes = []
        for nid, data in self._graph.nodes(data=True):
            node = {"id": nid, **data}
            nodes.append(node)

        edges = []
        for u, v, data in self._graph.edges(data=True):
            edge = {"source": u, "target": v, **data}
            edges.append(edge)

        return {
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "node_count": self.node_count,
                "edge_count": self.edge_count,
            },
            "nodes": nodes,
            "edges": edges,
        }

    def export_json(self, path: Path) -> None:
        """Export graph to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackGraph":
        """Import graph from a dict (reverse of to_dict)."""
        graph = cls()
        for node in data.get("nodes", []):
            node = dict(node)  # copy to avoid mutating input
            nid = node.pop("id")
            ntype = NodeType(node.pop("node_type", "host"))
            label = node.pop("label", nid)
            risk = node.pop("risk_score", 0.0)
            graph.add_node(AttackNode(
                id=nid, node_type=ntype, label=label,
                risk_score=risk, properties=node,
            ))

        for edge in data.get("edges", []):
            edge = dict(edge)  # copy to avoid mutating input
            src = edge.pop("source")
            tgt = edge.pop("target")
            etype = EdgeType(edge.pop("edge_type", "HOSTS"))
            weight = edge.pop("weight", 1.0)
            graph.add_edge(AttackEdge(
                source_id=src, target_id=tgt,
                edge_type=etype, weight=weight, properties=edge,
            ))
        return graph
