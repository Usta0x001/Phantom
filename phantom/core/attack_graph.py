"""
Attack Graph Engine (NetworkX-based)

Pure Python attack surface modeling using NetworkX.
No external infrastructure required (no Neo4j).

Builds directed graphs of:
- Hosts, services, endpoints, vulnerabilities
- Relationships: EXPOSES, RUNS_ON, LEADS_TO, CHAINS_WITH
- Attack paths from entry points to high-value targets

Intelligence Plan 3.x enhancements:
- infer_attack_chains(): automated chain detection from graph topology
- get_priority_targets(): PageRank-based target prioritisation
- get_unexplored_frontiers(): nodes with high degree but low vuln coverage
- ExploitPrerequisite / add_exploit_edge(): prerequisite reasoning
- Path caching with invalidation (_cache_version)
- prune_unreachable(): garbage-collect orphaned subgraphs
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

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


@dataclass
class ExploitPrerequisite:
    """Intelligence Plan 3.4: Prerequisite reasoning for exploits.

    Captures what conditions must hold before an exploit tool can succeed.
    """
    vuln_id: str
    requires: list[str] = field(default_factory=list)  # node IDs that must exist
    requires_verified: list[str] = field(default_factory=list)  # vuln IDs that must be verified
    description: str = ""


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

    def __init__(self, *, validate_on_mutate: bool = False) -> None:
        if nx is None:
            raise ImportError(
                "networkx is required for attack graph analysis. "
                "Install it with: pip install networkx"
            )
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, AttackNode] = {}
        self._prerequisites: dict[str, ExploitPrerequisite] = {}
        self._cache_version: int = 0  # Bumped on every mutation for cache invalidation
        self._lock = threading.RLock()
        self._validate_on_mutate = validate_on_mutate
        self._mutation_count: int = 0

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    # --- Node Management ---

    def add_node(self, node: AttackNode) -> None:
        """Add or merge a node in the graph.

        BUG-024 FIX: If node already exists, merge properties instead of
        blindly overwriting. Risk score takes the max of old and new.
        Thread-safe: protected by RLock (H-GR-001).
        """
        with self._lock:
            self._cache_version += 1
            self._mutation_count += 1
            existing = self._nodes.get(node.id)
            if existing is not None:
                # Merge: update properties, keep higher risk score
                existing.properties.update(node.properties)
                existing.risk_score = max(existing.risk_score, node.risk_score)
                if node.label and node.label != existing.label:
                    existing.label = node.label
                # LOW-01 FIX: Also update node_type if it changed
                if node.node_type != existing.node_type:
                    existing.node_type = node.node_type
                node = existing

            self._nodes[node.id] = node
            self._graph.add_node(
                node.id,
                node_type=node.node_type.value,
                label=node.label,
                risk_score=node.risk_score,
                **node.properties,
            )
            self._run_mutation_hook()

    def add_edge(self, edge: AttackEdge) -> None:
        """Add an edge between two nodes.

        Thread-safe: protected by RLock (H-GR-001).
        """
        with self._lock:
            self._cache_version += 1
            self._mutation_count += 1
            self._graph.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=edge.edge_type.value,
                weight=edge.weight,
                **edge.properties,
            )
            self._run_mutation_hook()

    def _run_mutation_hook(self) -> None:
        """Run optional integrity validation after mutations (H-GR-004)."""
        if not self._validate_on_mutate:
            return
        # Only validate every 50 mutations to avoid quadratic cost
        if self._mutation_count % 50 != 0:
            return
        try:
            from phantom.core.graph_integrity_validator import GraphIntegrityValidator
            validator = GraphIntegrityValidator()
            report = validator.validate_graph(self)
            if not report.valid:
                _logger.warning(
                    "Graph integrity issue detected after mutation #%d: %s",
                    self._mutation_count, "; ".join(report.issues[:3]),
                )
        except Exception as exc:
            _logger.debug("Mutation hook skipped: %s", exc)

    def snapshot(self) -> dict[str, Any]:
        """Thread-safe snapshot of the current graph state (H-GR-003)."""
        with self._lock:
            return self.to_dict()

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
        queue: deque[str] = deque([host_id])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            node_data = self._graph.nodes.get(current, {})
            if node_data.get("node_type") == NodeType.VULNERABILITY.value:
                if current in self._nodes:
                    vulns.append(self._nodes[current])
            else:
                # MED-09 FIX: Follow both forward and backward edges
                # to capture laterally-connected vulnerabilities
                queue.extend(self._graph.successors(current))
                queue.extend(self._graph.predecessors(current))

        return vulns

    # --- Attack Path Analysis ---

    def find_attack_paths(
        self,
        source: str,
        target: str | None = None,
        *,
        target_type: NodeType | None = None,
        max_depth: int = 10,
        max_paths: int = 500,
    ) -> list[list[str]]:
        """
        Find attack paths from source to target(s).

        Args:
            source: Source node ID
            target: Specific target node ID
            target_type: Find paths to all nodes of this type
            max_depth: Maximum path length
            max_paths: Maximum number of paths to return (prevents combinatorial explosion)

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
                    if len(paths) >= max_paths:
                        break
            except nx.NetworkXNoPath:
                pass
        elif target_type:
            targets = [
                nid for nid, d in self._graph.nodes(data=True)
                if d.get("node_type") == target_type.value
            ]
            for t in targets:
                if len(paths) >= max_paths:
                    break
                try:
                    for path in nx.all_simple_paths(self._graph, source, t, cutoff=max_depth):
                        paths.append(list(path))
                        if len(paths) >= max_paths:
                            break
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        return paths

    def find_critical_paths(
        self, min_severity: float = 7.0, *, max_paths: int = 500,
    ) -> list[dict[str, Any]]:
        """
        Find paths that traverse high-severity vulnerabilities.

        BUG-023 FIX: Use geometric mean of node risk scores instead of
        naive sum, so longer paths don't automatically score higher.

        Args:
            min_severity: Minimum risk score for target vulnerabilities.
            max_paths: Maximum number of paths to return (prevents combinatorial explosion).

        Returns paths annotated with normalized risk scores.
        """
        hosts = self.get_nodes_by_type(NodeType.HOST)
        vulns = [
            n for n in self.get_nodes_by_type(NodeType.VULNERABILITY)
            if n.risk_score >= min_severity
        ]

        critical_paths: list[dict[str, Any]] = []

        for host_node in hosts:
            if len(critical_paths) >= max_paths:
                break
            for vuln_node in vulns:
                if len(critical_paths) >= max_paths:
                    break
                try:
                    for path in nx.all_simple_paths(
                        self._graph, host_node.id, vuln_node.id, cutoff=8
                    ):
                        scores = [
                            self._nodes[n].risk_score
                            for n in path
                            if n in self._nodes and self._nodes[n].risk_score > 0
                        ]
                        # Geometric mean: (prod(scores))^(1/len)
                        if scores:
                            log_sum = sum(math.log(max(s, 0.01)) for s in scores)
                            risk = math.exp(log_sum / len(scores))
                        else:
                            risk = 0.0
                        critical_paths.append({
                            "path": path,
                            "risk_score": round(risk, 3),
                            "entry_point": host_node.label,
                            "target_vuln": vuln_node.label,
                            "length": len(path),
                            "max_node_risk": max(scores) if scores else 0.0,
                        })
                        if len(critical_paths) >= max_paths:
                            break
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        # Sort by risk score descending
        critical_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return critical_paths

    def find_shortest_attack_path(self, source: str, target: str) -> list[str] | None:
        """Find the shortest (hop-count) path between two nodes."""
        try:
            return list(nx.shortest_path(self._graph, source, target))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def find_highest_risk_path(self, source: str, target: str) -> list[str] | None:
        """Find the path with the highest cumulative risk between two nodes.

        BUG-009 FIX: Uses inverted weights so that Dijkstra's algorithm
        finds the path traversing the highest-risk nodes.
        """
        try:
            # Create a view with inverted weights for Dijkstra
            # Higher risk_score → lower weight → preferred by shortest_path
            max_risk = 11.0  # Just above the max possible risk score
            return list(nx.shortest_path(
                self._graph, source, target,
                weight=lambda u, v, d: max_risk - d.get("weight", 1.0),
            ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def detect_cycles(self) -> list[list[str]]:
        """Detect cycles in the attack graph.

        Returns a list of cycles found. An empty list means the graph is a DAG.
        """
        try:
            cycles = list(nx.simple_cycles(self._graph))
            return [list(c) for c in cycles[:100]]  # Cap at 100
        except nx.NetworkXError:
            return []

    def validate_graph(self) -> dict[str, Any]:
        """Validate graph integrity and return a health report."""
        issues: list[str] = []

        # Check for orphan nodes (no edges)
        orphans = [n for n in self._graph.nodes if self._graph.degree(n) == 0]
        if orphans:
            issues.append(f"{len(orphans)} orphan nodes with no connections")

        # Check for cycles
        cycles = self.detect_cycles()
        if cycles:
            issues.append(f"{len(cycles)} cycles detected (longest: {max(len(c) for c in cycles)} nodes)")

        # Check for nodes without type
        untyped = [n for n, d in self._graph.nodes(data=True) if "node_type" not in d]
        if untyped:
            issues.append(f"{len(untyped)} nodes without type attribution")

        # Check for missing node data
        missing_data = [n for n in self._graph.nodes if n not in self._nodes]
        if missing_data:
            issues.append(f"{len(missing_data)} graph nodes missing AttackNode data")

        return {
            "healthy": len(issues) == 0,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "orphan_count": len(orphans),
            "cycle_count": len(cycles),
            "issues": issues,
        }

    # --- Risk Analysis ---

    def propagate_risk(
        self,
        *,
        decay: float = 0.6,
        iterations: int = 5,
    ) -> dict[str, float]:
        """
        Propagate risk scores through the graph.

        BUG-008 FIX: Configurable decay factor and iteration count.
        BUG-009 FIX: Use sum aggregation (capped at 10.0) instead of max(),
        since a host with 3 vulns is riskier than one with 1 vuln.

        Args:
            decay: Risk propagation decay per hop (default 0.6)
            iterations: Number of propagation rounds (default 5)
        """
        risk_map: dict[str, float] = {}

        for node_id in self._graph.nodes:
            if node_id in self._nodes:
                risk_map[node_id] = self._nodes[node_id].risk_score

        # Propagate risk backward from vulns to hosts
        for _ in range(iterations):
            new_risk = dict(risk_map)
            for u, v in self._graph.edges:
                child_risk = risk_map.get(v, 0)
                if child_risk > 0:
                    inherited = child_risk * decay
                    # MED-07 FIX: Use max aggregation per iteration to prevent
                    # exponential accumulation across iterations.
                    new_risk[u] = min(10.0, max(new_risk.get(u, 0), risk_map.get(u, 0) + inherited))
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
            try:
                ntype = NodeType(node.pop("node_type", "host"))
            except ValueError:
                ntype = NodeType.HOST
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
            try:
                etype = EdgeType(edge.pop("edge_type", "HOSTS"))
            except ValueError:
                etype = EdgeType.HOSTS
            weight = edge.pop("weight", 1.0)
            graph.add_edge(AttackEdge(
                source_id=src, target_id=tgt,
                edge_type=etype, weight=weight, properties=edge,
            ))
        return graph

    # ------------------------------------------------------------------
    # Intelligence Plan 3.1: Automated Attack Chain Inference
    # ------------------------------------------------------------------

    def infer_attack_chains(self, min_chain_length: int = 2, max_chains: int = 500) -> list[list[str]]:
        """Infer multi-step attack chains from graph topology.

        Chains are paths: host → service → endpoint → vuln → (LEADS_TO/CHAINS_WITH) → ...
        Only includes chains containing at least one vulnerability node.
        """
        vuln_nodes = self.get_nodes_by_type(NodeType.VULNERABILITY)
        chains: list[list[str]] = []

        for vuln in vuln_nodes:
            # Follow CHAINS_WITH and LEADS_TO edges forward from each vuln
            visited: set[str] = set()
            stack: list[tuple[str, list[str]]] = [(vuln.id, [vuln.id])]

            while stack:
                current, path = stack.pop()
                if current in visited and current != vuln.id:
                    continue
                visited.add(current)

                for successor in self._graph.successors(current):
                    # T3-05: Skip self-referencing edges
                    if successor == current:
                        continue
                    edge_data = self._graph.edges[current, successor]
                    etype = edge_data.get("edge_type", "")
                    if etype in (EdgeType.CHAINS_WITH.value, EdgeType.LEADS_TO.value):
                        new_path = path + [successor]
                        if len(new_path) >= min_chain_length:
                            chains.append(new_path)
                        if len(new_path) < 8:  # Depth limit
                            stack.append((successor, new_path))

        # Deduplicate
        seen: set[tuple[str, ...]] = set()
        unique: list[list[str]] = []
        for chain in chains:
            key = tuple(chain)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
            if len(unique) >= max_chains:
                break
        return unique

    # ------------------------------------------------------------------
    # Intelligence Plan 3.2: Graph-Driven Target Prioritisation
    # ------------------------------------------------------------------

    def get_priority_targets(self, top_n: int = 10) -> list[dict[str, Any]]:
        """Rank nodes by a PageRank-weighted risk score.

        Combines structural importance (PageRank) with local risk score
        to surface the most impactful attack targets.
        """
        if self.node_count == 0:
            return []

        try:
            pr = nx.pagerank(self._graph, alpha=0.85, max_iter=100)
        except nx.PowerIterationFailedConvergence:
            pr = {n: 1.0 / self.node_count for n in self._graph.nodes}

        targets: list[dict[str, Any]] = []
        for nid, pagerank in pr.items():
            node = self._nodes.get(nid)
            if node is None:
                continue
            # Combined score: 60% local risk + 40% structural importance
            local = node.risk_score / 10.0  # Normalise to [0, 1]
            combined = local * 0.6 + pagerank * 0.4 * self.node_count
            targets.append({
                "id": nid,
                "label": node.label,
                "node_type": node.node_type.value,
                "risk_score": node.risk_score,
                "pagerank": round(pagerank, 6),
                "combined_priority": round(combined, 4),
            })

        targets.sort(key=lambda t: t["combined_priority"], reverse=True)
        return targets[:top_n]

    # ------------------------------------------------------------------
    # Intelligence Plan 3.3: Unexplored Frontier Detection
    # ------------------------------------------------------------------

    def get_unexplored_frontiers(self) -> list[dict[str, Any]]:
        """Identify nodes with high connectivity but no vulnerability coverage.

        These are promising targets for deeper scanning — many services
        or endpoints but no vulns discovered yet.
        """
        frontiers: list[dict[str, Any]] = []

        for nid, node in self._nodes.items():
            if node.node_type == NodeType.VULNERABILITY:
                continue  # Skip vulns themselves

            degree = self._graph.degree(nid)
            if degree < 2:
                continue

            # Count vuln children: successors with VULNERABILITY type
            vuln_children = sum(
                1 for s in self._graph.successors(nid)
                if self._graph.nodes[s].get("node_type") == NodeType.VULNERABILITY.value
            )
            if vuln_children == 0:
                frontiers.append({
                    "id": nid,
                    "label": node.label,
                    "node_type": node.node_type.value,
                    "degree": degree,
                    "reason": "high connectivity with no vulnerabilities found",
                })

        frontiers.sort(key=lambda f: f["degree"], reverse=True)
        return frontiers

    # ------------------------------------------------------------------
    # Intelligence Plan 3.4: Exploit Prerequisite Reasoning
    # ------------------------------------------------------------------

    def add_exploit_prerequisite(self, prereq: ExploitPrerequisite) -> None:
        """Register an exploit prerequisite."""
        self._prerequisites[prereq.vuln_id] = prereq

    def get_unsatisfied_prerequisites(self) -> list[ExploitPrerequisite]:
        """Return prerequisites not yet met by the current graph state."""
        unsatisfied: list[ExploitPrerequisite] = []
        for prereq in self._prerequisites.values():
            for req_node in prereq.requires:
                if req_node not in self._graph:
                    unsatisfied.append(prereq)
                    break
            else:
                # All required nodes exist — check verified requirements
                for req_vuln in prereq.requires_verified:
                    vid = f"vuln:{req_vuln}" if not req_vuln.startswith("vuln:") else req_vuln
                    node = self._nodes.get(vid)
                    if node is None or not node.properties.get("verified", False):
                        unsatisfied.append(prereq)
                        break
        return unsatisfied

    # ------------------------------------------------------------------
    # FIX-P2-003: Node Pruning
    # ------------------------------------------------------------------

    def prune_unreachable(self, root_ids: list[str] | None = None) -> int:
        """Remove nodes not reachable from any root (host) node.

        Returns the number of nodes pruned.
        """
        if root_ids is None:
            root_ids = [n.id for n in self.get_nodes_by_type(NodeType.HOST)]

        if not root_ids:
            return 0

        reachable: set[str] = set()
        for root in root_ids:
            if root in self._graph:
                reachable.update(nx.descendants(self._graph, root))
                reachable.add(root)

        to_remove = [n for n in list(self._graph.nodes) if n not in reachable]
        for nid in to_remove:
            self._graph.remove_node(nid)
            self._nodes.pop(nid, None)
            self._prerequisites.pop(nid, None)

        if to_remove:
            self._cache_version += 1
        return len(to_remove)
