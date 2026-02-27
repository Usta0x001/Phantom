"""
Attack Path Analyzer

Advanced attack-path analysis on top of the AttackGraph engine.
Identifies multi-step exploit chains, calculates composite risk scores,
and recommends remediation priorities based on attack reachability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    import networkx as nx
except ImportError:
    nx = None

from phantom.core.attack_graph import (
    AttackGraph,
    EdgeType,
    NodeType,
    _severity_to_score,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AttackStep:
    """A single step in an attack path."""
    node_id: str
    node_type: str
    label: str
    risk_score: float
    action: str = ""  # Human-readable description of this step


@dataclass
class AttackPath:
    """A complete multi-step attack path."""
    path_id: str
    steps: list[AttackStep]
    total_risk: float
    exploitability: float  # 0-10 composite exploitability score
    impact: float          # 0-10 composite impact score
    entry_point: str
    final_target: str
    vuln_count: int
    description: str = ""

    @property
    def length(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "length": self.length,
            "total_risk": round(self.total_risk, 2),
            "exploitability": round(self.exploitability, 2),
            "impact": round(self.impact, 2),
            "entry_point": self.entry_point,
            "final_target": self.final_target,
            "vuln_count": self.vuln_count,
            "description": self.description,
            "steps": [
                {
                    "node_id": s.node_id,
                    "node_type": s.node_type,
                    "label": s.label,
                    "risk_score": round(s.risk_score, 2),
                    "action": s.action,
                }
                for s in self.steps
            ],
        }


@dataclass
class AttackPathReport:
    """Complete attack path analysis report."""
    total_paths: int
    critical_paths: int
    high_risk_paths: int
    max_path_length: int
    most_targeted_nodes: list[dict[str, Any]]
    remediation_priorities: list[dict[str, Any]]
    paths: list[AttackPath]
    choke_points: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_paths": self.total_paths,
                "critical_paths": self.critical_paths,
                "high_risk_paths": self.high_risk_paths,
                "max_path_length": self.max_path_length,
            },
            "choke_points": self.choke_points,
            "most_targeted_nodes": self.most_targeted_nodes,
            "remediation_priorities": self.remediation_priorities,
            "paths": [p.to_dict() for p in self.paths],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AttackPathAnalyzer:
    """
    Performs advanced attack-path analysis on an AttackGraph.

    Features:
    - Multi-step exploit chain discovery
    - Choke-point identification (nodes that appear on many paths)
    - Remediation prioritization (fix one node to break most paths)
    - Composite risk scoring (exploitability * impact)
    - Entry-point enumeration

    Usage:
        graph = AttackGraph()
        # ... populate graph ...
        analyzer = AttackPathAnalyzer(graph)
        report = analyzer.full_analysis()
    """

    def __init__(self, graph: AttackGraph) -> None:
        if nx is None:
            raise ImportError("networkx is required for attack path analysis")
        self.graph = graph
        self._g = graph._graph  # Direct access to NetworkX DiGraph

    # --- Entry Point Discovery ---

    def find_entry_points(self) -> list[str]:
        """
        Identify network entry points (hosts and externally-exposed services).
        Entry points are nodes with in-degree 0 or host nodes.
        """
        entries: list[str] = []
        for nid, data in self._g.nodes(data=True):
            ntype = data.get("node_type", "")
            if ntype == NodeType.HOST.value:
                entries.append(nid)
            elif self._g.in_degree(nid) == 0 and ntype in (
                NodeType.SERVICE.value, NodeType.ENDPOINT.value
            ):
                entries.append(nid)
        return entries

    def find_high_value_targets(self) -> list[str]:
        """
        Identify high-value targets: data assets, critical vulns, credentials.
        """
        targets: list[str] = []
        for nid, data in self._g.nodes(data=True):
            ntype = data.get("node_type", "")
            risk = data.get("risk_score", 0)
            if ntype == NodeType.DATA_ASSET.value:
                targets.append(nid)
            elif ntype == NodeType.VULNERABILITY.value and risk >= 8.0:
                targets.append(nid)
            elif ntype == NodeType.CREDENTIAL.value:
                targets.append(nid)
        return targets

    # --- Path Discovery ---

    def discover_all_paths(
        self, *, max_depth: int = 8, max_paths: int = 500
    ) -> list[AttackPath]:
        """
        Discover all attack paths from entry points to high-value targets.
        """
        entries = self.find_entry_points()
        targets = self.find_high_value_targets()

        # If no explicit HVTs, use all vuln nodes as targets
        if not targets:
            targets = [
                nid for nid, d in self._g.nodes(data=True)
                if d.get("node_type") == NodeType.VULNERABILITY.value
            ]

        paths: list[AttackPath] = []
        path_counter = 0

        for entry in entries:
            for target in targets:
                if entry == target:
                    continue
                try:
                    for raw_path in nx.all_simple_paths(
                        self._g, entry, target, cutoff=max_depth
                    ):
                        if path_counter >= max_paths:
                            break
                        ap = self._build_attack_path(
                            f"AP-{path_counter:04d}", list(raw_path)
                        )
                        paths.append(ap)
                        path_counter += 1
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                if path_counter >= max_paths:
                    break
            if path_counter >= max_paths:
                break

        # Sort by total risk descending
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        return paths

    def _build_attack_path(self, path_id: str, node_ids: list[str]) -> AttackPath:
        """Convert a raw path (list of node IDs) into an AttackPath."""
        steps: list[AttackStep] = []
        total_risk = 0.0
        vuln_count = 0
        max_impact = 0.0

        for nid in node_ids:
            data = self._g.nodes.get(nid, {})
            ntype = data.get("node_type", "unknown")
            label = data.get("label", nid)
            risk = data.get("risk_score", 0.0)

            action = _describe_step(ntype, label)
            steps.append(AttackStep(
                node_id=nid,
                node_type=ntype,
                label=label,
                risk_score=risk,
                action=action,
            ))
            total_risk += risk
            if ntype == NodeType.VULNERABILITY.value:
                vuln_count += 1
                max_impact = max(max_impact, risk)

        exploitability = min(10.0, total_risk / max(len(node_ids), 1) * 2)
        impact = max_impact

        entry_label = steps[0].label if steps else "unknown"
        target_label = steps[-1].label if steps else "unknown"

        return AttackPath(
            path_id=path_id,
            steps=steps,
            total_risk=total_risk,
            exploitability=exploitability,
            impact=impact,
            entry_point=entry_label,
            final_target=target_label,
            vuln_count=vuln_count,
            description=f"{entry_label} → {target_label} ({len(steps)} steps, {vuln_count} vulns)",
        )

    # --- Choke Point Analysis ---

    def find_choke_points(self, paths: list[AttackPath] | None = None) -> list[dict[str, Any]]:
        """
        Find nodes that appear on the most attack paths.

        Fixing a choke point breaks the most attack paths at once.
        Returns sorted list of choke points with path counts.
        """
        if paths is None:
            paths = self.discover_all_paths()

        node_path_count: dict[str, int] = {}
        node_risk_sum: dict[str, float] = {}

        for path in paths:
            for step in path.steps:
                nid = step.node_id
                node_path_count[nid] = node_path_count.get(nid, 0) + 1
                node_risk_sum[nid] = node_risk_sum.get(nid, 0) + path.total_risk

        choke_points: list[dict[str, Any]] = []
        for nid, count in node_path_count.items():
            if count < 2:
                continue  # Only interesting if shared across paths
            data = self._g.nodes.get(nid, {})
            choke_points.append({
                "node_id": nid,
                "label": data.get("label", nid),
                "node_type": data.get("node_type", "unknown"),
                "paths_through": count,
                "cumulative_risk": round(node_risk_sum.get(nid, 0), 2),
                "remediation_impact": round(
                    count / len(paths) * 100 if paths else 0, 1
                ),
            })

        choke_points.sort(key=lambda c: c["paths_through"], reverse=True)
        return choke_points[:20]

    # --- Remediation Prioritization ---

    def prioritize_remediation(
        self, paths: list[AttackPath] | None = None
    ) -> list[dict[str, Any]]:
        """
        Recommend which vulnerabilities to fix first based on:
        - Number of attack paths they appear on
        - Cumulative risk across paths
        - Whether they're choke points

        Returns prioritized remediation list.
        """
        if paths is None:
            paths = self.discover_all_paths()

        vuln_stats: dict[str, dict[str, Any]] = {}

        for path in paths:
            for step in path.steps:
                if step.node_type != NodeType.VULNERABILITY.value:
                    continue
                nid = step.node_id
                if nid not in vuln_stats:
                    vuln_stats[nid] = {
                        "node_id": nid,
                        "label": step.label,
                        "own_risk": step.risk_score,
                        "path_count": 0,
                        "total_path_risk": 0.0,
                        "max_path_risk": 0.0,
                    }
                vuln_stats[nid]["path_count"] += 1
                vuln_stats[nid]["total_path_risk"] += path.total_risk
                vuln_stats[nid]["max_path_risk"] = max(
                    vuln_stats[nid]["max_path_risk"], path.total_risk
                )

        # Composite priority score
        priorities: list[dict[str, Any]] = []
        for nid, stats in vuln_stats.items():
            # Weight: own severity * log(paths) * normalized cumulative risk
            import math
            priority_score = (
                stats["own_risk"]
                * (1 + math.log2(max(stats["path_count"], 1)))
                * (stats["total_path_risk"] / max(len(paths), 1))
            )
            priorities.append({
                **stats,
                "priority_score": round(priority_score, 2),
                "paths_broken_pct": round(
                    stats["path_count"] / len(paths) * 100 if paths else 0, 1
                ),
            })

        priorities.sort(key=lambda p: p["priority_score"], reverse=True)
        return priorities

    # --- Most Targeted Nodes ---

    def most_targeted_nodes(
        self, paths: list[AttackPath] | None = None, top_n: int = 10
    ) -> list[dict[str, Any]]:
        """Find nodes that are final targets in the most attack paths."""
        if paths is None:
            paths = self.discover_all_paths()

        target_count: dict[str, int] = {}
        for path in paths:
            if path.steps:
                tid = path.steps[-1].node_id
                target_count[tid] = target_count.get(tid, 0) + 1

        results: list[dict[str, Any]] = []
        for nid, count in sorted(target_count.items(), key=lambda x: x[1], reverse=True):
            data = self._g.nodes.get(nid, {})
            results.append({
                "node_id": nid,
                "label": data.get("label", nid),
                "node_type": data.get("node_type", "unknown"),
                "targeted_by_paths": count,
            })
            if len(results) >= top_n:
                break
        return results

    # --- Full Analysis ---

    def full_analysis(self, *, max_depth: int = 8, max_paths: int = 500) -> AttackPathReport:
        """
        Run complete attack path analysis.

        Returns an AttackPathReport with:
        - All discovered paths
        - Choke points
        - Remediation priorities
        - Most targeted nodes
        """
        paths = self.discover_all_paths(max_depth=max_depth, max_paths=max_paths)

        critical = sum(1 for p in paths if p.total_risk >= 8.0)
        high_risk = sum(1 for p in paths if 5.0 <= p.total_risk < 8.0)
        max_len = max((p.length for p in paths), default=0)

        return AttackPathReport(
            total_paths=len(paths),
            critical_paths=critical,
            high_risk_paths=high_risk,
            max_path_length=max_len,
            most_targeted_nodes=self.most_targeted_nodes(paths),
            remediation_priorities=self.prioritize_remediation(paths),
            paths=paths[:50],  # Top 50 riskiest paths
            choke_points=self.find_choke_points(paths),
        )

    def to_markdown(self) -> str:
        """Generate a Markdown attack path report."""
        report = self.full_analysis()
        lines: list[str] = []

        lines.append("# Attack Path Analysis Report\n")
        lines.append("## Summary\n")
        lines.append(f"- **Total attack paths:** {report.total_paths}")
        lines.append(f"- **Critical paths (risk >= 8.0):** {report.critical_paths}")
        lines.append(f"- **High-risk paths (risk 5.0-8.0):** {report.high_risk_paths}")
        lines.append(f"- **Maximum path length:** {report.max_path_length}\n")

        if report.choke_points:
            lines.append("## Choke Points (Fix These First)\n")
            lines.append("| Node | Type | Paths Through | Remediation Impact |")
            lines.append("|------|------|:-------------:|:------------------:|")
            for cp in report.choke_points[:10]:
                lines.append(
                    f"| {cp['label']} | {cp['node_type']} | "
                    f"{cp['paths_through']} | {cp['remediation_impact']}% |"
                )
            lines.append("")

        if report.remediation_priorities:
            lines.append("## Remediation Priorities\n")
            lines.append("| # | Vulnerability | Risk | Paths | Priority Score |")
            lines.append("|:--|:-------------|:----:|:-----:|:--------------:|")
            for i, rem in enumerate(report.remediation_priorities[:15], 1):
                lines.append(
                    f"| {i} | {rem['label']} | {rem['own_risk']:.1f} | "
                    f"{rem['path_count']} | {rem['priority_score']:.1f} |"
                )
            lines.append("")

        if report.most_targeted_nodes:
            lines.append("## Most Targeted Nodes\n")
            for node in report.most_targeted_nodes[:10]:
                lines.append(
                    f"- **{node['label']}** ({node['node_type']}) — "
                    f"targeted by {node['targeted_by_paths']} paths"
                )
            lines.append("")

        if report.paths:
            lines.append("## Top Attack Paths\n")
            for path in report.paths[:10]:
                lines.append(f"### {path.path_id}: {path.description}\n")
                lines.append(f"- Risk: {path.total_risk:.1f} | "
                             f"Exploitability: {path.exploitability:.1f} | "
                             f"Impact: {path.impact:.1f}")
                lines.append("")
                for j, step in enumerate(path.steps):
                    arrow = "→" if j < len(path.steps) - 1 else "⬤"
                    lines.append(f"  {arrow} **{step.label}** [{step.node_type}] "
                                 f"(risk: {step.risk_score:.1f}) — {step.action}")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _describe_step(node_type: str, label: str) -> str:
    """Generate a human-readable description for an attack step."""
    descriptions = {
        NodeType.HOST.value: f"Access host {label}",
        NodeType.SERVICE.value: f"Connect to service {label}",
        NodeType.ENDPOINT.value: f"Request endpoint {label}",
        NodeType.VULNERABILITY.value: f"Exploit {label}",
        NodeType.CREDENTIAL.value: f"Use credential {label}",
        NodeType.DATA_ASSET.value: f"Access data asset {label}",
    }
    return descriptions.get(node_type, f"Interact with {label}")
