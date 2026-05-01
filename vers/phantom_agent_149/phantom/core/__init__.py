"""phantom.core — shared data models and utilities used across CLI commands."""

from .attack_graph import (
    AttackGraph,
    AttackNodeType,
    AttackEdgeType,
    AttackNode,
    AttackEdge,
    build_attack_graph_from_vulnerabilities,
)

__all__ = [
    "AttackGraph",
    "AttackNodeType",
    "AttackEdgeType",
    "AttackNode",
    "AttackEdge",
    "build_attack_graph_from_vulnerabilities",
]
