"""Pytest configuration and shared fixtures for phantom tests."""

import logging
import pytest
from unittest.mock import MagicMock

from phantom.core.confidence_engine import ConfidenceEngine
from phantom.core.evidence_registry import EvidenceRegistry, EvidenceType, EvidenceQuality
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState
from phantom.core.attack_graph import (
    AttackGraph, AttackNode, AttackEdge, NodeType, EdgeType,
)
from phantom.core.strategic_planner import StrategicPlanner
from phantom.core.adversarial_critic import AdversarialCritic
from phantom.core.scan_state_machine import ScanStateMachine, ScanState


@pytest.fixture
def confidence_engine():
    return ConfidenceEngine()


@pytest.fixture
def evidence_registry():
    return EvidenceRegistry()


@pytest.fixture
def circuit_breaker():
    return CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)


@pytest.fixture
def attack_graph():
    g = AttackGraph()
    g.add_node(AttackNode(id="host-1", node_type=NodeType.HOST, label="Host 1", properties={"ip": "10.0.0.1"}))
    g.add_node(AttackNode(id="svc-http", node_type=NodeType.SERVICE, label="HTTP", properties={"port": 80}))
    g.add_node(AttackNode(id="vuln-sqli", node_type=NodeType.VULNERABILITY, label="SQLi", risk_score=8.5))
    g.add_node(AttackNode(id="vuln-xss", node_type=NodeType.VULNERABILITY, label="XSS", risk_score=5.4))
    g.add_edge(AttackEdge(source_id="host-1", target_id="svc-http", edge_type=EdgeType.HOSTS))
    g.add_edge(AttackEdge(source_id="svc-http", target_id="vuln-sqli", edge_type=EdgeType.HAS_VULN))
    g.add_edge(AttackEdge(source_id="vuln-sqli", target_id="vuln-xss", edge_type=EdgeType.CHAINS_WITH))
    return g


@pytest.fixture
def mock_state(attack_graph):
    state = MagicMock()
    state.attack_graph = attack_graph
    state.verified_vulns = set()
    state.false_positives = set()
    state.iteration_count = 5
    state.discovered_vulns = {"vuln-1": {"severity": "high"}}
    state.vulnerabilities = {}
    state.findings_ledger = []
    state.tested_endpoints = {}
    state.hosts = {"h1": MagicMock(ports=[80])}
    state.subdomains = set()
    state.endpoints = set()
    state.vuln_stats = {"total": 1}
    state.pending_verification = []
    return state


@pytest.fixture
def critic(mock_state):
    return AdversarialCritic(critic_llm=MagicMock())


@pytest.fixture
def strategic_planner(attack_graph):
    return StrategicPlanner(attack_graph=attack_graph)


@pytest.fixture(autouse=True)
def capture_phantom_logs(caplog):
    with caplog.at_level(logging.DEBUG, logger="phantom"):
        yield
