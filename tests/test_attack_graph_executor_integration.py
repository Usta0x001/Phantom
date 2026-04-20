from types import SimpleNamespace

from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.core.attack_graph import AttackGraph
from phantom.tools.executor import _auto_record_hypothesis


def test_auto_record_hypothesis_enriches_attack_graph_with_belief_metadata() -> None:
    ledger = HypothesisLedger()
    graph = AttackGraph()
    owner = SimpleNamespace(
        hypothesis_ledger=ledger,
        coverage_tracker=None,
        correlation_engine=None,
        attack_graph=graph,
    )

    _auto_record_hypothesis(
        tool_inv={
            "toolName": "send_request",
            "args": {
                "url": "https://target.example/api/users?id=1",
                "method": "GET",
                "body": "",
            },
        },
        observation_xml="response: injectable parameter confirmed with SQL syntax error",
        agent_state=None,
        owner_agent=owner,
        vuln_signals=["SQL_INJECTION: confirmed injectable parameter"],
    )

    nodes = graph._nodes
    vuln_nodes = [node for node in nodes.values() if node.type.value == "vulnerability"]
    assert vuln_nodes

    vuln = vuln_nodes[0]
    metadata = vuln.metadata
    assert "hypothesis_id" in metadata
    assert 0.01 <= float(metadata.get("success_probability", 0.0)) <= 0.99
    assert 0.01 <= float(metadata.get("confidence", 0.0)) <= 0.99

    outgoing = list(graph._graph.out_edges(vuln.id))
    assert outgoing
    edge_data = graph._graph.get_edge_data(*outgoing[0]) or {}
    assert 0.01 <= float(edge_data.get("success_probability", 0.0)) <= 0.99
    assert float(edge_data.get("cost", 0.0)) >= 0.2


def test_auto_record_hypothesis_probability_drifts_up_with_repeated_signals() -> None:
    ledger = HypothesisLedger()
    graph = AttackGraph()
    owner = SimpleNamespace(
        hypothesis_ledger=ledger,
        coverage_tracker=None,
        correlation_engine=None,
        attack_graph=graph,
    )

    kwargs = {
        "tool_inv": {
            "toolName": "send_request",
            "args": {
                "url": "https://target.example/api/users?id=1",
                "method": "GET",
                "body": "",
            },
        },
        "agent_state": None,
        "owner_agent": owner,
        "vuln_signals": ["SQL_INJECTION: confirmed injectable parameter"],
    }

    _auto_record_hypothesis(observation_xml="response: SQL syntax error", **kwargs)
    first_vuln = next(node for node in graph._nodes.values() if node.type.value == "vulnerability")
    first_edge = graph._graph.get_edge_data(*next(iter(graph._graph.out_edges(first_vuln.id)))) or {}
    first_node_probability = float(first_vuln.metadata.get("success_probability", 0.0))
    first_edge_probability = float(first_edge.get("success_probability", 0.0))

    _auto_record_hypothesis(
        observation_xml="response: SQL syntax error and access granted to authenticated area",
        **kwargs,
    )
    updated_vuln = graph._nodes[first_vuln.id]
    updated_edge = graph._graph.get_edge_data(*next(iter(graph._graph.out_edges(updated_vuln.id)))) or {}

    assert float(updated_vuln.metadata.get("success_probability", 0.0)) >= first_node_probability
    assert float(updated_edge.get("success_probability", 0.0)) >= first_edge_probability
