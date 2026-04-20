from types import SimpleNamespace

from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.core.attack_graph import AttackEdgeType, AttackGraph
from phantom.tools.executor import _auto_record_hypothesis
from phantom.tools.scan_status.scan_status_actions import (
    clear_scan_status_context,
    get_scan_status,
    set_scan_status_context,
)


def test_planner_traces_surface_in_scan_status_and_scheduler_events() -> None:
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

    report = ledger.get_scheduler_report()
    assert any(evt.get("event_type") == "planner_trace" for evt in report.get("scheduler_events", []))

    try:
        set_scan_status_context(attack_graph=graph, agent_state=SimpleNamespace(agent_id="planner-agent"))
        status = get_scan_status(include_recommendations=True, agent_id="planner-agent")

        attack_graph = status.get("attack_graph")
        assert isinstance(attack_graph, dict)
        assert attack_graph.get("planner_traces")
        assert attack_graph.get("top_attack_plans")
        assert "Prioritize top attack chain" in str(status.get("recommended_next_action", ""))
    finally:
        clear_scan_status_context("planner-agent")
