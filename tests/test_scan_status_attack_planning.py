from phantom.core.attack_graph import AttackEdgeType, AttackGraph
from phantom.tools.scan_status.scan_status_actions import (
    clear_scan_status_context,
    get_scan_status,
    set_scan_status_context,
)


class _State:
    agent_id = "agent-attack-plan"
    iteration = 18
    max_iterations = 100


def test_scan_status_includes_top_attack_plans_when_graph_present() -> None:
    graph = AttackGraph()
    graph.add_vulnerability("V1", "Entry", "high", "confirmed")
    graph.add_vulnerability("V2", "Pivot", "high", "rejected")
    graph.add_asset("A1", "Sensitive API")

    graph.add_edge(
        "V1",
        "V2",
        AttackEdgeType.ENABLES,
        metadata={"success_probability": 0.85, "cost": 0.2},
    )
    graph.add_edge(
        "V2",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.75, "cost": 0.2},
    )

    try:
        set_scan_status_context(attack_graph=graph, agent_state=_State())
        status = get_scan_status(include_recommendations=False, agent_id="agent-attack-plan")

        attack_graph = status.get("attack_graph")
        assert isinstance(attack_graph, dict)

        plans = attack_graph.get("top_attack_plans")
        assert isinstance(plans, list)
        assert plans

        top = plans[0]
        assert top.get("path") == ["V1", "V2", "A1"]
        assert 0.0 <= float(top.get("probability", 0.0)) <= 1.0
        assert float(top.get("cost", 0.0)) > 0.0
        assert float(top.get("score", 0.0)) > 0.0
    finally:
        clear_scan_status_context("agent-attack-plan")


def test_scan_status_recommendation_prioritizes_top_attack_plan() -> None:
    graph = AttackGraph()
    graph.add_vulnerability("V1", "Entry", "high", "confirmed")
    graph.add_vulnerability("V2", "Pivot", "high", "rejected")
    graph.add_asset("A1", "Sensitive API")

    graph.add_edge(
        "V1",
        "V2",
        AttackEdgeType.ENABLES,
        metadata={"success_probability": 0.9, "cost": 0.2},
    )
    graph.add_edge(
        "V2",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.8, "cost": 0.2},
    )

    try:
        set_scan_status_context(attack_graph=graph, agent_state=_State())
        status = get_scan_status(include_recommendations=True, agent_id="agent-attack-plan")
        recommendation = str(status.get("recommended_next_action", ""))

        assert "Prioritize top attack chain" in recommendation
        assert "V1 -> V2 -> A1" in recommendation
    finally:
        clear_scan_status_context("agent-attack-plan")
