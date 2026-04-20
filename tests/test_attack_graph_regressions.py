from phantom.core.attack_graph import AttackGraph, AttackEdgeType


def test_attack_graph_add_edge_replaces_existing_edge_state() -> None:
    graph = AttackGraph()
    graph.add_vulnerability("V1", "SQLi", "critical", "confirmed")
    graph.add_vulnerability("V2", "RCE", "critical", "suspected")

    graph.add_edge("V1", "V2", AttackEdgeType.ENABLES, weight=0.5, metadata={"note": "first"})
    graph.add_edge("V1", "V2", AttackEdgeType.ENABLES, weight=0.8, metadata={"note": "second"})

    assert len(graph._edges) == 1
    assert graph._edges[0].weight == 0.8
    assert graph._edges[0].metadata == {"note": "second"}


def test_attack_graph_from_dict_keeps_edges_idempotent() -> None:
    original = AttackGraph()
    original.add_vulnerability("V1", "SQLi", "critical", "confirmed")
    original.add_vulnerability("V2", "RCE", "critical", "suspected")
    original.add_edge("V1", "V2", AttackEdgeType.ENABLES, weight=0.5)

    restored = AttackGraph.from_dict(original.to_dict())

    assert len(restored._edges) == 1
    assert restored._graph.number_of_edges() == 1
    assert restored._edges[0].source == "V1"
    assert restored._edges[0].target == "V2"


def test_attack_graph_plan_attack_paths_prefers_higher_probability_route() -> None:
    graph = AttackGraph()
    graph.add_vulnerability("V1", "Entry", "high", "confirmed")
    graph.add_vulnerability("V2", "Low confidence step", "medium", "testing")
    graph.add_vulnerability("V3", "Strong pivot", "critical", "confirmed")
    graph.add_asset("A1", "Customer DB")

    graph.add_edge(
        "V1",
        "V2",
        AttackEdgeType.ENABLES,
        metadata={"success_probability": 0.30, "cost": 0.30},
    )
    graph.add_edge(
        "V2",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.40, "cost": 0.40},
    )
    graph.add_edge(
        "V1",
        "V3",
        AttackEdgeType.ENABLES,
        metadata={"success_probability": 0.90, "cost": 0.20},
    )
    graph.add_edge(
        "V3",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.80, "cost": 0.20},
    )

    plans = graph.plan_attack_paths("V1", "A1", cutoff=3, max_plans=3)

    assert len(plans) == 2
    assert plans[0].path == ["V1", "V3", "A1"]
    assert plans[0].score > plans[1].score
    assert plans[0].probability > plans[1].probability
    assert 0.0 <= plans[0].probability <= 1.0
    assert plans[0].cost > 0.0


def test_attack_graph_get_ranked_attack_plans_excludes_rejected_sources() -> None:
    graph = AttackGraph()
    graph.add_vulnerability("V-good", "Usable path", "high", "open")
    graph.add_vulnerability("V-bad", "Rejected path", "high", "rejected")
    graph.add_asset("A1", "Target Asset")

    graph.add_edge(
        "V-good",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.70, "cost": 0.30},
    )
    graph.add_edge(
        "V-bad",
        "A1",
        AttackEdgeType.AFFECTS,
        metadata={"success_probability": 0.99, "cost": 0.10},
    )

    plans = graph.get_ranked_attack_plans(max_plans=5, cutoff=3)

    assert plans
    assert all(plan.path[0] != "V-bad" for plan in plans)
    assert len({tuple(plan.path) for plan in plans}) == len(plans)
