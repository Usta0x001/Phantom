from phantom.agents.correlation_engine import CorrelationEngine
from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.tools.scan_status.scan_status_actions import get_scan_status, set_scan_status_context


class _MockState:
    agent_id = "agent-corr-status"
    iteration = 12
    max_iterations = 100


def test_scan_status_includes_correlation_learning_metrics() -> None:
    ledger = HypothesisLedger()
    corr = CorrelationEngine()

    hyp_id = ledger.add("/api/login::username", "sqli")
    ledger.record_payload(hyp_id, "' UNION SELECT NULL--")
    ledger.record_result(hyp_id, "testing", "signal")

    for _ in range(3):
        corr.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="confirmed",
            payload_family="union",
        )

    set_scan_status_context(
        hypothesis_ledger=ledger,
        correlation_engine=corr,
        agent_state=_MockState(),
    )

    status = get_scan_status(include_recommendations=True)
    learning = status.get("correlation_learning")
    assert isinstance(learning, dict)
    assert learning.get("surface_attempts", 0) >= 3
    assert learning.get("surface_models", 0) >= 1
    assert isinstance(learning.get("top_surface_priors"), list)


def test_recommendation_exposes_correlation_confidence() -> None:
    ledger = HypothesisLedger()
    corr = CorrelationEngine()

    hyp_id = ledger.add("/api/login::username", "sqli")
    ledger.record_payload(hyp_id, "' OR 1=1--")
    ledger.record_result(hyp_id, "testing", "signal")

    for _ in range(3):
        corr.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="confirmed",
            payload_family="union",
        )

    set_scan_status_context(
        hypothesis_ledger=ledger,
        correlation_engine=corr,
        agent_state=_MockState(),
    )

    status = get_scan_status(include_recommendations=True)
    rec = str(status.get("recommended_next_action", ""))
    assert "belief" in rec or "score:" in rec


def test_scan_status_without_agent_id_uses_single_context() -> None:
    ledger = HypothesisLedger()
    corr = CorrelationEngine()

    set_scan_status_context(
        hypothesis_ledger=ledger,
        correlation_engine=corr,
        agent_state=_MockState(),
    )

    status = get_scan_status(include_recommendations=False)
    assert isinstance(status, dict)
    assert "scan_progress" in status
