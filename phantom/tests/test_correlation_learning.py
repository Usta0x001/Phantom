"""Correlation and DABS regression tests."""

from phantom.agents.correlation_engine import CorrelationEngine
from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_correlation_engine_learns_success_vs_failure_priors() -> None:
    engine = CorrelationEngine()

    for _ in range(3):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="confirmed",
            payload_family="union",
        )
    engine.record_outcome(
        vuln_class="sqli",
        surface="/api/login::username",
        outcome="rejected",
        payload_family="union",
    )

    for _ in range(3):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/profile::id",
            outcome="rejected",
            payload_family="boolean",
        )

    strong_surface = engine.get_surface_success_score("sqli", "/api/login::password")
    weak_surface = engine.get_surface_success_score("sqli", "/api/profile::account_id")
    union_score = engine.get_payload_family_success_score("sqli", "union")
    boolean_score = engine.get_payload_family_success_score("sqli", "boolean")

    assert strong_surface > weak_surface
    assert union_score > boolean_score


def test_dabs_belief_propagation_moves_related_hypotheses() -> None:
    ledger = HypothesisLedger()

    h_exec = ledger.add("/api/login::username", "sqli")
    h_related = ledger.add("/api/login::password", "sqli")
    h_unrelated = ledger.add("/profile/view::id", "xss")

    before_related = ledger.get_belief(h_related)
    before_unrelated = ledger.get_belief(h_unrelated)

    ledger.record_result(h_exec, "confirmed", "signal")

    after_related = ledger.get_belief(h_related)
    after_unrelated = ledger.get_belief(h_unrelated)

    assert after_related > before_related
    assert after_unrelated == before_unrelated


def test_next_best_tests_prioritize_stronger_family_correlation() -> None:
    engine = CorrelationEngine()
    ledger = HypothesisLedger()
    ledger.set_correlation_engine(engine)

    hyp_id = ledger.add("/api/login::username", "sqli")

    # Make sure all families are still considered "missing".
    hyp = ledger.get(hyp_id)
    assert hyp is not None
    hyp.payload_family_examples["union"] = ["' UNION SELECT NULL--"]
    hyp.payload_family_examples["boolean"] = ["' OR 1=1--"]

    for _ in range(4):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="confirmed",
            payload_family="union",
        )
    for _ in range(4):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="rejected",
            payload_family="boolean",
        )

    next_tests = ledger.get_next_best_tests(hyp_id, limit=3)
    assert next_tests
    assert next_tests[0]["family"] == "union"
    assert next_tests[0].get("correlation_score", 0) >= next_tests[-1].get("correlation_score", 0)


def test_chain_relation_propagates_from_sqli_to_rce() -> None:
    ledger = HypothesisLedger()

    h_sqli = ledger.add("/api/query::id", "sqli")
    h_rce = ledger.add("/api/exec::cmd", "rce")

    before = ledger.get_belief(h_rce)
    ledger.record_result(h_sqli, "confirmed", "confirmed injection")
    after = ledger.get_belief(h_rce)

    assert after > before
