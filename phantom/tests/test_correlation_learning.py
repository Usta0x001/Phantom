"""
Correlation learning regression tests.

These tests prove that the correlation engine now influences planning,
not only prompt summaries.
"""

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


def test_hypothesis_scoring_uses_correlation_prior() -> None:
    engine = CorrelationEngine()
    ledger = HypothesisLedger()
    ledger.set_correlation_engine(engine)

    favored = ledger.add("/api/login::username", "sqli")
    unfavored = ledger.add("/api/profile::id", "sqli")

    # Keep raw evidence and investment identical.
    ledger.record_payload(favored, "' OR 1=1--")
    ledger.record_result(favored, "testing", "signal")
    ledger.record_payload(unfavored, "' OR 1=1--")
    ledger.record_result(unfavored, "testing", "signal")

    for _ in range(4):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/login::username",
            outcome="confirmed",
            payload_family="union",
        )
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/profile::id",
            outcome="rejected",
            payload_family="boolean",
        )

    scored = ledger.get_scored_hypotheses()
    assert scored, "Expected scored hypotheses"

    top = scored[0]
    assert top["hypothesis_id"] == favored
    assert top["score_factors"].get("correlation_prior", 0) > 0


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
