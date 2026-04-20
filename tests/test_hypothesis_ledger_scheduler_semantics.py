from datetime import UTC, datetime, timedelta

from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.config.config import Config


def _patch_scheduler_mode(monkeypatch, mode: str | None) -> None:
    def _fake_get(key: str):
        if key == "phantom_scheduler_mode":
            return mode
        return None

    monkeypatch.setattr(Config, "get", staticmethod(_fake_get))


def _prepare_credible_rejection(ledger: HypothesisLedger, hyp_id: str) -> None:
    ledger.record_payload(hyp_id, "' OR 1=1--")
    ledger.record_payload(hyp_id, "' UNION SELECT NULL--")
    for _ in range(5):
        ledger.record_result(hyp_id, "testing", "response: candidate signal")
    ledger.record_result(hyp_id, "rejected", "WAF blocked after exhaustive payload families")


def test_scheduler_defaults_to_dabs_when_config_missing(monkeypatch) -> None:
    _patch_scheduler_mode(monkeypatch, None)

    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/admin::id=1", "sqli")
    ledger.record_result(hyp_id, "testing", "response: SQL syntax error")

    scored = ledger.get_scored_hypotheses()
    assert scored
    assert "dabs" in scored[0].get("score_factors", {})

    report = ledger.get_scheduler_report()
    assert report.get("scheduler_mode") == "dabs"


def test_thompson_mode_uses_deterministic_beta_sample(monkeypatch) -> None:
    _patch_scheduler_mode(monkeypatch, "thompson")

    ledger = HypothesisLedger()
    h1 = ledger.add("/api/users::id=1", "idor")
    h2 = ledger.add("/api/users::id=2", "idor")

    ledger.record_result(h1, "testing", "response: object diff")
    ledger.record_result(h1, "testing", "response: object diff 2")
    ledger.record_result(h2, "testing", "response: baseline")

    scored_first = ledger.get_scored_hypotheses()
    scored_second = ledger.get_scored_hypotheses()

    assert [(x["hypothesis_id"], x["priority_score"]) for x in scored_first] == [
        (x["hypothesis_id"], x["priority_score"]) for x in scored_second
    ]
    for entry in scored_first:
        factors = entry.get("score_factors", {})
        assert entry["priority_score"] == factors.get("thompson")
        assert 0.0 <= float(entry["priority_score"]) <= 1.0
        assert "alpha" in factors and "beta" in factors


def test_rejection_status_transitions_to_underdetermined_without_credible_signal() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/profile::id=7", "idor")

    ledger.record_result(hyp_id, "rejected", "No clear exploit path")

    hyp = ledger.get(hyp_id)
    assert hyp is not None
    assert hyp.status == "underdetermined"


def test_rejection_status_becomes_rejected_when_credible() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/orders::id=9", "sqli")

    _prepare_credible_rejection(ledger, hyp_id)

    hyp = ledger.get(hyp_id)
    assert hyp is not None
    assert hyp.status == "rejected"
    assert hyp_id in ledger._rejection_memory


def test_rejection_memory_decay_reduces_penalty_over_time() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/orders::id=12", "sqli")

    _prepare_credible_rejection(ledger, hyp_id)

    fresh = ledger.get_belief(hyp_id)
    ledger._rejection_memory[hyp_id]["ts"] = (
        datetime.now(UTC) - timedelta(days=365)
    ).timestamp()
    decayed = ledger.get_belief(hyp_id)

    assert decayed > fresh


def test_param_type_filtering_penalizes_disallowed_class_in_ranking(monkeypatch) -> None:
    _patch_scheduler_mode(monkeypatch, "dabs")

    ledger = HypothesisLedger()
    allowed_id = ledger.add("/api/users::id=123", "sqli")
    disallowed_id = ledger.add("/api/users::filename=report.txt", "sqli")

    scored = ledger.get_scored_hypotheses()
    by_id = {row["hypothesis_id"]: row for row in scored}

    assert by_id[allowed_id]["param_type"] == "integer_id"
    assert by_id[allowed_id]["allowed_for_surface"] is True
    assert by_id[disallowed_id]["param_type"] == "filename"
    assert by_id[disallowed_id]["allowed_for_surface"] is False
    assert by_id[allowed_id]["priority_score"] > by_id[disallowed_id]["priority_score"]


def test_confidence_calibration_rises_with_repeated_strong_updates() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/login::username", "sqli")

    initial = ledger.get(hyp_id)
    assert initial is not None
    initial_posterior = initial.posterior_mean
    initial_confidence = initial.confidence_score

    for _ in range(3):
        ledger.record_result(
            hyp_id,
            "confirmed",
            "response: SQL syntax error and authenticated access confirmed",
        )

    updated = ledger.get(hyp_id)
    assert updated is not None
    assert updated.posterior_mean >= initial_posterior
    assert updated.confidence_score >= initial_confidence
    assert ledger.get_belief(hyp_id) >= initial_posterior
