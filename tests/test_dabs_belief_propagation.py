from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_dabs_initial_belief_is_0_5() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/login::username", "sqli")

    assert ledger.get_belief(hyp_id) == 0.5


def test_dabs_selection_uses_evidence_in_addition_to_belief() -> None:
    ledger = HypothesisLedger()
    strong = ledger.add("/api/strong::id", "sqli")
    weak = ledger.add("/api/weak::id", "sqli")

    strong_h = ledger.get(strong)
    weak_h = ledger.get(weak)
    assert strong_h is not None
    assert weak_h is not None

    strong_h.tests_executed = 2
    weak_h.tests_executed = 2

    ledger._belief_map[strong] = 0.5
    ledger._belief_map[weak] = 0.5
    assert ledger.get_belief(strong) == ledger.get_belief(weak) == 0.5

    scored = ledger.get_scored_hypotheses()
    strong_entry = next(item for item in scored if item["hypothesis_id"] == strong)
    weak_entry = next(item for item in scored if item["hypothesis_id"] == weak)

    assert strong_entry["score_factors"]["belief"] == weak_entry["score_factors"]["belief"]
    assert strong_entry["score_factors"]["exploration"] == weak_entry["score_factors"]["exploration"]
    assert strong_entry["score_factors"]["redundancy"] == weak_entry["score_factors"]["redundancy"]


def test_dabs_propagates_to_confirmed_and_rejected_nodes() -> None:
    ledger = HypothesisLedger()
    source = ledger.add("/api/login::username", "sqli")
    related_confirmed = ledger.add("/api/login::password", "sqli")
    related_rejected = ledger.add("/api/login::token", "sqli")

    ledger.record_result(related_confirmed, "confirmed", "confirmed baseline")
    ledger.record_result(related_rejected, "rejected", "rejected baseline")

    before_confirmed = ledger.get_belief(related_confirmed)
    before_rejected = ledger.get_belief(related_rejected)

    ledger.propagate_update(source, "confirmed")

    assert ledger.get_belief(related_confirmed) > before_confirmed
    assert ledger.get_belief(related_rejected) > before_rejected


def test_dabs_relation_strength_stays_with_claimed_factors() -> None:
    ledger = HypothesisLedger()
    left = ledger.add("/api/login::username", "sqli")
    right = ledger.add("/api/login::password", "sqli")
    hyp_left = ledger.get(left)
    hyp_right = ledger.get(right)

    assert hyp_left is not None
    assert hyp_right is not None

    rel = ledger._relation_strength(hyp_left, hyp_right)
    assert 0.0 <= rel <= 1.0
