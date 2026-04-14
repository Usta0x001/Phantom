from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_get_decision_trace_is_side_effect_free_for_selection_events() -> None:
    ledger = HypothesisLedger()
    h = ledger.add("/api/login::username", "sqli")
    ledger.record_result(h, "testing", "signal")

    before = len(ledger.get_scheduler_events())
    _ = ledger.get_decision_trace()
    after = len(ledger.get_scheduler_events())

    assert after == before


def test_get_scheduler_report_is_side_effect_free_for_selection_events() -> None:
    ledger = HypothesisLedger()
    h = ledger.add("/api/profile::id", "idor")
    ledger.record_result(h, "testing", "signal")

    before = len(ledger.get_scheduler_events())
    _ = ledger.get_scheduler_report()
    after = len(ledger.get_scheduler_events())

    assert after == before
