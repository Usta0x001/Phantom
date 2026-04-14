import json
from pathlib import Path

from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_scheduler_mode_dabs_is_default(monkeypatch) -> None:
    monkeypatch.delenv("PHANTOM_SCHEDULER_MODE", raising=False)

    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/default::id", "sqli")
    ledger.record_result(hyp_id, "testing", "signal")

    top = ledger.get_scored_hypotheses()[0]
    assert top["scheduler_mode"] == "dabs"


def test_scheduler_mode_fifo_orders_by_tests_executed(monkeypatch) -> None:
    monkeypatch.setenv("PHANTOM_SCHEDULER_MODE", "fifo")

    ledger = HypothesisLedger()
    h0 = ledger.add("/api/a::id", "sqli")
    h1 = ledger.add("/api/b::id", "sqli")

    ledger.record_result(h0, "testing", "first")
    ledger.record_result(h0, "testing", "second")
    ledger.record_result(h1, "testing", "first")

    scored = ledger.get_scored_hypotheses()
    assert scored[0]["hypothesis_id"] == h1
    assert scored[-1]["hypothesis_id"] == h0


def test_scheduler_mode_heuristic_uses_heuristic_prior(monkeypatch) -> None:
    monkeypatch.setenv("PHANTOM_SCHEDULER_MODE", "heuristic")

    ledger = HypothesisLedger()
    admin = ledger.add("/admin/panel::token", "auth_bypass")
    low = ledger.add("/public/info::q", "open_redirect")

    scored = ledger.get_scored_hypotheses()
    assert scored[0]["hypothesis_id"] == admin
    assert scored[0]["score_factors"].get("heuristic_prior", 0) >= scored[-1]["score_factors"].get("heuristic_prior", 0)


def test_scheduler_mode_flat_disables_propagation(monkeypatch) -> None:
    monkeypatch.setenv("PHANTOM_SCHEDULER_MODE", "flat")

    ledger = HypothesisLedger()
    source = ledger.add("/api/login::username", "sqli")
    related = ledger.add("/api/login::password", "sqli")

    before = ledger.get_belief(related)
    ledger.record_result(source, "confirmed", "signal")
    after = ledger.get_belief(related)

    assert after == before


def test_scheduler_export_json_contains_beliefs_and_events(monkeypatch, tmp_path: Path) -> None:
    out = tmp_path / "scheduler_trace.json"
    monkeypatch.setenv("PHANTOM_SCHEDULER_EXPORT_JSON", str(out))

    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/login::username", "sqli")
    ledger.record_result(hyp_id, "confirmed", "signal")
    ledger.get_scored_hypotheses()

    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "belief_map" in payload
    assert hyp_id in payload["belief_map"]
    assert isinstance(payload.get("events"), list)
