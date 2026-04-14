import json
from pathlib import Path

from experiments.export_dabs_metrics import export_metrics
from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_export_metrics_contains_required_fields(tmp_path: Path) -> None:
    ledger = HypothesisLedger()
    h1 = ledger.add("/api/login::username", "sqli")
    ledger.record_payload(h1, "' OR 1=1--")
    ledger.record_result(h1, "confirmed", "SQL error")
    _ = ledger.get_scored_hypotheses()

    state_path = tmp_path / "ledger.json"
    out_path = tmp_path / "metrics.json"
    state_path.write_text(json.dumps(ledger.to_dict(), indent=2), encoding="utf-8")

    metrics = export_metrics(state_path, out_path)
    assert out_path.exists()
    assert "exploit_success_rate" in metrics
    assert "steps_to_first_exploit" in metrics
    assert "belief_map" in metrics
    assert "events" in metrics
