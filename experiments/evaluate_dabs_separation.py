from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phantom.agents.hypothesis_ledger import HypothesisLedger


@dataclass(frozen=True)
class EvaluationResult:
    mode: str
    metrics: dict[str, Any]
    trace: dict[str, Any]


def _build_fixture_ledger() -> HypothesisLedger:
    ledger = HypothesisLedger()
    h1 = ledger.add("/api/login::username", "sqli")
    h2 = ledger.add("/api/profile::id", "sqli")
    h3 = ledger.add("/search::q", "xss")

    ledger.record_payload(h1, "' OR 1=1--")
    ledger.record_result(h1, "testing", "baseline")
    ledger.record_payload(h2, "' OR 1=1--")
    ledger.record_result(h2, "testing", "baseline")
    ledger.record_payload(h3, "<script>alert(1)</script>")
    ledger.record_result(h3, "testing", "baseline")
    return ledger


def _run_mode(mode: str) -> EvaluationResult:
    prev = os.environ.get("PHANTOM_SCHEDULER_MODE")
    try:
        os.environ["PHANTOM_SCHEDULER_MODE"] = mode
        ledger = _build_fixture_ledger()
        scored = ledger.get_scored_hypotheses()
        trace = ledger.get_decision_trace()
        metrics = {
            "mode": mode,
            "selected_hypothesis_id": trace.get("selected_hypothesis_id"),
            "scores": trace.get("scores", []),
            "belief_map": trace.get("belief_map", {}),
            "steps_to_first_exploit": None,
            "exploit_success_rate": 0.0,
            "false_positives": 0,
            "false_negatives": len([h for h in ledger.get_all().values() if h.status in {"open", "testing"}]),
            "cost": {
                "tests_executed_total": sum(h.tests_executed for h in ledger.get_all().values()),
                "payloads_tested_total": sum(len(h.payloads_tested) for h in ledger.get_all().values()),
            },
        }
        return EvaluationResult(mode=mode, metrics=metrics, trace=trace)
    finally:
        if prev is None:
            os.environ.pop("PHANTOM_SCHEDULER_MODE", None)
        else:
            os.environ["PHANTOM_SCHEDULER_MODE"] = prev


def run_evaluation() -> dict[str, Any]:
    modes = ["dabs", "flat", "heuristic", "fifo"]
    results = [_run_mode(mode) for mode in modes]
    return {
        "modes": [r.mode for r in results],
        "results": [{"mode": r.mode, "metrics": r.metrics, "trace": r.trace} for r in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate strict DABS separation and baselines")
    parser.add_argument("--out", default="thesis_output/dabs_separation_eval.json")
    args = parser.parse_args()

    report = run_evaluation()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
