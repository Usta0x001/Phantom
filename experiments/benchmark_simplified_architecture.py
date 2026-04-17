from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path
from statistics import mean
from typing import Any

from phantom.agents.hypothesis_ledger import HypothesisLedger


MODES = ("flat", "heuristic", "fifo")


def _seed_ledger() -> HypothesisLedger:
    ledger = HypothesisLedger()
    ledger.add("/api/login::username", "sqli")
    ledger.add("/api/profile::id", "idor")
    ledger.add("/search::q", "xss")
    ledger.add("/admin::token", "auth_bypass")
    return ledger


def _truth() -> dict[str, bool]:
    return {
        "/api/login::username|sqli": True,
        "/api/profile::id|idor": True,
        "/search::q|xss": False,
        "/admin::token|auth_bypass": False,
    }


def _key(entry: dict[str, Any]) -> str:
    return f"{entry.get('surface')}|{entry.get('vuln_class')}"


def _simulate(mode: str, seed: int, max_steps: int) -> dict[str, Any]:
    prev = os.environ.get("PHANTOM_SCHEDULER_MODE")
    random.seed(seed)
    try:
        os.environ["PHANTOM_SCHEDULER_MODE"] = mode
        ledger = _seed_ledger()
        truth = _truth()

        first_confirmed = None
        confirmed = 0
        false_positive = 0
        false_negative = 0

        for step in range(1, max_steps + 1):
            scored = ledger.get_scored_hypotheses()
            if not scored:
                break
            choice = scored[0]
            key = _key(choice)
            is_true = truth.get(key, False)
            noisy = random.random() < 0.08
            outcome_true = is_true if not noisy else not is_true

            if outcome_true:
                ledger.record_result(choice["hypothesis_id"], "confirmed", f"confirmed:{key}")
                confirmed += 1
                if first_confirmed is None:
                    first_confirmed = step
            else:
                ledger.record_result(choice["hypothesis_id"], "rejected", f"rejected:{key}")

        for hyp in ledger.get_all().values():
            k = f"{hyp.surface}|{hyp.vuln_class}"
            if hyp.status == "confirmed" and not truth.get(k, False):
                false_positive += 1
            if hyp.status in {"open", "testing"} and truth.get(k, False):
                false_negative += 1

        return {
            "mode": mode,
            "seed": seed,
            "success_rate": confirmed / 2.0,
            "steps_to_first_confirmed": first_confirmed,
            "false_positives": false_positive,
            "false_negatives": false_negative,
            "tests_executed": sum(h.tests_executed for h in ledger.get_all().values()),
            "belief_map": ledger.get_belief_snapshot(),
        }
    finally:
        if prev is None:
            os.environ.pop("PHANTOM_SCHEDULER_MODE", None)
        else:
            os.environ["PHANTOM_SCHEDULER_MODE"] = prev


def run(seeds: int, max_steps: int) -> dict[str, Any]:
    rows = []
    for mode in MODES:
        for seed in range(seeds):
            rows.append(_simulate(mode, seed, max_steps))

    summary: dict[str, Any] = {}
    for mode in MODES:
        items = [r for r in rows if r["mode"] == mode]
        steps = [r["steps_to_first_confirmed"] for r in items if r["steps_to_first_confirmed"] is not None]
        summary[mode] = {
            "runs": len(items),
            "success_rate_mean": round(mean(r["success_rate"] for r in items), 4),
            "steps_to_first_confirmed_mean": round(mean(steps), 4) if steps else None,
            "false_positives_mean": round(mean(r["false_positives"] for r in items), 4),
            "false_negatives_mean": round(mean(r["false_negatives"] for r in items), 4),
            "tests_executed_mean": round(mean(r["tests_executed"] for r in items), 4),
        }

    return {"summary": summary, "rows": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark simplified architecture")
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--out", default="thesis_output/simplified_architecture_benchmark.json")
    args = parser.parse_args()

    report = run(args.seeds, args.max_steps)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
