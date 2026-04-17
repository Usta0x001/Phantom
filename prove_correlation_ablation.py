"""
Deterministic ablation runner for DABS belief-driven scheduling.

Compares:
- Baseline DABS ranking (no external correlation priors injected)
- Learned DABS ranking (same scheduler with deterministic signal injection)

Outputs:
- JSON report with raw metrics
- Markdown report with thesis-ready summary tables
"""

from __future__ import annotations

import argparse
import json
import os
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.agents.correlation_engine import CorrelationEngine
from phantom.agents.hypothesis_ledger import HypothesisLedger


@dataclass(frozen=True)
class Scenario:
    name: str
    target_hypothesis_id: str
    positive_signals: list[tuple[str, str, str]]
    negative_signals: list[tuple[str, str, str]]


RANDOM_SEED = 1337


def _build_common_ledger() -> tuple[HypothesisLedger, dict[str, str]]:
    ledger = HypothesisLedger()
    ids: dict[str, str] = {}

    ids["login_sqli"] = ledger.add("/api/login::username", "sqli")
    ids["profile_sqli"] = ledger.add("/api/profile::id", "sqli")
    ids["search_xss"] = ledger.add("/api/search::q", "xss")

    # Keep baseline evidence symmetric for sqli candidates.
    ledger.record_payload(ids["login_sqli"], "' OR 1=1--")
    ledger.record_result(ids["login_sqli"], "testing", "baseline testing signal")

    ledger.record_payload(ids["profile_sqli"], "' OR 1=1--")
    ledger.record_result(ids["profile_sqli"], "testing", "baseline testing signal")

    ledger.record_payload(ids["search_xss"], "<script>alert(1)</script>")
    ledger.record_result(ids["search_xss"], "testing", "reflected payload observed")

    return ledger, ids


def _clone_ledger(source: HypothesisLedger) -> HypothesisLedger:
    cloned = HypothesisLedger.from_dict(source.to_dict())
    assert isinstance(cloned, HypothesisLedger)
    return cloned


def _rank_map(scored: list[dict[str, Any]]) -> dict[str, int]:
    return {entry["hypothesis_id"]: idx + 1 for idx, entry in enumerate(scored)}


def _score_map(scored: list[dict[str, Any]]) -> dict[str, float]:
    return {entry["hypothesis_id"]: float(entry["priority_score"]) for entry in scored}


def _compute_expected_win_uplift(
    baseline_score: float,
    learned_score: float,
) -> float:
    # Convert score deltas into a bounded uplift proxy [-1, 1].
    denom = max(abs(baseline_score), 1.0)
    uplift = (learned_score - baseline_score) / denom
    return round(max(min(uplift, 1.0), -1.0), 4)


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1)))))
    return float(ordered[idx])


def _bootstrap_ci(values: list[float], samples: int = 2000, seed: int = RANDOM_SEED) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "ci95_low": 0.0, "ci95_high": 0.0}

    rng = random.Random(seed)
    means: list[float] = []
    n = len(values)
    for _ in range(max(50, samples)):
        draw = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(draw) / n)

    return {
        "mean": round(sum(values) / n, 4),
        "ci95_low": round(_percentile(means, 2.5), 4),
        "ci95_high": round(_percentile(means, 97.5), 4),
    }


def _run_scenario(scenario: Scenario) -> dict[str, Any]:
    base_ledger, ids = _build_common_ledger()

    prev_mode = os.environ.get("PHANTOM_SCHEDULER_MODE")
    try:
        os.environ["PHANTOM_SCHEDULER_MODE"] = "dabs"
        baseline_ledger = _clone_ledger(base_ledger)
        baseline_scored = baseline_ledger.get_scored_hypotheses()
        baseline_ranks = _rank_map(baseline_scored)
        baseline_scores = _score_map(baseline_scored)

        os.environ["PHANTOM_SCHEDULER_MODE"] = "dabs"
        learned_ledger = _clone_ledger(base_ledger)
        corr_engine = CorrelationEngine()
        learned_ledger.set_correlation_engine(corr_engine)

        for vuln_class, surface, family in scenario.positive_signals:
            corr_engine.record_outcome(
                vuln_class=vuln_class,
                surface=surface,
                outcome="confirmed",
                payload_family=family,
            )

        for vuln_class, surface, family in scenario.negative_signals:
            corr_engine.record_outcome(
                vuln_class=vuln_class,
                surface=surface,
                outcome="rejected",
                payload_family=family,
            )

        applied_positive = 0
        for vuln_class, surface, _family in scenario.positive_signals:
            hyp = learned_ledger.find_by_surface_and_class(surface, vuln_class)
            if hyp is None:
                continue
            learned_ledger.propagate_update(hyp.id, "confirmed")
            applied_positive += 1

        applied_negative = 0
        for vuln_class, surface, _family in scenario.negative_signals:
            hyp = learned_ledger.find_by_surface_and_class(surface, vuln_class)
            if hyp is None:
                continue
            learned_ledger.propagate_update(hyp.id, "rejected")
            applied_negative += 1

        learned_scored = learned_ledger.get_scored_hypotheses()
        learned_ranks = _rank_map(learned_scored)
        learned_scores = _score_map(learned_scored)
    finally:
        if prev_mode is None:
            os.environ.pop("PHANTOM_SCHEDULER_MODE", None)
        else:
            os.environ["PHANTOM_SCHEDULER_MODE"] = prev_mode

    target_id = ids[scenario.target_hypothesis_id]
    baseline_rank = int(baseline_ranks[target_id])
    learned_rank = int(learned_ranks[target_id])
    rank_shift = baseline_rank - learned_rank

    baseline_score = float(baseline_scores[target_id])
    learned_score = float(learned_scores[target_id])
    expected_uplift = _compute_expected_win_uplift(baseline_score, learned_score)

    # Approximate redundant tests avoided:
    # if target moves to rank 1 from lower rank, we avoid testing skipped higher ranks first.
    redundant_tests_avoided = max(0, baseline_rank - learned_rank)

    return {
        "scenario": scenario.name,
        "target_hypothesis_key": scenario.target_hypothesis_id,
        "target_hypothesis_id": target_id,
        "baseline": {
            "rank": baseline_rank,
            "score": baseline_score,
        },
        "learned": {
            "rank": learned_rank,
            "score": learned_score,
        },
        "metrics": {
            "rank_shift": rank_shift,
            "redundant_tests_avoided": redundant_tests_avoided,
            "expected_win_uplift": expected_uplift,
        },
        "learning_metrics": corr_engine.get_learning_metrics(top_n=3),
        "dabs_signal_application": {
            "positive_signals_applied": applied_positive,
            "negative_signals_applied": applied_negative,
        },
        "top_baseline": baseline_scored[:3],
        "top_learned": learned_scored[:3],
    }


def _scenario_pack() -> list[Scenario]:
    return [
        Scenario(
            name="sqli_login_prioritization",
            target_hypothesis_id="login_sqli",
            positive_signals=[("sqli", "/api/login::username", "union")] * 5,
            negative_signals=[("sqli", "/api/profile::id", "boolean")] * 4,
        ),
        Scenario(
            name="xss_search_prioritization",
            target_hypothesis_id="search_xss",
            positive_signals=[("xss", "/api/search::q", "script_tag")] * 4,
            negative_signals=[("sqli", "/api/profile::id", "boolean")] * 3,
        ),
        Scenario(
            name="sqli_profile_deprioritization",
            target_hypothesis_id="profile_sqli",
            positive_signals=[("sqli", "/api/login::username", "union")] * 5,
            negative_signals=[("sqli", "/api/profile::id", "boolean")] * 5,
        ),
        Scenario(
            name="mixed_signal_bias_to_login_sqli",
            target_hypothesis_id="login_sqli",
            positive_signals=[("sqli", "/api/login::username", "union")] * 3
            + [("xss", "/api/search::q", "script_tag")] * 2,
            negative_signals=[("sqli", "/api/profile::id", "boolean")] * 4,
        ),
        Scenario(
            name="xss_robustness_against_sqli_noise",
            target_hypothesis_id="search_xss",
            positive_signals=[("xss", "/api/search::q", "script_tag")] * 5,
            negative_signals=[("sqli", "/api/login::username", "union")] * 2
            + [("sqli", "/api/profile::id", "boolean")] * 2,
        ),
    ]


def run_ablation() -> dict[str, Any]:
    scenarios = [
        *_scenario_pack(),
    ]

    results = [_run_scenario(s) for s in scenarios]

    redundant_values = [float(r["metrics"]["redundant_tests_avoided"]) for r in results]
    rank_shift_values = [float(r["metrics"]["rank_shift"]) for r in results]
    expected_uplift_values = [float(r["metrics"]["expected_win_uplift"]) for r in results]

    total_redundant_avoided = int(sum(redundant_values))
    avg_rank_shift = round(sum(rank_shift_values) / len(rank_shift_values), 4)
    avg_expected_uplift = round(sum(expected_uplift_values) / len(expected_uplift_values), 4)

    rank_shift_ci = _bootstrap_ci(rank_shift_values)
    expected_uplift_ci = _bootstrap_ci(expected_uplift_values)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "comparison": "dabs_baseline_vs_dabs_with_signal_injection",
        "scenario_count": len(results),
        "summary": {
            "total_redundant_tests_avoided": total_redundant_avoided,
            "average_rank_shift": avg_rank_shift,
            "average_expected_win_uplift": avg_expected_uplift,
            "rank_shift_ci95": rank_shift_ci,
            "expected_win_uplift_ci95": expected_uplift_ci,
        },
        "scenarios": results,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    lines = []
    lines.append("# DABS Ablation Report")
    lines.append("")
    lines.append(f"Generated at: `{report['generated_at']}`")
    lines.append(f"Comparison: `{report['comparison']}`")
    lines.append("")

    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total redundant tests avoided | {summary['total_redundant_tests_avoided']} |")
    lines.append(f"| Average rank shift | {summary['average_rank_shift']} |")
    lines.append(f"| Average expected-win uplift | {summary['average_expected_win_uplift']} |")
    rank_ci = summary.get("rank_shift_ci95", {})
    uplift_ci = summary.get("expected_win_uplift_ci95", {})
    lines.append(
        "| Rank shift 95% CI | "
        f"[{rank_ci.get('ci95_low', 0.0)}, {rank_ci.get('ci95_high', 0.0)}] |"
    )
    lines.append(
        "| Expected-win uplift 95% CI | "
        f"[{uplift_ci.get('ci95_low', 0.0)}, {uplift_ci.get('ci95_high', 0.0)}] |"
    )
    lines.append("")

    lines.append("## Scenario Results")
    lines.append("")
    lines.append("| Scenario | Baseline Rank | Learned Rank | Rank Shift | Redundant Tests Avoided | Expected-Win Uplift |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in report["scenarios"]:
        m = row["metrics"]
        lines.append(
            "| "
            f"{row['scenario']} | {row['baseline']['rank']} | {row['learned']['rank']} | "
            f"{m['rank_shift']} | {m['redundant_tests_avoided']} | {m['expected_win_uplift']} |"
        )

    lines.append("")
    lines.append("## Per-Scenario Learning Snapshot")
    lines.append("")
    for row in report["scenarios"]:
        lines.append(f"### {row['scenario']}")
        lm = row.get("learning_metrics", {})
        lines.append(
            "- "
            f"Surface models: {lm.get('surface_models', 0)}, "
            f"Payload-family models: {lm.get('payload_family_models', 0)}, "
            f"Surface success rate: {lm.get('surface_success_rate', 0.0)}"
        )
        priors = lm.get("top_surface_priors", [])
        if priors:
            lines.append("- Top surface priors:")
            for prior in priors[:2]:
                lines.append(
                    "  - "
                    f"{prior.get('vuln_class')} @ {prior.get('surface')}: "
                    f"p={prior.get('posterior_success')} "
                    f"(n={prior.get('attempts')})"
                )
        else:
            lines.append("- Top surface priors: none")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- `rank_shift > 0` means the target moved earlier in the queue under DABS signal injection.")
    lines.append("- `redundant_tests_avoided` estimates how many earlier-ranked tests can be skipped before targeting the likely winner.")
    lines.append("- `expected_win_uplift` is a normalized score-delta proxy for improved expected payoff.")

    return "\n".join(lines) + "\n"


def write_report(output_dir: Path) -> tuple[Path, Path, dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)

    report = run_ablation()
    json_path = output_dir / "dabs_ablation_report.json"
    md_path = output_dir / "dabs_ablation_report.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")

    return json_path, md_path, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DABS ablation and generate thesis evidence report.")
    parser.add_argument(
        "--output-dir",
        default="thesis_output/ablation",
        help="Directory for report outputs (default: thesis_output/ablation)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    json_path, md_path, report = write_report(output_dir)

    print("DABS ablation complete")
    print(f"Scenarios: {report['scenario_count']}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    print("Summary:")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
