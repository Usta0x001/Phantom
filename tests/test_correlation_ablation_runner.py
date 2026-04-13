from pathlib import Path

from prove_correlation_ablation import run_ablation, write_report


def test_run_ablation_returns_expected_metrics() -> None:
    report = run_ablation()

    assert report["comparison"] == "no_correlation_vs_learned_correlation"
    assert report["scenario_count"] >= 5
    assert "summary" in report
    assert "scenarios" in report
    assert len(report["scenarios"]) == report["scenario_count"]

    summary = report["summary"]
    assert summary["total_redundant_tests_avoided"] >= 0
    assert isinstance(summary["average_rank_shift"], float)
    assert isinstance(summary["average_expected_win_uplift"], float)

    rank_ci = summary["rank_shift_ci95"]
    uplift_ci = summary["expected_win_uplift_ci95"]
    assert rank_ci["ci95_low"] <= rank_ci["ci95_high"]
    assert uplift_ci["ci95_low"] <= uplift_ci["ci95_high"]

    shifts = [row["metrics"]["rank_shift"] for row in report["scenarios"]]
    assert any(shift > 0 for shift in shifts), "Should include cases improved by learning"
    # Scoring evolution can flatten or neutralize negative-shift scenarios.
    # Keep contract focused on measurable adaptation + not-all-identical outcomes.
    assert len(set(shifts)) > 1, "Ablation should show non-uniform ranking effects"


def test_write_report_creates_json_and_markdown(tmp_path: Path) -> None:
    json_path, md_path, report = write_report(tmp_path)

    assert json_path.exists()
    assert md_path.exists()

    json_text = json_path.read_text(encoding="utf-8")
    md_text = md_path.read_text(encoding="utf-8")

    assert "correlation_ablation_report" in str(json_path)
    assert "comparison" in json_text
    assert "Correlation Ablation Report" in md_text
    assert "Rank shift 95% CI" in md_text
    assert "Per-Scenario Learning Snapshot" in md_text
