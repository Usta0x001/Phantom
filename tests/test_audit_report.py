from pathlib import Path

from audit_report import compare_runs, generate_audit_report, ingest_checkpoint_artifacts, ingest_trace_ablation, write_report


def test_generate_audit_report_has_core_sections() -> None:
    report = generate_audit_report()

    assert "state_health" in report
    assert "schema_drift" in report
    assert "tool_contract" in report
    assert "scan_state" in report
    assert "learning" in report


def test_write_audit_report_creates_files(tmp_path: Path) -> None:
    json_path, md_path, report = write_report(tmp_path)

    assert json_path.exists()
    assert md_path.exists()
    assert report["tool_contract"]["registered_tools"] > 0
    assert "Phantom Audit Report" in md_path.read_text(encoding="utf-8")


def test_ingest_trace_ablation_gracefully_handles_missing_events(tmp_path: Path) -> None:
    result = ingest_trace_ablation(tmp_path)
    assert result["success"] is False
    assert result["reason"] == "events_missing"


def test_ingest_checkpoint_artifacts_gracefully_handles_missing_checkpoint(tmp_path: Path) -> None:
    result = ingest_checkpoint_artifacts(tmp_path)
    assert result["success"] is False
    assert result["reason"] == "checkpoint_missing"


def test_compare_runs_gracefully_handles_missing_artifacts(tmp_path: Path) -> None:
    report = compare_runs(tmp_path, tmp_path)
    assert "comparison" in report
    assert "trace_ingestion" in report
    assert "checkpoint_ingestion" in report
    assert "top_risks" in report
