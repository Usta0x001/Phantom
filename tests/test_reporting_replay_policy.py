import pytest


def test_suspected_reports_skip_background_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    class _TracerStub:
        def get_existing_vulnerabilities(self) -> list[dict]:
            return []

        def add_vulnerability_report(self, **kwargs):  # noqa: ANN003
            return "vuln-0001"

    monkeypatch.setattr("phantom.telemetry.tracer.get_global_tracer", lambda: _TracerStub())
    monkeypatch.setattr(
        "phantom.llm.dedupe.check_duplicate",
        lambda candidate, existing: {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": "",
        },
    )

    result = create_vulnerability_report(
        title="SUSPECTED replay policy",
        description="Potential sensitive error disclosure",
        impact="Aids attacker reconnaissance",
        target="https://example.com",
        technical_analysis=(
            "Sent GET /api/invalid and observed HTTP 500 with stack trace path disclosure in response body."
        ),
        poc_script_code="curl -v https://example.com/api/invalid",
        severity="MEDIUM",
        confidence="SUSPECTED",
    )

    assert result["success"] is True
    assert result["replay_status"] == "SKIPPED"
