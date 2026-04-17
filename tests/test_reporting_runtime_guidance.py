def test_proof_validation_failure_escalates_after_retries() -> None:
    from phantom.tools.reporting import reporting_actions as ra

    title = "Retry guidance proof test"

    for _ in range(3):
        result = ra.create_vulnerability_report(
            title=title,
            description="Potential SQLi",
            impact="Potential data exposure",
            target="https://example.com",
            technical_analysis="This might be vulnerable and could be exploitable.",
            poc_description="Could be exploitable with SQL payloads",
            poc_script_code="print('test')",
            cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            confidence="LIKELY",
        )

    assert result["success"] is False
    assert "Stop retrying" in result["message"]
    assert "confidence=SUSPECTED" in result["message"]
