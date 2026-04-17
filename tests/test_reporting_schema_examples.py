def test_reporting_schema_mentions_cwe_format_and_suspected_fast_path() -> None:
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parent.parent
        / "phantom"
        / "tools"
        / "reporting"
        / "reporting_actions_schema.xml"
    )
    schema = schema_path.read_text(encoding="utf-8")

    assert "CWE-89" in schema
    assert "confidence=SUSPECTED" in schema
    assert "https://example.com" in schema
