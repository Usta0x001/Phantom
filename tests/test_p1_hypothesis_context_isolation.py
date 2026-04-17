import pytest


def test_hypothesis_tools_are_agent_scoped_via_contextvar() -> None:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.tools.context import reset_current_agent_id, set_current_agent_id
    from phantom.tools.hypothesis.hypothesis_actions import (
        add_hypothesis,
        clear_hypothesis_context,
        get_ledger,
        query_hypotheses,
        set_ledger,
    )

    clear_hypothesis_context()
    token_a = set_current_agent_id("agent-a")
    try:
        ledger_a = HypothesisLedger()
        set_ledger(ledger_a, agent_id="agent-a")
        add_hypothesis("/api/a::id", "idor")
    finally:
        reset_current_agent_id(token_a)

    token_b = set_current_agent_id("agent-b")
    try:
        ledger_b = HypothesisLedger()
        set_ledger(ledger_b, agent_id="agent-b")
        add_hypothesis("/api/b::q", "sqli")
    finally:
        reset_current_agent_id(token_b)

    token_a2 = set_current_agent_id("agent-a")
    try:
        result_a = query_hypotheses()
        assert result_a["success"] is True
        assert result_a["count"] == 1
        assert result_a["hypotheses"][0]["surface"] == "/api/a::id"
    finally:
        reset_current_agent_id(token_a2)

    token_b2 = set_current_agent_id("agent-b")
    try:
        result_b = query_hypotheses()
        assert result_b["success"] is True
        assert result_b["count"] == 1
        assert result_b["hypotheses"][0]["surface"] == "/api/b::q"
    finally:
        reset_current_agent_id(token_b2)

    assert get_ledger("agent-a") is not None
    assert get_ledger("agent-b") is not None


def test_reporting_uses_active_agent_correlation_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    from phantom.agents.correlation_engine import CorrelationEngine
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.tools.context import reset_current_agent_id, set_current_agent_id
    from phantom.tools.hypothesis.hypothesis_actions import (
        clear_hypothesis_context,
        get_correlation_engine,
        set_correlation_engine,
        set_ledger,
    )
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    class _TracerStub:
        def __init__(self):
            self.reports = []

        def get_existing_vulnerabilities(self):
            return []

        def add_vulnerability_report(self, **kwargs):  # noqa: ANN003
            self.reports.append(kwargs)
            return f"vuln-{len(self.reports):04d}"

    clear_hypothesis_context()
    tracer = _TracerStub()
    monkeypatch.setattr("phantom.telemetry.tracer.get_global_tracer", lambda: tracer)
    monkeypatch.setattr(
        "phantom.llm.dedupe.check_duplicate",
        lambda candidate, existing: {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": "",
        },
    )

    token_a = set_current_agent_id("agent-a")
    try:
        set_ledger(HypothesisLedger(), agent_id="agent-a")
        set_correlation_engine(CorrelationEngine(), agent_id="agent-a")
        res_a = create_vulnerability_report(
            title="SQL Injection in agent a",
            description="SQL injection vulnerability",
            impact="auth bypass",
            target="https://example.com",
            technical_analysis="Sent payload union select and observed status code: 500 with SQL error.",
            poc_description="PoC replay",
            poc_script_code="print('a')",
            cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            endpoint="/api/a/login",
            method="POST",
            parameter="username",
            confidence="LIKELY",
        )
        assert res_a["success"] is True
    finally:
        reset_current_agent_id(token_a)

    token_b = set_current_agent_id("agent-b")
    try:
        set_ledger(HypothesisLedger(), agent_id="agent-b")
        set_correlation_engine(CorrelationEngine(), agent_id="agent-b")
        res_b = create_vulnerability_report(
            title="SQL Injection in agent b",
            description="SQL injection vulnerability",
            impact="auth bypass",
            target="https://example.com",
            technical_analysis="Sent payload union select and observed status code: 500 with SQL error.",
            poc_description="PoC replay",
            poc_script_code="print('b')",
            cvss_breakdown="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            endpoint="/api/b/login",
            method="POST",
            parameter="username",
            confidence="LIKELY",
        )
        assert res_b["success"] is True
    finally:
        reset_current_agent_id(token_b)

    assert get_correlation_engine("agent-a") is not None
    assert get_correlation_engine("agent-b") is not None
