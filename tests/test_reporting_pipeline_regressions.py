from __future__ import annotations

from unittest.mock import patch


def _cvss_xml() -> str:
    return (
        "<attack_vector>N</attack_vector>"
        "<attack_complexity>L</attack_complexity>"
        "<privileges_required>N</privileges_required>"
        "<user_interaction>N</user_interaction>"
        "<scope>U</scope>"
        "<confidentiality>L</confidentiality>"
        "<integrity>L</integrity>"
        "<availability>N</availability>"
    )


def test_create_vulnerability_report_accepts_confidence_and_replay_fields() -> None:
    from phantom.telemetry.tracer import Tracer, set_global_tracer
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    tracer = Tracer("tmp-report-regression")
    set_global_tracer(tracer)

    result = create_vulnerability_report(
        title="SQL Injection in Login",
        description="Auth bypass through SQL injection",
        impact="Admin takeover",
        target="http://example.com",
        technical_analysis="Unsanitized SQL query",
        poc_description="Inject OR 1=1",
        poc_script_code="echo ok",
        remediation_steps="Use parameterized queries",
        cvss_breakdown=_cvss_xml(),
        confidence="SUSPECTED",
    )

    assert result.get("success") is True
    assert tracer.vulnerability_reports
    last = tracer.vulnerability_reports[-1]
    assert last.get("confidence") == "SUSPECTED"
    assert last.get("replay_status") in {"PENDING", "SKIPPED"}


def test_scope_rules_returns_clear_error_when_gql_unavailable(monkeypatch) -> None:
    from phantom.tools.proxy import proxy_manager

    monkeypatch.setattr(proxy_manager, "_GQL_AVAILABLE", False)
    monkeypatch.setattr(proxy_manager, "gql", None)

    mgr = proxy_manager.ProxyManager()
    result = mgr.scope_rules("list")

    assert "error" in result
    assert "gql package" in result["error"]
    assert result.get("error_type") == "dependency_unavailable"


def test_ssrf_registered_localhost_is_allowed(monkeypatch) -> None:
    from phantom.tools.proxy import proxy_manager

    # Reset allowlist for deterministic test.
    proxy_manager._ALLOWED_SSRF_HOSTS.clear()
    proxy_manager.allow_ssrf_host("localhost")

    assert proxy_manager._is_ssrf_safe("http://localhost:3000/rest/products") is True
    assert proxy_manager._is_ssrf_safe("http://127.0.0.1:3000/rest/products") is True
    assert proxy_manager._is_ssrf_safe("http://host.docker.internal:3000/rest/products") is True


def test_send_request_not_blocked_for_registered_host(monkeypatch) -> None:
    from phantom.tools.proxy.proxy_manager import ProxyManager, _ALLOWED_SSRF_HOSTS, allow_ssrf_host

    _ALLOWED_SSRF_HOSTS.clear()
    allow_ssrf_host("host.docker.internal")

    mgr = ProxyManager()
    result = mgr.send_simple_request("GET", "http://host.docker.internal:3000/")

    # We only verify SSRF gate behavior. Network/proxy may still fail.
    if "error" in result:
        assert "Blocked: URL targets a private/internal address" not in result["error"]


def test_create_vulnerability_report_fails_closed_without_tracer() -> None:
    from phantom.telemetry.tracer import set_global_tracer
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    set_global_tracer(None)

    result = create_vulnerability_report(
        title="XSS in search",
        description="Reflected XSS",
        impact="Account hijack",
        target="http://example.com",
        technical_analysis="Unsanitized reflection",
        poc_description="Inject script",
        poc_script_code="echo xss",
        remediation_steps="Escape output",
        cvss_breakdown=_cvss_xml(),
    )

    assert result.get("success") is False
    assert "not persisted" in (result.get("message") or "")


def test_dedupe_keeps_distinct_endpoint_variant() -> None:
    from phantom.telemetry.tracer import Tracer, set_global_tracer
    from phantom.tools.reporting.reporting_actions import create_vulnerability_report

    tracer = Tracer("tmp-dedupe-variant")
    set_global_tracer(tracer)

    # Existing report in a different endpoint
    tracer.add_vulnerability_report(
        title="SQLi in /api/login",
        severity="high",
        description="SQLi",
        target="http://example.com",
        endpoint="/api/login",
        method="POST",
    )

    with patch("phantom.llm.dedupe.check_duplicate") as mock_dedupe:
        mock_dedupe.return_value = {
            "is_duplicate": True,
            "duplicate_id": "vuln-0001",
            "confidence": 0.99,
            "reason": "looks similar",
        }
        result = create_vulnerability_report(
            title="SQLi in /api/search",
            description="SQLi variant",
            impact="Data exfiltration",
            target="http://example.com",
            technical_analysis="Different injectable query",
            poc_description="Inject in q",
            poc_script_code="echo sqli",
            remediation_steps="Parameterized query",
            cvss_breakdown=_cvss_xml(),
            endpoint="/api/search",
            method="GET",
        )

    assert result.get("success") is True


def test_finish_scan_fails_closed_without_tracer() -> None:
    from phantom.telemetry.tracer import set_global_tracer
    from phantom.tools.finish.finish_actions import finish_scan

    set_global_tracer(None)
    result = finish_scan(
        executive_summary="sum",
        methodology="m",
        technical_analysis="ta",
        recommendations="r",
    )

    assert result.get("success") is False
    assert result.get("scan_completed") is False
    assert result.get("error") == "tracer_unavailable"


