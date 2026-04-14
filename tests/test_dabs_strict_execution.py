from phantom.agents.dabs_execution_planner import plan_tool_invocation
from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.config import Config


def test_planner_builds_send_request_for_selected_hypothesis() -> None:
    selected = {
        "hypothesis_id": "H-0001",
        "surface": "/api/login::username",
        "vuln_class": "sqli",
    }
    action = plan_tool_invocation(selected, {"target_url": "http://example.local"})
    assert action is not None
    assert action["toolName"] == "send_request"
    assert action["args"]["method"] in {"GET", "POST"}
    assert action["args"]["url"].startswith("http://example.local")


def test_planner_is_deterministic_for_same_input() -> None:
    selected = {
        "hypothesis_id": "H-0002",
        "surface": "/search::q",
        "vuln_class": "xss",
    }
    ctx = {"target_url": "https://target.tld"}
    a1 = plan_tool_invocation(selected, ctx)
    a2 = plan_tool_invocation(selected, ctx)
    assert a1 == a2


def test_strict_validation_report_fields_exist() -> None:
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/test::id", "sqli")
    ledger.record_result(hyp_id, "testing", "signal")
    report = ledger.get_scheduler_report()
    validation = report.get("strict_validation")
    assert isinstance(validation, dict)
    assert validation.get("no_external_ranking") is True
    assert validation.get("no_llm_scoring_path") is True
    assert validation.get("dabs_only_selection_index") is True


def test_strict_dabs_execution_default_is_on() -> None:
    assert str(Config.get("phantom_strict_dabs_execution")).lower() == "true"
