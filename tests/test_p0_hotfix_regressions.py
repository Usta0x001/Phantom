import asyncio

from phantom.checkpoint.checkpoint import CheckpointManager
from phantom.tools.hypothesis.hypothesis_actions import (
    confirm_hypothesis,
    query_hypotheses,
    set_correlation_engine,
    set_global_ledger,
    set_ledger,
)
from phantom.tools.scan_status.scan_status_actions import get_scan_status, set_scan_status_context
from phantom.agents.correlation_engine import CorrelationEngine
from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_confirm_hypothesis_records_finding_when_engine_has_only_learning() -> None:
    ledger = HypothesisLedger()
    engine = CorrelationEngine()

    # Preload outcome-only learning so engine remains falsey by __len__.
    engine.record_outcome("sqli", "/api/login::username", "confirmed", "union")
    assert len(engine) == 0

    set_global_ledger(ledger)
    set_correlation_engine(engine)

    hyp_id = ledger.add("/api/login::username", "sqli")
    asyncio.run(confirm_hypothesis(hyp_id, "confirmed exploitation proof"))

    findings = engine.get_findings()
    assert len(findings) >= 1


def test_checkpoint_serializes_correlation_outcomes_even_when_falsey(tmp_path) -> None:
    ledger = HypothesisLedger()
    engine = CorrelationEngine()
    engine.record_outcome("sqli", "/api/login::username", "confirmed", "union")
    assert len(engine) == 0

    state = type("S", (), {})()
    state.iteration = 1
    state.task = "audit"
    state.final_result = None
    state.model_dump = lambda: {
        "messages": [],
        "sandbox_token": None,
        "sandbox_id": None,
        "sandbox_info": None,
    }

    cp = CheckpointManager.build(
        run_name="test-run",
        state=state,
        tracer=None,
        scan_config={},
        correlation_engine=engine,
        hypothesis_ledger=ledger,
    )

    assert cp.correlation_engine_state
    assert "surface_outcomes" in cp.correlation_engine_state


def test_query_hypotheses_uses_active_ledger_dict_path() -> None:
    ledger = HypothesisLedger()
    set_ledger(ledger, "default")

    ledger.add("/api/users::id", "idor")
    result = query_hypotheses(status="open")
    assert result.get("success") is True
    assert result.get("count", 0) >= 1


def test_scan_status_chain_surface_uses_finding_surface() -> None:
    ledger = HypothesisLedger()
    engine = CorrelationEngine()

    finding = engine.add_finding("sqli", "/api/login::username", details={"outcome": "confirmed"})
    assert finding.get("new_suggestions")

    state = type("S", (), {})()
    state.iteration = 10
    state.max_iterations = 100

    set_scan_status_context(
        hypothesis_ledger=ledger,
        correlation_engine=engine,
        agent_state=state,
    )
    status = get_scan_status(include_recommendations=True)
    chains = status.get("chain_opportunities") or []
    assert chains
    assert chains[0].get("surface") == "/api/login::username"
