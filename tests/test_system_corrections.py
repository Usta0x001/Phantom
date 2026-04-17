from types import SimpleNamespace

import pytest


def test_external_completion_usage_tracks_global_stats_and_drift() -> None:
    from phantom.llm.llm import (
        get_token_drift_events,
        record_external_completion_usage,
        reset_global_llm_stats,
    )
    from phantom.telemetry.tracer import Tracer

    reset_global_llm_stats()
    tracer = Tracer(run_name="test-corrections-token")

    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=120,
            completion_tokens=30,
            prompt_tokens_details=SimpleNamespace(cached_tokens=20),
        )
    )

    record_external_completion_usage(
        response=response,
        model_name="openai/gpt-4o-mini",
        messages=[{"role": "user", "content": "x"}],
        estimated_tokens=100,
    )

    stats = tracer.get_total_llm_stats()["total"]
    assert stats["input_tokens"] == 100
    assert stats["output_tokens"] == 30
    assert stats["cached_tokens"] == 20
    assert stats["completed_requests"] == 1

    events = get_token_drift_events()
    assert events
    assert events[-1]["estimated_tokens"] == 100
    assert events[-1]["actual_prompt_tokens"] == 120
    assert events[-1]["actual_completion_tokens"] == 30
    assert events[-1]["drift"] == 20


def test_scan_status_requires_context_when_agent_not_resolvable() -> None:
    from phantom.tools.scan_status.scan_status_actions import (
        clear_scan_status_context,
        get_scan_status,
    )

    clear_scan_status_context()
    with pytest.raises(ValueError, match="scan status context missing"):
        get_scan_status(include_recommendations=False)


def test_hypothesis_scope_requires_agent_context() -> None:
    from phantom.tools.hypothesis.hypothesis_actions import (
        add_hypothesis,
        clear_hypothesis_context,
    )

    clear_hypothesis_context()
    with pytest.raises(ValueError, match="agent_id required"):
        add_hypothesis("/api/login::user", "sqli")


def test_safe_reduce_preserves_pinned_facts() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="PhantomAgent")
    state = SimpleNamespace(
        finding_anchors=[
            {"text": "Confirmed SQLi on /api/login::username", "status": "active"},
            {"text": "obsolete", "status": "invalidated"},
        ]
    )
    llm.set_agent_state(state)

    reduced = llm._safe_reduce_messages(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "noise-1"},
            {"role": "assistant", "content": "noise-2"},
        ]
    )

    joined = "\n".join(str(m.get("content", "")) for m in reduced)
    assert "<pinned_facts>" in joined
    assert "Confirmed SQLi" in joined
    assert "obsolete" not in joined
