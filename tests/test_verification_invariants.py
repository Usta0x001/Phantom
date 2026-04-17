from types import SimpleNamespace


def _mk_response(prompt_tokens: int, completion_tokens: int, cached_tokens: int = 0):
    return SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            prompt_tokens_details=SimpleNamespace(cached_tokens=cached_tokens),
        )
    )


def test_token_accounting_invariants_hold_for_external_calls() -> None:
    from phantom.llm.llm import (
        record_external_completion_usage,
        reset_global_llm_stats,
        validate_llm_accounting_invariants,
    )

    reset_global_llm_stats()

    for _ in range(3):
        record_external_completion_usage(
            response=_mk_response(prompt_tokens=100, completion_tokens=20, cached_tokens=30),
            model_name="openai/gpt-4o-mini",
            messages=[{"role": "user", "content": "hello"}],
            estimated_tokens=90,
        )

    report = validate_llm_accounting_invariants()
    assert all(report["checks"].values())


def test_tracked_wrapper_call_count_matches_recorded_usage_events() -> None:
    from phantom.llm import tracked_completion as tc
    from phantom.llm.llm import get_usage_events, reset_global_llm_stats

    reset_global_llm_stats()
    wrapper_calls = 0

    async def _fake_acompletion(**_kwargs):
        return _mk_response(prompt_tokens=50, completion_tokens=10, cached_tokens=5)

    original = tc.litellm.acompletion
    tc.litellm.acompletion = _fake_acompletion
    try:
        import asyncio

        for _ in range(4):
            wrapper_calls += 1
            asyncio.run(
                tc.tracked_acompletion(
                    model="openai/gpt-4o-mini",
                    messages=[{"role": "user", "content": "hello"}],
                )
            )
    finally:
        tc.litellm.acompletion = original

    assert len(get_usage_events()) == wrapper_calls


def test_hypothesis_context_isolated_from_other_hypothesis_noise() -> None:
    from phantom.agents.base_agent import BaseAgent
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.agents.state import AgentState
    from phantom.llm.config import LLMConfig

    class _Agent(BaseAgent):
        agent_name = "VerifierAgent"

    state = AgentState(task="test")
    ledger = HypothesisLedger()
    h1 = ledger.add("/api/login::username", "sqli")
    h2 = ledger.add("/proxy::url", "ssrf")

    state.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": f"Working hypothesis {h1} on /api/login::username"},
        {"role": "assistant", "content": "SQLi evidence line"},
        {"role": "user", "content": f"Noise from {h2} /proxy::url ssrf chain"},
    ]

    agent = _Agent(
        {
            "state": state,
            "llm_config": LLMConfig(model_name="openai/gpt-4o-mini"),
            "hypothesis_ledger": ledger,
            "non_interactive": True,
        }
    )

    scoped = agent._build_hypothesis_context()
    joined = "\n".join(str(m.get("content", "")) for m in scoped)
    assert "/api/login::username" in joined
    assert "sqli" in joined.lower()
    assert "/proxy::url" not in joined
    assert "ssrf" not in joined.lower()


def test_safe_reduce_preserves_pinned_and_hypothesis_evidence() -> None:
    from phantom.agents.state import AgentState
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="Verifier")
    state = AgentState(task="test")
    state.finding_anchors = [
        {"text": "CRITICAL evidence for SQLi", "status": "active"},
        {"text": "obsolete", "status": "invalidated"},
    ]
    llm.set_agent_state(state)

    reduced = llm._safe_reduce_messages(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "noise"},
            {"role": "assistant", "content": "more noise"},
        ]
    )
    blob = "\n".join(str(m.get("content", "")) for m in reduced)
    assert "CRITICAL evidence for SQLi" in blob
    assert "obsolete" not in blob
    assert "<pinned_facts>" in blob


def test_large_output_hypothesis_extraction_uses_raw_path_consistently() -> None:
    import asyncio
    import os

    from phantom.tools.executor import _execute_single_tool

    class _Ledger:
        def __init__(self):
            self.items = []

        def add(self, surface, vuln_class):
            hid = f"H-{len(self.items)+1:04d}"
            self.items.append({"id": hid, "surface": surface, "vuln_class": vuln_class, "signals": []})
            return hid

        def record_payload(self, hyp_id, payload):
            for item in self.items:
                if item["id"] == hyp_id:
                    item["signals"].append(payload)

        def record_result(self, hyp_id, *_args):
            return None

    class _Owner:
        def __init__(self):
            self.hypothesis_ledger = _Ledger()
            self.coverage_tracker = None
            self.correlation_engine = None
            self.attack_graph = None

    async def _run_case(use_summarize: bool):
        old = os.environ.get("PHANTOM_USE_AUTO_SUMMARIZE")
        os.environ["PHANTOM_USE_AUTO_SUMMARIZE"] = "true" if use_summarize else "false"
        owner = _Owner()
        tool_inv = {
            "toolName": "terminal_execute",
            "args": {"command": "sqlmap -u http://target/login"},
        }

        async def _fake_exec(*_a, **_k):
            return "\n".join(["header"] + ["line"] * 17000 + ["is vulnerable"])

        from phantom.tools import executor as ex

        original = ex.execute_tool_invocation
        ex.execute_tool_invocation = _fake_exec
        try:
            await _execute_single_tool(tool_inv, None, owner, None, "agent-x", 0)
        finally:
            ex.execute_tool_invocation = original
            if old is None:
                os.environ.pop("PHANTOM_USE_AUTO_SUMMARIZE", None)
            else:
                os.environ["PHANTOM_USE_AUTO_SUMMARIZE"] = old

        return [(i["surface"], i["vuln_class"], tuple(i["signals"])) for i in owner.hypothesis_ledger.items]

    off = asyncio.run(_run_case(False))
    on = asyncio.run(_run_case(True))
    assert off == on


def test_safe_reduce_invoked_when_request_exceeds_budget() -> None:
    import asyncio

    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM

    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name="Verifier")

    called = {"count": 0}

    def _spy_reduce(messages):
        called["count"] += 1
        return messages[-2:]

    llm._safe_reduce_messages = _spy_reduce  # type: ignore[method-assign]

    async def _run():
        await llm._enforce_request_size_limits(
            [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "x" * 20000},
                {"role": "assistant", "content": "y" * 20000},
            ]
        )

    from phantom.config import Config

    old = Config.get("phantom_max_request_estimated_tokens")
    try:
        import os

        os.environ["PHANTOM_MAX_REQUEST_ESTIMATED_TOKENS"] = "10"
        try:
            asyncio.run(_run())
        except Exception:
            pass
    finally:
        import os

        if old is None:
            os.environ.pop("PHANTOM_MAX_REQUEST_ESTIMATED_TOKENS", None)
        else:
            os.environ["PHANTOM_MAX_REQUEST_ESTIMATED_TOKENS"] = old

    assert called["count"] >= 1


def test_no_archive_auto_injection_in_status_message() -> None:
    from phantom.agents.base_agent import BaseAgent
    from phantom.agents.state import AgentState
    from phantom.llm.config import LLMConfig

    class _Agent(BaseAgent):
        agent_name = "VerifierAgent"

    state = AgentState(task="test")
    agent = _Agent({"state": state, "llm_config": LLMConfig(model_name="openai/gpt-4o-mini")})

    status = {
        "scan_progress": {"phase": "TESTING", "iteration": 5, "max_iterations": 100, "percent_complete": 5.0},
        "findings": {"confirmed_vulnerabilities": 0, "actively_testing": 1, "pending_hypotheses": 2},
        "coverage": {"surfaces_tested": 2, "surfaces_remaining": 3, "coverage_percent": 40.0},
        "archived_messages": {"count": 2, "recent": ["secret-old-a", "secret-old-b"]},
        "blocked_surfaces": [],
        "top_hypotheses": [],
        "chain_opportunities": [],
        "recommended_next_action": None,
        "warnings": [],
    }

    msg = agent._format_scan_status(status)
    assert "secret-old-a" not in msg
    assert "secret-old-b" not in msg


def test_non_interactive_no_action_loop_stops_within_threshold() -> None:
    import asyncio

    from phantom.agents.base_agent import BaseAgent
    from phantom.agents.state import AgentState
    from phantom.llm.config import LLMConfig

    class _Agent(BaseAgent):
        agent_name = "VerifierAgent"

    state = AgentState(task="test", max_iterations=100)
    agent = _Agent(
        {
            "state": state,
            "llm_config": LLMConfig(model_name="openai/gpt-4o-mini"),
            "non_interactive": True,
        }
    )

    async def _fake_process_iteration(_tracer):
        agent._last_iteration_action_count = 0
        return False

    async def _fake_init(_task):
        if not state.messages:
            state.add_message("user", "start")

    agent._process_iteration = _fake_process_iteration  # type: ignore[method-assign]
    agent._initialize_sandbox_and_state = _fake_init  # type: ignore[method-assign]

    result = asyncio.run(agent.agent_loop("task"))
    assert result.get("success") is False
    assert "no-action loop" in str(result.get("error", "")).lower()
    assert state.iteration <= 8


def test_replay_determinism_for_hypothesis_context_builder() -> None:
    from phantom.agents.base_agent import BaseAgent
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.agents.state import AgentState
    from phantom.llm.config import LLMConfig

    class _Agent(BaseAgent):
        agent_name = "VerifierAgent"

    def _build_once():
        state = AgentState(task="test")
        ledger = HypothesisLedger()
        h1 = ledger.add("/api/login::username", "sqli")
        ledger.add("/proxy::url", "ssrf")
        state.messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": f"{h1} /api/login::username sqli evidence"},
            {"role": "assistant", "content": "proof"},
            {"role": "user", "content": "noise /proxy::url ssrf"},
        ]
        agent = _Agent(
            {
                "state": state,
                "llm_config": LLMConfig(model_name="openai/gpt-4o-mini"),
                "hypothesis_ledger": ledger,
                "non_interactive": True,
            }
        )
        return [dict(m) for m in agent._build_hypothesis_context()]

    first = _build_once()
    second = _build_once()
    assert first == second
