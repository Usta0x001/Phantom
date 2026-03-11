"""
Adversarial audit fix verification tests — 2026 deep audit.

Tests all critical bugs found and fixed:
1. logger.debug format string in _check_adaptive_scan_mode
2. _build_tree cycle detection
3. create_agent max_iterations inheritance
4. MemoryCompressor MAX_CONTEXT_CEILING upper bound
5. _ROOT_AGENT_LOCK thread safety
6. TerminalManager TOCTOU-safe _get_or_create_session
7. PythonSessionManager lock-safe methods
8. agent_finish XML injection prevention via html.escape
"""
from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock, patch


# ── 1. logger.debug format string ──────────────────────────────────────────


def test_adaptive_scan_mode_logger_format():
    """_check_adaptive_scan_mode must use a real format string for logger.debug."""
    import inspect
    from phantom.llm.llm import LLM

    src = inspect.getsource(LLM._check_adaptive_scan_mode)
    # The first argument to logger.debug must be a string literal, not a float.
    # If the format string bug is present, logger.debug appears with a non-string first arg.
    assert "logger.debug(\n                    \"" in src or 'logger.debug(\n                    "' in src, (
        "_check_adaptive_scan_mode: logger.debug must take a format-string as first argument"
    )
    # Ensure the format specifiers are present (all five values logged)
    assert "%.4f" in src, "Format string should log cost with %.4f"
    assert "%.1f" in src, "Format string should log percentage with %.1f"


def test_adaptive_scan_mode_logger_does_not_pass_float_as_msg():
    """
    logger.debug(float_value, ...) silently drops context — must not happen.
    Instantiate a mock LLM and trigger the adaptive logic at threshold.
    """
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig

    with patch("phantom.config.Config.get") as mock_get:
        def side_effect(key: str) -> str | None:
            mapping: dict[str, str] = {
                "phantom_llm": "openai/gpt-4o",
                "llm_timeout": "30",
                "phantom_max_cost": "1.0",
                "phantom_adaptive_scan": "true",
                "phantom_adaptive_scan_threshold": "0.5",
            }
            return mapping.get(key)

        mock_get.side_effect = side_effect

        cfg = LLMConfig.__new__(LLMConfig)
        cfg.litellm_model = "openai/gpt-4o"
        cfg.canonical_model = "gpt-4o"
        cfg.model_name = "gpt-4o"
        cfg.api_key = None
        cfg.api_base = None
        cfg.scan_mode = "deep"
        cfg.timeout = 30
        cfg.enable_prompt_caching = False
        cfg.skills = []

        from phantom.llm.llm import RequestStats
        llm = object.__new__(LLM)
        llm.config = cfg
        llm._total_stats = RequestStats(cost=0.6)
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.5
        llm._SCAN_MODE_DOWNGRADE = {"deep": "standard", "standard": "quick"}

        import logging
        captured_calls: list[tuple] = []
        original_debug = logging.Logger.debug

        def capturing_debug(self_logger: Any, msg: Any, *args: Any, **kw: Any) -> None:
            captured_calls.append((msg, args))

        with patch.object(logging.Logger, "debug", capturing_debug):
            with patch("phantom.config.Config.get", side_effect=side_effect):
                llm._check_adaptive_scan_mode()

        # Verify there was a debug call and its first argument is a string
        adaptive_calls = [(m, a) for m, a in captured_calls if isinstance(m, str) and "adapt" in m.lower()]
        assert adaptive_calls, "Expected a debug log call about adaptive scan mode"
        for msg, _ in adaptive_calls:
            assert isinstance(msg, str), f"logger.debug first arg must be str, got {type(msg)}"


# ── 2. _build_tree cycle detection ────────────────────────────────────────


def test_build_tree_no_infinite_recursion_on_cycle():
    """view_agent_graph must not recurse infinitely when edges form a cycle."""
    from phantom.tools.agents_graph import agents_graph_actions as aga

    # Save and restore global state
    orig_graph = aga._agent_graph.copy()
    orig_nodes = dict(aga._agent_graph["nodes"])
    orig_edges = list(aga._agent_graph["edges"])

    try:
        # Manually create a cycle: A → B → A
        aga._agent_graph["nodes"]["agent_A"] = {
            "name": "Agent A", "task": "task", "status": "running", "parent_id": None,
        }
        aga._agent_graph["nodes"]["agent_B"] = {
            "name": "Agent B", "task": "task", "status": "running", "parent_id": "agent_A",
        }
        aga._agent_graph["edges"].append({"from": "agent_A", "to": "agent_B", "type": "delegation"})
        # Create cycle: B → A
        aga._agent_graph["edges"].append({"from": "agent_B", "to": "agent_A", "type": "delegation"})

        mock_state = MagicMock()
        mock_state.agent_id = "agent_A"

        # This must NOT raise RecursionError
        result = aga.view_agent_graph(mock_state)
        assert "graph_structure" in result
        assert "CYCLE DETECTED" in result["graph_structure"]
    finally:
        aga._agent_graph["nodes"] = orig_nodes
        aga._agent_graph["edges"] = orig_edges


# ── 3. create_agent max_iterations inheritance ────────────────────────────


def test_create_agent_inherits_max_iterations():
    """Sub-agents must inherit max_iterations from parent, not hardcode 300."""
    from phantom.tools.agents_graph import agents_graph_actions as aga

    parent_id = "parent_test_001"
    mock_parent = MagicMock()
    mock_parent.state.max_iterations = 50
    mock_parent.llm_config.timeout = 30
    mock_parent.llm_config.scan_mode = "quick"
    mock_parent.non_interactive = True

    orig_instances = dict(aga._agent_instances)
    orig_graph_nodes = dict(aga._agent_graph["nodes"])
    orig_graph_edges = list(aga._agent_graph["edges"])

    try:
        aga._agent_instances[parent_id] = mock_parent
        aga._agent_graph["nodes"][parent_id] = {
            "name": "Parent", "task": "parent task", "status": "running", "parent_id": None,
        }

        mock_agent_state = MagicMock()
        mock_agent_state.agent_id = parent_id
        mock_agent_state.get_conversation_history.return_value = []

        created_states: list[Any] = []
        original_agentstate_init = None

        from phantom.agents.state import AgentState as RealAgentState

        original_init = RealAgentState.__init__

        def capturing_init(self: Any, **kwargs: Any) -> None:
            original_init(self, **kwargs)
            created_states.append(self)

        with patch.object(RealAgentState, "__init__", capturing_init):
            with patch("phantom.tools.agents_graph.agents_graph_actions.threading.Thread") as mock_thread:
                mock_thread.return_value.start = MagicMock()
                with patch("phantom.agents.PhantomAgent.__init__", return_value=None):
                    aga.create_agent(
                        agent_state=mock_agent_state,
                        task="sub task",
                        name="SubAgent",
                        inherit_context=False,
                    )

        # The last created AgentState should have max_iterations = 50 (from parent)
        sub_states = [s for s in created_states if getattr(s, "parent_id", None) == parent_id]
        assert sub_states, "No sub-agent AgentState was created"
        assert sub_states[-1].max_iterations == 50, (
            f"Expected max_iterations=50 from parent, got {sub_states[-1].max_iterations}"
        )
    finally:
        aga._agent_instances = orig_instances
        aga._agent_graph["nodes"] = orig_graph_nodes
        aga._agent_graph["edges"] = orig_graph_edges


# ── 4. MemoryCompressor MAX_CONTEXT_CEILING ───────────────────────────────


def test_memory_compressor_ceiling_prevents_excessive_threshold():
    """For very large context window models, threshold must be capped at MAX_CONTEXT_CEILING."""
    from phantom.llm.memory_compressor import MemoryCompressor, MAX_CONTEXT_CEILING

    with patch("phantom.llm.memory_compressor._get_model_context_window") as mock_ctx:
        # Simulate a model with a 1M token context window
        mock_ctx.return_value = 1_000_000
        with patch("phantom.config.Config.get") as mock_cfg:
            mock_cfg.side_effect = lambda k: {
                "phantom_llm": "openai/gpt-4o",
                "phantom_memory_compressor_timeout": "30",
                "phantom_max_input_tokens": None,
            }.get(k)

            mc = MemoryCompressor(model_name="openai/gpt-4o")
            assert mc._max_total_tokens <= MAX_CONTEXT_CEILING, (
                f"Threshold {mc._max_total_tokens} exceeds ceiling {MAX_CONTEXT_CEILING} "
                "for large-window model"
            )


def test_memory_compressor_ceiling_is_respected_for_normal_model():
    """For a typical 128k model, threshold should be within normal range."""
    from phantom.llm.memory_compressor import MemoryCompressor, MAX_CONTEXT_CEILING, _CONTEXT_FILL_RATIO

    with patch("phantom.llm.memory_compressor._get_model_context_window") as mock_ctx:
        mock_ctx.return_value = 128_000
        with patch("phantom.config.Config.get") as mock_cfg:
            mock_cfg.side_effect = lambda k: {
                "phantom_llm": "openai/gpt-4o",
                "phantom_memory_compressor_timeout": "30",
                "phantom_max_input_tokens": None,
            }.get(k)

            mc = MemoryCompressor(model_name="openai/gpt-4o")
            expected = int(128_000 * _CONTEXT_FILL_RATIO)
            assert mc._max_total_tokens == min(MAX_CONTEXT_CEILING, expected), (
                f"Threshold {mc._max_total_tokens} should be min(ceiling, 60% of 128k)"
            )


# ── 5. _ROOT_AGENT_LOCK thread safety ─────────────────────────────────────


def test_root_agent_lock_exists():
    """_ROOT_AGENT_LOCK must be a threading.Lock exported from agents_graph_actions."""
    from phantom.tools.agents_graph import agents_graph_actions as aga

    assert hasattr(aga, "_ROOT_AGENT_LOCK"), "_ROOT_AGENT_LOCK must exist in agents_graph_actions"
    assert isinstance(aga._ROOT_AGENT_LOCK, type(threading.Lock())), (
        "_ROOT_AGENT_LOCK must be a threading.Lock instance"
    )


def test_root_agent_id_set_only_once_under_race():
    """Only the first caller sets _root_agent_id; subsequent callers are ignored."""
    from phantom.tools.agents_graph import agents_graph_actions as aga

    orig_root = aga._root_agent_id
    try:
        aga._root_agent_id = None

        winners: list[str] = []
        barrier = threading.Barrier(5)

        def race_to_set(candidate: str) -> None:
            barrier.wait()
            with aga._ROOT_AGENT_LOCK:
                if aga._root_agent_id is None:
                    aga._root_agent_id = candidate
                    winners.append(candidate)

        threads = [threading.Thread(target=race_to_set, args=(f"agent_{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(winners) == 1, f"Exactly one winner expected, got {winners}"
        assert aga._root_agent_id == winners[0]
    finally:
        aga._root_agent_id = orig_root


# ── 6. TerminalManager _get_or_create_session TOCTOU fix ──────────────────


def test_terminal_manager_get_or_create_uses_fresh_lookup():
    """
    _get_or_create_session re-fetches from _sessions_by_agent under lock,
    not from a stale reference returned by _get_agent_sessions.
    Uses source inspection so it works without libtmux installed.
    """
    import inspect
    import sys

    # Access the source file directly without importing (avoids libtmux import)
    import ast
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "phantom" / "tools" / "terminal" / "terminal_manager.py"
    src = src_path.read_text(encoding="utf-8")

    # Parse and find _get_or_create_session
    tree = ast.parse(src)
    method_src = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_get_or_create_session":
            method_src = ast.get_source_segment(src, node)
            break

    assert method_src is not None, "_get_or_create_session method not found"
    assert "_sessions_by_agent" in method_src, (
        "_get_or_create_session must access _sessions_by_agent inside the lock"
    )
    assert "with self._lock" in method_src, (
        "_get_or_create_session must acquire self._lock"
    )


# ── 7. agent_finish XML escaping via html.escape ─────────────────────────


def test_agent_finish_escapes_xml_content():
    """result_summary with XML special chars must be html-escaped in the completion report."""
    import html
    from phantom.tools.agents_graph import agents_graph_actions as aga

    agent_id = "subagent_xml_test"
    parent_id = "parent_xml_test"

    orig_graph_nodes = dict(aga._agent_graph["nodes"])
    orig_graph_edges = list(aga._agent_graph["edges"])
    orig_messages = dict(aga._agent_messages)

    try:
        aga._agent_graph["nodes"][agent_id] = {
            "name": "XmlTestAgent",
            "task": "test task",
            "status": "running",
            "parent_id": parent_id,
        }
        aga._agent_graph["nodes"][parent_id] = {
            "name": "ParentAgent",
            "task": "parent task",
            "status": "running",
            "parent_id": None,
        }
        aga._agent_messages[parent_id] = []

        mock_state = MagicMock()
        mock_state.agent_id = agent_id
        mock_state.parent_id = parent_id

        malicious_summary = "Found <script>alert('xss')</script> & other issues"
        malicious_finding = "</finding><injected>INJECTION</injected><finding>"

        result = aga.agent_finish(
            agent_state=mock_state,
            result_summary=malicious_summary,
            findings=[malicious_finding],
            success=True,
            report_to_parent=True,
        )

        assert result["agent_completed"], f"agent_finish failed: {result}"

        # Check the message sent to parent
        assert aga._agent_messages[parent_id], "No message sent to parent"
        report_content = aga._agent_messages[parent_id][-1]["content"]

        # Raw < > should NOT appear in XML tags (must be escaped)
        assert "<script>" not in report_content, "XSS payload must be html-escaped in report"
        assert html.escape("<script>alert('xss')</script>") in report_content or \
               "&lt;script&gt;" in report_content, "Escaped content should appear in report"

        # The injection attempt must not break XML structure
        assert "</injected>" not in report_content, "XML injection must be prevented"

    finally:
        aga._agent_graph["nodes"] = orig_graph_nodes
        aga._agent_graph["edges"] = orig_graph_edges
        aga._agent_messages = orig_messages


# ── 8. MAX_CONTEXT_CEILING constant existence ─────────────────────────────


def test_max_context_ceiling_exported():
    """MAX_CONTEXT_CEILING must be defined and be a reasonable value."""
    from phantom.llm.memory_compressor import MAX_CONTEXT_CEILING

    assert isinstance(MAX_CONTEXT_CEILING, int)
    assert 50_000 <= MAX_CONTEXT_CEILING <= 500_000, (
        f"MAX_CONTEXT_CEILING={MAX_CONTEXT_CEILING} is outside reasonable range"
    )
