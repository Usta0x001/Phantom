"""Tests for finish_scan guard — LLM-004 fix."""

import pytest
from unittest.mock import MagicMock


class TestFinishGuard:
    """v0.9.39: finish_scan blocked before MIN_SCAN_DEPTH."""

    def _make_agent_state(self, iteration=0, actions=None, findings=None):
        state = MagicMock()
        state.iteration = iteration
        state.actions_taken = actions or []
        state.findings_ledger = findings or []
        state.agent_type = "root"
        state.agent_id = "root"
        state.parent_agent_id = None
        return state

    def test_blocked_before_min_iterations(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_FF_FINISH_GUARD", "true")
        from phantom.core.feature_flags import clear_cache
        clear_cache()

        from phantom.tools.finish.finish_actions import finish_scan
        state = self._make_agent_state(iteration=2, actions=["a"] * 10)
        result = finish_scan(
            executive_summary="test",
            methodology="test",
            technical_analysis="test",
            recommendations="test",
            agent_state=state,
        )
        assert result.get("success") is False
        assert "Cannot finish scan yet" in result.get("message", "")

        clear_cache()

    def test_allowed_after_min_iterations(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_FF_FINISH_GUARD", "true")
        from phantom.core.feature_flags import clear_cache
        clear_cache()

        from phantom.tools.finish.finish_actions import finish_scan
        state = self._make_agent_state(
            iteration=15,
            actions=["a"] * 15,
            findings=["finding"] * 5,
        )
        result = finish_scan(
            executive_summary="test summary",
            methodology="test method",
            technical_analysis="test analysis",
            recommendations="test recs",
            agent_state=state,
        )
        # Should NOT be blocked — may fail for other reasons (no tracer etc.)
        # but should NOT have the "Cannot finish scan yet" message
        if isinstance(result, dict) and result.get("success") is False:
            assert "Cannot finish scan yet" not in result.get("message", "")

        clear_cache()

    def test_early_finish_allowed_with_findings(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_FF_FINISH_GUARD", "true")
        from phantom.core.feature_flags import clear_cache
        clear_cache()

        from phantom.tools.finish.finish_actions import finish_scan
        state = self._make_agent_state(
            iteration=3,
            actions=["a"] * 10,
            findings=["sqli", "xss", "rce"],  # 3 findings
        )
        result = finish_scan(
            executive_summary="test",
            methodology="test",
            technical_analysis="test",
            recommendations="test",
            agent_state=state,
        )
        # Should NOT be blocked by iteration check — findings override
        if isinstance(result, dict) and result.get("success") is False:
            assert "Cannot finish scan yet" not in result.get("message", "")

        clear_cache()
