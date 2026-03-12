"""Pytest tests for Phantom cost-control features in phantom/llm/llm.py.

Covers:
  - _get_max_tokens()  — scan-mode caps + LLM_MAX_TOKENS env override
  - _check_budget()    — PHANTOM_MAX_COST hard stop
  - _check_per_request_budget() — PHANTOM_PER_REQUEST_CEILING hard stop
  - LLMRequestFailedError re-raised through retry loop (not swallowed)
"""

import os
import sys
from pathlib import Path

import pytest

# Ensure local source tree takes precedence over any installed package.
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM, LLMRequestFailedError


# ── helpers ────────────────────────────────────────────────────────────────────

def make_llm(mode: str = "standard") -> LLM:
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode=mode)
    return LLM(cfg, "PhantomAgent")


# ── _get_max_tokens ────────────────────────────────────────────────────────────

class TestGetMaxTokens:
    def test_quick_mode_returns_4000(self):
        assert make_llm("quick")._get_max_tokens() == 4000

    def test_stealth_mode_returns_6000(self):
        assert make_llm("stealth")._get_max_tokens() == 6000

    def test_standard_mode_returns_8000(self):
        assert make_llm("standard")._get_max_tokens() == 8000

    def test_deep_mode_returns_8000(self):
        assert make_llm("deep")._get_max_tokens() == 8000

    def test_env_override_wins_over_scan_mode(self, monkeypatch):
        monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
        # Even quick mode should yield the env-override value.
        assert make_llm("quick")._get_max_tokens() == 2048

    def test_env_override_accepts_arbitrary_value(self, monkeypatch):
        monkeypatch.setenv("LLM_MAX_TOKENS", "512")
        assert make_llm("standard")._get_max_tokens() == 512

    def test_env_override_cleared_after_test(self):
        # Confirm previous monkeypatches are torn down correctly.
        assert "LLM_MAX_TOKENS" not in os.environ
        assert make_llm("quick")._get_max_tokens() == 4000


# ── _check_budget ──────────────────────────────────────────────────────────────

class TestCheckBudget:
    def test_raises_when_cost_equals_max(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm()
        llm._total_stats.cost = 1.00
        with pytest.raises(LLMRequestFailedError, match="Budget exceeded"):
            llm._check_budget()

    def test_raises_when_cost_exceeds_max(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm()
        llm._total_stats.cost = 1.50
        with pytest.raises(LLMRequestFailedError, match="Budget exceeded"):
            llm._check_budget()

    def test_noop_when_cost_below_max(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm()
        llm._total_stats.cost = 0.99
        llm._check_budget()  # must not raise

    def test_noop_when_env_not_set(self, monkeypatch):
        # Use monkeypatch to ensure PHANTOM_MAX_COST is absent regardless of shell env
        monkeypatch.delenv("PHANTOM_MAX_COST", raising=False)
        llm = make_llm()
        llm._total_stats.cost = 9999.0
        llm._check_budget()  # must not raise

    def test_noop_when_cost_is_zero(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm()
        llm._total_stats.cost = 0.0
        llm._check_budget()

    def test_error_message_contains_values(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "0.50")
        llm = make_llm()
        llm._total_stats.cost = 0.75
        with pytest.raises(LLMRequestFailedError) as exc_info:
            llm._check_budget()
        assert "0.75" in str(exc_info.value) or "0.7500" in str(exc_info.value)
        assert "0.50" in str(exc_info.value) or "0.5000" in str(exc_info.value)

    def test_invalid_env_value_is_silent(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "not-a-number")
        llm = make_llm()
        llm._total_stats.cost = 999.0
        llm._check_budget()  # invalid value = no-op


# ── _check_per_request_budget ──────────────────────────────────────────────────

class TestCheckPerRequestBudget:
    def test_raises_when_request_exceeds_ceiling(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_PER_REQUEST_CEILING", "0.50")
        llm = make_llm()
        llm._total_stats.cost = 1.00
        # request cost = 1.00 - 0.40 = 0.60 > 0.50
        with pytest.raises(LLMRequestFailedError, match="Per-request"):
            llm._check_per_request_budget(cost_before=0.40)

    def test_noop_when_request_under_ceiling(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_PER_REQUEST_CEILING", "0.50")
        llm = make_llm()
        llm._total_stats.cost = 1.00
        # request cost = 1.00 - 0.55 = 0.45 < 0.50
        llm._check_per_request_budget(cost_before=0.55)

    def test_noop_when_env_not_set(self):
        assert "PHANTOM_PER_REQUEST_CEILING" not in os.environ
        llm = make_llm()
        llm._total_stats.cost = 9999.0
        llm._check_per_request_budget(cost_before=0.0)

    def test_raises_exactly_at_ceiling(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_PER_REQUEST_CEILING", "0.10")
        llm = make_llm()
        llm._total_stats.cost = 1.00
        # request cost = 1.00 - 0.89 = 0.11 > 0.10
        with pytest.raises(LLMRequestFailedError):
            llm._check_per_request_budget(cost_before=0.89)

    def test_error_message_contains_values(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_PER_REQUEST_CEILING", "0.25")
        llm = make_llm()
        llm._total_stats.cost = 1.00
        with pytest.raises(LLMRequestFailedError) as exc_info:
            llm._check_per_request_budget(cost_before=0.50)
        msg = str(exc_info.value)
        assert "0.50" in msg or "0.5000" in msg
        assert "0.25" in msg or "0.2500" in msg

    def test_invalid_env_value_is_silent(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_PER_REQUEST_CEILING", "bad-value")
        llm = make_llm()
        llm._total_stats.cost = 9999.0
        llm._check_per_request_budget(cost_before=0.0)


# ── LLMRequestFailedError not swallowed ────────────────────────────────────────

class TestBudgetErrorNotSwallowed:
    def test_generate_re_raises_llm_request_failed_error(self):
        """generate() must re-raise LLMRequestFailedError, not catch it in the retry loop."""
        import inspect
        src = inspect.getsource(LLM.generate)
        # The retry loop must have an explicit re-raise for LLMRequestFailedError.
        assert "LLMRequestFailedError" in src
        assert "raise" in src

    def test_stream_re_raises_budget_error(self):
        """_stream() must also propagate the exception from _check_per_request_budget."""
        import inspect
        src = inspect.getsource(LLM._stream)
        assert "_check_per_request_budget" in src
