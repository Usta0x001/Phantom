"""Tests for 0.9.60 LLM features: per-model stats, fallback model, adaptive scan,
multi-model routing, compression call counting, and call type counters.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM, LLMRequestFailedError, RequestStats


# ── helpers ────────────────────────────────────────────────────────────────────

def make_llm(mode: str = "standard", model: str = "openai/gpt-4o") -> LLM:
    cfg = LLMConfig(model_name=model, scan_mode=mode)
    return LLM(cfg, "PhantomAgent")


# ── Per-model stats ────────────────────────────────────────────────────────────

class TestPerModelStats:
    def test_per_model_stats_dict_starts_empty(self):
        llm = make_llm()
        assert llm._per_model_stats == {}

    def test_update_per_model_stats_creates_entry(self):
        llm = make_llm()
        mock_resp = MagicMock()
        mock_resp.usage.prompt_tokens = 100
        mock_resp.usage.completion_tokens = 20
        mock_resp.usage.prompt_tokens_details = None
        # Patch _extract_cost to return zero (no billing in tests)
        with patch.object(llm, "_extract_cost", return_value=0.001):
            llm._update_per_model_stats(mock_resp)

        assert "openai/gpt-4o" in llm._per_model_stats
        stats = llm._per_model_stats["openai/gpt-4o"]
        assert stats.input_tokens == 100
        assert stats.output_tokens == 20
        assert stats.requests == 1

    def test_update_per_model_stats_accumulates(self):
        llm = make_llm()
        mock_resp = MagicMock()
        mock_resp.usage.prompt_tokens = 50
        mock_resp.usage.completion_tokens = 10
        mock_resp.usage.prompt_tokens_details = None
        with patch.object(llm, "_extract_cost", return_value=0.0):
            llm._update_per_model_stats(mock_resp)
            llm._update_per_model_stats(mock_resp)

        stats = llm._per_model_stats["openai/gpt-4o"]
        assert stats.input_tokens == 100
        assert stats.output_tokens == 20
        assert stats.requests == 2

    def test_agent_calls_counter_starts_zero(self):
        llm = make_llm()
        assert llm._agent_calls == 0

    def test_error_calls_counter_starts_zero(self):
        llm = make_llm()
        assert llm._error_calls == 0


# ── Adaptive scan mode ─────────────────────────────────────────────────────────

class TestAdaptiveScanMode:
    def test_no_downgrade_when_disabled(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_ADAPTIVE_SCAN", "false")
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm("deep")
        llm._total_stats.cost = 0.99
        llm._adaptive_scan_enabled = False
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "deep"

    def test_no_downgrade_when_no_max_cost(self, monkeypatch):
        monkeypatch.delenv("PHANTOM_MAX_COST", raising=False)
        llm = make_llm("deep")
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 999.0
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "deep"

    def test_downgrade_deep_to_standard(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm("deep")
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 0.85  # 85% > 80% threshold
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "standard"

    def test_downgrade_standard_to_quick(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm("standard")
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 0.90
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "quick"

    def test_no_downgrade_below_threshold(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm("deep")
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 0.50  # 50% < 80% threshold
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "deep"

    def test_quick_is_not_downgraded_further(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_COST", "1.00")
        llm = make_llm("quick")
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 0.95
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "quick"  # No further downgrade


# ── Multi-model routing ────────────────────────────────────────────────────────

class TestRouting:
    def test_routing_disabled_returns_none(self):
        llm = make_llm()
        llm._routing_enabled = False
        result = llm._pick_routing_model([{"role": "user", "content": "hello"}])
        assert result is None

    def test_routing_picks_tool_model_for_tool_result(self):
        llm = make_llm()
        llm._routing_enabled = True
        llm._routing_tool_model = "deepseek/deepseek-chat"
        llm._routing_reasoning_model = "kimi/k2-5"
        messages = [
            {"role": "user", "content": "<tool_result>some output</tool_result>"},
        ]
        assert llm._pick_routing_model(messages) == "deepseek/deepseek-chat"

    def test_routing_picks_reasoning_model_for_plain_message(self):
        llm = make_llm()
        llm._routing_enabled = True
        llm._routing_tool_model = "deepseek/deepseek-chat"
        llm._routing_reasoning_model = "kimi/k2-5"
        messages = [
            {"role": "user", "content": "Please analyze the target application."},
        ]
        assert llm._pick_routing_model(messages) == "kimi/k2-5"

    def test_routing_returns_none_if_no_models_configured(self):
        llm = make_llm()
        llm._routing_enabled = True
        llm._routing_tool_model = None
        llm._routing_reasoning_model = None
        messages = [{"role": "user", "content": "hello"}]
        assert llm._pick_routing_model(messages) is None

    def test_routing_with_function_results_tag(self):
        llm = make_llm()
        llm._routing_enabled = True
        llm._routing_tool_model = "model-b"
        llm._routing_reasoning_model = "model-a"
        messages = [
            {"role": "user", "content": "<function_results>stdout: ok</function_results>"},
        ]
        assert llm._pick_routing_model(messages) == "model-b"


# ── Fallback model config ──────────────────────────────────────────────────────

class TestFallbackConfig:
    def test_fallback_model_none_by_default(self, monkeypatch):
        monkeypatch.delenv("PHANTOM_FALLBACK_LLM", raising=False)
        llm = make_llm()
        assert llm._fallback_llm_name is None

    def test_fallback_model_read_from_env(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_FALLBACK_LLM", "groq/llama-3.3-70b-versatile")
        llm = make_llm()
        assert llm._fallback_llm_name == "groq/llama-3.3-70b-versatile"


# ── Memory compressor compression_calls ───────────────────────────────────────

class TestCompressionCallCounting:
    def test_compression_calls_starts_at_zero(self):
        from phantom.llm.memory_compressor import MemoryCompressor
        mc = MemoryCompressor(model_name="openai/gpt-4o")
        assert mc.compression_calls == 0

    def test_compression_calls_increments_per_chunk(self, monkeypatch):
        from phantom.llm.memory_compressor import MemoryCompressor

        # Patch out the actual LLM summarization call
        def fake_summarize(messages, model, timeout=30):
            return {"role": "user", "content": "summary"}

        monkeypatch.setattr(
            "phantom.llm.memory_compressor._summarize_messages", fake_summarize
        )
        mc = MemoryCompressor(model_name="openai/gpt-4o")
        # Force threshold to be very low so compression triggers
        mc._max_total_tokens = 1  # everything exceeds 1 token

        # 23 messages → MIN_RECENT_MESSAGES(8) kept recent → 15 old msgs
        # 15 / chunk_size(5) = 3 compression calls
        msgs = [{"role": "user", "content": f"msg {i}"} for i in range(23)]
        mc.compress_history(msgs)
        assert mc.compression_calls == 3


# ── force compress increments compression_calls ───────────────────────────────

class TestForceCompressCallCounting:
    def test_force_compress_increments_compression_calls(self, monkeypatch):
        """LLM._force_compress_messages() should increment memory_compressor.compression_calls."""

        def fake_summarize(messages, model, timeout=30):
            return {"role": "user", "content": "summary"}

        monkeypatch.setattr(
            "phantom.llm.memory_compressor._summarize_messages", fake_summarize
        )
        llm = make_llm()
        # Build messages with enough non-system content to trigger compression
        messages = [{"role": "system", "content": "sys"}]
        messages += [{"role": "user", "content": f"user msg {i}"} for i in range(20)]
        messages += [{"role": "assistant", "content": f"assistant msg {i}"} for i in range(20)]

        initial = llm.memory_compressor.compression_calls
        llm._force_compress_messages(messages)
        assert llm.memory_compressor.compression_calls == initial + 1
