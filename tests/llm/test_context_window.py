"""Tests for model-aware compression threshold and context-too-large recovery."""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _get_model_context_window,
    MAX_TOTAL_TOKENS,
    MIN_RECENT_MESSAGES,
    _CONTEXT_FILL_RATIO,
)
from phantom.llm.config import LLMConfig
from phantom.llm.llm import LLM


# ── _get_model_context_window ──────────────────────────────────────────────────

class TestGetModelContextWindow:
    def test_returns_max_input_tokens_when_available(self):
        with patch("litellm.get_model_info", return_value={"max_input_tokens": 8000}):
            assert _get_model_context_window("kimi-k2.5") == 8000

    def test_falls_back_to_max_tokens(self):
        with patch("litellm.get_model_info", return_value={"max_tokens": 16000}):
            assert _get_model_context_window("some-model") == 16000

    def test_max_input_tokens_takes_priority_over_max_tokens(self):
        with patch("litellm.get_model_info", return_value={
            "max_input_tokens": 8000, "max_tokens": 128000
        }):
            assert _get_model_context_window("some-model") == 8000

    def test_returns_default_when_model_info_unavailable(self):
        with patch("litellm.get_model_info", side_effect=Exception("no info")):
            assert _get_model_context_window("unknown-model") == MAX_TOTAL_TOKENS

    def test_returns_default_on_empty_info(self):
        with patch("litellm.get_model_info", return_value={}):
            assert _get_model_context_window("some-model") == MAX_TOTAL_TOKENS

    def test_returns_default_on_zero_value(self):
        with patch("litellm.get_model_info", return_value={"max_input_tokens": 0}):
            assert _get_model_context_window("some-model") == MAX_TOTAL_TOKENS


# ── MemoryCompressor._max_total_tokens ────────────────────────────────────────

class TestMemoryCompressorContextAware:
    def test_kimi_8k_model_gets_small_threshold(self):
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=8000):
            mc = MemoryCompressor(model_name="moonshot/kimi-k2.5")
        expected = int(8000 * _CONTEXT_FILL_RATIO)
        assert mc._max_total_tokens == expected

    def test_gpt4o_128k_gets_large_threshold(self):
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=128000):
            mc = MemoryCompressor(model_name="openai/gpt-4o")
        expected = int(128000 * _CONTEXT_FILL_RATIO)
        assert mc._max_total_tokens == expected

    def test_unknown_model_falls_back_to_default(self):
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=MAX_TOTAL_TOKENS):
            mc = MemoryCompressor(model_name="openai/gpt-4o")
        expected = int(MAX_TOTAL_TOKENS * _CONTEXT_FILL_RATIO)
        assert mc._max_total_tokens == expected

    def test_phantom_max_input_tokens_env_overrides_model_info(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_MAX_INPUT_TOKENS", "5000")
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=128000):
            mc = MemoryCompressor(model_name="openai/gpt-4o")
        assert mc._max_total_tokens == 5000

    def test_threshold_never_below_minimum(self):
        # Even a 100-token context should not compress down to 0
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=100):
            mc = MemoryCompressor(model_name="tiny-model")
        assert mc._max_total_tokens >= MIN_RECENT_MESSAGES * 200

    def test_compresses_when_context_near_model_limit(self):
        """With kimi-k2.5 @ 8k, messages exceeding the threshold should be compressed."""
        with patch("phantom.llm.memory_compressor._get_model_context_window", return_value=8000):
            mc = MemoryCompressor(model_name="moonshot/kimi-k2.5")

        # threshold = int(8000 * 0.6) = 4800, trigger at 4800 * 0.9 = 4320 tokens.
        # Patch token counter so each message reports 200 tokens → 60 msgs = 12k > 4320.
        msgs = [
            {"role": "user" if i % 2 == 0 else "assistant", "content": f"msg {i}"}
            for i in range(60)
        ]

        with patch("phantom.llm.memory_compressor._get_message_tokens", return_value=200), \
             patch("phantom.llm.memory_compressor._summarize_messages",
                   return_value={"role": "user", "content": "<context_summary>summary</context_summary>"}):
            result = mc.compress_history(list(msgs))

        assert len(result) < len(msgs)


# ── LLM._is_context_too_large ──────────────────────────────────────────────────

class TestIsContextTooLarge:
    def make_llm(self):
        cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
        return LLM(cfg, "PhantomAgent")

    def test_detects_kimi_error(self):
        llm = self.make_llm()
        e = Exception("litellm.APIError: Request body too large for kimi-k2.5 model. Max size: 8000 tokens.")
        assert llm._is_context_too_large(e)

    def test_detects_openai_context_length_exceeded(self):
        llm = self.make_llm()
        e = Exception("context_length_exceeded: This model's maximum context length is 8192 tokens.")
        assert llm._is_context_too_large(e)

    def test_detects_anthropic_too_long(self):
        llm = self.make_llm()
        e = Exception("Input is too long for the requested model")
        assert llm._is_context_too_large(e)

    def test_detects_reduce_length_message(self):
        llm = self.make_llm()
        e = Exception("Please reduce the length of the messages or completion.")
        assert llm._is_context_too_large(e)

    def test_does_not_trigger_on_regular_error(self):
        llm = self.make_llm()
        e = Exception("Connection timeout after 30s")
        assert not llm._is_context_too_large(e)

    def test_does_not_trigger_on_auth_error(self):
        llm = self.make_llm()
        e = Exception("AuthenticationError: Invalid API key")
        assert not llm._is_context_too_large(e)


# ── LLM._force_compress_messages ──────────────────────────────────────────────

class TestForceCompressMessages:
    def make_llm(self):
        cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
        return LLM(cfg, "PhantomAgent")

    def test_shrinks_message_list(self):
        import asyncio
        llm = self.make_llm()
        messages = [
            {"role": "system", "content": "sys"},
        ] + [
            {"role": "user" if i % 2 == 0 else "assistant", "content": f"msg {i}"}
            for i in range(20)
        ]
        with patch("phantom.llm.memory_compressor._summarize_messages",
                   return_value={"role": "user", "content": "<context_summary>summary</context_summary>"}):
            result = asyncio.run(llm._force_compress_messages(messages))
        # Must end up shorter than original
        assert len(result) < len(messages)

    def test_preserves_system_messages(self):
        import asyncio
        llm = self.make_llm()
        messages = [{"role": "system", "content": "SYSTEM"}] + [
            {"role": "user", "content": f"msg {i}"} for i in range(20)
        ]
        with patch("phantom.llm.memory_compressor._summarize_messages",
                   return_value={"role": "user", "content": "summary"}):
            result = asyncio.run(llm._force_compress_messages(messages))
        assert result[0]["role"] == "system"
        assert result[0]["content"] == "SYSTEM"

    def test_keeps_minimum_recent_messages(self):
        import asyncio
        llm = self.make_llm()
        # Only MIN_RECENT_MESSAGES messages — nothing to compress
        messages = [
            {"role": "user" if i % 2 == 0 else "assistant", "content": f"msg {i}"}
            for i in range(MIN_RECENT_MESSAGES)
        ]
        result = asyncio.run(llm._force_compress_messages(messages))
        # Should not crash and should return at least the minimum tail
        assert len(result) >= 1
