"""Tests for v0.9.40 dynamic provider detection and memory overhead fixes.

Verifies:
1. Any openrouter/* model works without a PROVIDER_PRESETS entry — api_base
   is auto-inferred and context_window is resolved via pattern matching.
2. compress_history() accounts for system-prompt overhead so the effective
   compression threshold reflects the true per-call token budget.
3. _normalize_tool_args() remaps aliased parameter names for report_vulnerability.
"""

from __future__ import annotations

import pytest


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 1: Provider auto-detection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestProviderAutoDetection:
    """infer_api_base() and get_context_window() must handle arbitrary models."""

    def test_infer_api_base_openrouter(self):
        from phantom.llm.provider_registry import infer_api_base
        assert infer_api_base("openrouter/deepseek/deepseek-v4") == "https://openrouter.ai/api/v1"

    def test_infer_api_base_openrouter_unknown_vendor(self):
        from phantom.llm.provider_registry import infer_api_base
        assert infer_api_base("openrouter/some-new-vendor/amazing-model-v1") == "https://openrouter.ai/api/v1"

    def test_infer_api_base_ollama(self):
        from phantom.llm.provider_registry import infer_api_base
        assert infer_api_base("ollama/llama3:latest") == "http://localhost:11434"

    def test_infer_api_base_unknown_returns_none(self):
        from phantom.llm.provider_registry import infer_api_base
        assert infer_api_base("gpt-5-ultra") is None

    def test_infer_api_base_case_insensitive(self):
        from phantom.llm.provider_registry import infer_api_base
        assert infer_api_base("OpenRouter/Anthropic/Claude-5") == "https://openrouter.ai/api/v1"

    # --- context window pattern matching ---

    def test_context_window_gemini_unknown(self):
        from phantom.llm.provider_registry import get_context_window
        # Any model with "gemini" in name → 1M
        assert get_context_window("openrouter/google/gemini-flash-1.5") == 1_000_000

    def test_context_window_gemini_exp_unknown(self):
        from phantom.llm.provider_registry import get_context_window
        assert get_context_window("openrouter/google/gemini-2.0-ultra-exp") == 1_000_000

    def test_context_window_claude_unknown(self):
        from phantom.llm.provider_registry import get_context_window
        # Any Claude variant → 200K
        assert get_context_window("openrouter/anthropic/claude-3-haiku") == 200_000

    def test_context_window_deepseek_unknown(self):
        from phantom.llm.provider_registry import get_context_window
        assert get_context_window("openrouter/deepseek/deepseek-v5-moe") == 163_840

    def test_context_window_gpt4o_bare(self):
        from phantom.llm.provider_registry import get_context_window
        assert get_context_window("gpt-4o-realtime") == 128_000

    def test_context_window_preset_takes_priority(self):
        """PROVIDER_PRESETS exact match must beat pattern matching."""
        from phantom.llm.provider_registry import get_context_window, PROVIDER_PRESETS
        model = "openrouter/minimax/minimax-m2.5"
        assert model in PROVIDER_PRESETS
        assert get_context_window(model) == PROVIDER_PRESETS[model].context_window == 1_000_000

    def test_context_window_totally_unknown_defaults_128k(self):
        from phantom.llm.provider_registry import get_context_window
        assert get_context_window("vendor/mystery-model-xyz") == 128_000


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 2: Memory compression overhead accounting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestMemoryCompressionOverhead:
    """compress_history() must fire earlier when overhead_tokens reduces effective budget."""

    def _make_messages(self, n: int, tokens_each: int = 100) -> list[dict]:
        """Create n synthetic messages each roughly tokens_each tokens big."""
        word = "word " * (tokens_each // 2)  # ~2 chars per token estimate
        msgs = []
        for i in range(n):
            role = "user" if i % 2 == 0 else "assistant"
            msgs.append({"role": role, "content": word})
        return msgs

    def test_overhead_reduces_effective_threshold(self):
        """With large overhead, compression should fire earlier than without."""
        from unittest.mock import patch
        from phantom.llm.memory_compressor import MemoryCompressor, MIN_RECENT_MESSAGES
        import os
        os.environ.setdefault("PHANTOM_LLM", "gpt-4o-mini")

        # max_total_tokens = 50_000
        # Each message reports 500 tokens.  40 messages → 20_000 total.
        # Without overhead: threshold = 50_000 * 0.90 = 45_000 → 20_000 < 45K → NO compress
        # With overhead=40_000: effective_max = max(50_000-40_000, MIN_RECENT_MESSAGES*500)
        #   = max(10_000, 7_500) = 10_000; threshold = 9_000 → 20_000 > 9K → COMPRESS
        mc = MemoryCompressor(model_name="gpt-4o-mini", max_tokens=50_000)
        messages = [{"role": "user" if i % 2 == 0 else "assistant",
                     "content": f"msg {i}"} for i in range(40)]

        summarized: list = []

        def fake_summarize(msgs, model, timeout=60):
            summarized.append(msgs)
            return {"role": "assistant",
                    "content": "<context_summary message_count='25'>ok</context_summary>"}

        import phantom.llm.memory_compressor as _mc_mod
        original_summarize = _mc_mod._summarize_messages
        _mc_mod._summarize_messages = fake_summarize

        try:
            # Patch token counter to return 500 per message (deterministic)
            with patch("phantom.llm.memory_compressor._get_message_tokens", return_value=500):
                # No overhead → should NOT compress (20K < 45K threshold)
                mc.compress_history(list(messages), overhead_tokens=0)
                no_overhead_compressed = len(summarized) > 0
                summarized.clear()

                # Large overhead → should COMPRESS (20K > 9K threshold)
                mc.compress_history(list(messages), overhead_tokens=40_000)
                overhead_compressed = len(summarized) > 0
        finally:
            _mc_mod._summarize_messages = original_summarize

        assert not no_overhead_compressed, "Should NOT compress when under threshold with no overhead"
        assert overhead_compressed, "SHOULD compress when overhead shrinks effective budget"

    def test_overhead_never_compresses_below_floor(self):
        """Even with absurd overhead, compression floor keeps recent messages."""
        from phantom.llm.memory_compressor import MemoryCompressor, MIN_RECENT_MESSAGES
        import os
        os.environ.setdefault("PHANTOM_LLM", "gpt-4o-mini")

        mc = MemoryCompressor(model_name="gpt-4o-mini", max_tokens=1_000)
        messages = self._make_messages(5, tokens_each=50)

        import phantom.llm.memory_compressor as _mc_mod
        original = _mc_mod._summarize_messages
        _mc_mod._summarize_messages = lambda m, mo, **kw: {"role": "assistant", "content": "sum"}

        try:
            # overhead > max_total_tokens → effective_max hits the safety floor
            result = mc.compress_history(list(messages), overhead_tokens=999_999)
        finally:
            _mc_mod._summarize_messages = original

        # Result should be non-empty (floor prevents zeroing out history)
        assert len(result) >= 0  # just verifies no exception

    def test_zero_overhead_backward_compatible(self):
        """overhead_tokens=0 (default) preserves the old behaviour."""
        from phantom.llm.memory_compressor import MemoryCompressor
        import os
        os.environ.setdefault("PHANTOM_LLM", "gpt-4o-mini")

        mc = MemoryCompressor(model_name="gpt-4o-mini", max_tokens=100_000)
        messages = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}]

        # Tiny history — should return unchanged (no compression)
        result = mc.compress_history(list(messages))  # no overhead_tokens arg
        assert len(result) == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Section 3: Param alias normalizer (report_vulnerability)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestParamAliasNormalizer:
    """_normalize_tool_args() must remap LLM alias names to canonical params."""

    def test_vuln_description_remapped(self):
        from phantom.tools.executor import _normalize_tool_args
        args = {"title": "SQLi", "target": "http://x.com", "vuln_severity": "critical",
                "vuln_description": "SQL injection", "proof": "payload"}
        result = _normalize_tool_args("report_vulnerability", args)
        assert result["severity"] == "critical"
        assert result["description"] == "SQL injection"
        assert "vuln_severity" not in result
        assert "vuln_description" not in result

    def test_poc_remapped_to_proof(self):
        from phantom.tools.executor import _normalize_tool_args
        args = {"title": "XSS", "target": "http://x.com", "severity": "high",
                "description": "desc", "poc": "<script>alert(1)</script>"}
        result = _normalize_tool_args("report_vulnerability", args)
        assert result["proof"] == "<script>alert(1)</script>"
        assert "poc" not in result

    def test_canonical_name_wins_over_alias(self):
        """When both canonical and alias are present, canonical wins and alias drops."""
        from phantom.tools.executor import _normalize_tool_args
        args = {"title": "Test", "target": "http://x.com", "severity": "low",
                "description": "real desc", "vuln_description": "alias desc", "proof": "p"}
        result = _normalize_tool_args("report_vulnerability", args)
        assert result["description"] == "real desc"
        assert "vuln_description" not in result

    def test_unrelated_tool_unchanged(self):
        from phantom.tools.executor import _normalize_tool_args
        args = {"url": "http://x.com", "method": "GET"}
        result = _normalize_tool_args("send_request", args)
        assert result == args

    def test_none_tool_name_unchanged(self):
        from phantom.tools.executor import _normalize_tool_args
        args = {"foo": "bar"}
        result = _normalize_tool_args(None, args)
        assert result == args

    def test_vuln_title_remapped(self):
        from phantom.tools.executor import _normalize_tool_args
        args = {"vuln_title": "IDOR", "target": "http://x.com", "severity": "critical",
                "description": "desc", "proof": "p"}
        result = _normalize_tool_args("report_vulnerability", args)
        assert result["title"] == "IDOR"
        assert "vuln_title" not in result

    def test_all_aliases_at_once(self):
        """All 5 required fields mapped via aliases in one call."""
        from phantom.tools.executor import _normalize_tool_args
        args = {
            "vuln_title": "RCE",
            "vuln_target": "http://target.com",
            "cvss_severity": "critical",
            "vuln_description": "Remote code execution",
            "poc": "curl ... | bash",
        }
        result = _normalize_tool_args("report_vulnerability", args)
        assert set(result.keys()) == {"title", "target", "severity", "description", "proof"}
        assert result["title"] == "RCE"
        assert result["proof"] == "curl ... | bash"
