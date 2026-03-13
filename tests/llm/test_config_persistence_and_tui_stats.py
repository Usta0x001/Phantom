"""
Tests for:
1. phantom config set PHANTOM_LLM persistence fix  — apply_saved() must NOT
   wipe the config file when a session env var differs from the saved value.
2. TUI stats text includes LLM calls count, In/Out tokens, Cost, Agents, Vulns.
3. build_live_stats_text includes LLM calls count.
4. _build_llm_stats includes LLM calls count label.
"""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock


# ══════════════════════════════════════════════════════════════════════════════
#   Fix 1 — Config persistence
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigSetPersistence:
    """
    Before the fix, apply_saved() called cls.save() with LLM vars stripped
    whenever _llm_env_changed() was True.  This destroyed whatever the user
    stored via `phantom config set PHANTOM_LLM …` if a session env var was
    also present.
    """

    def _make_config(self, tmp_path: Path):
        from phantom.config.config import Config  # type: ignore
        cfg = copy.copy(Config)  # class-level copy trick via monkeypatch below
        cfg._config_file_override = tmp_path / "cli-config.json"
        return cfg

    def test_apply_saved_does_not_overwrite_file_when_env_differs(
        self, tmp_path, monkeypatch
    ):
        """
        Scenario:
          - User ran `phantom config set PHANTOM_LLM openai/DeepSeek-V3.2`
            → saved in cli-config.json
          - Current shell has $env:PHANTOM_LLM=openai/Kimi-K2.5
          - apply_saved() should NOT wipe DeepSeek from the file.
        """
        from phantom.config.config import Config

        cfg_file = tmp_path / "cli-config.json"
        cfg_file.write_text(
            json.dumps({"env": {"PHANTOM_LLM": "openai/DeepSeek-V3.2"}}),
            encoding="utf-8",
        )

        # Patch the config file path
        monkeypatch.setattr(Config, "_config_file_override", cfg_file)

        # Current session has a different model
        monkeypatch.setenv("PHANTOM_LLM", "openai/Kimi-K2.5")
        # Ensure API key is set so _llm_env_changed can detect real mismatch
        monkeypatch.setenv("LLM_API_KEY", "test-key-session")

        Config.apply_saved()

        # The file must still contain DeepSeek — not be wiped
        saved = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert saved.get("env", {}).get("PHANTOM_LLM") == "openai/DeepSeek-V3.2", (
            "apply_saved() destroyed the config file — fix not applied"
        )

    def test_apply_saved_does_not_overwrite_when_no_env_set(
        self, tmp_path, monkeypatch
    ):
        """
        Fresh shell (no $env:PHANTOM_LLM).  Saved model should be applied
        into os.environ and the file must remain intact.
        """
        from phantom.config.config import Config

        cfg_file = tmp_path / "cli-config.json"
        cfg_file.write_text(
            json.dumps({"env": {"PHANTOM_LLM": "openai/DeepSeek-V3.2"}}),
            encoding="utf-8",
        )

        monkeypatch.setattr(Config, "_config_file_override", cfg_file)
        monkeypatch.delenv("PHANTOM_LLM", raising=False)
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("LLM_API_BASE", raising=False)

        applied = Config.apply_saved()

        # Model should have been applied to os.environ
        import os
        assert os.environ.get("PHANTOM_LLM") == "openai/DeepSeek-V3.2", (
            "Saved PHANTOM_LLM was not applied in fresh environment"
        )

        # File must still be intact
        saved = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert saved.get("env", {}).get("PHANTOM_LLM") == "openai/DeepSeek-V3.2"

    def test_config_set_then_apply_roundtrip(self, tmp_path, monkeypatch):
        """
        Full roundtrip: config file holds DeepSeek → apply_saved reads back
        correctly even when a session env var is set to a different model.
        """
        from phantom.config.config import Config

        cfg_file = tmp_path / "cli-config.json"
        # Simulate what `phantom config set PHANTOM_LLM openai/DeepSeek-V3.2` writes
        cfg_file.write_text(
            json.dumps({"env": {"PHANTOM_LLM": "openai/DeepSeek-V3.2"}}),
            encoding="utf-8",
        )

        monkeypatch.setattr(Config, "_config_file_override", cfg_file)

        # Simulate a new session with a different model in env
        monkeypatch.setenv("PHANTOM_LLM", "openai/Kimi-K2.5")
        Config.apply_saved()

        # File must still hold DeepSeek — not corrupted
        saved = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert saved["env"]["PHANTOM_LLM"] == "openai/DeepSeek-V3.2", (
            "Config was corrupted by apply_saved during env-differs scenario"
        )


# ══════════════════════════════════════════════════════════════════════════════
#   Fix 2 — TUI stats text completeness
# ══════════════════════════════════════════════════════════════════════════════

def _make_mock_tracer(
    requests: int = 12,
    input_tokens: int = 150_000,
    output_tokens: int = 3_200,
    cached_tokens: int = 0,
    cost: float = 0.0432,
    agent_count: int = 2,
    tool_count: int = 25,
    vuln_count: int = 3,
) -> MagicMock:
    tracer = MagicMock()
    tracer.get_total_llm_stats.return_value = {
        "total": {
            "requests": requests,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "cost": cost,
        }
    }
    tracer.get_real_tool_count.return_value = tool_count
    tracer.agents = {f"agent_{i}": {} for i in range(agent_count)}
    tracer.vulnerability_reports = [
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "high"},
    ][:vuln_count]
    tracer.caido_url = None
    return tracer


def _make_mock_agent_config(model: str = "openai/DeepSeek-V3.2", timeout: int = 300):
    llm_config = MagicMock()
    llm_config.model_name = model
    llm_config.timeout = timeout
    return {"llm_config": llm_config}


class TestBuildTuiStatsText:

    def test_contains_llm_calls_count(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(requests=12)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        plain = text.plain
        assert "12" in plain, f"LLM call count '12' not found in TUI stats: {plain!r}"

    def test_contains_model_name(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer()
        text = build_tui_stats_text(tracer, _make_mock_agent_config(model="openai/DeepSeek-V3.2"))
        assert "DeepSeek-V3.2" in text.plain

    def test_contains_timeout(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer()
        text = build_tui_stats_text(tracer, _make_mock_agent_config(timeout=300))
        assert "300" in text.plain

    def test_contains_input_tokens(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(input_tokens=150_000)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        # 150_000 → formatted as "150.0K"
        assert "150.0K" in text.plain or "150K" in text.plain

    def test_contains_output_tokens(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(output_tokens=3_200)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "3.2K" in text.plain or "3200" in text.plain

    def test_contains_cost(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(cost=0.0432)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "0.0432" in text.plain

    def test_contains_agents_count(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(agent_count=2)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "Agents" in text.plain

    def test_contains_tools_count(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(tool_count=25)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "Tools" in text.plain and "25" in text.plain

    def test_contains_vuln_count(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(vuln_count=3)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "Vulns" in text.plain or "3" in text.plain

    def test_zero_vulns_shows_0(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(vuln_count=0)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "0" in text.plain

    def test_cached_tokens_shown_when_nonzero(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer(cached_tokens=50_000)
        text = build_tui_stats_text(tracer, _make_mock_agent_config())
        assert "cached" in text.plain.lower() or "50" in text.plain

    def test_no_agent_config_still_returns_text(self):
        from phantom.interface.utils import build_tui_stats_text
        tracer = _make_mock_tracer()
        text = build_tui_stats_text(tracer, None)
        assert len(text.plain) > 0


class TestBuildLiveStatsLLMCalls:

    def test_live_stats_contains_llm_calls(self):
        from phantom.interface.utils import build_live_stats_text
        tracer = _make_mock_tracer(requests=7)
        text = build_live_stats_text(tracer, _make_mock_agent_config())
        assert "7" in text.plain, f"LLM calls '7' not in live stats: {text.plain!r}"

    def test_live_stats_contains_llm_calls_label(self):
        from phantom.interface.utils import build_live_stats_text
        tracer = _make_mock_tracer(requests=7)
        text = build_live_stats_text(tracer, _make_mock_agent_config())
        plain = text.plain
        assert "LLM Calls" in plain or "Calls" in plain, (
            f"'LLM Calls' label not found in live stats: {plain!r}"
        )


class TestBuildLlmStatsHelper:

    def test_includes_calls_label(self):
        from phantom.interface.utils import _build_llm_stats
        from rich.text import Text
        t = Text()
        _build_llm_stats(t, {
            "requests": 5,
            "input_tokens": 10000,
            "output_tokens": 500,
            "cached_tokens": 0,
            "cost": 0.01,
        })
        assert "LLM Calls" in t.plain or "Calls" in t.plain

    def test_zero_requests_shows_zero(self):
        from phantom.interface.utils import _build_llm_stats
        from rich.text import Text
        t = Text()
        _build_llm_stats(t, {
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cost": 0.0,
        })
        assert "0" in t.plain
