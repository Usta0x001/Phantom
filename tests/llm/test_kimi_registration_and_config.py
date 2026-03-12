"""
Tests for Kimi-K2.5 litellm registration, config show improvements,
and PHANTOM_PORT_RANGE system prompt toggle.

These tests catch regressions if:
  - litellm changes its model_cost API
  - Config.tracked_vars() drops the new cost/compressor vars
  - config_show reverts to showing only saved vars
  - system_prompt.jinja loses the PORT SCAN SCOPE block
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Kimi-K2.5 is registered in litellm.model_cost with correct values
# ─────────────────────────────────────────────────────────────────────────────

class TestKimiK25LitellmRegistration:
    """Verify phantom/llm/__init__.py registers Kimi-K2.5 in litellm.model_cost."""

    def test_kimi_in_model_cost(self):
        """After importing phantom.llm, openai/Kimi-K2.5 must be in litellm.model_cost."""
        import litellm
        import phantom.llm  # noqa: F401  — triggers __init__.py registration

        assert "openai/Kimi-K2.5" in litellm.model_cost, (
            "openai/Kimi-K2.5 missing from litellm.model_cost — "
            "check phantom/llm/__init__.py _PHANTOM_EXTRA_MODELS"
        )

    def test_kimi_context_window_is_131072(self):
        """Registered context window must be 131072 (not the 128K fallback)."""
        import litellm
        import phantom.llm  # noqa: F401

        entry = litellm.model_cost["openai/Kimi-K2.5"]
        ctx = entry.get("max_input_tokens", 0)
        assert ctx == 131_072, f"Expected 131072, got {ctx}"

    def test_kimi_input_cost_per_1m_is_015(self):
        """Input cost must be $0.15/1M tokens."""
        import litellm
        import phantom.llm  # noqa: F401

        entry = litellm.model_cost["openai/Kimi-K2.5"]
        rate_per_1m = entry.get("input_cost_per_token", 0) * 1_000_000
        assert abs(rate_per_1m - 0.15) < 0.001, f"Expected $0.15/1M, got ${rate_per_1m}"

    def test_kimi_output_cost_per_1m_is_060(self):
        """Output cost must be $0.60/1M tokens."""
        import litellm
        import phantom.llm  # noqa: F401

        entry = litellm.model_cost["openai/Kimi-K2.5"]
        rate_per_1m = entry.get("output_cost_per_token", 0) * 1_000_000
        assert abs(rate_per_1m - 0.60) < 0.001, f"Expected $0.60/1M, got ${rate_per_1m}"

    def test_get_model_info_does_not_throw(self):
        """litellm.get_model_info('openai/Kimi-K2.5') must not raise an exception."""
        import litellm
        import phantom.llm  # noqa: F401

        try:
            info = litellm.get_model_info("openai/Kimi-K2.5")
            ctx = info.get("max_input_tokens") or info.get("max_tokens")
            assert ctx == 131_072, f"Expected 131072 from get_model_info, got {ctx}"
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"litellm.get_model_info raised: {exc}")

    def test_compression_threshold_uses_registry_not_fallback(self):
        """MemoryCompressor for Kimi-K2.5 must use 131072-based threshold, not 128K fallback."""
        import phantom.llm  # noqa: F401  — registers Kimi-K2.5
        from phantom.llm.memory_compressor import (
            _get_model_context_window,
            MAX_TOTAL_TOKENS,
            _CONTEXT_FILL_RATIO,
        )

        ctx_w = _get_model_context_window("openai/Kimi-K2.5")
        # Must use exact registry value, not the 128000 fallback constant
        assert ctx_w == 131_072, f"Expected 131072, got {ctx_w} (MAX_TOTAL_TOKENS={MAX_TOTAL_TOKENS})"

        threshold = int(ctx_w * _CONTEXT_FILL_RATIO * 0.9)
        # Old threshold was 10800 (20K * 0.6 * 0.9) — new must be »6x higher
        assert threshold > 60_000, (
            f"Compression threshold too low: {threshold}. "
            "Budget guard would fire prematurely on short scans."
        )

    def test_bare_kimi_name_also_registered(self):
        """Plain 'Kimi-K2.5' (no openai/ prefix) should also be in model_cost."""
        import litellm
        import phantom.llm  # noqa: F401

        assert "Kimi-K2.5" in litellm.model_cost


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: Config.tracked_vars() exposes cost + compressor variables
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigTrackedVarsCompleteness:
    """New cost and compressor vars must appear in Config.tracked_vars().

    If they're missing, phantom config show and phantom config set can't
    see or save them.
    """

    REQUIRED = [
        "PHANTOM_COST_PER_1M_INPUT",
        "PHANTOM_COST_PER_1M_OUTPUT",
        "PHANTOM_COMPRESSOR_LLM",
        "PHANTOM_COMPRESSOR_CHUNK_SIZE",
        # Previously always tracked:
        "PHANTOM_MAX_COST",
        "PHANTOM_MAX_INPUT_TOKENS",
        "PHANTOM_LLM",
        "LLM_API_KEY",
        "LLM_API_BASE",
    ]

    def test_all_required_vars_tracked(self):
        from phantom.config.config import Config
        tracked = set(Config.tracked_vars())
        missing = [v for v in self.REQUIRED if v not in tracked]
        assert not missing, (
            f"Missing from Config.tracked_vars(): {missing}\n"
            "Add them as class attributes in phantom/config/config.py"
        )

    def test_tracked_vars_count_at_least_38(self):
        """Sanity — if someone removes a bulk of vars we'll catch it."""
        from phantom.config.config import Config
        count = len(Config.tracked_vars())
        assert count >= 38, f"Expected >=38 tracked vars, got {count}"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: config_show reads env + saved + defaults (not just saved JSON)
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigShowDisplaysAllSources:
    """config_show must display env vars, saved config, and defaults — not just saved."""

    def test_config_show_source_column_in_source(self):
        """config_show implementation must have a Source column."""
        import inspect
        from phantom.interface import cli_app

        src = inspect.getsource(cli_app.config_show)
        assert '"Source"' in src or "'Source'" in src, (
            "config_show is missing the Source column — "
            "users can't tell where a value comes from"
        )

    def test_config_show_reads_os_environ(self):
        """config_show must read os.environ, not only the saved JSON."""
        import inspect
        from phantom.interface import cli_app

        src = inspect.getsource(cli_app.config_show)
        assert "os.environ" in src, (
            "config_show does not read os.environ — "
            "env-only vars (set via setx or shell) will be invisible"
        )

    def test_config_show_includes_defaults(self):
        """config_show must show vars that have built-in defaults even if not explicitly set."""
        import inspect
        from phantom.interface import cli_app

        src = inspect.getsource(cli_app.config_show)
        assert "default" in src.lower(), (
            "config_show never shows default values — "
            "users will see a blank table on fresh install"
        )

    def test_config_show_env_var_appears_in_rows(self):
        """An env var set before config_show runs must appear in the output rows."""
        import os
        from phantom.config.config import Config

        test_key = "PHANTOM_COST_PER_1M_INPUT"
        old = os.environ.get(test_key)
        os.environ[test_key] = "0.99"
        try:
            rows: dict[str, str] = {}
            for attr_name in Config._tracked_names():
                key = attr_name.upper()
                env_val = os.environ.get(key)
                default = getattr(Config, attr_name, None)
                if env_val is not None:
                    rows[key] = env_val
                elif default is not None:
                    rows[key] = default
            assert test_key in rows, f"{test_key} not found in simulated config_show rows"
            assert rows[test_key] == "0.99", f"Expected 0.99, got {rows[test_key]}"
        finally:
            if old is None:
                os.environ.pop(test_key, None)
            else:
                os.environ[test_key] = old

    def test_config_show_shows_more_than_2_rows(self):
        """On any machine, config_show must show more than 2 rows (defaults exist)."""
        import os
        from phantom.config.config import Config

        row_count = 0
        for attr_name in Config._tracked_names():
            key = attr_name.upper()
            env_val = os.environ.get(key)
            default = getattr(Config, attr_name, None)
            if env_val is not None or default is not None:
                row_count += 1
        assert row_count > 2, (
            f"config_show would only show {row_count} rows — "
            "this is the original bug; defaults must fill the table"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 (bonus): PHANTOM_PORT_RANGE injected into system prompt render
# ─────────────────────────────────────────────────────────────────────────────

class TestPortRangeSystemPromptToggle:
    """PHANTOM_PORT_RANGE env var must appear in the rendered system prompt."""

    def test_system_prompt_jinja_has_port_scan_scope(self):
        """system_prompt.jinja must contain the PORT SCAN SCOPE block."""
        prompt_path = _ROOT / "phantom" / "agents" / "PhantomAgent" / "system_prompt.jinja"
        assert prompt_path.exists(), f"system_prompt.jinja not found at {prompt_path}"
        text = prompt_path.read_text(encoding="utf-8")
        assert "PORT SCAN SCOPE" in text
        assert "top-1000" in text

    def test_system_prompt_jinja_has_port_range_conditional(self):
        """system_prompt.jinja must use phantom_port_range for conditional rendering."""
        prompt_path = _ROOT / "phantom" / "agents" / "PhantomAgent" / "system_prompt.jinja"
        text = prompt_path.read_text(encoding="utf-8")
        assert "phantom_port_range" in text, (
            "system_prompt.jinja missing phantom_port_range conditional — "
            "PHANTOM_PORT_RANGE env var override won't work"
        )

    def test_phantom_port_range_passed_to_jinja_render(self):
        """_load_system_prompt must pass phantom_port_range to the Jinja render call."""
        import inspect
        from phantom.llm.llm import LLM

        src = inspect.getsource(LLM._load_system_prompt)
        assert "phantom_port_range" in src, (
            "LLM._load_system_prompt does not pass phantom_port_range to Jinja — "
            "PHANTOM_PORT_RANGE env var will have no effect on the agent's behavior"
        )

    def test_port_range_override_in_rendered_prompt(self):
        """When PHANTOM_PORT_RANGE=8080,443 is set, rendered prompt must mention it."""
        import os
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from phantom.skills import load_skills
        from phantom.tools import get_tools_prompt

        prompt_dir = _ROOT / "phantom" / "agents" / "PhantomAgent"
        skills_dir = _ROOT / "phantom" / "skills"

        jinja_env = Environment(
            loader=FileSystemLoader([str(prompt_dir), str(skills_dir)]),
            autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        )
        skill_content = load_skills(["scan_modes/quick"])
        jinja_env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        # Render with override
        rendered = jinja_env.get_template("system_prompt.jinja").render(
            get_tools_prompt=get_tools_prompt,
            loaded_skill_names=list(skill_content.keys()),
            phantom_port_range="8080,443",
            **skill_content,
        )
        assert "8080,443" in rendered, (
            "PHANTOM_PORT_RANGE value '8080,443' not found in rendered system prompt"
        )
        assert "override" in rendered.lower() or "8080" in rendered, (
            "Port range override block not rendered correctly"
        )

    def test_default_scope_when_port_range_empty(self):
        """When PHANTOM_PORT_RANGE is not set, top-1000 default must appear."""
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from phantom.skills import load_skills
        from phantom.tools import get_tools_prompt

        prompt_dir = _ROOT / "phantom" / "agents" / "PhantomAgent"
        skills_dir = _ROOT / "phantom" / "skills"

        jinja_env = Environment(
            loader=FileSystemLoader([str(prompt_dir), str(skills_dir)]),
            autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        )
        skill_content = load_skills(["scan_modes/quick"])
        jinja_env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = jinja_env.get_template("system_prompt.jinja").render(
            get_tools_prompt=get_tools_prompt,
            loaded_skill_names=list(skill_content.keys()),
            phantom_port_range="",  # empty = use default
            **skill_content,
        )
        assert "top-1000" in rendered, (
            "Default top-1000 port scope missing when PHANTOM_PORT_RANGE is empty"
        )
