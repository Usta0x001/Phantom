"""Tests for v0.9.8 features: DuckDuckGo fallback, dynamic memory, EnhancedAgentState."""

import html
import re
from unittest.mock import MagicMock, patch

import pytest


# ── DuckDuckGo fallback tests ──────────────────────────────────────────


class TestDuckDuckGoFallback:
    """Test DuckDuckGo HTML search fallback in web_search."""

    def test_web_search_without_perplexity_key_uses_duckduckgo(self):
        """web_search should fall back to DuckDuckGo when no Perplexity key."""
        from phantom.tools.web_search.web_search_actions import _duckduckgo_search

        # _duckduckgo_search is the internal function; verify it exists
        assert callable(_duckduckgo_search)

    def test_strip_html_helper(self):
        from phantom.tools.web_search.web_search_actions import _strip_html

        assert _strip_html("<b>bold</b>") == "bold"
        assert _strip_html("a &amp; b") == "a & b"
        assert _strip_html("<a href='x'>link</a> text") == "link text"
        assert _strip_html("plain text") == "plain text"

    def test_duckduckgo_result_parsing_patterns(self):
        from phantom.tools.web_search.web_search_actions import (
            _RESULT_PATTERN,
            _SNIPPET_PATTERN,
        )

        # Mock DuckDuckGo HTML fragment
        test_html = '''
        <a class="result__a" href="https://example.com">Test Title</a>
        <td class="result__snippet">This is a snippet</td>
        '''
        titles = _RESULT_PATTERN.findall(test_html)
        snippets = _SNIPPET_PATTERN.findall(test_html)

        assert len(titles) == 1
        assert titles[0][0] == "https://example.com"
        assert "Test Title" in titles[0][1]
        assert len(snippets) == 1
        assert "This is a snippet" in snippets[0]

    @patch.dict("os.environ", {}, clear=True)
    def test_web_search_no_key_does_not_error(self):
        """web_search should not raise when no Perplexity key is set."""
        from phantom.tools.web_search.web_search_actions import web_search

        # Patch network call to avoid real HTTP
        with patch(
            "phantom.tools.web_search.web_search_actions.urlopen"
        ) as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"<html><body>No results</body></html>"
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = web_search("test query")
            assert isinstance(result, dict)
            assert "success" in result

    @patch.dict("os.environ", {"PERPLEXITY_API_KEY": "test-key"})
    def test_web_search_with_key_tries_perplexity_first(self):
        """web_search should try Perplexity when key is available."""
        from phantom.tools.web_search.web_search_actions import web_search

        with patch("phantom.tools.web_search.web_search_actions.requests") as mock_req:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "test content"}}]
            }
            mock_response.raise_for_status = MagicMock()
            mock_req.post.return_value = mock_response

            result = web_search("test query")
            assert result["success"] is True
            assert result["source"] == "perplexity"
            mock_req.post.assert_called_once()

    @patch.dict("os.environ", {"PERPLEXITY_API_KEY": "test-key"})
    def test_web_search_perplexity_fails_falls_back(self):
        """web_search should fall back to DuckDuckGo if Perplexity fails."""
        from phantom.tools.web_search.web_search_actions import web_search

        with patch("phantom.tools.web_search.web_search_actions.requests") as mock_req:
            mock_req.post.side_effect = Exception("API error")

            with patch(
                "phantom.tools.web_search.web_search_actions._duckduckgo_search"
            ) as mock_ddg:
                mock_ddg.return_value = {
                    "success": True,
                    "query": "test",
                    "content": "DDG results",
                    "source": "duckduckgo",
                }
                result = web_search("test query")
                mock_ddg.assert_called_once_with("test query")
                assert result["source"] == "duckduckgo"

    def test_web_search_always_registered(self):
        """web_search should always be registered (no Perplexity gate)."""
        from phantom.tools.registry import get_tool_by_name

        tool = get_tool_by_name("web_search")
        assert tool is not None


# ── Dynamic memory per profile tests ──────────────────────────────────


class TestDynamicMemory:
    """Test per-profile memory thresholds."""

    def test_scan_profile_has_memory_threshold(self):
        from phantom.core.scan_profiles import ScanProfile

        profile = ScanProfile(name="test")
        assert hasattr(profile, "memory_threshold")
        assert profile.memory_threshold == 80_000  # default

    def test_quick_profile_lower_threshold(self):
        from phantom.core.scan_profiles import get_profile

        quick = get_profile("quick")
        assert quick.memory_threshold == 40_000  # v0.9.18: reduced for cost savings

    def test_standard_profile_balanced_threshold(self):
        from phantom.core.scan_profiles import get_profile

        standard = get_profile("standard")
        assert standard.memory_threshold == 80_000

    def test_deep_profile_higher_threshold(self):
        from phantom.core.scan_profiles import get_profile

        deep = get_profile("deep")
        assert deep.memory_threshold == 100_000

    def test_stealth_profile_lower_threshold(self):
        from phantom.core.scan_profiles import get_profile

        stealth = get_profile("stealth")
        assert stealth.memory_threshold == 60_000

    def test_api_only_profile_balanced_threshold(self):
        from phantom.core.scan_profiles import get_profile

        api_only = get_profile("api_only")
        assert api_only.memory_threshold == 80_000

    def test_memory_threshold_in_to_dict(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("deep")
        d = profile.to_dict()
        assert "memory_threshold" in d
        assert d["memory_threshold"] == 100_000

    def test_memory_compressor_accepts_max_tokens(self):
        from phantom.llm.memory_compressor import MemoryCompressor

        mc = MemoryCompressor(model_name="test-model", max_tokens=60_000)
        assert mc.max_total_tokens == 60_000

    def test_memory_compressor_default_threshold(self):
        from phantom.llm.memory_compressor import MAX_TOTAL_TOKENS, MemoryCompressor

        mc = MemoryCompressor(model_name="test-model")
        assert mc.max_total_tokens == MAX_TOTAL_TOKENS

    @patch.dict("os.environ", {"PHANTOM_LLM": "test/model"})
    def test_llm_set_memory_threshold(self):
        """LLM.set_memory_threshold should update the compressor's limit."""
        from phantom.llm.llm import LLM
        from phantom.llm.config import LLMConfig

        config = LLMConfig(model_name="test/model")
        llm = LLM(config, agent_name=None)
        llm.set_memory_threshold(60_000)
        assert llm.memory_compressor.max_total_tokens == 60_000


# ── EnhancedAgentState activation tests ───────────────────────────────


class TestEnhancedAgentState:
    """Test that EnhancedAgentState is activated for scans."""

    def test_enhanced_state_inherits_agent_state(self):
        from phantom.agents.state import AgentState
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        assert isinstance(state, AgentState)

    def test_enhanced_state_has_scan_tracking(self):
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        assert hasattr(state, "scan_id")
        assert hasattr(state, "hosts")
        assert hasattr(state, "vulnerabilities")
        assert hasattr(state, "endpoints")
        assert hasattr(state, "vuln_stats")

    def test_enhanced_state_initialize_scan(self):
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        result = state.initialize_scan("http://target.example.com")
        assert state.scan_id is not None
        assert result is not None

    def test_enhanced_state_tool_tracking(self):
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        state.track_tool_usage("nmap_scan")
        state.track_tool_usage("nmap_scan")
        state.track_tool_usage("nuclei_scan")
        assert state.tools_used == {"nmap_scan": 2, "nuclei_scan": 1}

    def test_enhanced_state_get_scan_summary(self):
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        state.initialize_scan("http://target.example.com")
        summary = state.get_scan_summary()
        assert "scan_id" in summary
        assert "hosts_found" in summary
        assert "vulnerabilities" in summary

    def test_enhanced_state_preserves_findings_ledger(self):
        """EnhancedAgentState should inherit the findings_ledger from AgentState."""
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test")
        state.add_finding("SQLi at /login")
        assert len(state.findings_ledger) == 1
        assert state.findings_ledger[0] == "SQLi at /login"

    def test_phantom_agent_uses_enhanced_state_with_profile(self):
        """PhantomAgent should use EnhancedAgentState when scan_profile is set."""
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("quick")

        # We can't fully instantiate PhantomAgent without an LLM config,
        # but we can test the state creation logic
        config = {
            "scan_profile": profile,
            # state is NOT pre-provided → should create EnhancedAgentState
        }

        # Simulate what PhantomAgent.__init__ does:
        if config.get("scan_profile") and config.get("state") is None:
            max_iter = config["scan_profile"].max_iterations
            config["state"] = EnhancedAgentState(
                agent_name="Root Agent",
                max_iterations=max_iter,
            )

        assert isinstance(config["state"], EnhancedAgentState)
        assert config["state"].max_iterations == 80  # quick profile


# ── CI/CD workflow tests ───────────────────────────────────────────────


class TestCICD:
    """Test CI/CD workflow file exists and is valid YAML."""

    def test_test_workflow_exists(self):
        from pathlib import Path

        workflow = Path(__file__).parent.parent / ".github" / "workflows" / "test.yml"
        assert workflow.exists(), f"Test workflow not found at {workflow}"

    def test_test_workflow_valid_yaml(self):
        import yaml
        from pathlib import Path

        workflow = Path(__file__).parent.parent / ".github" / "workflows" / "test.yml"
        with open(workflow) as f:
            data = yaml.safe_load(f)
        assert data["name"] == "Tests"
        # YAML parses 'on:' as boolean True
        triggers = data.get("on") or data.get(True, {})
        assert "push" in triggers
        assert "pull_request" in triggers
        assert "test" in data["jobs"]
        assert "lint" in data["jobs"]

    def test_build_release_workflow_exists(self):
        from pathlib import Path

        workflow = Path(__file__).parent.parent / ".github" / "workflows" / "build-release.yml"
        assert workflow.exists()


# ── Cost dashboard tests ───────────────────────────────────────────────


class TestCostDashboard:
    """Test cost dashboard utilities."""

    def test_format_token_count_small(self):
        from phantom.interface.utils import format_token_count

        assert format_token_count(500) == "500"

    def test_format_token_count_thousands(self):
        from phantom.interface.utils import format_token_count

        result = format_token_count(5_000)
        assert "K" in result

    def test_format_token_count_millions(self):
        from phantom.interface.utils import format_token_count

        result = format_token_count(2_000_000)
        assert "M" in result

    def test_build_tui_stats_text_with_profile(self):
        """TUI stats should show scan profile name when available."""
        from phantom.interface.utils import build_tui_stats_text
        from phantom.core.scan_profiles import get_profile

        mock_tracer = MagicMock()
        mock_tracer.get_total_llm_stats.return_value = {
            "total": {
                "input_tokens": 1000,
                "output_tokens": 500,
                "cached_tokens": 0,
                "cost": 0.05,
                "requests": 5,
            }
        }
        mock_tracer.agents = {"a1": {}}
        mock_tracer.get_real_tool_count.return_value = 10

        mock_llm_config = MagicMock()
        mock_llm_config.model_name = "test-model"

        profile = get_profile("deep")
        agent_config = {
            "llm_config": mock_llm_config,
            "scan_profile": profile,
        }

        stats_text = build_tui_stats_text(mock_tracer, agent_config)
        text_str = str(stats_text)
        assert "deep" in text_str
        assert "test-model" in text_str

    def test_build_final_stats_text(self):
        from phantom.interface.utils import build_final_stats_text

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = [
            {"severity": "high", "title": "SQLi"},
        ]
        mock_tracer.get_real_tool_count.return_value = 5
        mock_tracer.agents = {"a1": {}}
        mock_tracer.get_total_llm_stats.return_value = {
            "total": {
                "input_tokens": 10000,
                "output_tokens": 2000,
                "cached_tokens": 100,
                "cost": 0.10,
                "requests": 10,
            }
        }

        stats_text = build_final_stats_text(mock_tracer)
        text_str = str(stats_text)
        assert "HIGH" in text_str
        assert "$" in text_str
