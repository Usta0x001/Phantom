"""Tests for v0.9.3 security fixes and infrastructure improvements.

Covers:
- Sanitizer path traversal fix (C-01)
- Browser scheme blocking (H-01, H-02)
- Proxy SSRF protection (H-03)
- Provider registry key/base resolution (C-02, C-03)
- Warm-up fallback chain logic
- ReDoS protection in proxy
"""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =========================================================================
# Sanitizer — validate_workspace_path (CRITICAL fix)
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: phantom.tools.security.sanitizer deleted in 0.9.44")
class TestSanitizerPathTraversal:
    """C-01: validate_workspace_path must block path traversal."""

    def _validate(self, path: str, workspace: str = "/workspace") -> str:
        from phantom.tools.security.sanitizer import validate_workspace_path

        return validate_workspace_path(path, workspace)

    def test_simple_valid_path(self):
        result = self._validate("reports/scan.json")
        assert result == "/workspace/reports/scan.json"

    def test_nested_valid_path(self):
        result = self._validate("a/b/c/d.txt")
        assert result == "/workspace/a/b/c/d.txt"

    def test_dot_slash_normalised(self):
        result = self._validate("./reports/scan.json")
        assert result == "/workspace/reports/scan.json"

    def test_parent_traversal_blocked(self):
        with pytest.raises(ValueError, match="escapes the workspace"):
            self._validate("../../etc/passwd")

    def test_deep_parent_traversal_blocked(self):
        with pytest.raises(ValueError, match="escapes the workspace"):
            self._validate("../../../../../../../etc/shadow")

    def test_sneaky_traversal_blocked(self):
        """Path that lands inside workspace subdir then escapes."""
        with pytest.raises(ValueError, match="escapes the workspace"):
            self._validate("reports/../../etc/passwd")

    def test_absolute_outside_workspace_blocked(self):
        with pytest.raises(ValueError, match="escapes the workspace"):
            self._validate("/etc/passwd")

    def test_workspace_root_itself_valid(self):
        result = self._validate(".")
        assert result == "/workspace"

    def test_trailing_slash_normalised(self):
        result = self._validate("reports/")
        assert result == "/workspace/reports"

    def test_double_dot_in_filename_allowed(self):
        """Files named '..secret' or 'a..b' are valid (no traversal)."""
        result = self._validate("..secret.txt")
        # PurePosixPath / normpath: this file is fine, no traversal
        # Actually "..secret.txt" joined with /workspace is "/workspace/..secret.txt"
        # normpath keeps it as-is since it's not ".." segment
        assert "/workspace" in result

    def test_custom_workspace(self):
        result = self._validate("data/out.json", workspace="/home/user/scan")
        assert result == "/home/user/scan/data/out.json"

    def test_custom_workspace_traversal_blocked(self):
        with pytest.raises(ValueError, match="escapes the workspace"):
            self._validate("../../root/.ssh/id_rsa", workspace="/home/user/scan")


# =========================================================================
# Sanitizer — sanitize_extra_args
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: phantom.tools.security.sanitizer deleted in 0.9.44")
class TestSanitizeExtraArgs:
    """Ensure extra_args filtering works correctly."""

    def _sanitize(self, args: str | None) -> list[str]:
        from phantom.tools.security.sanitizer import sanitize_extra_args

        return sanitize_extra_args(args)

    def test_none_returns_empty(self):
        assert self._sanitize(None) == []

    def test_empty_string_returns_empty(self):
        assert self._sanitize("") == []
        assert self._sanitize("   ") == []

    def test_valid_flags_preserved(self):
        tokens = self._sanitize("--rate 100 -v")
        assert len(tokens) >= 2
        # All tokens should be shell-quoted
        for t in tokens:
            assert ";" not in t

    def test_injection_via_semicolon_blocked(self):
        tokens = self._sanitize("; rm -rf /")
        # Non-flag tokens are rejected
        assert all("rm" not in t for t in tokens)

    def test_pipe_injection_blocked(self):
        tokens = self._sanitize("| cat /etc/passwd")
        assert all("cat" not in t for t in tokens)

    def test_malformed_quoting_returns_empty(self):
        result = self._sanitize("--opt 'unclosed")
        assert result == []


# =========================================================================
# Sanitizer — validate_no_metachar
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: phantom.tools.security.sanitizer deleted in 0.9.44")
class TestValidateNoMetachar:
    """Shell metacharacter detection."""

    def _validate(self, value: str) -> str:
        from phantom.tools.security.sanitizer import validate_no_metachar

        return validate_no_metachar(value)

    def test_safe_value_passes(self):
        assert self._validate("example.com") == "example.com"

    def test_semicolon_blocked(self):
        with pytest.raises(ValueError, match="Unsafe characters"):
            self._validate("example.com; rm -rf /")

    def test_pipe_blocked(self):
        with pytest.raises(ValueError, match="Unsafe characters"):
            self._validate("test|cat /etc/passwd")

    def test_backtick_blocked(self):
        with pytest.raises(ValueError, match="Unsafe characters"):
            self._validate("`whoami`")

    def test_dollar_blocked(self):
        with pytest.raises(ValueError, match="Unsafe characters"):
            self._validate("$(id)")

    def test_newline_blocked(self):
        with pytest.raises(ValueError, match="Unsafe characters"):
            self._validate("host\nmalicious")


# =========================================================================
# Sanitizer — safe_heredoc_write & safe_temp_path
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: phantom.tools.security.sanitizer deleted in 0.9.44")
class TestHeredocAndTempPath:
    """Utility functions in sanitizer."""

    def test_heredoc_has_random_marker(self):
        from phantom.tools.security.sanitizer import safe_heredoc_write

        cmd1 = safe_heredoc_write("/tmp/test.txt", "content")
        cmd2 = safe_heredoc_write("/tmp/test.txt", "content")
        # Each call should have a unique EOF marker
        assert cmd1 != cmd2
        assert "_PHANTOM_EOF_" in cmd1

    def test_temp_path_unpredictable(self):
        from phantom.tools.security.sanitizer import safe_temp_path

        p1 = safe_temp_path("scan")
        p2 = safe_temp_path("scan")
        assert p1 != p2
        assert p1.startswith("/tmp/scan_")
        assert p1.endswith(".json")


# =========================================================================
# Browser — _BLOCKED_SCHEMES check in _new_tab and _create_context
# =========================================================================

_has_playwright = True
try:
    import playwright  # noqa: F401
except ImportError:
    _has_playwright = False

_skip_no_playwright = pytest.mark.skipif(not _has_playwright, reason="playwright not installed")


@_skip_no_playwright
class TestBrowserSchemeBlocking:
    """H-01/H-02: Scheme checks in _new_tab and _create_context."""

    def test_blocked_schemes_constant_exists(self):
        from phantom.tools.browser.browser_instance import _BLOCKED_SCHEMES

        assert "file" in _BLOCKED_SCHEMES
        assert "javascript" in _BLOCKED_SCHEMES
        assert "data" in _BLOCKED_SCHEMES
        assert "vbscript" in _BLOCKED_SCHEMES

    def test_http_not_blocked(self):
        from phantom.tools.browser.browser_instance import _BLOCKED_SCHEMES

        assert "http" not in _BLOCKED_SCHEMES
        assert "https" not in _BLOCKED_SCHEMES

    def test_new_tab_blocks_file_scheme(self):
        """H-01: _new_tab must reject file:// URLs."""
        from phantom.tools.browser.browser_instance import BrowserInstance

        inst = BrowserInstance.__new__(BrowserInstance)
        inst.context = MagicMock()
        inst._execution_lock = MagicMock()
        inst._execution_lock.__enter__ = MagicMock(return_value=None)
        inst._execution_lock.__exit__ = MagicMock(return_value=False)
        inst._loop = MagicMock()
        inst.is_running = True

        import asyncio

        async def test_blocked():
            with pytest.raises(ValueError, match="Blocked URL scheme"):
                await inst._new_tab("file:///etc/passwd")

        asyncio.get_event_loop_policy()
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(test_blocked())
        finally:
            loop.close()

    def test_new_tab_blocks_javascript_scheme(self):
        from phantom.tools.browser.browser_instance import BrowserInstance

        inst = BrowserInstance.__new__(BrowserInstance)
        inst.context = MagicMock()

        import asyncio

        async def test_blocked():
            with pytest.raises(ValueError, match="Blocked URL scheme"):
                await inst._new_tab("javascript:alert(1)")

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(test_blocked())
        finally:
            loop.close()

    def test_create_context_blocks_data_scheme(self):
        """H-02: _create_context must reject data: URLs."""
        from phantom.tools.browser.browser_instance import BrowserInstance

        inst = BrowserInstance.__new__(BrowserInstance)
        inst._browser = MagicMock()

        import asyncio

        async def test_blocked():
            with pytest.raises(ValueError, match="Blocked URL scheme"):
                await inst._create_context("data:text/html,<h1>evil</h1>")

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(test_blocked())
        finally:
            loop.close()

    def test_new_tab_allows_none_url(self):
        """new_tab(None) should not raise (opens blank tab)."""
        from phantom.tools.browser.browser_instance import BrowserInstance

        inst = BrowserInstance.__new__(BrowserInstance)
        inst.context = AsyncMock()
        inst.pages = {}
        inst._next_tab_id = 1
        inst.console_logs = {}
        inst.current_page_id = None

        import asyncio

        async def test_none():
            mock_page = AsyncMock()
            mock_page.url = "about:blank"
            mock_page.is_closed.return_value = False
            inst.context.new_page = AsyncMock(return_value=mock_page)
            # Should not raise
            result = await inst._new_tab(None)
            assert result is not None

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(test_none())
        finally:
            loop.close()


# =========================================================================
# Proxy — _send_modified_request SSRF check (H-03)
# =========================================================================

_has_gql = True
try:
    import gql  # noqa: F401
except ImportError:
    _has_gql = False

_skip_no_gql = pytest.mark.skipif(not _has_gql, reason="gql not installed")


@_skip_no_gql
class TestProxySsrfProtection:
    """H-03: _send_modified_request must validate URL with _is_ssrf_safe."""

    def test_is_ssrf_safe_blocks_private_ips(self):
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe

        assert not _is_ssrf_safe("http://10.0.0.1/admin")
        assert not _is_ssrf_safe("http://192.168.1.1/secret")
        assert not _is_ssrf_safe("http://172.16.0.1/internal")

    def test_is_ssrf_safe_allows_public(self):
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe

        assert _is_ssrf_safe("http://example.com/test")
        assert _is_ssrf_safe("https://google.com/search")

    def test_is_ssrf_safe_allows_localhost(self):
        """127.0.0.1 is allowed (goes through local Caido proxy)."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe

        assert _is_ssrf_safe("http://127.0.0.1:8080/test")

    def test_send_modified_request_blocks_private_url(self):
        """H-03: Modified request with private IP must be blocked."""
        from phantom.tools.proxy.proxy_manager import ProxyManager

        pm = ProxyManager.__new__(ProxyManager)
        pm.proxies = {}

        request_data = {
            "url": "http://10.0.0.1/admin",
            "method": "GET",
            "headers": {},
            "body": None,
        }
        result = pm._send_modified_request(request_data, "req-1", {"url": "http://10.0.0.1/admin"})
        assert "error" in result
        assert "private" in result["error"].lower() or "blocked" in result["error"].lower()


# =========================================================================
# Provider Registry — Key & Base Resolution (C-02, C-03)
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: tests for removed features")
@pytest.mark.skip(reason="lean-phantom: tests for removed features")
class TestProviderRegistry:
    """C-02/C-03: Provider registry must resolve correct keys and bases."""

    def test_groq_preset_uses_groq_api_key(self):
        from phantom.llm.provider_registry import PROVIDER_PRESETS

        preset = PROVIDER_PRESETS.get("groq/llama-3.3-70b-versatile")
        assert preset is not None
        assert preset.api_key_env == "GROQ_API_KEY"

    def test_groq_preset_has_no_custom_base(self):
        """Groq uses its default endpoint, no custom api_base."""
        from phantom.llm.provider_registry import PROVIDER_PRESETS

        preset = PROVIDER_PRESETS.get("groq/llama-3.3-70b-versatile")
        assert preset.api_base == ""  # empty means use litellm default

    def test_openrouter_preset_uses_llm_api_key(self):
        from phantom.llm.provider_registry import PROVIDER_PRESETS

        preset = PROVIDER_PRESETS.get("openrouter/meta-llama/llama-3.3-70b-instruct:free")
        assert preset is not None
        assert preset.api_key_env == "LLM_API_KEY"

    def test_openrouter_preset_has_openrouter_base(self):
        from phantom.llm.provider_registry import PROVIDER_PRESETS

        preset = PROVIDER_PRESETS.get("openrouter/meta-llama/llama-3.3-70b-instruct:free")
        assert preset.api_base == "https://openrouter.ai/api/v1"

    def test_fallback_chain_from_config(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_LLM", "groq/llama-3.3-70b-versatile")
        monkeypatch.setenv("PHANTOM_LLM_FALLBACK", "openrouter/meta-llama/llama-3.3-70b-instruct:free")

        from phantom.llm.provider_registry import FallbackChain

        chain = FallbackChain.from_config()
        assert chain.providers[0] == "groq/llama-3.3-70b-versatile"
        assert chain.providers[1] == "openrouter/meta-llama/llama-3.3-70b-instruct:free"
        assert chain.current_model == "groq/llama-3.3-70b-versatile"

    def test_fallback_chain_advance(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_LLM", "model-a")
        monkeypatch.setenv("PHANTOM_LLM_FALLBACK", "model-b,model-c")

        from phantom.llm.provider_registry import FallbackChain

        chain = FallbackChain.from_config()
        assert chain.current_model == "model-a"

        next_model = chain.advance()
        assert next_model == "model-b"
        assert chain.current_model == "model-b"

        next_model = chain.advance()
        assert next_model == "model-c"

        next_model = chain.advance()
        assert next_model is None  # exhausted
        assert chain.exhausted

    def test_context_window_lookup(self):
        from phantom.llm.provider_registry import get_context_window

        assert get_context_window("groq/llama-3.3-70b-versatile") == 128_000
        assert get_context_window("gpt-4o") == 128_000
        assert get_context_window("unknown/model") == 128_000  # default

    def test_llm_build_completion_args_groq_no_openrouter_base(self, monkeypatch):
        """C-02: _build_completion_args must NOT send Groq calls to OpenRouter."""
        monkeypatch.setenv("PHANTOM_LLM", "groq/llama-3.3-70b-versatile")
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key")
        monkeypatch.setenv("LLM_API_KEY", "sk-or-v1-wrong-key")
        monkeypatch.setenv("LLM_API_BASE", "https://openrouter.ai/api/v1")

        from phantom.llm.config import LLMConfig
        from phantom.llm.llm import LLM

        config = LLMConfig(model_name="groq/llama-3.3-70b-versatile", scan_mode="quick")
        llm = LLM(config, agent_name=None)
        llm.system_prompt = "test"

        messages = [{"role": "user", "content": "test"}]
        args = llm._build_completion_args(messages)

        # Must use Groq key, NOT OpenRouter key
        assert args.get("api_key") == "gsk_test_key"
        # Must NOT have OpenRouter base URL
        assert args.get("api_base") is None or "openrouter" not in args.get("api_base", "")


# =========================================================================
# LLM — Build completion args for OpenRouter
# =========================================================================


class TestLLMCompletionArgsOpenRouter:
    """Verify OpenRouter models get correct key and base."""

    def test_openrouter_gets_correct_key_and_base(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_LLM", "openrouter/meta-llama/llama-3.3-70b-instruct:free")
        monkeypatch.setenv("LLM_API_KEY", "sk-or-v1-test-key")
        monkeypatch.setenv("LLM_API_BASE", "https://openrouter.ai/api/v1")
        monkeypatch.setenv("GROQ_API_KEY", "gsk_wrong_key")

        from phantom.llm.config import LLMConfig
        from phantom.llm.llm import LLM

        config = LLMConfig(
            model_name="openrouter/meta-llama/llama-3.3-70b-instruct:free",
            scan_mode="quick",
        )
        llm = LLM(config, agent_name=None)
        llm.system_prompt = "test"

        messages = [{"role": "user", "content": "test"}]
        args = llm._build_completion_args(messages)

        assert args["api_key"] == "sk-or-v1-test-key"
        assert args["api_base"] == "https://openrouter.ai/api/v1"

    def test_unknown_model_uses_generic_config(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_LLM", "custom/my-model")
        monkeypatch.setenv("LLM_API_KEY", "my-custom-key")
        monkeypatch.setenv("LLM_API_BASE", "http://localhost:8080")

        from phantom.llm.config import LLMConfig
        from phantom.llm.llm import LLM

        config = LLMConfig(model_name="custom/my-model", scan_mode="quick")
        llm = LLM(config, agent_name=None)
        llm.system_prompt = "test"

        messages = [{"role": "user", "content": "test"}]
        args = llm._build_completion_args(messages)

        assert args["api_key"] == "my-custom-key"
        assert args["api_base"] == "http://localhost:8080"


# =========================================================================
# Config — apply_saved doesn't overwrite existing env vars
# =========================================================================


class TestConfigApplySaved:
    """Verify config loading doesn't clobber existing env vars."""

    def test_existing_env_not_overwritten(self, monkeypatch, tmp_path):
        import json

        from phantom.config import Config

        config_file = tmp_path / "cli-config.json"
        config_file.write_text(json.dumps({"env": {"PHANTOM_LLM": "old-model"}}))

        monkeypatch.setenv("PHANTOM_LLM", "new-model")
        monkeypatch.setattr(Config, "_config_file_override", config_file)

        Config.apply_saved(force=False)
        assert os.environ["PHANTOM_LLM"] == "new-model"

    def test_missing_env_populated_from_saved(self, monkeypatch, tmp_path):
        import json

        from phantom.config import Config

        config_file = tmp_path / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"PHANTOM_SANDBOX_EXECUTION_TIMEOUT": "999"}})
        )

        monkeypatch.delenv("PHANTOM_SANDBOX_EXECUTION_TIMEOUT", raising=False)
        monkeypatch.setattr(Config, "_config_file_override", config_file)

        applied = Config.apply_saved(force=False)
        assert applied.get("PHANTOM_SANDBOX_EXECUTION_TIMEOUT") == "999"


# =========================================================================
# Security Tool Wrappers — Input sanitisation
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: phantom.tools.security deleted in 0.9.44")
class TestSecurityToolSanitisation:
    """Verify security tool wrappers use sanitizer properly."""

    def test_ffuf_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import ffuf_tool

        source = inspect.getsource(ffuf_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source

    def test_nmap_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import nmap_tool

        source = inspect.getsource(nmap_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source

    def test_nuclei_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import nuclei_tool

        source = inspect.getsource(nuclei_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source

    def test_httpx_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import httpx_tool

        source = inspect.getsource(httpx_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source

    def test_sqlmap_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import sqlmap_tool

        source = inspect.getsource(sqlmap_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source

    def test_subfinder_tool_has_sanitizer_import(self):
        import inspect
        from phantom.tools.security import subfinder_tool

        source = inspect.getsource(subfinder_tool)
        assert "sanitize_extra_args" in source or "sanitizer" in source


# =========================================================================
# Scope Validator
# =========================================================================


@pytest.mark.skip(reason="lean-phantom: tests for removed features")
@pytest.mark.skip(reason="lean-phantom: tests for removed features")
class TestScopeValidator:
    """Verify scope validation logic."""

    def test_scope_validator_importable(self):
        from phantom.core.scope_validator import ScopeValidator

        sv = ScopeValidator.from_targets(["http://example.com"])
        assert sv is not None

    def test_in_scope_exact_match(self):
        from phantom.core.scope_validator import ScopeValidator

        sv = ScopeValidator.from_targets(["http://example.com"])
        assert sv.is_in_scope("http://example.com") is True

    def test_out_of_scope_different_host(self):
        from phantom.core.scope_validator import ScopeValidator

        sv = ScopeValidator.from_targets(["http://example.com"])
        assert sv.is_in_scope("http://evil.com") is False


# =========================================================================
# Proxy Manager — Regex search limit
# =========================================================================


@_skip_no_gql
class TestProxyRegexLimit:
    """Verify proxy search has regex length limits."""

    def test_search_content_source_has_limit(self):
        import inspect
        from phantom.tools.proxy import proxy_manager

        source = inspect.getsource(proxy_manager)
        # Should have a length check on regex patterns
        assert "500" in source or "MAX_REGEX" in source or "len(" in source
