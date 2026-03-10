"""Tests for tool-name prefix normalisation (0.9.59).

Some LLMs (e.g. kimi-k2.5) read the XML section headers in get_tools_prompt()
and call tools with a module prefix like "proxy_tools.scope_rules" instead of
just "scope_rules".

Two-layer fix:
1. execute_tool_with_validation() strips module prefix before lookup.
2. get_tools_prompt() uses XML comments for section headers (not wrapper tags).
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phantom.tools.executor import execute_tool_with_validation, validate_tool_availability
from phantom.tools.registry import get_tools_prompt


# ── validate_tool_availability — baseline behaviour ───────────────────────────

class TestValidateToolAvailability:
    def test_valid_tool_name_passes(self):
        with patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
            ok, msg = validate_tool_availability("scope_rules")
        assert ok is True
        assert msg == ""

    def test_missing_tool_name_fails(self):
        with patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
            ok, msg = validate_tool_availability(None)
        assert ok is False
        assert "missing" in msg.lower()

    def test_unknown_tool_name_fails(self):
        with patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
            ok, msg = validate_tool_availability("does_not_exist")
        assert ok is False
        assert "not available" in msg.lower()


# ── execute_tool_with_validation — prefix normalisation ────────────────────────

class TestToolNamePrefixNormalisation:
    """When an LLM calls "proxy_tools.scope_rules" the executor must silently
    normalise it to "scope_rules" and invoke the tool successfully."""

    def test_prefixed_name_is_normalised(self):
        async def _run():
            with (
                patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]),
                patch("phantom.tools.executor.validate_tool_availability", return_value=(True, "")),
                patch("phantom.tools.executor._validate_tool_arguments", return_value=None),
                patch("phantom.tools.executor.execute_tool", new=AsyncMock(return_value="OK")),
            ):
                return await execute_tool_with_validation("proxy_tools.scope_rules")
        assert asyncio.run(_run()) == "OK"

    def test_bare_name_still_works(self):
        async def _run():
            with (
                patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]),
                patch("phantom.tools.executor.validate_tool_availability", return_value=(True, "")),
                patch("phantom.tools.executor._validate_tool_arguments", return_value=None),
                patch("phantom.tools.executor.execute_tool", new=AsyncMock(return_value="OK")),
            ):
                return await execute_tool_with_validation("scope_rules")
        assert asyncio.run(_run()) == "OK"

    def test_unknown_suffix_returns_error(self):
        """If the stripped suffix is also unknown, error must be returned."""
        async def _run():
            with patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
                return await execute_tool_with_validation("proxy_tools.nonexistent")
        result = asyncio.run(_run())
        assert "Error" in result
        assert "not available" in result.lower()

    def test_deeply_prefixed_name_normalised(self):
        """Tools called as "a.b.proxy_tools.scope_rules" → "scope_rules"."""
        async def _run():
            with (
                patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]),
                patch("phantom.tools.executor.validate_tool_availability", return_value=(True, "")),
                patch("phantom.tools.executor._validate_tool_arguments", return_value=None),
                patch("phantom.tools.executor.execute_tool", new=AsyncMock(return_value="OK")),
            ):
                return await execute_tool_with_validation("a.b.proxy_tools.scope_rules")
        assert asyncio.run(_run()) == "OK"

    def test_none_tool_name_returns_error(self):
        async def _run():
            with patch("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
                return await execute_tool_with_validation(None)
        result = asyncio.run(_run())
        assert "Error" in result


# ── get_tools_prompt — comment-style section headers ──────────────────────────

class TestGetToolsPromptCommentHeaders:
    """Sections must use <!-- proxy tools --> not <proxy_tools> so that LLMs
    cannot interpret the container tag as a namespace prefix."""

    def _build_prompt(self):
        from phantom.tools import registry

        fake_tools = [
            {
                "name": "scope_rules",
                "module": "proxy",
                "xml_schema": '<tool name="scope_rules"><description>scope</description></tool>',
                "sandbox_execution": False,
            },
            {
                "name": "nmap_scan",
                "module": "network",
                "xml_schema": '<tool name="nmap_scan"><description>scan</description></tool>',
                "sandbox_execution": False,
            },
        ]
        original = registry.tools[:]
        registry.tools[:] = fake_tools
        try:
            return get_tools_prompt()
        finally:
            registry.tools[:] = original

    def test_section_header_is_xml_comment(self):
        prompt = self._build_prompt()
        assert "<!-- proxy tools -->" in prompt
        assert "<!-- network tools -->" in prompt

    def test_old_wrapper_tags_absent(self):
        prompt = self._build_prompt()
        assert "<proxy_tools>" not in prompt
        assert "</proxy_tools>" not in prompt
        assert "<network_tools>" not in prompt
        assert "</network_tools>" not in prompt

    def test_individual_tool_name_attributes_intact(self):
        prompt = self._build_prompt()
        assert 'name="scope_rules"' in prompt
        assert 'name="nmap_scan"' in prompt

    def test_end_comment_present(self):
        prompt = self._build_prompt()
        assert "<!-- end proxy tools -->" in prompt
        assert "<!-- end network tools -->" in prompt
