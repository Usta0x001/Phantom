"""
Tests for v0.9.17 fixes:
- SEC-006: Full SHA-256 hash in authorization signatures
- LOGIC-003: DNS pinning in scope validator
- LOGIC-004: Compression audit logging
- IMPL-004: Keyring integration for credential storage
- ARCH-004: Egress filtering in container entrypoint
- Sandbox image overlay build (CRLF fix, tool_server 0.0.0.0 binding)
- Timeout chain: Config(600) → docker_runtime → entrypoint → tool_server
"""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── SEC-006: Full SHA-256 hash ──────────────────────────────────────────────


class TestAuthorizationSignature:
    """Verify authorization signature uses full SHA-256.
    NOTE: authorization.py removed in v0.9.37 (dead code — never used in scan pipeline).
    """

    def test_signature_is_full_sha256(self):
        pytest.skip("authorization.py removed in v0.9.37 (dead code)")

    def test_signature_not_truncated(self):
        pytest.skip("authorization.py removed in v0.9.37 (dead code)")

    def test_signature_source_code_no_truncation(self):
        pytest.skip("authorization.py removed in v0.9.37 (dead code)")


# ── LOGIC-003: DNS pinning ──────────────────────────────────────────────────


@pytest.mark.skip(reason="lean-phantom: tests for removed features")
@pytest.mark.skip(reason="lean-phantom: tests for removed features")
class TestDNSPinning:
    """Verify scope validator has DNS pin cache."""

    def test_dns_pin_cache_initialized(self):
        from phantom.core.scope_validator import ScopeValidator

        sv = ScopeValidator.from_targets(["http://example.com"])
        assert hasattr(sv, "_dns_pin_cache")
        assert isinstance(sv._dns_pin_cache, dict)

    def test_dns_pin_violation_detection(self):
        """Simulate DNS rebinding by manually poisoning the pin cache."""
        from phantom.core.scope_validator import ScopeValidator

        sv = ScopeValidator.from_targets(["http://example.com"])
        # Pin 'evil.test' to a known IP
        sv._dns_pin_cache["evil.test"] = {"1.2.3.4"}

        # Now a request to 'evil.test' that resolves to a different IP
        # should fail if the DNS resolution returns different IPs.
        # We test the cache exists and is populated correctly.
        assert sv._dns_pin_cache["evil.test"] == {"1.2.3.4"}

    def test_scope_validator_source_has_dns_pinning(self):
        """Verify DNS pin cache is in the source code."""
        src = Path(__file__).parent.parent / "phantom" / "core" / "scope_validator.py"
        content = src.read_text()
        assert "_dns_pin_cache" in content
        assert "dns_pin_violation" in content


# ── LOGIC-004: Compression audit logging ────────────────────────────────────


@pytest.mark.skip(reason="lean-phantom: compression audit logging removed in 0.9.44")
class TestCompressionAuditLogging:
    """Verify memory compressor logs to audit trail."""

    def test_compression_audit_code_present(self):
        """Verify audit logging code exists in memory_compressor.py."""
        src = Path(__file__).parent.parent / "phantom" / "llm" / "memory_compressor.py"
        content = src.read_text()
        assert "get_global_audit_logger" in content
        assert '"compression"' in content or "'compression'" in content

    def test_compression_logs_event_type(self):
        """The audit event should use event_type='compression'."""
        src = Path(__file__).parent.parent / "phantom" / "llm" / "memory_compressor.py"
        content = src.read_text()
        assert 'event_type="compression"' in content


# ── IMPL-004: Keyring credential storage ────────────────────────────────────


@pytest.mark.skip(reason="lean-phantom: keyring/_SENSITIVE_KEYS/_load_secret removed in 0.9.44")
class TestKeyringIntegration:
    """Verify Config uses OS keyring for sensitive credentials."""

    def test_sensitive_keys_defined(self):
        from phantom.config.config import _SENSITIVE_KEYS

        assert "LLM_API_KEY" in _SENSITIVE_KEYS
        assert "OPENROUTER_API_KEY" in _SENSITIVE_KEYS
        assert "GROQ_API_KEY" in _SENSITIVE_KEYS

    def test_keyring_sentinel_in_save(self):
        """When keyring is available, sensitive values get __KEYRING__ sentinel."""
        src = Path(__file__).parent.parent / "phantom" / "config" / "config.py"
        content = src.read_text()
        assert "__KEYRING__" in content

    def test_keyring_load_fallback(self):
        """When __KEYRING__ sentinel is found but keyring unavailable, key is removed."""
        from phantom.config import Config

        # Create a mock config file with __KEYRING__ sentinel
        test_data = {"env": {"LLM_API_KEY": "__KEYRING__", "PHANTOM_LLM": "test-model"}}

        with patch.object(Config, "config_file") as mock_cf:
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(test_data, f)
                f.flush()
                mock_cf.return_value = Path(f.name)

                # With keyring unavailable, __KEYRING__ keys should be removed
                with patch("phantom.config.config._load_secret", return_value=None):
                    loaded = Config.load()
                    env = loaded.get("env", {})
                    # LLM_API_KEY should be removed (no keyring)
                    assert "LLM_API_KEY" not in env
                    # Non-sensitive keys should be preserved
                    assert env.get("PHANTOM_LLM") == "test-model"

            Path(f.name).unlink(missing_ok=True)


# ── ARCH-004: Egress filtering ──────────────────────────────────────────────


class TestEgressFiltering:
    """Verify egress filtering is configured in entrypoint."""

    def test_entrypoint_has_iptables_rules(self):
        """docker-entrypoint.sh should contain iptables egress rules."""
        src = Path(__file__).parent.parent / "containers" / "docker-entrypoint.sh"
        content = src.read_text(encoding="utf-8")
        assert "iptables" in content
        assert "EGRESS" in content or "egress" in content.lower()
        assert "OUTPUT" in content  # iptables OUTPUT chain
        assert "DROP" in content


# ── Timeout chain verification ──────────────────────────────────────────────


@pytest.mark.skip(reason="lean-phantom: timeout chain 600s removed in 0.9.44")
class TestTimeoutChain:
    """Verify timeout is consistently 600s across all components."""

    def test_config_default_600(self):
        from phantom.config import Config

        assert Config.get("phantom_sandbox_execution_timeout") == "600"

    def test_tool_server_default_600(self):
        """tool_server.py argparse default should be 600."""
        src = Path(__file__).parent.parent / "phantom" / "runtime" / "tool_server.py"
        content = src.read_text()
        assert "default=600" in content

    def test_entrypoint_fallback_600(self):
        """docker-entrypoint.sh should fall back to 600, not 120."""
        src = Path(__file__).parent.parent / "containers" / "docker-entrypoint.sh"
        content = src.read_text(encoding="utf-8")
        assert "PHANTOM_SANDBOX_EXECUTION_TIMEOUT:-600" in content

    def test_entrypoint_binds_0000(self):
        """tool_server inside Docker should bind to 0.0.0.0 for port forwarding."""
        src = Path(__file__).parent.parent / "containers" / "docker-entrypoint.sh"
        content = src.read_text(encoding="utf-8")
        assert "--host=0.0.0.0" in content


# ── Sandbox Dockerfile verification ─────────────────────────────────────────


class TestSandboxDockerfile:
    """Verify Dockerfile.sandbox has required fixes."""

    def test_crlf_fix(self):
        """Dockerfile.sandbox should strip CRLF from entrypoint."""
        src = Path(__file__).parent.parent / "containers" / "Dockerfile.sandbox"
        content = src.read_text()
        assert "sed -i 's/\\r$//' /usr/local/bin/docker-entrypoint.sh" in content

    def test_python_crlf_fix(self):
        """Python files should also get CRLF stripped."""
        src = Path(__file__).parent.parent / "containers" / "Dockerfile.sandbox"
        content = src.read_text()
        assert "find /app/phantom" in content
        assert "sed -i" in content

    def test_findings_copied(self):
        """Findings module should be copied into sandbox."""
        src = Path(__file__).parent.parent / "containers" / "Dockerfile.sandbox"
        content = src.read_text()
        assert "phantom/tools/findings/" in content

    def test_no_cache_pip(self):
        """pip install should use --no-cache-dir."""
        src = Path(__file__).parent.parent / "containers" / "Dockerfile.sandbox"
        content = src.read_text()
        assert "--no-cache-dir" in content


# ── Dedupe resilience ───────────────────────────────────────────────────────


@pytest.mark.skip(reason="lean-phantom: dedupe resilience removed in 0.9.44")
class TestDedupeResilience:
    """Verify dedupe parser handles non-XML LLM responses."""

    def test_infers_not_duplicate_from_text(self):
        from phantom.llm.dedupe import _parse_dedupe_response

        result = _parse_dedupe_response("This is not a duplicate vulnerability.")
        assert result["is_duplicate"] is False

    def test_infers_duplicate_from_text(self):
        from phantom.llm.dedupe import _parse_dedupe_response

        result = _parse_dedupe_response(
            "This is a duplicate of vuln-0001, same vulnerability."
        )
        assert result["is_duplicate"] is True

    def test_unknown_text_defaults_to_not_duplicate(self):
        """When LLM text is ambiguous, default to not-duplicate (safer)."""
        from phantom.llm.dedupe import _parse_dedupe_response

        result = _parse_dedupe_response("I'm not sure what to say about this.")
        assert result["is_duplicate"] is False
        assert result["confidence"] == 0.5

    def test_still_parses_xml_format(self):
        from phantom.llm.dedupe import _parse_dedupe_response

        xml_response = (
            "<dedupe_result>"
            "<is_duplicate>false</is_duplicate>"
            "<duplicate_id></duplicate_id>"
            "<confidence>0.95</confidence>"
            "<reason>Different vulnerability type</reason>"
            "</dedupe_result>"
        )
        result = _parse_dedupe_response(xml_response)
        assert result["is_duplicate"] is False
        assert result["confidence"] == 0.95
