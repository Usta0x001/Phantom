"""Tests for phantom.core.scope_validator — enforce_scope + existing behavior."""

import pytest
from unittest import mock

from phantom.core.scope_validator import ScopeValidator, ScopeConfig, ScopeRule, _extract_host
from phantom.core.exceptions import ScopeViolationError


class TestExtractHost:
    def test_url_extracts_hostname(self):
        assert _extract_host("http://example.com/path") == "example.com"

    def test_strips_userinfo(self):
        """PHT-045: user-info in URLs must be stripped."""
        assert _extract_host("http://admin:pass@10.0.0.1/path") == "10.0.0.1"

    def test_bare_host_port(self):
        assert _extract_host("10.0.0.1:8080") == "10.0.0.1"

    def test_bare_domain(self):
        assert _extract_host("example.com") == "example.com"


class TestScopeRules:
    def test_domain_exact_match(self):
        rule = ScopeRule(pattern="example.com", rule_type="domain", action="allow")
        assert rule.matches("example.com") is True
        assert rule.matches("evil.com") is False

    def test_wildcard_domain(self):
        rule = ScopeRule(pattern="*.example.com", rule_type="domain", action="allow")
        assert rule.matches("sub.example.com") is True
        assert rule.matches("example.com") is True
        assert rule.matches("evil.com") is False

    def test_ip_match(self):
        rule = ScopeRule(pattern="10.0.0.1", rule_type="ip", action="allow")
        assert rule.matches("10.0.0.1") is True
        assert rule.matches("10.0.0.2") is False

    def test_cidr_match(self):
        rule = ScopeRule(pattern="10.0.0.0/8", rule_type="cidr", action="allow")
        assert rule.matches("10.255.255.255") is True
        assert rule.matches("192.168.1.1") is False


class TestScopeValidatorBasic:
    def test_from_targets_allows_listed(self):
        sv = ScopeValidator.from_targets(["example.com"])
        assert sv.is_in_scope("example.com") is True

    def test_strict_mode_denies_unlisted(self):
        sv = ScopeValidator.from_targets(["example.com"])
        assert sv.is_in_scope("evil.com") is False

    def test_permissive_allows_all(self):
        sv = ScopeValidator.permissive()
        assert sv.is_in_scope("anything.com") is True

    def test_deny_rule_takes_priority(self):
        config = ScopeConfig()
        config.add_target("*.example.com")
        config.add_deny("admin.example.com")
        sv = ScopeValidator(config)
        assert sv.is_in_scope("app.example.com") is True
        assert sv.is_in_scope("admin.example.com") is False


class TestPrivateIpRejection:
    """PHT-023: Private IPs should be detected."""

    def test_rejects_private_ip_resolution(self):
        sv = ScopeValidator.from_targets(["safe.com"])
        # DNS resolving to private IP should be blocked
        with mock.patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("10.0.0.1", 80)),
        ]):
            assert sv.is_in_scope("evil-dns.com") is False

    def test_allows_explicitly_listed_target(self):
        sv = ScopeValidator.from_targets(["example.com"])
        assert sv.is_in_scope("example.com") is True


class TestEnforceScope:
    """v0.9.39: Per-request scope enforcement for tool invocations."""

    def test_passes_valid_in_scope_target(self):
        sv = ScopeValidator.from_targets(["http://target.com"])
        args = sv.enforce_scope("http_request", {"url": "http://target.com/api"})
        assert args["url"] == "http://target.com/api"

    def test_raises_for_out_of_scope_target(self):
        sv = ScopeValidator.from_targets(["http://target.com"])
        with pytest.raises(ScopeViolationError) as exc_info:
            sv.enforce_scope("http_request", {"url": "http://evil.com/"})
        assert "evil.com" in str(exc_info.value)
        assert exc_info.value.tool_name == "http_request"

    def test_checks_multiple_params(self):
        sv = ScopeValidator.from_targets(["safe.com"])
        # nmap_scan checks both 'target' and 'host'
        with pytest.raises(ScopeViolationError):
            sv.enforce_scope("nmap_scan", {"target": "evil.com"})

    def test_generic_fallback_for_unknown_tool(self):
        """Unknown tools still get checked via generic param names."""
        sv = ScopeValidator.from_targets(["safe.com"])
        with pytest.raises(ScopeViolationError):
            sv.enforce_scope("custom_tool", {"url": "http://evil.com/"})

    def test_skips_non_string_params(self):
        sv = ScopeValidator.from_targets(["target.com"])
        # Non-string params should be silently ignored
        args = sv.enforce_scope("http_request", {"url": None, "data": {"key": "val"}})
        assert args is not None

    def test_passes_with_no_url_params(self):
        sv = ScopeValidator.from_targets(["target.com"])
        args = sv.enforce_scope("some_tool", {"content": "hello"})
        assert args["content"] == "hello"


class TestSerializationRoundTrip:
    def test_to_dict_from_dict(self):
        sv = ScopeValidator.from_targets(["example.com", "10.0.0.0/8"])
        data = sv.to_dict()
        sv2 = ScopeValidator.from_dict(data)
        assert sv2.is_in_scope("example.com") is True
        assert sv2.is_in_scope("10.0.0.1") is True


class TestViolationLog:
    def test_violations_are_logged(self):
        sv = ScopeValidator.from_targets(["safe.com"])
        sv.is_in_scope("evil.com")
        violations = sv.get_violations()
        assert len(violations) >= 1
        assert violations[-1]["target"] == "evil.com"
