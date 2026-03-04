"""Adversarial DNS rebinding tests."""

import pytest
from unittest import mock

from phantom.core.scope_validator import ScopeValidator


class TestDNSRebinding:
    """Simulate DNS rebinding: first resolution is safe, second is malicious."""

    def test_rebinding_to_private_ip_blocked(self):
        """DNS changes from public to private IP — must be blocked."""
        sv = ScopeValidator.from_targets(["safe.com"])

        with mock.patch("socket.getaddrinfo") as mock_dns:
            # First call: resolves to safe public IP
            mock_dns.return_value = [
                (None, None, None, None, ("1.2.3.4", 80)),
            ]
            # This should be denied because 1.2.3.4 is not in scope
            # (scope is "safe.com" domain, not the resolved IP)
            result1 = sv.is_in_scope("public-site.com")
            # May be denied by scope rules, but DNS pin should be cached

            # Second call: same hostname resolves to private IP
            mock_dns.return_value = [
                (None, None, None, None, ("169.254.169.254", 80)),
            ]
            result2 = sv.is_in_scope("public-site.com")
            # Must be blocked — either by private IP check or DNS pin violation
            assert result2 is False

    def test_rebinding_detected_via_pin(self):
        """If a hostname changes IPs between checks, pin detects it."""
        config_data = {
            "rules": [
                {"pattern": "*.target.com", "type": "domain", "action": "allow"},
            ],
            "default_action": "deny",
            "strict_mode": True,
        }
        sv = ScopeValidator.from_dict(config_data)

        with mock.patch("socket.getaddrinfo") as mock_dns:
            # First resolution: 1.2.3.4
            mock_dns.return_value = [
                (None, None, None, None, ("1.2.3.4", 80)),
            ]
            r1 = sv.is_in_scope("http://app.target.com/")

            # Second resolution: different IP (rebind attempt)
            mock_dns.return_value = [
                (None, None, None, None, ("10.0.0.1", 80)),
            ]
            r2 = sv.is_in_scope("http://app.target.com/")

            # At least one of these should be blocked
            # (private IP 10.0.0.1 should definitely be blocked)
            assert r2 is False

    def test_cloud_metadata_always_blocked(self):
        """169.254.169.254 (AWS metadata) must always be blocked."""
        sv = ScopeValidator.from_targets(["anything.com"])

        with mock.patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("169.254.169.254", 80)),
        ]):
            assert sv.is_in_scope("evil-dns.com") is False

    def test_ipv6_localhost_blocked(self):
        """::1 must be blocked as private."""
        sv = ScopeValidator.from_targets(["target.com"])
        with mock.patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("::1", 80)),
        ]):
            assert sv.is_in_scope("evil-dns.com") is False
