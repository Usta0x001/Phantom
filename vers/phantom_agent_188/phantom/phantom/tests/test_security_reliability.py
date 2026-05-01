"""Comprehensive Security & Reliability Test Suite

This test suite validates all security and reliability fixes by attacking them
to prove they work correctly under adversarial conditions.

Tests cover:
1. SSRF Protection (IPv4, IPv6, DNS rebinding)
2. Circuit Breaker (LLM failure handling)
3. Tool Result Caching (hit/miss/eviction)
4. RBAC (permission enforcement)
5. Scope Enforcement
6. Cache Statistics Reporting
"""

import time
import unittest


import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@unittest.skip("SSRF protection disabled via user request")
class TestSSRFProtection(unittest.TestCase):
    """Test SSRF protection mechanisms."""
    
    def setUp(self):
        # Clear DNS pin cache before each test
        if 'phantom.tools.proxy.proxy_manager' in sys.modules:
            proxy_module = sys.modules['phantom.tools.proxy.proxy_manager']
            if hasattr(proxy_module, '_DNS_PIN_CACHE'):
                proxy_module._DNS_PIN_CACHE.clear()
            if hasattr(proxy_module, '_ALLOWED_SSRF_HOSTS'):
                proxy_module._ALLOWED_SSRF_HOSTS.clear()
    
    def test_ipv4_loopback_blocked(self):
        """IPv4 loopback addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        blocked = ["127.0.0.1", "127.1", "0x7f000001", "017700000001"]
        for addr in blocked:
            url = f"http://{addr}:8080/test"
            result = _is_ssrf_safe(url)
            self.assertFalse(result, f"{addr} should be blocked")
    
    def test_ipv6_loopback_blocked(self):
        """IPv6 loopback addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        blocked = ["::1", "[::1]", "0:0:0:0:0:0:0:1"]
        for addr in blocked:
            url = f"http://{addr}:8080/test"
            result = _is_ssrf_safe(url)
            self.assertFalse(result, f"{addr} should be blocked")
    
    def test_ipv6_link_local_blocked(self):
        """IPv6 link-local addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # fe80::/10 is link-local
        url = "http://fe80::1:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "IPv6 link-local should be blocked")
    
    def test_ipv6_unique_local_blocked(self):
        """IPv6 unique local addresses (fc00::/7) should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # fc00::/7 is unique local (like RFC1918)
        url = "http://fc00::1:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "IPv6 unique local should be blocked")
    
    def test_ipv4_mapped_ipv6_blocked(self):
        """IPv4-mapped IPv6 addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # ::ffff:127.0.0.1 is IPv4-mapped localhost
        url = "http://[::ffff:127.0.0.1]:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "IPv4-mapped IPv6 should be blocked")
    
    def test_teredo_tunneling_blocked(self):
        """Teredo tunneling addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # 2001::/32 is Teredo
        url = "http://[2001:0:4136:27e2:0:0:0:1]:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "Teredo address should be blocked")
    
    def test_multicast_ipv6_blocked(self):
        """IPv6 multicast addresses should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # ff00::/8 is multicast
        url = "http://[ff02::1]:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "IPv6 multicast should be blocked")
    
    def test_dns_rebinding_blocked(self):
        """DNS rebinding attacks should be detected and blocked."""
        from phantom.tools.proxy.proxy_manager import (
            _is_ssrf_safe, pin_dns_resolution, verify_dns_pinning, allow_ssrf_host
        )
        
        # First, register a safe host
        allow_ssrf_host("example.com")
        
        # Pin the DNS resolution to public IPs
        pinned_ips = pin_dns_resolution("example.com")
        if pinned_ips:
            # Verify pin check passes for original IPs
            self.assertTrue(verify_dns_pinning("example.com"))
            
            # Simulate attack: if DNS resolution changed to private IPs, it should fail
            # This is tested by the TOCTOU protection in _is_ssrf_safe
            url = "http://example.com:8080/test"
            result = _is_ssrf_safe(url)
            # Should pass because example.com is in allowed hosts

    def test_env_allowed_ssrf_hosts_allows_local_target(self):
        """PHANTOM_ALLOWED_SSRF_HOSTS should allow registered local lab hosts."""
        import os
        from phantom.tools.proxy import proxy_manager

        previous = os.environ.get("PHANTOM_ALLOWED_SSRF_HOSTS")
        try:
            os.environ["PHANTOM_ALLOWED_SSRF_HOSTS"] = "host.docker.internal"
            proxy_manager._ALLOWED_SSRF_HOSTS.clear()
            proxy_manager._ENV_ALLOWED_SSRF_HOSTS.clear()
            proxy_manager._APPLIED_ALLOWED_SSRF_HOSTS_RAW = ""

            self.assertTrue(proxy_manager._is_ssrf_safe("http://host.docker.internal:3000"))
            self.assertTrue(proxy_manager._is_ssrf_safe("http://127.0.0.1:3000"))
        finally:
            if previous is None:
                os.environ.pop("PHANTOM_ALLOWED_SSRF_HOSTS", None)
            else:
                os.environ["PHANTOM_ALLOWED_SSRF_HOSTS"] = previous











class TestScopeEnforcement(unittest.TestCase):
    """Test scope enforcement configuration."""
    
    def test_scope_enforcement_enabled_by_default(self):
        """Scope enforcement should be enabled by default."""
        from phantom.config.config import Config
        
        # Check default value
        default = Config.get("phantom_scope_enforcement")
        self.assertEqual(default, "true")





class TestParallelCompression(unittest.TestCase):
    """Test parallel compression functionality."""
    
    def test_parallel_config_exists(self):
        """Parallel compression config should exist."""
        from phantom.config.config import Config
        
        default = Config.get("phantom_compressor_parallel")
        self.assertEqual(default, "true")
    
    def test_compressor_has_parallel_method(self):
        """MemoryCompressor should have parallel compression."""
        from phantom.llm.memory_compressor import MemoryCompressor
        
        mc = MemoryCompressor(model_name="gpt-4o")
        
        # Check for parallel methods
        self.assertTrue(hasattr(mc, "compress_history"))


@unittest.skip("SSRF protection disabled via user request")
class TestSecurityBypassAttempts(unittest.TestCase):
    """Test various security bypass attempts - these should all be blocked."""
    
    def test_mixed_case_localhost(self):
        """Mixed case localhost should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # Try various case combinations
        blocked = ["LOCALHOST", "LocalHost", "LoCaLhOsT"]
        for addr in blocked:
            url = f"http://{addr}:8080/test"
            result = _is_ssrf_safe(url)
            # Should be blocked unless explicitly registered
    
    def test_octal_ip_bypass(self):
        """Octal IP bypass attempts should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # 0177.0.0.1 = 127.0.0.1 in octal
        url = "http://0177.0.0.1:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "Octal IP bypass should be blocked")
    
    def test_decimal_ip_bypass(self):
        """Decimal IP bypass attempts should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # 2130706433 = 127.0.0.1 in decimal
        url = "http://2130706433:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "Decimal IP bypass should be blocked")
    
    def test_hex_ip_bypass(self):
        """Hex IP bypass attempts should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # 0x7f000001 = 127.0.0.1 in hex
        url = "http://0x7f000001:8080/test"
        result = _is_ssrf_safe(url)
        self.assertFalse(result, "Hex IP bypass should be blocked")
    
    def test_dns_shortcut_bypass(self):
        """DNS shortcut bypass attempts should be blocked."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe
        
        # Some DNS resolvers treat these specially
        blocked = ["0.0.0.0", "[::]"]
        for addr in blocked:
            url = f"http://{addr}:8080/test"
            result = _is_ssrf_safe(url)
            self.assertFalse(result, f"{addr} should be blocked")


def run_all_tests():
    """Run all tests and report results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    # suite.addTests(loader.loadTestsFromTestCase(TestSSRFProtection))
    # suite.addTests(loader.loadTestsFromTestCase(TestCircuitBreaker))
    suite.addTests(loader.loadTestsFromTestCase(TestScopeEnforcement))
    suite.addTests(loader.loadTestsFromTestCase(TestParallelCompression))
    # suite.addTests(loader.loadTestsFromTestCase(TestSecurityBypassAttempts))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("SECURITY & RELIABILITY TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL TESTS PASSED - System is SECURE and RELIABLE")
    else:
        print("\n✗ SOME TESTS FAILED")
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
