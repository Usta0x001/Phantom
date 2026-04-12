"""Phase 1 Enhancement Test Suite

Tests for the new Phase 1 tools:
1. OSINT Tools (crtsh_search, shodan_search, whois_lookup, dns_enum, github_dork)
2. Vulnerability Intelligence Tools (cve_search, exploit_search, version_to_cves, get_cve_details)
3. WAF Detection Tools (detect_waf, get_waf_evasion_strategies)

These tests validate:
- Tool registration with @register_tool decorator
- Parameter validation and error handling
- Rate limiting behavior
- Caching behavior
- XML schema loading
- Tool return value structure
"""

import asyncio
import sys
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestToolRegistration(unittest.TestCase):
    """Test that all Phase 1 tools are properly registered."""
    
    @classmethod
    def setUpClass(cls):
        """Import tools to ensure they're registered before tests run."""
        # These imports trigger @register_tool decorators
        import phantom.tools.osint.osint_actions
        import phantom.tools.vuln_intel.vuln_intel_actions
        import phantom.tools.waf.waf_actions
    
    def test_osint_tools_registered(self):
        """OSINT tools should be registered in the tool registry."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        osint_tools = [
            "crtsh_search",
            "shodan_search", 
            "whois_lookup",
            "dns_enum",
            "github_dork",
        ]
        
        registered = get_tool_names()
        for tool in osint_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_vuln_intel_tools_registered(self):
        """Vulnerability intelligence tools should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        vuln_tools = [
            "cve_search",
            "exploit_search",
            "version_to_cves",
            "get_cve_details",
        ]
        
        registered = get_tool_names()
        for tool in vuln_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_waf_tools_registered(self):
        """WAF detection tools should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        waf_tools = [
            "detect_waf",
            "get_waf_evasion_strategies",
        ]
        
        registered = get_tool_names()
        for tool in waf_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_sandbox_execution_disabled(self):
        """Phase 1 tools should have sandbox_execution=False."""
        from phantom.tools.registry import tools
        
        phase1_tools = [
            "crtsh_search", "shodan_search", "whois_lookup", "dns_enum", "github_dork",
            "cve_search", "exploit_search", "version_to_cves", "get_cve_details",
            "detect_waf", "get_waf_evasion_strategies",
        ]
        
        for tool_entry in tools:
            if tool_entry["name"] in phase1_tools:
                self.assertFalse(
                    tool_entry.get("sandbox_execution", True),
                    f"{tool_entry['name']} should have sandbox_execution=False"
                )


class TestOSINTTools(unittest.TestCase):
    """Test OSINT tool functionality."""
    
    def test_crtsh_search_domain_validation(self):
        """crtsh_search should validate domain format."""
        from phantom.tools.osint.osint_actions import crtsh_search
        
        # Invalid domain should return error
        result = asyncio.run(crtsh_search(""))
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        
        # Invalid format should return error
        result = asyncio.run(crtsh_search("not a domain!!!"))
        self.assertFalse(result["success"])
    
    def test_crtsh_search_url_normalization(self):
        """crtsh_search should normalize URLs to domains."""
        from phantom.tools.osint.osint_actions import _extract_domain
        
        test_cases = [
            ("https://example.com/path", "example.com"),
            ("http://www.example.com:8080/", "example.com"),
            ("example.com", "example.com"),
            ("WWW.EXAMPLE.COM", "example.com"),  # www is removed
            ("https://sub.example.com", "sub.example.com"),  # subdomain preserved
        ]
        
        for input_val, expected in test_cases:
            result = _extract_domain(input_val)
            self.assertEqual(result, expected, f"Failed for {input_val}")
    
    def test_shodan_search_requires_api_key(self):
        """shodan_search should return error without API key."""
        from phantom.tools.osint.osint_actions import shodan_search
        
        # Clear any existing API key (check both old and new config names)
        with patch.dict(os.environ, {"PHANTOM_SHODAN_API_KEY": ""}, clear=False):
            os.environ.pop("PHANTOM_SHODAN_API_KEY", None)
            os.environ.pop("SHODAN_API_KEY", None)  # Old name too
            result = asyncio.run(shodan_search("8.8.8.8"))
            self.assertFalse(result["success"])
            self.assertIn("PHANTOM_SHODAN_API_KEY", result.get("error", ""))
    
    def test_dns_enum_valid_domain(self):
        """dns_enum should work with valid domains."""
        from phantom.tools.osint.osint_actions import dns_enum
        
        # This will actually make DNS queries but to Google's DoH
        result = asyncio.run(dns_enum("google.com", ["A"]))
        
        # Should succeed (Google's domain should resolve)
        self.assertTrue(result["success"])
        self.assertIn("records", result)
        self.assertIn("domain", result)
    
    def test_github_dork_requires_target(self):
        """github_dork should require organization or domain."""
        from phantom.tools.osint.osint_actions import github_dork
        
        result = asyncio.run(github_dork())
        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestVulnIntelTools(unittest.TestCase):
    """Test vulnerability intelligence tool functionality."""
    
    def test_cve_search_basic(self):
        """cve_search should return results structure."""
        from phantom.tools.vuln_intel.vuln_intel_actions import cve_search
        
        # Mock the HTTP request to avoid actual API calls
        with patch('phantom.tools.vuln_intel.vuln_intel_actions.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "totalResults": 0,
                "vulnerabilities": []
            }
            mock_response.raise_for_status = MagicMock()
            
            mock_client_instance = MagicMock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_client_instance
            
            result = asyncio.run(cve_search("apache"))
            
            self.assertIn("success", result)
            self.assertIn("cves", result)  # Results are in 'cves' key
    
    def test_version_to_cves_format_validation(self):
        """version_to_cves should handle various version string formats."""
        from phantom.tools.vuln_intel.vuln_intel_actions import _parse_version
        
        test_cases = [
            ("Apache/2.4.49", ("apache", "2.4.49")),
            ("nginx/1.18.0", ("nginx", "1.18.0")),
            ("PHP/7.4.3", ("php", "7.4.3")),
            ("OpenSSH_8.2p1", ("openssh", "8.2p1")),
        ]
        
        for version_str, expected in test_cases:
            result = _parse_version(version_str)
            self.assertEqual(result[0].lower(), expected[0], f"Product mismatch for {version_str}")
    
    def test_get_cve_details_validation(self):
        """get_cve_details should validate CVE ID format."""
        from phantom.tools.vuln_intel.vuln_intel_actions import get_cve_details
        
        # Invalid CVE format
        result = asyncio.run(get_cve_details("not-a-cve"))
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        
        # Valid format (even if CVE doesn't exist)
        result = asyncio.run(get_cve_details("CVE-2021-44228"))
        # Should have success or appropriate error from API
        self.assertIn("success", result)


class TestWAFDetectionTools(unittest.TestCase):
    """Test WAF detection tool functionality."""
    
    def test_detect_waf_url_validation(self):
        """detect_waf should validate URL format."""
        from phantom.tools.waf.waf_actions import detect_waf
        
        # Invalid URL
        result = asyncio.run(detect_waf("not-a-url"))
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        
        # Non-HTTP URL
        result = asyncio.run(detect_waf("ftp://example.com"))
        self.assertFalse(result["success"])
    
    def test_waf_signatures_complete(self):
        """WAF signature database should have expected entries."""
        from phantom.tools.waf.waf_actions import WAF_SIGNATURES
        
        expected_wafs = [
            "cloudflare", "akamai", "aws_waf", "imperva_incapsula",
            "sucuri", "f5_big_ip", "modsecurity", "wordfence",
        ]
        
        for waf in expected_wafs:
            self.assertIn(waf, WAF_SIGNATURES, f"Missing WAF signature: {waf}")
            sig = WAF_SIGNATURES[waf]
            self.assertIn("name", sig)
            self.assertIn("vendor", sig)
    
    def test_get_waf_evasion_strategies_generic(self):
        """get_waf_evasion_strategies should return generic strategies."""
        from phantom.tools.waf.waf_actions import get_waf_evasion_strategies
        
        result = asyncio.run(get_waf_evasion_strategies(waf_id="generic"))
        
        self.assertTrue(result["success"])
        self.assertIn("strategies", result)
        self.assertGreater(len(result["strategies"]), 0)
    
    def test_get_waf_evasion_strategies_list(self):
        """get_waf_evasion_strategies without args should list available WAFs."""
        from phantom.tools.waf.waf_actions import get_waf_evasion_strategies
        
        result = asyncio.run(get_waf_evasion_strategies())
        
        self.assertTrue(result["success"])
        self.assertIn("available_wafs", result)
        self.assertGreater(len(result["available_wafs"]), 0)
    
    def test_detect_waf_signature_matching(self):
        """WAF signature matching should work correctly."""
        from phantom.tools.waf.waf_actions import _match_waf_signature, WAF_SIGNATURES
        
        # Simulate Cloudflare response
        headers = {"cf-ray": "abc123", "server": "cloudflare"}
        cookies = {"__cf_bm": "test"}
        body = ""
        status_code = 200
        
        result = _match_waf_signature(
            headers, cookies, body, status_code,
            "cloudflare", WAF_SIGNATURES["cloudflare"]
        )
        
        self.assertGreater(result["confidence"], 0.3)
        self.assertEqual(result["name"], "Cloudflare")


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting in Phase 1 tools."""
    
    def test_osint_rate_limit_state(self):
        """OSINT tools should have rate limiting state."""
        from phantom.tools.osint.osint_actions import _RATE_LIMIT_STATE, _RATE_LIMIT_INTERVALS
        
        self.assertIsInstance(_RATE_LIMIT_STATE, dict)
        self.assertIsInstance(_RATE_LIMIT_INTERVALS, dict)
        self.assertIn("crtsh", _RATE_LIMIT_INTERVALS)
        self.assertIn("shodan", _RATE_LIMIT_INTERVALS)
    
    def test_waf_rate_limit_state(self):
        """WAF tools should have rate limiting state."""
        from phantom.tools.waf.waf_actions import _RATE_LIMIT_STATE
        
        self.assertIsInstance(_RATE_LIMIT_STATE, dict)


class TestCaching(unittest.TestCase):
    """Test caching in Phase 1 tools."""
    
    def test_osint_cache_functions(self):
        """OSINT cache functions should work."""
        from phantom.tools.osint.osint_actions import (
            _get_cache_key, _get_cached, _set_cached, _OSINT_CACHE
        )
        
        # Clear cache
        _OSINT_CACHE.clear()
        
        # Test cache key generation
        key1 = _get_cache_key("test", "arg1", "arg2")
        key2 = _get_cache_key("test", "arg1", "arg2")
        key3 = _get_cache_key("test", "arg1", "arg3")
        
        self.assertEqual(key1, key2)  # Same args = same key
        self.assertNotEqual(key1, key3)  # Different args = different key
        
        # Test cache set/get
        _set_cached(key1, {"test": "data"})
        result = _get_cached(key1)
        self.assertEqual(result, {"test": "data"})
        
        # Non-existent key should return None
        self.assertIsNone(_get_cached("nonexistent"))
    
    def test_waf_cache_functions(self):
        """WAF cache functions should work."""
        from phantom.tools.waf.waf_actions import (
            _get_cache_key, _get_cached, _set_cached, _WAF_CACHE
        )
        
        # Clear cache
        _WAF_CACHE.clear()
        
        key = _get_cache_key("waf_detect", "https://example.com", False)
        
        _set_cached(key, {"waf": "cloudflare"})
        result = _get_cached(key)
        self.assertEqual(result, {"waf": "cloudflare"})


class TestXMLSchemas(unittest.TestCase):
    """Test that XML schemas are properly loaded."""
    
    def test_osint_schema_loaded(self):
        """OSINT tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        osint_tools = ["crtsh_search", "shodan_search", "whois_lookup", "dns_enum", "github_dork"]
        
        for tool_entry in tools:
            if tool_entry["name"] in osint_tools:
                self.assertIn("xml_schema", tool_entry, f"{tool_entry['name']} missing schema")
                schema = tool_entry.get("xml_schema", "")
                self.assertIn(tool_entry["name"], schema, f"{tool_entry['name']} schema should contain tool name")
    
    def test_vuln_intel_schema_loaded(self):
        """Vulnerability intelligence tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        vuln_tools = ["cve_search", "exploit_search", "version_to_cves", "get_cve_details"]
        
        for tool_entry in tools:
            if tool_entry["name"] in vuln_tools:
                self.assertIn("xml_schema", tool_entry, f"{tool_entry['name']} missing schema")
    
    def test_waf_schema_loaded(self):
        """WAF tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        waf_tools = ["detect_waf", "get_waf_evasion_strategies"]
        
        for tool_entry in tools:
            if tool_entry["name"] in waf_tools:
                self.assertIn("xml_schema", tool_entry, f"{tool_entry['name']} missing schema")


class TestIntegration(unittest.TestCase):
    """Integration tests for Phase 1 tools."""
    
    def test_tool_prompt_includes_phase1(self):
        """get_tools_prompt should include Phase 1 tools."""
        from phantom.tools.registry import get_tools_prompt
        
        prompt = get_tools_prompt()
        
        # Should include OSINT tools
        self.assertIn("crtsh_search", prompt)
        self.assertIn("shodan_search", prompt)
        
        # Should include CVE tools
        self.assertIn("cve_search", prompt)
        
        # Should include WAF tools
        self.assertIn("detect_waf", prompt)
    
    def test_system_prompt_references_tools(self):
        """System prompt should reference Phase 1 tools."""
        import jinja2
        
        prompt_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "agents", "PhantomAgent", "system_prompt.jinja"
        )
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Should reference OSINT tools
        self.assertIn("crtsh_search", content)
        self.assertIn("shodan_search", content)
        
        # Should reference WAF tools
        self.assertIn("detect_waf", content)
        
        # Should have passive recon section
        self.assertIn("PASSIVE RECON (query external DBs, not target):", content)


class TestSecurityProperties(unittest.TestCase):
    """Test that Phase 1 tools maintain security properties."""
    
    def test_tools_are_passive(self):
        """All Phase 1 tools should be passive (query external APIs only)."""
        # This is a design verification test
        # Tools should NOT:
        # - Send payloads to targets
        # - Modify any systems
        # - Execute commands on targets
        
        from phantom.tools.osint.osint_actions import crtsh_search
        from phantom.tools.waf.waf_actions import detect_waf
        
        # Verify docstrings mention passive nature
        self.assertIn("PASSIVE", crtsh_search.__doc__)
        self.assertIn("fingerprint", detect_waf.__doc__.lower())
    
    def test_no_credential_exposure(self):
        """Tools should not expose API keys in return values."""
        from phantom.tools.osint.osint_actions import shodan_search
        
        # Test with mock to avoid actual API calls
        with patch.dict(os.environ, {"SHODAN_API_KEY": "secret_key_12345"}):
            # Even with error, shouldn't expose key
            with patch('httpx.AsyncClient') as mock_client:
                mock_client_instance = MagicMock()
                mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
                mock_client_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client_instance.get = AsyncMock(side_effect=Exception("API Error"))
                mock_client.return_value = mock_client_instance
                
                result = asyncio.run(shodan_search("8.8.8.8"))
                result_str = str(result)
                
                self.assertNotIn("secret_key_12345", result_str)


if __name__ == "__main__":
    # Import tools to trigger registration
    import phantom.tools.osint.osint_actions
    import phantom.tools.vuln_intel.vuln_intel_actions
    import phantom.tools.waf.waf_actions
    
    unittest.main(verbosity=2)
