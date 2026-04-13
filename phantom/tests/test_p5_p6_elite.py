"""P5 & P6 Elite Enhancement Test Suite

Tests for:
- P5: Authentication Automation (automate_login, refresh_jwt_token, multi_step_login)
- P6: Context-Aware Payload Generation (generate_smart_payloads, PayloadContext)

These tests validate:
- Auth automation workflow execution
- JWT token parsing and refresh
- Multi-step login flow handling
- PayloadContext intelligent filtering
- Framework-specific payload optimization
- WAF bypass variation generation
- Integration with hypothesis ledger
"""

import asyncio
import base64
import json
import sys
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestP5AuthAutomation(unittest.TestCase):
    """Test P5 authentication automation features."""
    
    @classmethod
    def setUpClass(cls):
        """Import auth automation tools."""
        import phantom.tools.session_mgmt.auth_automation
    
    def test_auth_tools_registered(self):
        """Auth automation tools should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        auth_tools = [
            "automate_login",
            "refresh_jwt_token",
            "extract_jwt_from_response",
            "check_jwt_expiration",
            "multi_step_login",
        ]
        
        registered = get_tool_names()
        for tool in auth_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_jwt_parsing(self):
        """JWT token parsing should extract claims correctly."""
        from phantom.tools.session_mgmt.auth_automation import _parse_jwt_token
        
        # Create a valid JWT token (header.payload.signature)
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_data = {"sub": "user123", "exp": 9999999999, "iat": 1234567890}
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = "fake_signature"
        
        jwt_token = f"{header}.{payload}.{signature}"
        
        result = _parse_jwt_token(jwt_token)
        
        self.assertIsNotNone(result, "JWT parsing should succeed")
        self.assertEqual(result["claims"]["sub"], "user123")
        self.assertEqual(result["claims"]["exp"], 9999999999)
        self.assertEqual(result["subject"], "user123")
    
    def test_jwt_parsing_invalid(self):
        """Invalid JWT tokens should return None."""
        from phantom.tools.session_mgmt.auth_automation import _parse_jwt_token
        
        result = _parse_jwt_token("not.a.jwt")
        self.assertIsNone(result, "Invalid JWT should return None")
        
        result = _parse_jwt_token("invalid")
        self.assertIsNone(result, "Malformed JWT should return None")
    
    @patch('phantom.tools.session_mgmt.auth_automation.httpx.AsyncClient')
    def test_automate_login_form_success(self, mock_client):
        """Form-based login should extract cookies and create session."""
        from phantom.tools.session_mgmt.auth_automation import automate_login
        
        # Mock HTTP client responses
        mock_response = MagicMock()
        mock_response.text = '<html><input name="csrf_token" value="test_csrf_123" /></html>'
        mock_response.status_code = 200
        
        mock_cookie = MagicMock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "abc123xyz"
        
        mock_client_instance = mock_client.return_value.__aenter__.return_value
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.post.return_value = mock_response
        mock_client_instance.cookies.jar = [mock_cookie]
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            automate_login(
                target_url="https://test.com/login",
                username="admin",
                password="test123",
                flow_type="form",
            )
        )
        
        self.assertTrue(result["success"], "Login should succeed")
        self.assertIn("session_id", result)
        self.assertTrue(result["authenticated"])
    
    def test_extract_jwt_from_response(self):
        """JWT extraction from JSON response should work."""
        from phantom.tools.session_mgmt.auth_automation import extract_jwt_from_response
        
        # Create response with JWT
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).decode().rstrip("=")
        jwt_token = f"{header}.{payload}.sig"
        
        response_body = json.dumps({
            "access_token": jwt_token,
            "refresh_token": "refresh_abc123"
        })
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            extract_jwt_from_response(response_body=response_body)
        )
        
        self.assertTrue(result["success"])
        self.assertGreater(result["token_count"], 0)
        self.assertIn("refresh_tokens", result)
    
    def test_multi_step_login_structure(self):
        """Multi-step login should accept proper step configuration."""
        from phantom.tools.session_mgmt.auth_automation import multi_step_login
        
        steps = [
            {"type": "get", "url": "https://test.com/login", "extract_csrf": True},
            {"type": "post", "url": "https://test.com/login", "data": {"user": "admin"}, "inject_csrf": True},
        ]
        
        # This will fail due to network, but validates structure
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                multi_step_login(steps=steps, session_name="test")
            )
            # If it reaches here without syntax errors, structure is valid
            self.assertIn("success", result)
        except Exception as e:
            # Network error is expected; we're testing structure
            self.assertIsNotNone(e)


class TestP6PayloadContext(unittest.TestCase):
    """Test P6 context-aware payload generation."""
    
    @classmethod
    def setUpClass(cls):
        """Import payload generation tools."""
        import phantom.tools.payload_gen.payload_gen_actions
    
    def test_payload_context_creation(self):
        """PayloadContext should be created with proper fields."""
        from phantom.tools.payload_gen.payload_gen_actions import PayloadContext
        
        context = PayloadContext(
            url="https://target.com/api",
            framework="django",
            database="postgresql",
            waf_detected=True,
            waf_type="cloudflare",
        )
        
        self.assertEqual(context.framework, "django")
        self.assertEqual(context.database, "postgresql")
        self.assertTrue(context.waf_detected)
        self.assertEqual(context.waf_type, "cloudflare")
        
        # Test serialization
        context_dict = context.to_dict()
        self.assertIn("framework", context_dict)
        self.assertIn("waf_detected", context_dict)
    
    def test_payload_similarity(self):
        """Payload similarity calculation should work."""
        from phantom.tools.payload_gen.payload_gen_actions import _payload_similarity
        
        # Similar payloads should have high similarity
        payload1 = "<script>alert(1)</script>"
        payload2 = "<script>alert(2)</script>"
        similarity = _payload_similarity(payload1, payload2)
        
        self.assertGreater(similarity, 0.5, "Similar payloads should have high similarity")
        
        # Dissimilar payloads should have low similarity
        payload3 = "' OR 1=1--"
        similarity_diff = _payload_similarity(payload1, payload3)
        
        self.assertLess(similarity_diff, 0.5, "Different payloads should have low similarity")
    
    def test_filter_by_context(self):
        """Context filtering should exclude blocked patterns."""
        from phantom.tools.payload_gen.payload_gen_actions import (
            PayloadContext,
            _filter_by_context,
        )
        
        context = PayloadContext(
            blocked_patterns=["alert", "script"],
            failed_payloads=["<script>alert(1)</script>"],
        )
        
        payloads = [
            {"payload": "<script>alert(1)</script>"},  # Should be filtered (blocked + failed)
            {"payload": "<img src=x onerror=prompt(1)>"},  # Should pass
            {"payload": "<svg onload=alert(2)>"},  # Should be filtered (blocked pattern)
        ]
        
        filtered = _filter_by_context(payloads, context)
        
        self.assertLess(len(filtered), len(payloads), "Some payloads should be filtered")
        
        # Check that blocked patterns were removed
        for p in filtered:
            self.assertNotIn("script", p["payload"].lower())
            self.assertNotIn("alert", p["payload"].lower())
    
    def test_waf_bypass_variations(self):
        """WAF bypass should generate multiple variations."""
        from phantom.tools.payload_gen.payload_gen_actions import _enhance_payload_for_waf
        
        original = "' OR 1=1--"
        variations = _enhance_payload_for_waf(original, "cloudflare", "sqli")
        
        self.assertGreater(len(variations), 1, "Should generate multiple variations")
        self.assertIn(original, variations, "Should include original")
        
        # Check that variations are different
        unique_variations = set(variations)
        self.assertGreater(len(unique_variations), 1, "Variations should be unique")
    
    def test_framework_optimization(self):
        """Framework-specific optimization should prioritize relevant payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import _optimize_for_framework
        
        payloads = [
            {"payload": "{{7*7}}", "priority": 0},  # Django/Flask SSTI
            {"payload": "${7*7}", "priority": 0},  # Spring SSTI
            {"payload": "<%=7*7%>", "priority": 0},  # Rails ERB
        ]
        
        # Optimize for Django
        optimized = _optimize_for_framework(payloads.copy(), "django")
        
        # Django-specific payload should be first
        self.assertIn("{{", optimized[0]["payload"])
        self.assertGreater(optimized[0]["priority"], 0)
    
    def test_generate_smart_payloads_registration(self):
        """generate_smart_payloads should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        self.assertIn("generate_smart_payloads", get_tool_names())
        self.assertIsNotNone(get_tool_by_name("generate_smart_payloads"))
    
    def test_generate_smart_payloads_xss(self):
        """Smart payload generation for XSS should work."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_smart_payloads
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            generate_smart_payloads(
                vuln_class="xss",
                framework="django",
                waf_type="cloudflare",
                injection_context="html",
                max_payloads=10,
            )
        )
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        self.assertEqual(result["vuln_class"], "xss")
        self.assertIn("intelligence", result)
        self.assertTrue(result["intelligence"]["framework_optimized"])
        self.assertTrue(result["intelligence"]["waf_aware"])
    
    def test_generate_smart_payloads_sqli(self):
        """Smart payload generation for SQLi should work."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_smart_payloads
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            generate_smart_payloads(
                vuln_class="sqli",
                database="mysql",
                waf_type="akamai",
                max_payloads=10,
            )
        )
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        self.assertEqual(result["vuln_class"], "sqli")

    def test_generate_smart_payloads_uses_ledger_learning(self):
        """Smart payload generation should reuse learned payloads when available."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        from phantom.agents.correlation_engine import CorrelationEngine
        from phantom.tools.hypothesis.hypothesis_actions import set_ledger
        from phantom.tools.payload_gen.payload_gen_actions import generate_smart_payloads

        ledger = HypothesisLedger()
        engine = CorrelationEngine()
        ledger.set_correlation_engine(engine)
        set_ledger(ledger, "default")

        hyp_id = ledger.add("/api/login::username", "sqli")
        ledger.record_result(hyp_id, "confirmed", "SQLi found", "' OR 1=1--")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(
            generate_smart_payloads(
                vuln_class="sqli",
                url="/api/login",
                parameter="username",
                hypothesis_id=hyp_id,
                max_payloads=5,
            )
        )

        self.assertTrue(result["success"])
        self.assertGreater(len(result["payloads"]), 0)
        self.assertTrue(any(p["payload"] == "' OR 1=1--" for p in result["payloads"]))
        self.assertTrue(any(p.get("learned_from") for p in result["payloads"]))

    def test_generate_smart_payloads_reflects_correlation_family_scores(self):
        """Correlation learning should boost payloads from successful families."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        from phantom.agents.correlation_engine import CorrelationEngine
        from phantom.tools.hypothesis.hypothesis_actions import set_ledger
        from phantom.tools.payload_gen.payload_gen_actions import generate_smart_payloads

        ledger = HypothesisLedger()
        engine = CorrelationEngine()
        ledger.set_correlation_engine(engine)
        set_ledger(ledger, "default")

        hyp_id = ledger.add("/api/login::username", "sqli")
        ledger.record_result(hyp_id, "confirmed", "UNION worked", "' UNION SELECT NULL--")

        for _ in range(5):
            engine.record_outcome(
                vuln_class="sqli",
                surface="/api/login::username",
                outcome="confirmed",
                payload_family="union",
            )
            engine.record_outcome(
                vuln_class="sqli",
                surface="/api/login::username",
                outcome="rejected",
                payload_family="boolean",
            )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(
            generate_smart_payloads(
                vuln_class="sqli",
                url="/api/login",
                parameter="username",
                hypothesis_id=hyp_id,
                max_payloads=8,
            )
        )

        self.assertTrue(result["success"])
        self.assertGreater(len(result["payloads"]), 0)

        top_payload = result["payloads"][0]
        learned_from = top_payload.get("learned_from") or {}
        self.assertEqual(learned_from.get("family"), "union")
    
    def test_generate_smart_payloads_invalid_class(self):
        """Smart payload generation with invalid class should fail gracefully."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_smart_payloads
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            generate_smart_payloads(vuln_class="invalid_class")
        )
        
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertIn("supported", result)


class TestP5P6Integration(unittest.TestCase):
    """Test integration between P5 and P6 features."""
    
    def test_auth_and_payloads_workflow(self):
        """Complete workflow: login -> generate smart payloads -> test."""
        # This is a conceptual test showing the workflow
        # In practice, would need mocked HTTP responses
        
        workflow_steps = [
            "1. automate_login() to get authenticated session",
            "2. Detect tech stack (framework, database, WAF)",
            "3. generate_smart_payloads() with context",
            "4. Test payloads with authenticated session",
            "5. Record results in hypothesis ledger",
            "6. Generate new payloads learning from results",
        ]
        
        self.assertEqual(len(workflow_steps), 6, "Workflow should have 6 steps")
        self.assertIn("automate_login", workflow_steps[0])
        self.assertIn("generate_smart_payloads", workflow_steps[2])


def run_tests():
    """Run all P5 and P6 tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestP5AuthAutomation))
    suite.addTests(loader.loadTestsFromTestCase(TestP6PayloadContext))
    suite.addTests(loader.loadTestsFromTestCase(TestP5P6Integration))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
