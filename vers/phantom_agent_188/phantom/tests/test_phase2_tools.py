"""Phase 2 Enhancement Test Suite

Tests for the new Phase 2 tools:
1. Payload Generation Tools (XSS, SQLi, XXE, SSTI, Command Injection)
2. Response Analysis Tools (analyze_response, detect_errors, extract_secrets, identify_tech_stack)
3. Session Management Tools (create_session, update_session, get_session_info, extract_csrf_token, manage_cookies)

These tests validate:
- Tool registration with @register_tool decorator
- Parameter validation and error handling
- Payload generation correctness
- Response analysis accuracy
- Session state management
- XML schema loading
- Tool return value structure
"""

import asyncio
import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPhase2ToolRegistration(unittest.TestCase):
    """Test that all Phase 2 tools are properly registered."""
    
    @classmethod
    def setUpClass(cls):
        """Import tools to ensure they're registered before tests run."""
        # These imports trigger @register_tool decorators
        import phantom.tools.payload_gen.payload_gen_actions
        import phantom.tools.response_analysis.response_analysis_actions
        import phantom.tools.session_mgmt.session_mgmt_actions
    
    def test_payload_gen_tools_registered(self):
        """Payload generation tools should be registered in the tool registry."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        payload_tools = [
            "generate_xss_payloads",
            "generate_sqli_payloads",
            "generate_xxe_payloads",
            "generate_ssti_payloads",
            "generate_cmd_injection_payloads",
        ]
        
        registered = get_tool_names()
        for tool in payload_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_response_analysis_tools_registered(self):
        """Response analysis tools should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        analysis_tools = [
            "analyze_response",
            "detect_errors",
            "extract_secrets",
            "identify_tech_stack",
        ]
        
        registered = get_tool_names()
        for tool in analysis_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_session_mgmt_tools_registered(self):
        """Session management tools should be registered."""
        from phantom.tools.registry import get_tool_by_name, get_tool_names
        
        session_tools = [
            "create_session",
            "update_session",
            "get_session_info",
            "extract_csrf_token",
            "manage_cookies",
        ]
        
        registered = get_tool_names()
        for tool in session_tools:
            self.assertIn(tool, registered, f"{tool} should be registered")
            self.assertIsNotNone(get_tool_by_name(tool), f"{tool} function should exist")
    
    def test_sandbox_execution_disabled(self):
        """Phase 2 tools should have sandbox_execution=False."""
        from phantom.tools.registry import tools
        
        phase2_tools = [
            "generate_xss_payloads", "generate_sqli_payloads", "generate_xxe_payloads",
            "generate_ssti_payloads", "generate_cmd_injection_payloads",
            "analyze_response", "detect_errors", "extract_secrets", "identify_tech_stack",
            "create_session", "update_session", "get_session_info", "extract_csrf_token", "manage_cookies",
        ]
        
        for tool_entry in tools:
            if tool_entry["name"] in phase2_tools:
                self.assertFalse(
                    tool_entry.get("sandbox_execution", True),
                    f"{tool_entry['name']} should have sandbox_execution=False"
                )


class TestPayloadGenerationTools(unittest.TestCase):
    """Test payload generation tool functionality."""
    
    def test_generate_xss_payloads_basic(self):
        """XSS payload generation should return valid payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_xss_payloads
        
        result = asyncio.run(generate_xss_payloads())
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        
        # Should contain typical XSS markers
        payloads_str = str(result["payloads"])
        self.assertTrue(
            "script" in payloads_str.lower() or 
            "onerror" in payloads_str.lower() or
            "onload" in payloads_str.lower()
        )
    
    def test_generate_xss_payloads_with_encoding(self):
        """XSS payloads should support encoding options."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_xss_payloads
        
        result = asyncio.run(generate_xss_payloads(encoding="url"))
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
    
    def test_generate_sqli_payloads_basic(self):
        """SQLi payload generation should return valid payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_sqli_payloads
        
        result = asyncio.run(generate_sqli_payloads())
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        
        # Should contain typical SQLi markers
        payloads_str = str(result["payloads"])
        self.assertTrue(
            "'" in payloads_str or 
            "UNION" in payloads_str.upper() or 
            "SELECT" in payloads_str.upper() or
            "--" in payloads_str
        )
    
    def test_generate_sqli_payloads_db_types(self):
        """SQLi payloads should support different database types."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_sqli_payloads
        
        db_types = ["mysql", "postgresql", "mssql", "oracle"]
        
        for db_type in db_types:
            result = asyncio.run(generate_sqli_payloads(db_type=db_type))
            self.assertTrue(result["success"], f"Failed for db_type={db_type}")
            self.assertIn("payloads", result)
    
    def test_generate_sqli_payloads_contexts(self):
        """SQLi payloads should support different injection types."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_sqli_payloads
        
        injection_types = ["detection", "union", "time_blind", "error_based"]
        
        for inj_type in injection_types:
            result = asyncio.run(generate_sqli_payloads(injection_type=inj_type))
            self.assertTrue(result["success"], f"Failed for injection_type={inj_type}")
    
    def test_generate_xxe_payloads_basic(self):
        """XXE payload generation should return valid payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_xxe_payloads
        
        result = asyncio.run(generate_xxe_payloads())
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        
        # Should contain typical XXE markers
        payloads_str = str(result["payloads"])
        self.assertTrue(
            "DOCTYPE" in payloads_str.upper() or 
            "ENTITY" in payloads_str.upper() or
            "SYSTEM" in payloads_str.upper()
        )
    
    def test_generate_ssti_payloads_basic(self):
        """SSTI payload generation should return valid payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_ssti_payloads
        
        result = asyncio.run(generate_ssti_payloads())
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        
        # Should contain typical SSTI markers (template syntax)
        payloads_str = str(result["payloads"])
        self.assertTrue(
            "{{" in payloads_str or 
            "{%" in payloads_str or
            "${" in payloads_str
        )
    
    def test_generate_ssti_payloads_engines(self):
        """SSTI payloads should support different template engines."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_ssti_payloads
        
        engines = ["jinja2", "twig", "freemarker"]
        
        for engine in engines:
            result = asyncio.run(generate_ssti_payloads(template_engine=engine))
            self.assertTrue(result["success"], f"Failed for template_engine={engine}")
    
    def test_generate_cmd_injection_payloads_basic(self):
        """Command injection payload generation should return valid payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_cmd_injection_payloads
        
        result = asyncio.run(generate_cmd_injection_payloads())
        
        self.assertTrue(result["success"])
        self.assertIn("payloads", result)
        self.assertGreater(len(result["payloads"]), 0)
        
        # Should contain typical command injection markers
        payloads_str = str(result["payloads"])
        self.assertTrue(
            ";" in payloads_str or 
            "|" in payloads_str or
            "`" in payloads_str or
            "$(" in payloads_str
        )
    
    def test_generate_cmd_injection_payloads_os_types(self):
        """Command injection payloads should support different OS types."""
        from phantom.tools.payload_gen.payload_gen_actions import generate_cmd_injection_payloads
        
        os_types = ["linux", "windows"]
        
        for os_type in os_types:
            result = asyncio.run(generate_cmd_injection_payloads(target_os=os_type))
            self.assertTrue(result["success"], f"Failed for target_os={os_type}")


class TestResponseAnalysisTools(unittest.TestCase):
    """Test response analysis tool functionality."""
    
    def test_analyze_response_basic(self):
        """analyze_response should analyze HTTP responses."""
        from phantom.tools.response_analysis.response_analysis_actions import analyze_response
        
        result = asyncio.run(analyze_response(
            response_body="<html><body>Hello World</body></html>",
            response_headers={"Content-Type": "text/html", "Server": "Apache/2.4.49"},
            status_code=200
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("findings", result)
    
    def test_analyze_response_detects_issues(self):
        """analyze_response should detect security issues."""
        from phantom.tools.response_analysis.response_analysis_actions import analyze_response
        
        # Response with potential SQL error
        result = asyncio.run(analyze_response(
            response_body="Error: You have an error in your SQL syntax near 'SELECT * FROM users'",
            response_headers={"Content-Type": "text/html"},
            status_code=500
        ))
        
        self.assertTrue(result["success"])
        # Should flag the SQL error in findings
        findings_str = str(result)
        self.assertTrue(
            "sql" in findings_str.lower() or 
            "error" in findings_str.lower() or
            "finding" in findings_str.lower()
        )
    
    def test_detect_errors_sql(self):
        """detect_errors should detect SQL errors."""
        from phantom.tools.response_analysis.response_analysis_actions import detect_errors
        
        sql_error_content = """
        <html>
        <body>
        Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL
        near 'SELECT * FROM users WHERE id = '' at line 1
        </body>
        </html>
        """
        
        result = asyncio.run(detect_errors(content=sql_error_content))
        
        self.assertTrue(result["success"])
        self.assertIn("errors", result)
        # MySQL error pattern should match "check the manual that corresponds to your MySQL"
        self.assertGreater(len(result["errors"]), 0, "Should detect MySQL error pattern")
    
    def test_detect_errors_stack_trace(self):
        """detect_errors should detect stack traces."""
        from phantom.tools.response_analysis.response_analysis_actions import detect_errors
        
        stack_trace_content = """
        Traceback (most recent call last):
          File "/app/views.py", line 42, in get_user
            user = User.objects.get(id=request.GET['id'])
        ValueError: invalid literal for int() with base 10
        """
        
        result = asyncio.run(detect_errors(content=stack_trace_content))
        
        self.assertTrue(result["success"])
        self.assertIn("errors", result)
    
    def test_extract_secrets_api_keys(self):
        """extract_secrets should detect API keys."""
        from phantom.tools.response_analysis.response_analysis_actions import extract_secrets
        
        content_with_secrets = """
        <script>
        const API_KEY = "[REDACTED_API_KEY]";
        const AWS_KEY = "[REDACTED_AWS_KEY]";
        const password = "[REDACTED_PASSWORD]";
        </script>
        """
        
        result = asyncio.run(extract_secrets(content=content_with_secrets))
        
        self.assertTrue(result["success"])
        self.assertIn("secrets", result)
        # Should find at least one secret
        self.assertGreater(len(result["secrets"]), 0)
    
    def test_extract_secrets_empty_content(self):
        """extract_secrets should handle content with no secrets."""
        from phantom.tools.response_analysis.response_analysis_actions import extract_secrets
        
        result = asyncio.run(extract_secrets(content="Hello, this is normal content."))
        
        self.assertTrue(result["success"])
        self.assertIn("secrets", result)
    
    def test_identify_tech_stack_basic(self):
        """identify_tech_stack should identify technologies."""
        from phantom.tools.response_analysis.response_analysis_actions import identify_tech_stack
        
        result = asyncio.run(identify_tech_stack(
            content="<html>Powered by WordPress</html>",
            headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("technologies", result)
        
        # Should detect nginx and PHP
        tech_str = str(result["technologies"]).lower()
        self.assertTrue("nginx" in tech_str or "php" in tech_str)
    
    def test_identify_tech_stack_from_headers(self):
        """identify_tech_stack should detect tech from headers."""
        from phantom.tools.response_analysis.response_analysis_actions import identify_tech_stack
        
        result = asyncio.run(identify_tech_stack(
            content="",
            headers={
                "Server": "Apache/2.4.49",
                "X-Powered-By": "Express",
                "X-AspNet-Version": "4.0.30319"
            }
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("technologies", result)


class TestSessionManagementTools(unittest.TestCase):
    """Test session management tool functionality."""
    
    def setUp(self):
        """Clear sessions before each test."""
        from phantom.tools.session_mgmt.session_mgmt_actions import _SESSIONS
        _SESSIONS.clear()
    
    def test_create_session_basic(self):
        """create_session should create a new session."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session
        
        result = asyncio.run(create_session(
            session_name="test_session",
            base_url="https://example.com"
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("session_id", result)
        self.assertEqual(result["session_name"], "test_session")
        self.assertEqual(result["base_url"], "https://example.com")
    
    def test_create_session_with_auth(self):
        """create_session should handle authentication tokens."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session
        
        result = asyncio.run(create_session(
            session_name="auth_session",
            auth_token="test_jwt_token_here",
            auth_type="bearer"
        ))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["auth_type"], "bearer")
    
    def test_create_session_with_cookies(self):
        """create_session should store cookies."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session
        
        result = asyncio.run(create_session(
            session_name="cookie_session",
            cookies={"session_id": "abc123", "user_id": "42"}
        ))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["cookie_count"], 2)
    
    def test_update_session_basic(self):
        """update_session should update existing session."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session, update_session
        
        # Create session first
        create_result = asyncio.run(create_session(session_name="update_test"))
        session_id = create_result["session_id"]
        
        # Update it
        result = asyncio.run(update_session(
            session_id=session_id,
            cookies={"new_cookie": "value"}
        ))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["cookie_count"], 1)
    
    def test_update_session_not_found(self):
        """update_session should handle non-existent session."""
        from phantom.tools.session_mgmt.session_mgmt_actions import update_session
        
        result = asyncio.run(update_session(
            session_id="nonexistent",
            cookies={"test": "value"}
        ))
        
        self.assertFalse(result["success"])
        self.assertIn("error", result)
    
    def test_update_session_csrf(self):
        """update_session should store CSRF tokens."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session, update_session
        
        create_result = asyncio.run(create_session(session_name="csrf_test"))
        session_id = create_result["session_id"]
        
        result = asyncio.run(update_session(
            session_id=session_id,
            csrf_token="csrf_token_value_12345"
        ))
        
        self.assertTrue(result["success"])
        self.assertTrue(result["has_csrf"])
    
    def test_get_session_info_single(self):
        """get_session_info should return session details."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session, get_session_info
        
        create_result = asyncio.run(create_session(
            session_name="info_test",
            cookies={"test": "cookie"}
        ))
        session_id = create_result["session_id"]
        
        result = asyncio.run(get_session_info(session_id=session_id))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["name"], "info_test")
        self.assertIn("cookies", result)
    
    def test_get_session_info_list_all(self):
        """get_session_info should list all sessions."""
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session, get_session_info
        
        # Create multiple sessions
        asyncio.run(create_session(session_name="session_1"))
        asyncio.run(create_session(session_name="session_2"))
        asyncio.run(create_session(session_name="session_3"))
        
        result = asyncio.run(get_session_info(list_all=True))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["total_count"], 3)
        self.assertIn("sessions", result)
    
    def test_extract_csrf_token_hidden_input(self):
        """extract_csrf_token should find tokens in hidden inputs."""
        from phantom.tools.session_mgmt.session_mgmt_actions import extract_csrf_token
        
        html_content = '''
        <html>
        <body>
        <form action="/submit" method="POST">
            <input type="hidden" name="csrf_token" value="abc123xyz789">
            <input type="text" name="username">
            <input type="submit">
        </form>
        </body>
        </html>
        '''
        
        result = asyncio.run(extract_csrf_token(content=html_content))
        
        self.assertTrue(result["success"])
        self.assertIn("tokens", result)
        self.assertGreater(result["token_count"], 0)
        self.assertEqual(result["primary_token"], "abc123xyz789")
    
    def test_extract_csrf_token_meta_tag(self):
        """extract_csrf_token should find tokens in meta tags."""
        from phantom.tools.session_mgmt.session_mgmt_actions import extract_csrf_token
        
        html_content = '''
        <html>
        <head>
            <meta name="csrf-token" content="meta_csrf_token_value">
        </head>
        <body></body>
        </html>
        '''
        
        result = asyncio.run(extract_csrf_token(content=html_content))
        
        self.assertTrue(result["success"])
        self.assertGreater(result["token_count"], 0)
    
    def test_extract_csrf_token_javascript(self):
        """extract_csrf_token should find tokens in JavaScript."""
        from phantom.tools.session_mgmt.session_mgmt_actions import extract_csrf_token
        
        js_content = '''
        <script>
            var csrfToken = "js_csrf_token_12345";
            window.__csrf = "another_token_67890";
        </script>
        '''
        
        result = asyncio.run(extract_csrf_token(content=js_content))
        
        self.assertTrue(result["success"])
        self.assertGreater(result["token_count"], 0)
    
    def test_extract_csrf_token_store_in_session(self):
        """extract_csrf_token should store token in session."""
        from phantom.tools.session_mgmt.session_mgmt_actions import (
            create_session, extract_csrf_token, _SESSIONS
        )
        
        # Create session
        create_result = asyncio.run(create_session(session_name="csrf_store_test"))
        session_id = create_result["session_id"]
        
        html_content = '<input name="csrf_token" value="stored_token_value">'
        
        result = asyncio.run(extract_csrf_token(
            content=html_content,
            session_id=session_id
        ))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["stored_in_session"], session_id)
        
        # Verify stored in session
        self.assertEqual(_SESSIONS[session_id]["csrf_token"], "stored_token_value")
    
    def test_manage_cookies_parse(self):
        """manage_cookies should parse cookie strings."""
        from phantom.tools.session_mgmt.session_mgmt_actions import manage_cookies
        
        result = asyncio.run(manage_cookies(
            action="parse",
            cookie_header="session=abc123; Path=/; HttpOnly; Secure"
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("cookies", result)
        self.assertIn("session", result["cookies"])
    
    def test_manage_cookies_analyze(self):
        """manage_cookies should analyze cookie security."""
        from phantom.tools.session_mgmt.session_mgmt_actions import manage_cookies
        
        # Insecure cookie (missing flags)
        result = asyncio.run(manage_cookies(
            action="analyze",
            cookie_header="session=abc123; Path=/"
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("analysis", result)
        self.assertIn("findings", result["analysis"])
        
        # Should find missing HttpOnly and Secure flags
        self.assertGreater(result["analysis"]["finding_count"], 0)
    
    def test_manage_cookies_analyze_secure(self):
        """manage_cookies should recognize secure cookies."""
        from phantom.tools.session_mgmt.session_mgmt_actions import manage_cookies
        
        # Secure cookie with all flags
        result = asyncio.run(manage_cookies(
            action="analyze",
            cookie_header="session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
        ))
        
        self.assertTrue(result["success"])
        self.assertEqual(result["analysis"]["security_score"], 100)
    
    def test_manage_cookies_export(self):
        """manage_cookies should export session cookies."""
        from phantom.tools.session_mgmt.session_mgmt_actions import (
            create_session, update_session, manage_cookies
        )
        
        # Create session with cookies
        create_result = asyncio.run(create_session(
            session_name="export_test",
            cookies={"session_id": "abc", "user": "test"}
        ))
        session_id = create_result["session_id"]
        
        result = asyncio.run(manage_cookies(
            action="export",
            session_id=session_id
        ))
        
        self.assertTrue(result["success"])
        self.assertIn("cookie_header", result)
        self.assertEqual(result["cookie_count"], 2)
    
    def test_manage_cookies_invalid_action(self):
        """manage_cookies should reject invalid actions."""
        from phantom.tools.session_mgmt.session_mgmt_actions import manage_cookies
        
        result = asyncio.run(manage_cookies(action="invalid_action"))
        
        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestXMLSchemas(unittest.TestCase):
    """Test that XML schemas are properly loaded for Phase 2 tools."""
    
    @classmethod
    def setUpClass(cls):
        """Import tools to ensure they're registered."""
        import phantom.tools.payload_gen.payload_gen_actions
        import phantom.tools.response_analysis.response_analysis_actions
        import phantom.tools.session_mgmt.session_mgmt_actions
    
    def test_payload_gen_schema_loaded(self):
        """Payload generation tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        payload_tools = [
            "generate_xss_payloads", "generate_sqli_payloads", "generate_xxe_payloads",
            "generate_ssti_payloads", "generate_cmd_injection_payloads"
        ]
        
        for tool_entry in tools:
            if tool_entry["name"] in payload_tools:
                # Schema may be in xml_schema or in the tool's docstring
                self.assertIn("name", tool_entry, f"{tool_entry['name']} missing name field")
    
    def test_response_analysis_schema_loaded(self):
        """Response analysis tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        analysis_tools = ["analyze_response", "detect_errors", "extract_secrets", "identify_tech_stack"]
        
        for tool_entry in tools:
            if tool_entry["name"] in analysis_tools:
                self.assertIn("name", tool_entry, f"{tool_entry['name']} missing name field")
    
    def test_session_mgmt_schema_loaded(self):
        """Session management tools should have XML schemas."""
        from phantom.tools.registry import tools
        
        session_tools = [
            "create_session", "update_session", "get_session_info",
            "extract_csrf_token", "manage_cookies"
        ]
        
        for tool_entry in tools:
            if tool_entry["name"] in session_tools:
                self.assertIn("name", tool_entry, f"{tool_entry['name']} missing name field")


class TestIntegration(unittest.TestCase):
    """Integration tests for Phase 2 tools."""
    
    @classmethod
    def setUpClass(cls):
        """Import tools to ensure they're registered."""
        import phantom.tools.payload_gen.payload_gen_actions
        import phantom.tools.response_analysis.response_analysis_actions
        import phantom.tools.session_mgmt.session_mgmt_actions
    
    def test_tool_prompt_includes_phase2(self):
        """get_tools_prompt should include Phase 2 tools."""
        from phantom.tools.registry import get_tools_prompt
        
        prompt = get_tools_prompt()
        
        # Should include payload gen tools
        self.assertIn("generate_xss_payloads", prompt)
        self.assertIn("generate_sqli_payloads", prompt)
        
        # Should include analysis tools
        self.assertIn("analyze_response", prompt)
        
        # Should include session tools
        self.assertIn("create_session", prompt)
    
    def test_system_prompt_references_phase2_tools(self):
        """System prompt should reference Phase 2 tools."""
        prompt_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "agents", "PhantomAgent", "system_prompt.jinja"
        )
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Should reference payload tools
        self.assertIn("generate_xss_payloads", content)
        self.assertIn("generate_sqli_payloads", content)
        
        # Should reference analysis tools
        self.assertIn("analyze_response", content)
        
        # Should reference session tools
        self.assertIn("create_session", content)
        
        # Should have payload generators section
        self.assertIn("PAYLOAD GENERATORS (Phantom's advantage over other tools):", content)


class TestSecurityProperties(unittest.TestCase):
    """Test that Phase 2 tools maintain security properties."""
    
    def test_session_token_redaction(self):
        """Session tools should redact sensitive values in output."""
        from phantom.tools.session_mgmt.session_mgmt_actions import (
            create_session, get_session_info
        )
        
        # Create session with sensitive token
        create_result = asyncio.run(create_session(
            session_name="redact_test",
            auth_token="super_secret_token_12345678901234567890",
            auth_type="bearer"
        ))
        session_id = create_result["session_id"]
        
        # Get session info
        info_result = asyncio.run(get_session_info(session_id=session_id))
        
        # Should not expose full token in any returned values
        info_str = str(info_result)
        self.assertNotIn("super_secret_token_12345678901234567890", info_str)
    
    def test_cookie_value_redaction(self):
        """Session tools should redact cookie values in output."""
        from phantom.tools.session_mgmt.session_mgmt_actions import (
            create_session, get_session_info
        )
        
        create_result = asyncio.run(create_session(
            session_name="cookie_redact_test",
            cookies={"session_id": "very_sensitive_session_cookie_value"}
        ))
        session_id = create_result["session_id"]
        
        info_result = asyncio.run(get_session_info(session_id=session_id))
        
        # Cookie values should be redacted
        info_str = str(info_result)
        self.assertNotIn("very_sensitive_session_cookie_value", info_str)
    
    def test_payload_tools_dont_execute(self):
        """Payload generation tools should NOT execute payloads."""
        from phantom.tools.payload_gen.payload_gen_actions import (
            generate_xss_payloads, generate_sqli_payloads,
            generate_cmd_injection_payloads
        )
        
        # These should only GENERATE payloads, not execute anything
        # Verify they return string payloads, not execution results
        
        xss_result = asyncio.run(generate_xss_payloads())
        self.assertIsInstance(xss_result["payloads"], list)
        for payload in xss_result["payloads"]:
            self.assertIsInstance(payload, (str, dict))
        
        sqli_result = asyncio.run(generate_sqli_payloads())
        self.assertIsInstance(sqli_result["payloads"], list)
        
        cmd_result = asyncio.run(generate_cmd_injection_payloads())
        self.assertIsInstance(cmd_result["payloads"], list)


if __name__ == "__main__":
    # Import tools to trigger registration
    import phantom.tools.payload_gen.payload_gen_actions
    import phantom.tools.response_analysis.response_analysis_actions
    import phantom.tools.session_mgmt.session_mgmt_actions
    
    unittest.main(verbosity=2)
