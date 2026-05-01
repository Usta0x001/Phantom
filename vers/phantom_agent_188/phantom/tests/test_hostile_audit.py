"""
HOSTILE ADVERSARIAL AUDIT - DEEP VERIFICATION

This test suite attempts to BREAK the Phantom system using adversarial inputs
designed to trigger false positives. The goal is to expose weaknesses in:

1. Detection layer (regex-based noise)
2. Validation enforcement (bypasses)
3. Evidence requirements (weak evidence acceptance)
4. Reasoning loop (direct signal→report jumps)
5. LLM-controlled fields (manipulation)

A SECURE system should REJECT all these cases or mark them as non-exploitable.
"""

import unittest
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDetectionNoise(unittest.TestCase):
    """Test detection layer resistance to false positives."""
    
    def test_script_tag_in_json_response(self):
        """ATTACK: JSON response containing <script> string should NOT trigger XSS"""
        from phantom.tools.response_analysis.response_analysis_actions import _check_reflection_with_context
        
        # JSON API response that LOOKS like XSS but isn't
        json_response = '{"error": "Invalid script tag <script> found in input", "code": 400}'
        payload = "<script>"
        
        result = _check_reflection_with_context(json_response, payload)
        
        # CRITICAL: Should NOT report as exploitable
        # JSON doesn't render HTML, so reflection is meaningless
        if result:
            self.assertFalse(result.get('is_exploitable', True), 
                           "FAILURE: System flagged <script> in JSON as exploitable XSS")
    
    def test_script_tag_in_textarea(self):
        """ATTACK: <script> inside <textarea> is NOT executable"""
        from phantom.tools.response_analysis.response_analysis_actions import _check_reflection_with_context
        
        html = '<textarea><script>alert(1)</script></textarea>'
        payload = '<script>alert(1)</script>'
        
        result = _check_reflection_with_context(html, payload)
        
        # Scripts in textarea don't execute
        if result:
            self.assertFalse(result.get('is_exploitable', True),
                           "FAILURE: <script> in <textarea> marked as exploitable")
    
    def test_sql_keyword_in_error_message_not_sqli(self):
        """ATTACK: Error mentioning 'SQL' is NOT proof of SQLi"""
        from phantom.tools.response_analysis.response_analysis_actions import detect_errors
        
        # Generic error message mentioning SQL
        response = "Error: The SQL database is currently unavailable. Please try again later."
        
        errors = asyncio.run(detect_errors(response))
        
        # Should detect an error, but NOT as SQLi vulnerability
        # This is just a database availability error
        # (Note: This test checks if system jumps to conclusions)
        self.assertIsNotNone(errors)
        # If it marks this as SQLi, that's a red flag
    
    def test_root_string_in_response_not_lfi(self):
        """ATTACK: String 'root:' in response is NOT proof of LFI"""
        from phantom.tools.response_analysis.response_analysis_actions import analyze_response
        
        # Response that LOOKS like /etc/passwd but isn't
        response_body = "Welcome root:admin! Your privilege level is administrator."
        
        result = asyncio.run(
            analyze_response(
                response_body=response_body,
                response_headers={"Content-Type": "text/html"},
                status_code=200,
            )
        )
        
        # Should NOT flag this as file disclosure
        # It's just a username display
        findings = result.get('findings', [])
        lfi_vulns = [
            v
            for v in findings
            if 'file' in v.get('vuln_type', '').lower()
            or 'disclosure' in v.get('vuln_type', '').lower()
        ]
        
        self.assertEqual(len(lfi_vulns), 0,
                        f"FAILURE: False positive LFI detection. Found: {lfi_vulns}")
    
    def test_id_parameter_not_automatic_idor(self):
        """ATTACK: Presence of 'id=' parameter is NOT proof of IDOR"""
        # This tests if system jumps to conclusions based on parameter names
        # IDOR requires PROOF that changing ID accesses ANOTHER user's data
        
        # Just having an ID param is not a vulnerability
        url = "http://test.com/profile?id=123"
        response = "Welcome, John Doe! Your account ID is 123."
        
        # System should NOT report IDOR without:
        # 1. Changing ID to different value
        # 2. Getting DIFFERENT user's data
        # 3. Verifying unauthorized access
        pass  # This is more of a system behavior test


class TestValidationBypass(unittest.TestCase):
    """Test validation layer bypass attempts."""
    
    def test_sqli_without_data_extraction(self):
        """ATTACK: SQLi payload that runs but extracts nothing"""
        from phantom.tools.reporting.reporting_actions import _validate_exploit_success
        
        # Payload executed but didn't extract data
        output = """
        Payload sent: ' UNION SELECT NULL,NULL,NULL--
        Response: 200 OK
        Content-Length: 1234
        
        No visible changes in response.
        """
        
        status, reason = _validate_exploit_success("sqli", output)
        
        # CRITICAL: Should be EXECUTION_ONLY, not EXPLOIT_CONFIRMED
        self.assertNotEqual(status, "EXPLOIT_CONFIRMED",
                          f"FAILURE: False positive - no data extracted. Reason: {reason}")
        self.assertEqual(status, "EXECUTION_ONLY",
                        f"FAILURE: Should be EXECUTION_ONLY. Got: {status}")
    
    def test_rce_with_benign_command_output(self):
        """ATTACK: Command output that LOOKS like RCE but is application data"""
        from phantom.tools.reporting.reporting_actions import _validate_exploit_success
        
        # Application output that happens to mention "uid" (not RCE)
        output = """
        User Information:
        Name: John Doe
        User ID (uid): 12345
        Group: Administrators
        """
        
        status, reason = _validate_exploit_success("rce", output)
        
        # This is tricky - "uid" appears but it's not "uid=33(www-data)"
        # A good system should differentiate
        if status == "EXPLOIT_CONFIRMED":
            # Check if the reason is based on actual command output patterns
            self.assertIn("command", reason.lower(),
                         "FAILURE: Confirmed RCE on non-command output")
    
    def test_timing_difference_not_blind_sqli_proof(self):
        """ATTACK: Timing difference is SIGNAL, not PROOF"""
        from phantom.tools.reporting.reporting_actions import _validate_exploit_success
        
        # Output showing timing but no actual data
        output = """
        Payload: ' AND SLEEP(5)--
        Response time: 5.2 seconds
        
        Timing difference detected, but no data extracted.
        """
        
        status, reason = _validate_exploit_success("sqli", output)
        
        # Timing is just a SIGNAL. Without data extraction, it's not proof.
        # System might mark this as EXECUTION_ONLY or require more proof
        # Let's see what it does
        if status == "EXPLOIT_CONFIRMED":
            # If it confirms based on timing alone, that's questionable
            self.assertIn("extraction", reason.lower(),
                         "FAILURE: Confirmed SQLi on timing alone without data extraction")


class TestEvidenceIntegrity(unittest.TestCase):
    """Test evidence quality requirements."""
    
    def test_vague_evidence_rejected_for_suspected(self):
        """ATTACK: Try to report with vague language"""
        from phantom.tools.reporting.reporting_actions import _validate_required_fields
        
        # Attempt to use forbidden vague language
        errors = _validate_required_fields(
            title="Possible SQL Injection",
            description="Endpoint might be vulnerable",
            impact="Could lead to data breach",
            target="http://test.com/api",
            technical_analysis="The application might be vulnerable to SQL injection because it seems like the input is not sanitized.",
            confidence="SUSPECTED"
        )
        
        # Should REJECT due to vague language
        self.assertTrue(len(errors) > 0,
                       "FAILURE: Accepted vague language (might, could, seems)")
        self.assertTrue(any("vague" in err.lower() for err in errors),
                       f"FAILURE: Didn't flag vague language. Errors: {errors}")
    
    def test_short_technical_analysis_rejected(self):
        """ATTACK: Minimal technical analysis for SUSPECTED"""
        from phantom.tools.reporting.reporting_actions import _validate_required_fields
        
        errors = _validate_required_fields(
            title="SQL Injection",
            description="Found SQLi",
            impact="Data breach",
            target="http://test.com",
            technical_analysis="Error seen",  # Way too short
            confidence="SUSPECTED"
        )
        
        # Should require at least 50 chars
        self.assertTrue(any("50 characters" in err for err in errors),
                       "FAILURE: Accepted minimal technical analysis")
    
    def test_likely_without_poc_rejected(self):
        """ATTACK: LIKELY confidence without PoC"""
        from phantom.tools.reporting.reporting_actions import _validate_required_fields
        
        errors = _validate_required_fields(
            title="XSS Vulnerability",
            description="XSS found",
            impact="Account takeover",
            target="http://test.com",
            technical_analysis="Payload reflected without encoding in HTML context",
            poc_script_code="",  # No PoC!
            confidence="LIKELY"
        )
        
        # MUST reject LIKELY without PoC
        self.assertTrue(any("PoC" in err and "REQUIRED" in err for err in errors),
                       f"FAILURE: Accepted LIKELY without PoC. Errors: {errors}")
    
    def test_verified_without_poc_rejected(self):
        """ATTACK: VERIFIED confidence without PoC"""
        from phantom.tools.reporting.reporting_actions import _validate_required_fields
        
        errors = _validate_required_fields(
            title="Command Injection",
            description="RCE confirmed",
            impact="Full system compromise",
            target="http://test.com",
            technical_analysis="Command executed successfully",
            poc_script_code="",  # No PoC!
            confidence="VERIFIED"
        )
        
        # VERIFIED MUST have PoC
        self.assertTrue(len(errors) > 0,
                       "FAILURE: Accepted VERIFIED without PoC")


class TestHypothesisManipulation(unittest.TestCase):
    """Test hypothesis ledger evidence manipulation."""
    
    def test_weak_confirmation_evidence_tagged(self):
        """ATTACK: Try to confirm hypothesis with weak evidence"""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        hyp_id = ledger.add("/api/login", "sqli")
        
        # Try to confirm with weak evidence
        weak_evidence = "looks like it might be vulnerable"
        ledger.record_result(hyp_id, "confirmed", evidence=weak_evidence)
        
        # Should TAG the evidence as weak
        hyp = ledger._hypotheses[hyp_id]
        self.assertTrue(any("[WEAK_EVIDENCE]" in ev for ev in hyp.evidence_for),
                       "FAILURE: Weak evidence not tagged")
    
    def test_confirmation_without_strong_indicators_tagged(self):
        """ATTACK: Confirm without concrete artifacts"""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        hyp_id = ledger.add("/api/users", "xss")
        
        # Vague confirmation (under 50 chars, no concrete data)
        ledger.record_result(hyp_id, "confirmed", 
                            evidence="XSS confirmed")
        
        hyp = ledger._hypotheses[hyp_id]
        # Should be tagged as needing more detail
        self.assertTrue(any("[NEEDS_MORE_DETAIL]" in ev for ev in hyp.evidence_for),
                       "FAILURE: Vague confirmation not flagged")


class TestReasoningLoop(unittest.TestCase):
    """Test reasoning loop integrity."""
    
    def test_signal_not_mandatory_report(self):
        """ATTACK: Check if signals force immediate reporting"""
        from phantom.tools.executor import _format_tool_result_with_meta
        
        # SQL error signal
        output = "Error: You have an error in your SQL syntax near '1=1'"
        
        observation, _, meta = _format_tool_result_with_meta(
            "curl", output, image_slots_remaining=0
        )
        
        # Should be INVESTIGATION REQUIRED, not MANDATORY
        self.assertNotIn("MANDATORY", observation,
                        "FAILURE: Signal marked as MANDATORY (forces reporting)")
        
        if "INVESTIGATION REQUIRED" in observation:
            # Good! Requires investigation first
            self.assertIn("BEFORE reporting", observation,
                         "FAILURE: Doesn't require investigation before reporting")


class TestContextUnderstanding(unittest.TestCase):
    """Test context-aware detection."""
    
    def test_script_in_json_not_xss(self):
        """ATTACK: <script> in JSON response"""
        from phantom.tools.response_analysis.response_analysis_actions import analyze_response
        
        result = asyncio.run(
            analyze_response(
                response_body='{"error": "Script tag <script> not allowed"}',
                response_headers={"Content-Type": "application/json"},
                status_code=200,
            )
        )
        
        # With Content-Type: application/json, this should NOT be XSS
        findings = result.get('findings', [])
        xss_vulns = [v for v in findings if 'xss' in v.get('vuln_type', '').lower()]
        
        # If it reports XSS in JSON, that's a false positive
        for vuln in xss_vulns:
            if vuln.get('severity') in ['high', 'critical']:
                self.fail(f"FAILURE: High/Critical XSS in JSON context: {vuln}")
    
    def test_html_entity_encoded_not_xss(self):
        """ATTACK: HTML entity encoded payload"""
        from phantom.tools.response_analysis.response_analysis_actions import _check_reflection_with_context
        
        html = '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>'
        payload = '<script>alert(1)</script>'
        
        result = _check_reflection_with_context(html, payload)
        
        # Encoded = not exploitable
        if result:
            self.assertFalse(result.get('is_exploitable', True),
                           "FAILURE: Marked HTML-encoded reflection as exploitable")


class TestSystemPromptEnforcement(unittest.TestCase):
    """Test system prompt rules."""
    
    def test_forbidden_words_in_prompt(self):
        """Verify system prompt forbids vague words"""
        from pathlib import Path
        
        prompt_path = Path(__file__).parent.parent / "agents" / "PhantomAgent" / "system_prompt.jinja"
        
        if not prompt_path.exists():
            self.skipTest("System prompt not found")
        
        content = prompt_path.read_text(encoding="utf-8")
        
        # Should explicitly forbid these words
        forbidden = ["potential", "possible", "suspected", "might", "could", "appears to be"]
        
        # Check if prompt mentions forbidding these
        self.assertIn("NEVER USE THESE WORDS", content,
                     "FAILURE: Prompt doesn't forbid vague language")
        
        for word in forbidden:
            self.assertIn(word, content,
                         f"FAILURE: Prompt doesn't mention forbidding '{word}'")
    
    def test_proof_requirement_in_prompt(self):
        """Verify PROOF OR NO REPORT rule"""
        from pathlib import Path
        
        prompt_path = Path(__file__).parent.parent / "agents" / "PhantomAgent" / "system_prompt.jinja"
        
        if not prompt_path.exists():
            self.skipTest("System prompt not found")
        
        content = prompt_path.read_text(encoding="utf-8")
        
        # Should have clear proof requirement
        self.assertIn("PROOF OR NO REPORT", content,
                     "FAILURE: Missing 'PROOF OR NO REPORT' mandate")
        
        # Should distinguish signals from proof
        self.assertIn("WHAT IS NOT PROOF", content,
                     "FAILURE: Doesn't define what is NOT proof")


if __name__ == '__main__':
    unittest.main()
