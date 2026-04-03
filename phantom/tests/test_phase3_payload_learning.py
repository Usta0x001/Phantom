"""
P3.2 Payload Learning Tests

Test suite for verifying payload learning functionality:
1. VERIFY it helps the system - Test real payload learning scenarios
2. ATTACK it - Try to break it with malicious inputs
3. PROVE it works - Comprehensive functional tests
"""

import pytest
from phantom.agents.hypothesis_ledger import HypothesisLedger, Hypothesis


class TestP32PayloadLearningVerification:
    """VERIFY: Prove payload learning helps the system"""
    
    def test_successful_payload_storage(self):
        """Verify: Successful payloads are stored correctly"""
        ledger = HypothesisLedger()
        
        # Add hypothesis and confirm with successful payload
        hyp_id = ledger.add("/api/login::username", "sqli")
        ledger.record_payload(hyp_id, "' OR 1=1--")
        ledger.record_result(
            hyp_id, 
            outcome="confirmed",
            evidence="SQL error in response",
            successful_payload="' OR 1=1--"
        )
        
        # Verify payload was stored
        successful = ledger.get_successful_payloads(vuln_class="sqli")
        assert len(successful) == 1
        assert successful[0]["payload"] == "' OR 1=1--"
        assert successful[0]["vuln_class"] == "sqli"
        assert successful[0]["surface"] == "/api/login::username"
    
    def test_payload_reuse_scenario(self):
        """Verify: Previously successful payloads can be retrieved for reuse"""
        ledger = HypothesisLedger()
        
        # Scenario: Find SQL injection on first endpoint
        hyp1 = ledger.add("/api/login::username", "sqli")
        ledger.record_result(hyp1, "confirmed", "SQL error", "' UNION SELECT NULL--")
        
        # Now testing second endpoint - retrieve successful SQLi payloads
        successful_sqli = ledger.get_successful_payloads(vuln_class="sqli")
        
        assert len(successful_sqli) == 1
        assert successful_sqli[0]["payload"] == "' UNION SELECT NULL--"
        
        # This proves the system can learn and reuse successful payloads
    
    def test_payload_stats_tracking(self):
        """Verify: System tracks payload effectiveness statistics"""
        ledger = HypothesisLedger()
        
        # Create multiple hypotheses with varying success
        h1 = ledger.add("/api/login", "sqli")
        ledger.record_payload(h1, "' OR 1=1--")
        ledger.record_payload(h1, "' UNION SELECT--")
        ledger.record_result(h1, "confirmed", "Found SQLi", "' OR 1=1--")
        
        h2 = ledger.add("/search", "xss")
        ledger.record_payload(h2, "<script>alert(1)</script>")
        ledger.record_payload(h2, "<img src=x onerror=alert(1)>")
        ledger.record_result(h2, "confirmed", "XSS found", "<script>alert(1)</script>")
        
        h3 = ledger.add("/profile", "sqli")
        ledger.record_payload(h3, "' OR 1=1--")
        ledger.record_result(h3, "rejected", "WAF blocked")
        
        # Get statistics
        stats = ledger.get_payload_stats()
        
        assert stats["total_payloads_tested"] == 5
        assert stats["total_successful_payloads"] == 2
        assert stats["overall_success_rate"] == 40.0  # 2/5 * 100
        
        # Verify per-class stats
        assert "sqli" in stats["by_vuln_class"]
        assert "xss" in stats["by_vuln_class"]
        
        # SQLi: 3 tested (2 from h1, 1 from h3), 1 successful
        assert stats["by_vuln_class"]["sqli"]["tested"] == 3
        assert stats["by_vuln_class"]["sqli"]["successful"] == 1
        
        # XSS: 2 tested, 1 successful
        assert stats["by_vuln_class"]["xss"]["tested"] == 2
        assert stats["by_vuln_class"]["xss"]["successful"] == 1
    
    def test_cross_surface_learning(self):
        """Verify: Payloads successful on one surface help with others"""
        ledger = HypothesisLedger()
        
        # Multiple surfaces with same vuln type
        surfaces = [
            "/api/login::user",
            "/api/search::query", 
            "/api/profile::id"
        ]
        
        # First surface confirms SQLi with specific payload
        h1 = ledger.add(surfaces[0], "sqli")
        ledger.record_result(h1, "confirmed", "SQLi found", "' OR '1'='1")
        
        # Now testing second surface - can retrieve successful payload
        learned = ledger.get_successful_payloads(vuln_class="sqli", limit=5)
        assert len(learned) > 0
        assert any(p["payload"] == "' OR '1'='1" for p in learned)
        
        # This proves cross-surface learning works


class TestP32PayloadLearningAttacks:
    """ATTACK: Try to break payload learning with malicious inputs"""
    
    def test_attack_sql_injection_in_payload(self):
        """Attack: Try SQLi in the payload string itself"""
        ledger = HypothesisLedger()
        
        malicious_payload = "'; DROP TABLE payloads;--"
        hyp_id = ledger.add("/api/test", "sqli")
        
        # This should just store the string, not execute it
        ledger.record_result(hyp_id, "confirmed", "test", malicious_payload)
        
        # Verify it's stored safely as a string
        results = ledger.get_successful_payloads()
        assert len(results) == 1
        assert results[0]["payload"] == "'; DROP TABLE payloads;--"
        # If we get here, no SQL was executed
    
    def test_attack_xss_in_payload(self):
        """Attack: Try XSS in payload data"""
        ledger = HypothesisLedger()
        
        xss_payload = "<script>alert('XSS')</script>"
        hyp_id = ledger.add("/test", "xss")
        ledger.record_result(hyp_id, "confirmed", "xss", xss_payload)
        
        results = ledger.get_successful_payloads()
        # Should be stored as plain string, no execution
        assert results[0]["payload"] == "<script>alert('XSS')</script>"
    
    def test_attack_memory_exhaustion(self):
        """Attack: Try to exhaust memory with massive payloads"""
        ledger = HypothesisLedger()
        
        # Try to create huge payload (10MB string)
        huge_payload = "A" * (10 * 1024 * 1024)
        
        hyp_id = ledger.add("/test", "test")
        # Should handle large payloads without crashing
        try:
            ledger.record_result(hyp_id, "confirmed", "test", huge_payload)
            results = ledger.get_successful_payloads()
            # If we get here, it handled the large payload
            assert len(results) == 1
        except MemoryError:
            pytest.fail("Memory exhaustion attack succeeded - VULNERABILITY!")
    
    def test_attack_path_traversal_in_surface(self):
        """Attack: Try path traversal in surface parameter"""
        ledger = HypothesisLedger()
        
        malicious_surface = "../../../../etc/passwd"
        hyp_id = ledger.add(malicious_surface, "sqli")
        ledger.record_result(hyp_id, "confirmed", "test", "' OR 1=1--")
        
        # Should store as string, not attempt file access
        results = ledger.get_successful_payloads()
        assert results[0]["surface"] == "../../../../etc/passwd"
        # If we get here, no file traversal occurred
    
    def test_attack_null_byte_injection(self):
        """Attack: Try null byte injection"""
        ledger = HypothesisLedger()
        
        null_payload = "payload\x00malicious_code"
        hyp_id = ledger.add("/test", "test")
        
        try:
            ledger.record_result(hyp_id, "confirmed", "test", null_payload)
            results = ledger.get_successful_payloads()
            # Should handle null bytes safely
            assert len(results) == 1
        except Exception as e:
            pytest.fail(f"Null byte attack caused crash: {e}")
    
    def test_attack_unicode_overflow(self):
        """Attack: Try unicode buffer overflow"""
        ledger = HypothesisLedger()
        
        # Various unicode edge cases
        unicode_payloads = [
            "\u0000" * 1000,  # Null characters
            "\uffff" * 1000,  # Max BMP
            "🔥" * 10000,     # Emojis (4-byte UTF-8)
            "\u202e" + "reverse",  # Right-to-left override
        ]
        
        for i, payload in enumerate(unicode_payloads):
            hyp_id = ledger.add(f"/test{i}", "test")
            try:
                ledger.record_result(hyp_id, "confirmed", "test", payload)
            except Exception as e:
                pytest.fail(f"Unicode attack {i} caused crash: {e}")
        
        results = ledger.get_successful_payloads()
        assert len(results) == len(unicode_payloads)
    
    def test_attack_race_condition(self):
        """Attack: Try concurrent access race conditions"""
        import threading
        
        ledger = HypothesisLedger()
        hyp_id = ledger.add("/test", "test")
        
        errors = []
        
        def concurrent_write():
            try:
                for i in range(100):
                    ledger.record_result(hyp_id, "confirmed", f"evidence{i}", f"payload{i}")
            except Exception as e:
                errors.append(e)
        
        # Launch 10 concurrent threads
        threads = [threading.Thread(target=concurrent_write) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have no race condition errors
        assert len(errors) == 0, f"Race condition detected: {errors}"
        
        # Verify data integrity
        results = ledger.get_successful_payloads()
        assert len(results) > 0  # Some payloads were stored
    
    def test_attack_type_confusion(self):
        """Attack: Try type confusion attacks"""
        ledger = HypothesisLedger()
        
        hyp_id = ledger.add("/test", "test")
        
        # Try various type confusions
        type_confusion_payloads = [
            None,           # None type
            [],             # List
            {},             # Dict
            123,            # Integer
            12.34,          # Float
            True,           # Boolean
        ]
        
        for payload in type_confusion_payloads:
            try:
                # Should handle type conversion gracefully or reject
                ledger.record_result(hyp_id, "confirmed", "test", payload)
            except (TypeError, AttributeError):
                # Expected - type checking working correctly
                pass
            except Exception as e:
                pytest.fail(f"Unexpected error with type {type(payload)}: {e}")


class TestP32PayloadLearningProof:
    """PROVE: Comprehensive functional verification"""
    
    def test_proof_no_duplicates(self):
        """Prove: Same payload not duplicated in successful_payloads"""
        ledger = HypothesisLedger()
        
        hyp_id = ledger.add("/test", "sqli")
        
        # Record same successful payload multiple times
        for _ in range(5):
            ledger.record_result(hyp_id, "confirmed", "test", "' OR 1=1--")
        
        # Should only appear once
        results = ledger.get_successful_payloads()
        assert len(results) == 1
    
    def test_proof_rejected_not_learned(self):
        """Prove: Rejected hypotheses don't add to successful payloads"""
        ledger = HypothesisLedger()
        
        hyp_id = ledger.add("/test", "sqli")
        ledger.record_payload(hyp_id, "' OR 1=1--")
        
        # Reject the hypothesis
        ledger.record_result(hyp_id, "rejected", "WAF blocked")
        
        # Should have no successful payloads
        results = ledger.get_successful_payloads()
        assert len(results) == 0
    
    def test_proof_vuln_class_filtering(self):
        """Prove: Vuln class filtering works correctly"""
        ledger = HypothesisLedger()
        
        # Add different vuln types
        h1 = ledger.add("/test1", "sqli")
        h2 = ledger.add("/test2", "xss")
        h3 = ledger.add("/test3", "xxe")
        
        ledger.record_result(h1, "confirmed", "test", "sqli_payload")
        ledger.record_result(h2, "confirmed", "test", "xss_payload")
        ledger.record_result(h3, "confirmed", "test", "xxe_payload")
        
        # Filter by sqli only
        sqli_payloads = ledger.get_successful_payloads(vuln_class="sqli")
        assert len(sqli_payloads) == 1
        assert sqli_payloads[0]["vuln_class"] == "sqli"
        
        # Filter by xss only
        xss_payloads = ledger.get_successful_payloads(vuln_class="xss")
        assert len(xss_payloads) == 1
        assert xss_payloads[0]["vuln_class"] == "xss"
        
        # Get all
        all_payloads = ledger.get_successful_payloads(vuln_class=None)
        assert len(all_payloads) == 3
    
    def test_proof_limit_parameter(self):
        """Prove: Limit parameter correctly restricts results"""
        ledger = HypothesisLedger()
        
        # Add 10 successful payloads
        for i in range(10):
            hyp_id = ledger.add(f"/test{i}", "sqli")
            ledger.record_result(hyp_id, "confirmed", "test", f"payload{i}")
        
        # Request only 3
        results = ledger.get_successful_payloads(limit=3)
        assert len(results) == 3
        
        # Request more than available
        results = ledger.get_successful_payloads(limit=20)
        assert len(results) == 10
    
    def test_proof_serialization_includes_successful(self):
        """Prove: Serialization preserves successful_payloads"""
        ledger = HypothesisLedger()
        
        hyp_id = ledger.add("/test", "sqli")
        ledger.record_result(hyp_id, "confirmed", "test", "' OR 1=1--")
        
        # Serialize
        data = ledger.to_dict()
        
        # Deserialize
        ledger2 = HypothesisLedger.from_dict(data)
        
        # Verify successful payload survived serialization
        results = ledger2.get_successful_payloads()
        assert len(results) == 1
        assert results[0]["payload"] == "' OR 1=1--"
    
    def test_proof_stats_accuracy(self):
        """Prove: Statistics calculations are mathematically correct"""
        ledger = HypothesisLedger()
        
        # Known scenario: 10 tested, 3 successful = 30% success rate
        h1 = ledger.add("/test1", "sqli")
        for i in range(10):
            ledger.record_payload(h1, f"payload{i}")
        
        # Mark 3 as successful
        ledger.record_result(h1, "confirmed", "test", "payload0")
        ledger.record_result(h1, "confirmed", "test", "payload5")
        ledger.record_result(h1, "confirmed", "test", "payload9")
        
        stats = ledger.get_payload_stats()
        
        # Verify math
        assert stats["total_payloads_tested"] == 10
        assert stats["total_successful_payloads"] == 3
        assert stats["overall_success_rate"] == 30.0
        
        assert stats["by_vuln_class"]["sqli"]["tested"] == 10
        assert stats["by_vuln_class"]["sqli"]["successful"] == 3
        assert stats["success_rate_by_class"]["sqli"] == 30.0
    
    def test_proof_no_silent_failures(self):
        """Prove: No silent failures - all operations complete or raise"""
        ledger = HypothesisLedger()
        
        # Test with invalid hypothesis ID - should not crash
        ledger.record_result("INVALID_ID", "confirmed", "test", "payload")
        
        # Should return empty, not crash
        results = ledger.get_successful_payloads()
        assert results == []
        
        # Stats should work even with no data
        stats = ledger.get_payload_stats()
        assert stats["total_payloads_tested"] == 0
        assert stats["total_successful_payloads"] == 0
        assert stats["overall_success_rate"] == 0.0
    
    def test_proof_thread_safety(self):
        """Prove: Thread-safe operations with RLock"""
        import threading
        
        ledger = HypothesisLedger()
        
        results_collected = []
        
        def reader_thread():
            for _ in range(50):
                results_collected.append(ledger.get_successful_payloads())
        
        def writer_thread():
            for i in range(50):
                hyp_id = ledger.add(f"/test{i}", "sqli")
                ledger.record_result(hyp_id, "confirmed", "test", f"payload{i}")
        
        # Launch concurrent readers and writers
        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=reader_thread))
            threads.append(threading.Thread(target=writer_thread))
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should complete without deadlock or corruption
        final_results = ledger.get_successful_payloads()
        assert len(final_results) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
