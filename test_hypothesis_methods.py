"""
Test the 8 new hypothesis_ledger methods.
"""

import asyncio
from phantom.agents.hypothesis_ledger import HypothesisLedger


async def test_get_all():
    """Test get_all() method."""
    ledger = HypothesisLedger()
    
    # Empty ledger
    all_hyps = ledger.get_all()
    assert len(all_hyps) == 0, "Empty ledger should return empty dict"
    
    # Add some hypotheses
    h1 = ledger.add("/api/login", "sqli")
    h2 = ledger.add("/api/users", "idor")
    
    all_hyps = ledger.get_all()
    assert len(all_hyps) == 2, "Should have 2 hypotheses"
    assert h1 in all_hyps, "First hypothesis should be present"
    assert h2 in all_hyps, "Second hypothesis should be present"
    
    print("[PASS] test_get_all passed")


async def test_get_summary():
    """Test get_summary() method."""
    ledger = HypothesisLedger()
    
    # Empty ledger
    summary = ledger.get_summary()
    assert summary["total"] == 0, "Empty ledger should have 0 total"
    
    # Add hypotheses
    h1 = ledger.add("/api/login", "sqli")
    h2 = ledger.add("/api/users", "idor")
    h3 = ledger.add("/api/admin", "xss")
    
    # Confirm one
    await ledger.confirm(h1, "SQL error in response", {"payload": "' OR 1=1--"})
    
    summary = ledger.get_summary()
    assert summary["total"] == 3, "Should have 3 total"
    assert summary["by_status"]["confirmed"] == 1, "Should have 1 confirmed"
    assert summary["by_status"]["open"] == 2, "Should have 2 open"
    assert summary["confirmed_count"] == 1, "Should have 1 in confirmed_count"
    
    # Check token efficiency - should be compact
    import json
    summary_str = json.dumps(summary)
    # Rough estimate: each character ~= 0.25 tokens, so 500 tokens ~= 2000 chars
    assert len(summary_str) < 2000, f"Summary too large: {len(summary_str)} chars"
    
    print("[PASS] test_get_summary passed")


async def test_find_by_surface_and_class():
    """Test find_by_surface_and_class() method."""
    ledger = HypothesisLedger()
    
    # Not found in empty ledger
    result = ledger.find_by_surface_and_class("/api/test", "sqli")
    assert result is None, "Should return None when not found"
    
    # Add hypothesis
    h1 = ledger.add("/api/login", "sqli")
    ledger.add("/api/login", "xss")  # Same surface, different class
    ledger.add("/api/users", "sqli")  # Different surface, same class
    
    # Find it
    result = ledger.find_by_surface_and_class("/api/login", "sqli")
    assert result is not None, "Should find the hypothesis"
    assert result.id == h1, "Should return correct hypothesis"
    assert result.surface == "/api/login", "Should have correct surface"
    assert result.vuln_class == "sqli", "Should have correct vuln_class"
    
    # Not found with different combo
    result = ledger.find_by_surface_and_class("/api/login", "idor")
    assert result is None, "Should not find non-existent combo"
    
    print("[PASS] test_find_by_surface_and_class passed")


async def test_get():
    """Test get() method."""
    ledger = HypothesisLedger()
    
    # Not found
    result = ledger.get("H-9999")
    assert result is None, "Should return None for non-existent ID"
    
    # Add hypothesis
    h1 = ledger.add("/api/test", "sqli")
    
    # Get it
    result = ledger.get(h1)
    assert result is not None, "Should find hypothesis"
    assert result.id == h1, "Should have correct ID"
    assert result.surface == "/api/test", "Should have correct surface"
    
    print("[PASS] test_get passed")


async def test_add_evidence_for():
    """Test add_evidence_for() method."""
    ledger = HypothesisLedger()
    
    # Add hypothesis
    h1 = ledger.add("/api/test", "sqli")
    
    # Add evidence
    success = await ledger.add_evidence_for(h1, "SQL error: syntax error")
    assert success is True, "Should succeed"
    
    hyp = ledger.get(h1)
    assert hyp is not None
    assert len(hyp.evidence_for) == 1, "Should have 1 evidence"
    assert "SQL error" in hyp.evidence_for[0], "Should contain evidence text"
    assert hyp.status == "testing", "Status should change to testing"
    
    # Add more evidence
    await ledger.add_evidence_for(h1, "Error code 1064")
    hyp = ledger.get(h1)
    assert hyp is not None
    assert len(hyp.evidence_for) == 2, "Should have 2 evidence items"
    
    # Non-existent hypothesis
    success = await ledger.add_evidence_for("H-9999", "test")
    assert success is False, "Should fail for non-existent hypothesis"
    
    print("[PASS] test_add_evidence_for passed")


async def test_add_evidence_against():
    """Test add_evidence_against() method."""
    ledger = HypothesisLedger()
    
    # Add hypothesis
    h1 = ledger.add("/api/test", "sqli")
    
    # Add counter-evidence
    success = await ledger.add_evidence_against(h1, "No SQL errors, normal response")
    assert success is True, "Should succeed"
    
    hyp = ledger.get(h1)
    assert hyp is not None
    assert len(hyp.evidence_against) == 1, "Should have 1 counter-evidence"
    assert "No SQL errors" in hyp.evidence_against[0], "Should contain evidence text"
    assert hyp.status == "testing", "Status should change to testing"
    
    # Non-existent hypothesis
    success = await ledger.add_evidence_against("H-9999", "test")
    assert success is False, "Should fail for non-existent hypothesis"
    
    print("[PASS] test_add_evidence_against passed")


async def test_confirm():
    """Test confirm() method with callbacks."""
    ledger = HypothesisLedger()
    
    # Track callback invocations
    callback_called = []
    
    def test_callback(hyp_id, hyp):
        callback_called.append((hyp_id, hyp.status))
    
    # Register callback
    ledger.register_confirmation_callback(test_callback)
    
    # Add hypothesis
    h1 = ledger.add("/api/test", "sqli")
    
    # Add some evidence first
    await ledger.add_evidence_for(h1, "SQL error detected")
    
    # Confirm it
    success = await ledger.confirm(
        h1,
        "Extracted database schema with UNION injection",
        exploitation_details={"payload": "' UNION SELECT null--", "impact": "high"}
    )
    assert success is True, "Should succeed"
    
    # Check hypothesis state
    hyp = ledger.get(h1)
    assert hyp is not None
    assert hyp.status == "confirmed", "Status should be confirmed"
    assert len(hyp.evidence_for) == 2, "Should have 2 evidence items (1 from add_evidence_for + 1 from confirm)"
    assert "UNION injection" in hyp.evidence_for[1], "Should contain confirmation evidence"
    assert hyp.details.get("payload") == "' UNION SELECT null--", "Should have exploitation details"
    
    # Check callback was triggered
    assert len(callback_called) == 1, "Callback should be called once"
    assert callback_called[0][0] == h1, "Callback should receive correct ID"
    assert callback_called[0][1] == "confirmed", "Callback should see confirmed status"
    
    # Non-existent hypothesis
    success = await ledger.confirm("H-9999", "test")
    assert success is False, "Should fail for non-existent hypothesis"
    
    print("[PASS] test_confirm passed")


async def test_reject():
    """Test reject() method."""
    ledger = HypothesisLedger()
    
    # Add hypothesis
    h1 = ledger.add("/api/test", "sqli")
    
    # Reject it
    success = await ledger.reject(h1, "WAF blocks all SQL injection attempts")
    assert success is True, "Should succeed"
    
    # Check hypothesis state
    hyp = ledger.get(h1)
    assert hyp is not None
    assert hyp.status == "rejected", "Status should be rejected"
    assert len(hyp.evidence_against) == 1, "Should have 1 counter-evidence"
    assert "WAF blocks" in hyp.evidence_against[0], "Should contain rejection reason"
    
    # Non-existent hypothesis
    success = await ledger.reject("H-9999", "test")
    assert success is False, "Should fail for non-existent hypothesis"
    
    print("[PASS] test_reject passed")


async def main():
    """Run all tests."""
    print("Testing hypothesis_ledger new methods...\n")
    
    await test_get_all()
    await test_get_summary()
    await test_find_by_surface_and_class()
    await test_get()
    await test_add_evidence_for()
    await test_add_evidence_against()
    await test_confirm()
    await test_reject()
    
    print("\n[PASS] All tests passed!")


if __name__ == "__main__":
    asyncio.run(main())
