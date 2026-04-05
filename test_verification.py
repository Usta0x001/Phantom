"""
Verification script for hypothesis_ledger and scan_status fixes.
Runs the 6 verification steps:
1. Create a hypothesis
2. Call add_evidence_for() on it
3. Call confirm() on it
4. Call get() to retrieve it - verify status is confirmed and evidence is present
5. Call get_scan_status() - verify confirmed count is 1
6. Verify correlation_engine received the confirmation event
"""

import asyncio
from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.agents.correlation_engine import CorrelationEngine
from phantom.agents.coverage_tracker import CoverageTracker
from phantom.tools.scan_status.scan_status_actions import set_scan_status_context, get_scan_status


async def main():
    print("Running verification steps...\n")
    
    # Setup
    ledger = HypothesisLedger()
    correlation_engine = CorrelationEngine()
    coverage_tracker = CoverageTracker()
    
    # Mock agent state
    class MockState:
        iteration = 5
        max_iterations = 100
    
    state = MockState()
    
    # Wire up scan_status context
    set_scan_status_context(
        hypothesis_ledger=ledger,
        coverage_tracker=coverage_tracker,
        correlation_engine=correlation_engine,
        agent_state=state
    )
    
    # Track confirmation callbacks
    confirmation_events = []
    
    def track_confirmation(hyp_id, hyp):
        confirmation_events.append((hyp_id, hyp.status))
        # Also add to correlation engine
        correlation_engine.add_finding(
            vuln_class=hyp.vuln_class,
            surface=hyp.surface,
            severity="high",
            details=hyp.details
        )
    
    ledger.register_confirmation_callback(track_confirmation)
    
    # Step 1: Create a hypothesis
    print("Step 1: Creating hypothesis...")
    h_id = ledger.add("/api/login::username", "sqli")
    print(f"  Created hypothesis: {h_id}")
    assert h_id is not None
    
    # Step 2: Call add_evidence_for() on it
    print("\nStep 2: Adding evidence for hypothesis...")
    success = await ledger.add_evidence_for(h_id, "SQL error: near 'OR' at line 1")
    print(f"  Evidence added: {success}")
    assert success is True
    
    # Step 3: Call confirm() on it
    print("\nStep 3: Confirming hypothesis...")
    success = await ledger.confirm(
        h_id,
        "Extracted database version: MySQL 5.7.33 using UNION SELECT",
        exploitation_details={"payload": "' UNION SELECT @@version--", "impact": "critical"}
    )
    print(f"  Hypothesis confirmed: {success}")
    assert success is True
    
    # Step 4: Call get() to retrieve it - verify status is confirmed and evidence is present
    print("\nStep 4: Retrieving and verifying hypothesis...")
    hyp = ledger.get(h_id)
    assert hyp is not None, "Hypothesis should exist"
    assert hyp.status == "confirmed", f"Status should be 'confirmed', got '{hyp.status}'"
    assert len(hyp.evidence_for) >= 2, f"Should have at least 2 evidence items, got {len(hyp.evidence_for)}"
    assert "SQL error" in hyp.evidence_for[0], "First evidence should contain 'SQL error'"
    assert "UNION SELECT" in hyp.evidence_for[1], "Second evidence should contain 'UNION SELECT'"
    assert hyp.details.get("payload") == "' UNION SELECT @@version--", "Exploitation details should be stored"
    print(f"  Hypothesis status: {hyp.status}")
    print(f"  Evidence count: {len(hyp.evidence_for)}")
    print(f"  Exploitation payload: {hyp.details.get('payload')}")
    
    # Step 5: Call get_scan_status() - verify confirmed count is 1
    print("\nStep 5: Getting scan status...")
    status = get_scan_status(include_recommendations=True)
    confirmed_count = status["findings"]["confirmed_vulnerabilities"]
    assert confirmed_count == 1, f"Confirmed count should be 1, got {confirmed_count}"
    print(f"  Confirmed vulnerabilities: {confirmed_count}")
    print(f"  Phase: {status['scan_progress']['phase']}")
    print(f"  Recommended action: {status['recommended_next_action']}")
    
    # Step 6: Verify correlation_engine received the confirmation event
    print("\nStep 6: Verifying correlation_engine received confirmation...")
    assert len(confirmation_events) == 1, f"Should have 1 confirmation event, got {len(confirmation_events)}"
    assert confirmation_events[0][0] == h_id, "Event should be for correct hypothesis"
    assert confirmation_events[0][1] == "confirmed", "Event should show confirmed status"
    
    # Check correlation engine has the finding
    findings = correlation_engine.get_findings()
    assert len(findings) >= 1, "Correlation engine should have at least 1 finding"
    print(f"  Confirmation events received: {len(confirmation_events)}")
    print(f"  Findings in correlation engine: {len(findings)}")
    
    # Check if correlation engine suggested any chains
    suggestions = correlation_engine.get_all_suggestions()
    if suggestions:
        print(f"  Chain suggestions generated: {len(suggestions)}")
        for s in suggestions[:2]:
            print(f"    - {s.chain_name}")
    
    print("\n" + "="*50)
    print("[PASS] All verification steps passed!")
    print("="*50)


if __name__ == "__main__":
    asyncio.run(main())
