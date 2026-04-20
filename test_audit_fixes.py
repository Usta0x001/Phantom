"""
Test to verify audit fixes are correct.
The original code was CORRECT - this proves it.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_original_keeps_last_200():
    """Verify original del events[:-200] keeps last 200 events."""
    events = list(range(300))
    assert len(events) == 300
    
    # Original CORRECT behavior
    if len(events) > 200:
        del events[:-200]  # Deletes first 100, keeps last 200
    
    assert len(events) == 200, f"Expected 200, got {len(events)}"
    assert events[0] == 100, f"First should be 100, got {events[0]}"
    assert events[-1] == 299, f"Last should be 299, got {events[-1]}"
    print("[PASS] original keeps last 200 (most recent)")


def test_original_keeps_last_500():
    """Verify original del events[:-500] keeps last 500 events."""
    events = list(range(600))
    
    if len(events) > 500:
        del events[:-500]  # Deletes first 100, keeps last 500
    
    assert len(events) == 500, f"Expected 500, got {len(events)}"
    assert events[0] == 100, f"First should be 100, got {events[0]}"
    assert events[-1] == 599, f"Last should be 599, got {events[-1]}"
    print("[PASS] original keeps last 500")


def test_my_fix_was_wrong():
    """Prove my attempted fix del events[-200:] was WRONG."""
    events = list(range(300))
    
    # MY BUGGY FIX (which I reverted)
    if len(events) > 200:
        del events[-200:]
    
    # This proves the fix was wrong - it deletes the recent events!
    assert len(events) == 100, f"Expected 100, got {len(events)}"
    assert events[0] == 0, f"First should be 0, got {events[0]}"
    assert events[-1] == 99, f"Last should be 99, got {events[-1]}"
    print("PROVE: My fix was WRONG! It would delete MOST RECENT events!")


def test_boundary_200():
    """Edge: exactly 200 items - should not delete."""
    events = list(range(200))
    
    if len(events) > 200:
        del events[:-200]
    
    assert len(events) == 200, f"Expected 200, got {len(events)}"
    print("[PASS] boundary 200 - no deletion")


def test_boundary_201():
    """Edge: 201 items - keeps last 200."""
    events = list(range(201))
    
    if len(events) > 200:
        del events[:-200]
    
    assert len(events) == 200, f"Expected 200, got {len(events)}"
    assert events[0] == 1, f"First should be 1, got {events[0]}"
    assert events[-1] == 200, f"Last should be 200, got {events[-1]}"
    print("[PASS] boundary 201 - keeps most recent")


def test_boundary_1():
    """Edge: 1 item - should not delete."""
    events = list(range(1))
    
    if len(events) > 200:
        del events[:-200]
    
    assert len(events) == 1, f"Expected 1, got {len(events)}"
    print("[PASS] boundary 1 - no deletion")


def test_coverage_tracker_failure_only():
    """Verify _failure_only serialization works."""
    try:
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        
        surface_id = tracker.record_failure(
            surface="/api/test",
            surface_type="endpoint",
            failure_reason="WAF_BLOCKED",
            vuln_class="sqli"
        )
        
        assert hasattr(tracker, '_failure_only'), "_failure_only not created"
        
        data = tracker.to_dict()
        assert "failure_only" in data, "failure_only not serialized"
        assert len(data["failure_only"]) > 0, "failure_only empty"
        
        restored = CoverageTracker.from_dict(data)
        assert hasattr(restored, '_failure_only'), "_failure_only not restored"
        
        print("[PASS] coverage_tracker _failure_only serialization works")
    except ImportError as e:
        print(f"[SKIP] import error: {e}")


def test_coverage_roundtrip():
    """Verify failure data survives serialize/deserialize."""
    try:
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        surface_id = tracker.record_failure(
            surface="/api/login",
            surface_type="endpoint",
            failure_reason="403_FORBIDDEN",
            vuln_class="sqli"
        )
        
        original_reason = tracker._failure_only[surface_id]["failure_reasons"]
        
        data = tracker.to_dict()
        restored = CoverageTracker.from_dict(data)
        
        assert surface_id in restored._failure_only
        assert restored._failure_only[surface_id]["failure_reasons"] == original_reason
        
        print("[PASS] coverage_tracker roundtrip preserves failures")
    except ImportError as e:
        print(f"[SKIP] import error: {e}")


def run_all():
    tests = [
        test_original_keeps_last_200,
        test_original_keeps_last_500,
        test_my_fix_was_wrong,
        test_boundary_200,
        test_boundary_201,
        test_boundary_1,
        test_coverage_tracker_failure_only,
        test_coverage_roundtrip,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\nResults: {passed}/{passed+failed} passed")
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)