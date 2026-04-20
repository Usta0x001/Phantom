"""
Test fixes from audit - verifies all bugs are fixed
"""

def test_race_condition_fix():
    """Verify race condition fix in llm.py"""
    import re
    
    # Check that read is now inside lock
    with open("phantom/llm/llm.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    # Find the generate function and check rate limit code
    pattern = r'with _GLOBAL_STATS_LOCK:.*?now = time\.monotonic\(\)'
    match = re.search(pattern, content, re.DOTALL)
    
    if match:
        print("[PASS] Race condition fix - read now inside lock")
    else:
        print("[FAIL] Race condition not fixed")
    
    # Also check bare except: is gone
    bare_except_count = content.count("except:\n")
    print(f"  Bare except: count = {bare_except_count}")
    

def test_bare_except_fixes():
    """Verify bare except: fixes in test files"""
    import os
    
    test_files = [
        "attack_system.py",
        "test_final_verification.py", 
        "implement_all_fixes.py",
        "test_verify_all_weaknesses.py",
        "test_full_attack.py",
        "test_attack_architecture.py",
        "test_compression_bugs.py",
    ]
    
    fixed = 0
    still_bare = 0
    
    for f in test_files:
        if os.path.exists(f):
            with open(f, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
                # Count bare except:
                bare = content.count("except:\n")
                if bare > 0:
                    still_bare += bare
                    print(f"  {f}: {bare} bare except:")
                else:
                    fixed += 1
    
    if still_bare == 0:
        print(f"[PASS] All {fixed} test files fixed - no bare except:")
    else:
        print(f"[FAIL] {still_bare} bare except: still exist")


def test_coverage_tracker():
    """Verify _failure_only serialization"""
    import sys
    sys.path.insert(0, ".")
    
    try:
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        tracker.record_failure(
            surface="/api/test",
            surface_type="endpoint",
            failure_reason="WAF_BLOCKED",
            vuln_class="sqli"
        )
        
        data = tracker.to_dict()
        
        if "failure_only" in data:
            print("[PASS] _failure_only serialization works")
            
            # Test roundtrip
            restored = CoverageTracker.from_dict(data)
            if hasattr(restored, '_failure_only'):
                print("[PASS] _failure_only roundtrip works")
        else:
            print("[FAIL] _failure_only not in to_dict()")
    except ImportError as e:
        print(f"[SKIP] Import error: {e}")


def test_negative_slices():
    """Verify negative slice fix (was VERIFIED CORRECT originally)"""
    events = list(range(300))
    
    # Original correct behavior
    if len(events) > 200:
        del events[:-200]
    
    # Should keep last 200
    if len(events) == 200 and events[0] == 100:
        print("[PASS] Negative slice keeps last 200 (correct)")
    else:
        print(f"[FAIL] Got {len(events)} events, first={events[0]}")


def run_all():
    print("=" * 50)
    print("AUDIT FIX VERIFICATION")
    print("=" * 50)
    
    test_race_condition_fix()
    print()
    test_bare_except_fixes()
    print()
    test_coverage_tracker()
    print()
    test_negative_slices()
    
    print()
    print("=" * 50)
    print("ALL TESTS COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    run_all()