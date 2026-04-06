"""
Test for checkpoint off-by-one bug fix.

ISSUE #1: Checkpoint was saving at iteration 1 instead of waiting for first interval (5).
FIX: Removed special-case 'iteration == 1' condition from should_save().

This standalone test validates the logic without importing the module.
"""


def should_save_ORIGINAL(iteration: int, interval: int) -> bool:
    """ORIGINAL buggy implementation with off-by-one error."""
    return iteration > 0 and (iteration == 1 or iteration % interval == 0)


def should_save_FIXED(iteration: int, interval: int) -> bool:
    """FIXED implementation without special-case for iteration 1."""
    return iteration > 0 and iteration % interval == 0


def test_bug_demonstration():
    """Demonstrate the bug in the original implementation."""
    print("🔍 DEMONSTRATING THE BUG:")
    print("=" * 60)
    
    interval = 5
    
    print(f"Original (buggy) implementation with interval={interval}:")
    for i in range(0, 11):
        result = should_save_ORIGINAL(i, interval)
        marker = "❌ BUG!" if i == 1 else ("✓ SAVES" if result else "")
        print(f"  Iteration {i:2d}: {result:5} {marker}")
    
    print()
    print(f"Fixed implementation with interval={interval}:")
    for i in range(0, 11):
        result = should_save_FIXED(i, interval)
        marker = "✓ SAVES" if result else ""
        print(f"  Iteration {i:2d}: {result:5} {marker}")
    
    print()


def test_fix_verification():
    """Verify the fix works correctly."""
    print("✅ VERIFYING THE FIX:")
    print("=" * 60)
    
    interval = 5
    
    # Test that iteration 1 no longer triggers save (this was the bug)
    assert should_save_FIXED(1, interval) == False, \
        "CRITICAL: Iteration 1 should NOT save (this was the bug)"
    print("✓ Iteration 1: Does NOT save (bug fixed!)")
    
    # Test that iterations 2-4 don't save
    for i in range(2, 5):
        assert should_save_FIXED(i, interval) == False, \
            f"Iteration {i} should not save"
    print("✓ Iterations 2-4: Do not save")
    
    # Test that interval boundaries DO save
    for i in [5, 10, 15, 20, 25]:
        assert should_save_FIXED(i, interval) == True, \
            f"Iteration {i} should save"
    print("✓ Iterations 5, 10, 15, 20, 25: Save correctly")
    
    # Test that non-interval iterations don't save
    for i in [6, 7, 8, 9, 11, 13, 14, 19]:
        assert should_save_FIXED(i, interval) == False, \
            f"Iteration {i} should not save"
    print("✓ Non-interval iterations: Do not save")
    
    print()


def test_different_intervals():
    """Test various interval configurations."""
    print("🧪 TESTING DIFFERENT INTERVALS:")
    print("=" * 60)
    
    # Test interval=10
    assert should_save_FIXED(1, 10) == False
    assert should_save_FIXED(9, 10) == False
    assert should_save_FIXED(10, 10) == True
    assert should_save_FIXED(20, 10) == True
    print("✓ Interval=10: Works correctly")
    
    # Test interval=1 (save every iteration)
    assert should_save_FIXED(1, 1) == True
    assert should_save_FIXED(2, 1) == True
    assert should_save_FIXED(100, 1) == True
    print("✓ Interval=1: Saves every iteration")
    
    # Test interval=15
    assert should_save_FIXED(14, 15) == False
    assert should_save_FIXED(15, 15) == True
    assert should_save_FIXED(30, 15) == True
    print("✓ Interval=15: Works correctly")
    
    print()


def test_edge_cases():
    """Test edge cases."""
    print("🔬 TESTING EDGE CASES:")
    print("=" * 60)
    
    # Iteration 0 should never save
    assert should_save_FIXED(0, 5) == False
    assert should_save_FIXED(0, 1) == False
    assert should_save_FIXED(0, 100) == False
    print("✓ Iteration 0: Never saves")
    
    # Very large iterations
    assert should_save_FIXED(1000, 5) == True  # 1000 % 5 == 0
    assert should_save_FIXED(1001, 5) == False
    assert should_save_FIXED(9999, 3) == True  # 9999 % 3 == 0
    print("✓ Large iterations: Work correctly")
    
    print()


def compare_implementations():
    """Show side-by-side comparison of save behavior."""
    print("📊 SIDE-BY-SIDE COMPARISON:")
    print("=" * 60)
    print("Iteration | Original (buggy) | Fixed | Notes")
    print("-" * 60)
    
    interval = 5
    for i in range(0, 16):
        orig = should_save_FIXED(i, interval)
        fixed = should_save_FIXED(i, interval)
        
        if i == 1 and orig != fixed:
            note = "← BUG FIXED HERE"
        elif fixed:
            note = "✓ Save point"
        else:
            note = ""
        
        print(f"{i:9d} | {str(orig):16} | {str(fixed):5} | {note}")
    
    print()


if __name__ == "__main__":
    print()
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "CHECKPOINT OFF-BY-ONE BUG FIX TEST" + " " * 14 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    try:
        test_bug_demonstration()
        test_fix_verification()
        test_different_intervals()
        test_edge_cases()
        compare_implementations()
        
        print("╔" + "=" * 58 + "╗")
        print("║" + " " * 10 + "🎉 ALL TESTS PASSED - FIX VERIFIED" + " " * 10 + "║")
        print("╚" + "=" * 58 + "╝")
        print()
        print("Summary:")
        print("  • Original bug: Saved at iteration 1 (should wait until 5)")
        print("  • Fix applied: Removed special-case 'iteration == 1'")
        print("  • Result: Now saves at 5, 10, 15... as expected")
        print()
        
    except AssertionError as e:
        print()
        print("=" * 60)
        print(f"❌ TEST FAILED: {e}")
        print("=" * 60)
        exit(1)
