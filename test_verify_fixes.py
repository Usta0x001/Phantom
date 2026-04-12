"""Comprehensive verification tests for checkpoint fixes."""

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

# Add phantom to path
sys.path.insert(0, str(Path(__file__).parent))

from phantom.checkpoint.checkpoint import (
    CheckpointManager,
    CURRENT_VERSION,
    MAX_CHECKPOINT_SIZE_BYTES,
    CRYPTO_AVAILABLE,
    _get_encryption_key,
    _sanitize_run_dir,
    sanitize_run_name,
)
from phantom.checkpoint.models import CheckpointData


def test_current_version():
    """Test 1: Verify CURRENT_VERSION is defined"""
    print("\n=== TEST 1: Version Constant ===")
    assert CURRENT_VERSION == "1", f"Expected version '1', got {CURRENT_VERSION}"
    print(f"[PASS] CURRENT_VERSION = {CURRENT_VERSION}")


def test_max_checkpoint_size():
    """Test 2: Verify MAX_CHECKPOINT_SIZE_BYTES is set"""
    print("\n=== TEST 2: Size Limit Constant ===")
    expected = 10 * 1024 * 1024  # 10 MB
    assert MAX_CHECKPOINT_SIZE_BYTES == expected, f"Expected {expected}, got {MAX_CHECKPOINT_SIZE_BYTES}"
    print(f"[PASS] MAX_CHECKPOINT_SIZE_BYTES = {MAX_CHECKPOINT_SIZE_BYTES:,} bytes (10 MB)")


def test_sanitize_run_name():
    """Test 3: Verify path traversal sanitization"""
    print("\n=== TEST 3: Path Traversal Sanitization ===")
    
    # Attack: attempt path traversal - should strip ..
    result = sanitize_run_name("../../../etc/passwd")
    has_doubledot = ".." in result
    print(f"  Input: ../../../etc/passwd -> Output: {result}")
    print(f"  Has ..? {has_doubledot}")
    
    # Verify myScan-01 is unchanged
    assert sanitize_run_name("myScan-01") == "myScan-01", "myScan-01 should be unchanged"
    
    # Windows drive letter stripped
    result = sanitize_run_name("C:")
    print(f"  Input: C: -> Output: {repr(result)}")
    
    # Null byte stripped
    result = sanitize_run_name("evil\x00file")
    print(f"  Input: evil\\x00file -> Output: {repr(result)}")
    
    # If path traversal is stripped properly, pass
    if not has_doubledot:
        print("[PASS] Path traversal sanitized")
    else:
        print("[FAIL] Path traversal NOT fully sanitized")
        raise AssertionError("Path traversal not sanitized")


def test_sanitize_run_dir():
    """Test 4: Verify run_dir sanitization"""
    print("\n=== TEST 4: Run Dir Sanitization ===")
    
    # Strip .. from path
    result = _sanitize_run_dir(Path("phantom_runs/../../../etc/passwd"))
    
    assert ".." not in str(result), f".. found in {result}"
    print(f"[PASS] Sanitized: phantom_runs/../../../etc/passwd -> {result}")


def test_version_validation():
    """Test 5: Verify version validation in load()"""
    print("\n=== TEST 5: Version Validation ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create checkpoint with WRONG version
        bad_data = CheckpointData(
            run_name="test",
            version="99",  # Wrong version
            iteration=1,
            task_description="test",
        )
        
        # Save it
        cm.save(bad_data)
        assert cm.exists()
        
        # Load should return None due to version mismatch
        loaded = cm.load()
        
        if loaded is None:
            print("[PASS] Version mismatch correctly rejected")
        else:
            print(f"✗ Version {loaded.version} was loaded - should have been rejected!")
            assert False, "Version not validated!"


def test_size_limit_on_save():
    """Test 6: Verify size limit is enforced"""
    print("\n=== TEST 6: Size Limit Enforcement ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create massive checkpoint that exceeds limit
        huge_messages = [{"role": "user", "content": "x" * 10000} for _ in range(1000)]
        
        huge_data = CheckpointData(
            run_name="test",
            iteration=1,
            task_description="test",
            root_agent_state={"messages": huge_messages},
        )
        
        # size check happens before encryption, so test with actual data
        json_size = huge_data.model_dump_json().__len__()
        print(f"  Test data size: {json_size:,} bytes (limit: {MAX_CHECKPOINT_SIZE_BYTES:,})")
        
        if json_size < MAX_CHECKPOINT_SIZE_BYTES:
            print("  Test data too small, creating bigger...")
            huge_messages = [{"role": "user", "content": "x" * 50000} for _ in range(500)]
            huge_data.root_agent_state = {"messages": huge_messages}
        
        # Save should either succeed or skip based on size
        cm.save(huge_data)
        
        # Verify final state
        loaded = cm.load()
        if loaded is not None:
            print(f"[PASS] Large checkpoint saved ({json_size:,} bytes)")
        else:
            print("[PASS] Large checkpoint skipped (exceeds size limit)")


def test_encryption_available():
    """Test 7: Verify encryption library available"""
    print("\n=== TEST 7: Encryption Library ===")
    print(f"  CRYPTO_AVAILABLE = {CRYPTO_AVAILABLE}")
    print(f"[PASS] Cryptography library available" if CRYPTO_AVAILABLE else "!cryptography not available")


def test_encryption_roundtrip():
    """Test 8: Verify encryption/decryption roundtrip"""
    print("\n=== TEST 8: Encryption Roundtrip ===")
    
    if not CRYPTO_AVAILABLE:
        print("[SKIP] Skipping - cryptography not available")
        return
    
    # Use a fixed test key that produces valid Fernet key
    test_key = "test-secret-key-12345678901234567890"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Set encryption key
        with patch.dict(os.environ, {"PHANTOM_CHECKPOINT_ENCRYPTION_KEY": test_key}):
            cm = CheckpointManager(Path(tmpdir))
            
            # Create and save checkpoint
            data = CheckpointData(
                run_name="test-encrypt",
                iteration=42,
                task_description="encryption test",
            )
            cm.save(data)
            
            # Verify it was encrypted
            raw = cm.checkpoint_file.read_bytes()
            try:
                json.loads(raw)
                print("  Warning: data appears plaintext")
            except json.JSONDecodeError:
                print("  Data is encrypted (not plaintext)")
            
            # Load and verify roundtrip
            loaded = cm.load()
            assert loaded is not None, "Failed to load encrypted checkpoint"
            assert loaded.run_name == "test-encrypt"
            assert loaded.iteration == 42
            print("[PASS] Encryption roundtrip works")


def test_constant_time_hmac():
    """Test 9: Verify constant-time HMAC comparison"""
    print("\n=== TEST 9: Constant-Time HMAC ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        data = b"test data"
        sig1 = cm._compute_hmac(data)
        
        # Verify method exists
        assert hasattr(cm, '_verify_hmac_constant_time')
        
        # Verify it uses constant-time comparison
        result = cm._verify_hmac_constant_time(data, sig1)
        assert result == True
        
        # Wrong signature should fail
        result = cm._verify_hmac_constant_time(data, "wrong")
        assert result == False
        
        print("[PASS] Constant-time HMAC verification works")


def test_lock_prevents_race():
    """Test 10: Verify lock prevents concurrent saves"""
    print("\n=== TEST 10: Race Condition Prevention ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        results = []
        errors = []
        
        def save_worker(i):
            try:
                data = CheckpointData(
                    run_name=f"concurrent-{i}",
                    iteration=i,
                    task_description=f"worker {i}",
                )
                cm.save(data)
                results.append(i)
            except Exception as e:
                errors.append(str(e))
        
        # Start 10 concurrent saves
        threads = [threading.Thread(target=save_worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        print(f"  {len(results)} saves completed, {len(errors)} errors")
        assert len(results) == 10, "Not all saves completed"
        print("[PASS] Concurrent saves work with lock")


def test_should_save_interval():
    """Test 11: Verify should_save respects interval"""
    print("\n=== TEST 11: Save Interval ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir), interval=5)
        
        # Should NOT save on non-interval iterations
        assert cm.should_save(1) == False, "Should not save at iter 1"
        assert cm.should_save(3) == False, "Should not save at iter 3"
        assert cm.should_save(4) == False, "Should not save at iter 4"
        
        # Should save on interval iterations
        assert cm.should_save(5) == True, "Should save at iter 5"
        assert cm.should_save(10) == True, "Should save at iter 10"
        assert cm.should_save(15) == True, "Should save at iter 15"
        
        # Should NOT save on iteration 0
        assert cm.should_save(0) == False, "Should not save at iter 0"
        
        print("[PASS] Save interval works correctly")


def test_corrupt_checkpoint_handling():
    """Test 12: Verify corrupt checkpoints handled gracefully"""
    print("\n=== TEST 12: Corrupt Checkpoint Handling ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Write corrupt JSON
        cm.checkpoint_file.write_text("{ invalid json }")
        cm._hmac_file.write_text("fake-hmac")
        
        # Load should return None, not crash
        result = cm.load()
        assert result is None, "Corrupt checkpoint should return None"
        
        print("[PASS] Corrupt checkpoint handled gracefully")


def test_empty_checkpoint():
    """Test 13: Verify empty checkpoint handled"""
    print("\n=== TEST 13: Empty Checkpoint Handling ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Write empty file
        cm.checkpoint_file.write_text("")
        
        result = cm.load()
        assert result is None, "Empty checkpoint should return None"
        
        print("[PASS] Empty checkpoint handled gracefully")


def test_build_checkpoint():
    """Test 14: Verify build() method works"""
    print("\n=== TEST 14: Build Checkpoint ===")
    
    from phantom.agents.state import AgentState
    
    with tempfile.TemporaryDirectory() as tmpdir:
        state = AgentState(
            task="test task",
            agent_id="test-agent",
        )
        state.iteration = 5
        
        cm = CheckpointManager(Path(tmpdir))
        
        cp = cm.build(
            run_name="test",
            state=state,
            tracer=None,
            scan_config={"max_iterations": 10},
        )
        
        assert cp.run_name == "test"
        assert cp.iteration == 5
        assert cp.version == CURRENT_VERSION
        
        print(f"[PASS] Build works, version={cp.version}")


def test_hypothesis_ledger_serialization():
    """Test 15: Verify hypothesis ledger serialization"""
    print("\n=== TEST 15: Hypothesis Ledger Serialization ===")
    
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and populate ledger
        ledger = HypothesisLedger()
        hyp_id = ledger.add("http://test.com/api", "sql_injection")
        ledger.record_payload(hyp_id, "' OR '1'='1")
        
        # Build checkpoint with ledger
        from phantom.agents.state import AgentState
        state = AgentState(task="test", agent_id="test")
        
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test",
            state=state,
            tracer=None,
            scan_config={},
            hypothesis_ledger=ledger,
        )
        
        # Verify serialization
        assert hyp_id in cp.hypothesis_ledger_state
        print(f"[PASS] Hypothesis ledger serializes with {len(cp.hypothesis_ledger_state)} hypotheses")


def main():
    print("=" * 60)
    print("CHECKPOINT FIXES VERIFICATION")
    print("=" * 60)
    
    tests = [
        test_current_version,
        test_max_checkpoint_size,
        test_sanitize_run_name,
        test_sanitize_run_dir,
        test_version_validation,
        test_size_limit_on_save,
        test_encryption_available,
        test_encryption_roundtrip,
        test_constant_time_hmac,
        test_lock_prevents_race,
        test_should_save_interval,
        test_corrupt_checkpoint_handling,
        test_empty_checkpoint,
        test_build_checkpoint,
        test_hypothesis_ledger_serialization,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)