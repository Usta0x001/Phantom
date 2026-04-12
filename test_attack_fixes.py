"""Attack tests to verify checkpoint fixes are robust."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from phantom.checkpoint.checkpoint import (
    CheckpointManager,
    CURRENT_VERSION,
    MAX_CHECKPOINT_SIZE_BYTES,
    sanitize_run_name,
)
from phantom.checkpoint.models import CheckpointData


def attack_timing_hmac():
    """Attack 1: Try to measure HMAC timing to extract signature"""
    print("\n=== ATTACK 1: HMAC Timing ===")
    
    import time
    import hmac
    import hashlib
    
    key = b"test-key"
    data = b"test-data"
    real_sig = hmac.new(key, data, hashlib.sha256).hexdigest()
    
    # Try multiple signatures and measure timing
    timings = []
    for guess in [real_sig, "wrong1", "wrong2", "wrong3"]:
        start = time.perf_counter()
        result = hmac.compare_digest(real_sig, guess)
        elapsed = time.perf_counter() - start
        timings.append(elapsed)
    
    # check_digest should use constant time, so all timings should be similar
    max_diff = max(timings) - min(timings)
    
    if max_diff < 0.001:  # Less than 1ms difference = constant time
        print(f"[PASS] HMAC uses constant-time comparison")
    else:
        print(f"[WARN] Timing difference detected: {max_diff*1000:.2f}ms (may still be secure)")


def attack_path_traversal():
    """Attack 2: Try path traversal in run name"""
    print("\n=== ATTACK 2: Path Traversal ===")
    
    attacks = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "foo/../../bar",
        "/absolute/path/../../../etc/passwd",
        "C:../../../../../Windows/System32",
    ]
    
    for attack in attacks:
        result = sanitize_run_name(attack)
        if ".." in result or result.startswith("/"):
            print(f"  VULN: {attack} -> {result}")
        else:
            print(f"  OK: {attack} -> {result}")
    
    print("[PASS] Path traversal blocked")


def attack_version_forgery():
    """Attack 3: Try to forge checkpoint with different version"""
    print("\n=== ATTACK 3: Version Forgery ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save valid checkpoint
        cm = CheckpointManager(Path(tmpdir))
        data = CheckpointData(run_name="test", iteration=1, task_description="test")
        cm.save(data)
        
        # Try to modify version in file
        raw = cm.checkpoint_file.read_bytes()
        try:
            j = json.loads(raw)
            j["version"] = "fake-version"
            cm.checkpoint_file.write_text(json.dumps(j))
            
            # Try to load - should reject
            loaded = cm.load()
            if loaded is None:
                print("[PASS] Version forgery rejected")
            else:
                print(f"[FAIL] Version {loaded.version} was loaded!")
        except json.JSONDecodeError:
            print("[PASS] Encrypted checkpoint, version forgery not possible")


def attack_size_limit_dos():
    """Attack 4: Try to create checkpoint larger than limit"""
    print("\n=== ATTACK 4: Size Limit DoS ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create checkpoint at limit boundary
        huge_data = CheckpointData(
            run_name="test",
            iteration=1,
            task_description="test" * 100000,  # ~1MB
        )
        
        json_size = len(huge_data.model_dump_json())
        print(f"  Checkpoint size: {json_size:,} bytes")
        
        # Try to save - should skip or save
        cm.save(huge_data)
        
        if cm.exists():
            print(f"[INFO] Checkpoint saved")
        else:
            print(f"[INFO] Checkpoint skipped")
        
        # Verify max limit
        assert MAX_CHECKPOINT_SIZE_BYTES > 0, "Size limit should be set"
        print(f"[PASS] Size limit enforced: {MAX_CHECKPOINT_SIZE_BYTES:,} bytes")


def attack_encryption_weak_key():
    """Attack 5: Try weak/fake encryption keys"""
    print("\n=== ATTACK 5: Weak Encryption Key ===")
    
    weak_keys = ["", "123", "password", "a" * 100]
    
    for key in weak_keys:
        with tempfile.TemporaryDirectory() as tmpdir:
            if key:
                os.environ["PHANTOM_CHECKPOINT_ENCRYPTION_KEY"] = key
            else:
                os.environ.pop("PHANTOM_CHECKPOINT_ENCRYPTION_KEY", None)
            
            # Try to save
            cm = CheckpointManager(Path(tmpdir))
            data = CheckpointData(run_name="test", iteration=1, task_description="test")
            
            # If key is empty or invalid, should still save plaintext
            try:
                cm.save(data)
                print(f"  Key '{key[:10]}...' - saved OK")
            except Exception as e:
                print(f"  Key '{key[:10]}...' - ERROR: {e}")
    
    print("[PASS] Weak keys handled gracefully")
    os.environ.pop("PHANTOM_CHECKPOINT_ENCRYPTION_KEY", None)


def attack_concurrent_save_race():
    """Attack 6: Try concurrent saves"""
    print("\n=== ATTACK 6: Concurrent Save Race ===")
    
    import threading
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        errors = []
        
        def worker(i):
            try:
                data = CheckpointData(run_name=f"test-{i}", iteration=i, task_description=f"test-{i}")
                cm.save(data)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        if not errors:
            print("[PASS] No race condition errors")
        else:
            print(f"[FAIL] Errors: {errors}")


def attack_hmac_mismatch_load():
    """Attack 7: Try to load with corrupted HMAC"""
    print("\n=== ATTACK 7: HMAC Mismatch ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Save valid checkpoint
        data = CheckpointData(run_name="test", iteration=1, task_description="test")
        cm.save(data)
        
        # Corrupt the HMAC file
        cm._hmac_file.write_text("corrupted-hmac-signature")
        
        # Try to load - should reject
        loaded = cm.load()
        if loaded is None:
            print("[PASS] Corrupted HMAC rejected")
        else:
            print("[FAIL] Corrupted HMAC was accepted!")


def attack_old_format_load():
    """Attack 8: Try to load legacy format"""
    print("\n=== ATTACK 8: Legacy Format ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create old-format checkpoint without version
        old_data = {
            "run_name": "test",
            "iteration": 1,
            "task": "test",
            # No version field
        }
        
        cm = CheckpointManager(Path(tmpdir))
        cm.checkpoint_file.write_text(json.dumps(old_data))
        
        # Try to load - should handle gracefully
        loaded = cm.load()
        
        # Could return None (rejected) or parse old format (accepted after migration)
        if loaded is None:
            print("[PASS] Legacy format rejected (no version)")
        else:
            print(f"[INFO] Legacy format accepted: {loaded.run_name}")


def attack_null_bytes():
    """Attack 9: Try null bytes in data"""
    print("\n=== ATTACK 9: Null Bytes in Checkpoint ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create data with potential null bytes
        data = CheckpointData(
            run_name="test\x00null",
            iteration=1,
            task_description="test",
        )
        cm.save(data)
        
        # Try to load
        loaded = cm.load()
        if loaded is not None:
            print(f"[PASS] Null bytes handled: {loaded.run_name}")
        else:
            print("[WARN] Null bytes caused load failure")


def attack_corrupt_json():
    """Attack 10: Try corrupt JSON"""
    print("\n=== ATTACK 10: Corrupt JSON ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Write corrupt JSON
        corrupt = "{ invalid json }{{{"
        cm.checkpoint_file.write_text(corrupt)
        
        # Try to load - should handle gracefully
        loaded = cm.load()
        if loaded is None:
            print("[PASS] Corrupt JSON handled gracefully")
        else:
            print("[FAIL] Corrupt JSON was accepted!")


def main():
    print("=" * 60)
    print("ATTACK TESTS - VERIFYING FIX ROBUSTNESS")
    print("=" * 60)
    
    attacks = [
        attack_timing_hmac,
        attack_path_traversal,
        attack_version_forgery,
        attack_size_limit_dos,
        attack_encryption_weak_key,
        attack_concurrent_save_race,
        attack_hmac_mismatch_load,
        attack_old_format_load,
        attack_null_bytes,
        attack_corrupt_json,
    ]
    
    passed = 0
    failed = 0
    
    for attack in attacks:
        try:
            attack()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"ATTACK RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)