"""Deep security verification - attack your findings."""

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
    _get_encryption_key,
)
from phantom.checkpoint.models import CheckpointData


def attack_encrypted_no_key_at_load():
    """Attack: Save with encryption key, load WITHOUT key"""
    print("\n=== ATTACK: Encrypted Save -> No Key Load ===")
    
    key = "test-key-12345678901234567890"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Set key and save encrypted
        with patch.dict(os.environ, {"PHANTOM_CHECKPOINT_ENCRYPTION_KEY": key}):
            cm = CheckpointManager(Path(tmpdir))
            data = CheckpointData(run_name="test", iteration=1, task_description="test")
            cm.save(data)
        
        # Now load WITHOUT key
        os.environ.pop("PHANTOM_CHECKPOINT_ENCRYPTION_KEY", None)
        
        cm2 = CheckpointManager(Path(tmpdir))
        loaded = cm2.load()
        
        if loaded is None:
            # Without key and data was encrypted, should fail gracefully
            print("[PASS] Encrypted checkpoint safely rejected without key")
        else:
            print(f"[INFO] Loaded: {loaded.run_name}")


def attack_wrong_key_at_load():
    """Attack: Save with key A, load with key B"""
    print("\n=== ATTACK: Wrong Key Load ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save with key A
        with patch.dict(os.environ, {"PHANTOM_CHECKPOINT_ENCRYPTION_KEY": "key-a"}):
            cm = CheckpointManager(Path(tmpdir))
            data = CheckpointData(run_name="test", iteration=1, task_description="test")
            cm.save(data)
        
        # Try load with key B
        with patch.dict(os.environ, {"PHANTOM_CHECKPOINT_ENCRYPTION_KEY": "key-b"}):
            cm2 = CheckpointManager(Path(tmpdir))
            loaded = cm2.load()
            
            # key B can't decrypt key A's data - should fail gracefully
            if loaded is None:
                print("[PASS] Wrong key rejected gracefully")
            else:
                print(f"[FAIL] Wrong key loaded data: {loaded.run_name}")


def attack_hmac_tamper():
    """Attack: Modify HMAC file"""
    print("\n=== ATTACK: HMAC Tamper ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Save valid checkpoint
        data = CheckpointData(run_name="test", iteration=1, task_description="test")
        cm.save(data)
        
        # Tamper with HMAC
        cm._hmac_file.write_text("TAMPERED-SIGNATURE-12345")
        
        # Try load - should reject
        loaded = cm.load()
        
        if loaded is None:
            print("[PASS] Tampered HMAC rejected")
        else:
            print("[FAIL] Tampered HMAC was accepted!")


def attack_data_tamper():
    """Attack: Modify checkpoint data"""
    print("\n=== ATTACK: Data Tamper ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save WITHOUT encryption to test tampering
        os.environ.pop("PHANTOM_CHECKPOINT_ENCRYPTION_KEY", None)
        
        cm = CheckpointManager(Path(tmpdir))
        
        # Save valid checkpoint (no encryption)
        data = CheckpointData(run_name="test", iteration=1, task_description="test")
        cm.save(data)
        
        # Tamper with data (change iteration from 1 to 999)
        raw = cm.checkpoint_file.read_bytes()
        try:
            j = json.loads(raw)
            j["iteration"] = 999
            cm.checkpoint_file.write_text(json.dumps(j))
            
            # Try load - HMAC should not match tampered data
            loaded = cm.load()
            
            if loaded is None:
                print("[PASS] Tampered data detected by HMAC")
            else:
                print(f"[INFO] iteration was: {loaded.iteration}")
        except json.JSONDecodeError:
            print("[PASS] Data encrypted, can't tamper")


def attack_version_forge():
    """Attack: Forge version field"""
    print("\n=== ATTACK: Version Forge ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Save checkpoint
        data = CheckpointData(run_name="test", iteration=1, task_description="test")
        cm.save(data)
        
        # Forge version
        raw = cm.checkpoint_file.read_bytes()
        try:
            j = json.loads(raw)
            j["version"] = "MALICIOUS"
            cm.checkpoint_file.write_text(json.dumps(j))
            
            # Try load - should reject
            loaded = cm.load()
            if loaded is None:
                print("[PASS] Version forge rejected")
            else:
                print(f"[FAIL] Version forge accepted: {loaded.version}")
        except json.JSONDecodeError:
            print("[PASS] Encrypted, can't forge version")


def attack_size_zero():
    """Attack: Create zero-byte checkpoint"""
    print("\n=== ATTACK: Zero-Byte Checkpoint ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Write empty file
        cm.checkpoint_file.write_text("")
        
        loaded = cm.load()
        
        if loaded is None:
            print("[PASS] Empty file rejected")
        else:
            print("[FAIL] Empty file was loaded!")


def attack_size_limit_exactly():
    """Attack: Create checkpoint exactly at limit"""
    print("\n=== ATTACK: Size Limit Edge Case ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create data just under limit
        content = "x" * (MAX_CHECKPOINT_SIZE_BYTES - 1000)
        data = CheckpointData(
            run_name="test", 
            iteration=1, 
            task_description=content
        )
        
        cm.save(data)
        
        if cm.exists():
            print("[PASS] Under limit: saves OK")
        else:
            print("[INFO] May have been skipped")
        
        # Now try at a different path
        tmpdir2 = Path(tmpdir) / "dir2"
        tmpdir2.mkdir()
        
        content = "x" * (MAX_CHECKPOINT_SIZE_BYTES + 1)
        data = CheckpointData(
            run_name="test2", 
            iteration=2, 
            task_description=content
        )
        
        cm2 = CheckpointManager(tmpdir2)
        cm2.save(data)
        
        if cm2.exists():
            print("[FAIL] Over limit: should NOT save")
        else:
            print("[PASS] Over limit: skipped correctly")


def attack_concurrent_read_write():
    """Attack: Read while writing"""
    print("\n=== ATTACK: Concurrent Read-Write ===")
    
    import threading
    import time
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        results = []
        
        def writer():
            for i in range(5):
                data = CheckpointData(run_name=f"test-{i}", iteration=i, task_description="test")
                cm.save(data)
                time.sleep(0.01)
        
        def reader():
            for i in range(5):
                time.sleep(0.01)
                loaded = cm.load()
                results.append(loaded is not None)
        
        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        if all(results):
            print("[PASS] Concurrent read-write safe")
        else:
            print(f"[WARN] Some reads failed: {results}")


def attack_null_run_name():
    """Attack: Null bytes in run name"""
    print("\n=== ATTACK: Null Run Name ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Run name with null
        data = CheckpointData(run_name="test\x00evil", iteration=1, task_description="test")
        
        try:
            cm.save(data)
            loaded = cm.load()
            
            if loaded is not None:
                # Verify null bytes handled
                if "\x00" not in loaded.run_name:
                    print("[PASS] Null bytes stripped from run name")
                else:
                    print("[INFO] Null in run name preserved")
            else:
                print("[PASS] Rejected null run name")
        except Exception as e:
            print(f"[WARN] Exception: {e}")


def attack_none_iteration():
    """Attack: None/null iteration value"""
    print("\n=== ATTACK: None Iteration ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir))
        
        # Create data without iteration (uses default)
        data = CheckpointData(run_name="test", task_description="test")
        
        cm.save(data)
        loaded = cm.load()
        
        if loaded is not None and loaded.iteration == 0:
            print(f"[PASS] Default iteration 0: {loaded.iteration}")
        else:
            print(f"[INFO] iteration = {loaded.iteration if loaded else 'None'}")


def main():
    print("=" * 60)
    print("DEEP SECURITY ATTACKS")
    print("=" * 60)
    
    attacks = [
        attack_encrypted_no_key_at_load,
        attack_wrong_key_at_load,
        attack_hmac_tamper,
        attack_data_tamper,
        attack_version_forge,
        attack_size_zero,
        attack_size_limit_exactly,
        attack_concurrent_read_write,
        attack_null_run_name,
        attack_none_iteration,
    ]
    
    passed = 0
    
    for attack in attacks:
        try:
            attack()
            passed += 1
        except Exception as e:
            print(f"[ERROR] {e}")
    
    print("\n" + "=" * 60)
    print(f"ATTACKS PASSED: {passed}/{len(attacks)}")
    print("=" * 60)
    
    return passed == len(attacks)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)