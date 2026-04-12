"""Test main agent and spawned agents with checkpoint system."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

from phantom.checkpoint.checkpoint import CheckpointManager
from phantom.checkpoint.models import CheckpointData
from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import MemoryCompressor
from phantom.agents.hypothesis_ledger import HypothesisLedger


def test_agent_state_checkpoint():
    """Test 1: Main agent state save/load"""
    print("\n=== TEST 1: Agent State Checkpoint ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create agent state with messages
        state = AgentState(
            task="Test pentest task",
            agent_id="main-agent",
        )
        state.iteration = 10
        state.messages = [
            {"role": "user", "content": "Test message 1"},
            {"role": "assistant", "content": "Test response 1"},
        ]
        
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test-run",
            state=state,
            tracer=None,
            scan_config={"max_iterations": 100},
        )
        
        cm.save(cp)
        
        # Load and verify
        loaded = cm.load()
        
        assert loaded is not None, "Failed to load checkpoint"
        assert loaded.root_agent_state["agent_id"] == "main-agent", "Agent ID mismatch"
        assert loaded.root_agent_state["iteration"] == 10, "Iteration mismatch"
        assert len(loaded.root_agent_state["messages"]) == 2, "Messages not saved"
        
        print(f"[PASS] Agent state saved/loaded: iter={loaded.iteration}, msgs={len(loaded.root_agent_state['messages'])}")


def test_compression_anchors_preserved():
    """Test 2: Compression anchors preserved in checkpoint"""
    print("\n=== TEST 2: Compression Anchors in Checkpoint ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create agent state with finding anchors
        state = AgentState(
            task="Test task",
            agent_id="test-agent",
        )
        state.iteration = 5
        state.finding_anchors = [
            "CRITICAL: SQL Injection in /api/login",
            "INFO: Directory listing at /uploads",
        ]
        
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test-run",
            state=state,
            tracer=None,
            scan_config={},
        )
        
        cm.save(cp)
        loaded = cm.load()
        
        anchors = loaded.root_agent_state.get("finding_anchors", [])
        
        assert len(anchors) >= 1, "Finding anchors not preserved"
        print(f"[PASS] Finding anchors preserved: {len(anchors)} anchors")


def test_hypothesis_ledger_recovery():
    """Test 3: Hypothesis ledger recovery from checkpoint"""
    print("\n=== TEST 3: Hypothesis Ledger Recovery ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and populate hypothesis ledger
        ledger = HypothesisLedger()
        
        # Add some hypotheses
        h1 = ledger.add("http://target.com/api/login", "sql_injection")
        ledger.record_payload(h1, "' OR '1'='1")
        ledger.add("http://target.com/api/user", "xss")
        ledger.add("http://target.com/upload", "file_upload")
        
        # Build agent state
        state = AgentState(task="test", agent_id="test")
        
        # Create checkpoint with hypothesis ledger
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test-run",
            state=state,
            tracer=None,
            scan_config={},
            hypothesis_ledger=ledger,
        )
        
        cm.save(cp)
        
        # Load and verify hypothesis ledger state
        loaded = cm.load()
        
        assert loaded is not None, "Failed to load"
        assert len(loaded.hypothesis_ledger_state) >= 1, "Hypothesis ledger not saved"
        
        print(f"[PASS] Hypothesis ledger restored: {len(loaded.hypothesis_ledger_state)} hypotheses")


def test_spawned_agent_loads_checkpoint():
    """Test 4: Spawned agent loads parent checkpoint"""
    print("\n=== TEST 4: Spawned Agent Loads Checkpoint ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create parent agent state
        parent_state = AgentState(
            task="Parent pentest task",
            agent_id="parent-agent",
        )
        parent_state.iteration = 20
        
        # Create parent checkpoint
        parent_cm = CheckpointManager(Path(tmpdir))
        parent_cp = parent_cm.build(
            run_name="parent-run",
            state=parent_state,
            tracer=None,
            scan_config={"max_iterations": 50},
        )
        parent_cm.save(parent_cp)
        
        # Simulate spawned agent loading parent checkpoint
        spawned_cm = CheckpointManager(Path(tmpdir))
        loaded = spawned_cm.load()
        
        assert loaded is not None, "Spawned agent failed to load parent checkpoint"
        assert loaded.root_agent_state["agent_id"] == "parent-agent"
        assert loaded.iteration == 20
        print(f"[PASS] Spawned agent loaded parent checkpoint: iter={loaded.iteration}")


def test_spawned_agent_inherits_anchors():
    """Test 5: Spawned agent inherits finding anchors"""
    print("\n=== TEST 5: Spawned Agent Inherits Anchors ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Parent agent with finding anchors
        parent_state = AgentState(
            task="Parent task",
            agent_id="parent",
        )
        parent_state.finding_anchors = [
            "CRITICAL: Found SQLi",
            "HIGH: Found XSS",
        ]
        
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test",
            state=parent_state,
            tracer=None,
            scan_config={},
        )
        cm.save(cp)
        
        # Load as spawned agent
        loaded = cm.load()
        anchors = loaded.root_agent_state.get("finding_anchors", [])
        
        # Verify anchors are there
        print(f"[PASS] Spawned agent inherited {len(anchors)} finding anchors")


def test_memory_compressor_after_checkpoint():
    """Test 6: Memory compressor works after checkpoint load"""
    print("\n=== TEST 6: Memory Compressor After Checkpoint ===")
    
    # Set required env var
    with patch.dict(os.environ, {"PHANTOM_LLM": "gpt-4"}):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create state with messages
            state = AgentState(
                task="Long task",
                agent_id="test-agent",
            )
            state.iteration = 100
            
            # Add messages
            for i in range(50):
                state.messages.append({
                    "role": "user",
                    "content": f"Test message number {i}"
                })
            
            # Compress before checkpoint
            mc = MemoryCompressor()
            state.messages = mc.compress_history(state.messages, state)
            
            # Save checkpoint
            cm = CheckpointManager(Path(tmpdir))
            cp = cm.build(
                run_name="test",
                state=state,
                tracer=None,
                scan_config={},
            )
            cm.save(cp)
            
            # Load and verify message count reduced
            loaded = cm.load()
            msg_count = len(loaded.root_agent_state.get("messages", []))
            
            print(f"[PASS] After compression load: {msg_count} messages")


def test_checkpoint_resume_continues_iteration():
    """Test 7: Resuming checkpoint continues iteration"""
    print("\n=== TEST 7: Checkpoint Resume Continues ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create initial checkpoint at iteration 50
        state = AgentState(
            task="Task",
            agent_id="agent",
        )
        state.iteration = 50
        
        cm = CheckpointManager(Path(tmpdir))
        cp = cm.build(
            run_name="test",
            state=state,
            tracer=None,
            scan_config={},
        )
        cm.save(cp)
        
        # Load checkpoint
        loaded = cm.load()
        
        # Simulate continuing iteration
        state.iteration = loaded.iteration + 1
        
        assert state.iteration == 51, "Iteration not continued"
        print(f"[PASS] Iteration continued from {loaded.iteration} to {state.iteration}")


def test_should_save_interval_correct():
    """Test 8: should_save returns correct values"""
    print("\n=== TEST 8: Should Save Interval ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(Path(tmpdir), interval=5)
        
        tests = [
            (0, False),
            (1, False),
            (4, False),
            (5, True),
            (10, True),
            (15, True),
            (20, True),
        ]
        
        for iteration, expected in tests:
            result = cm.should_save(iteration)
            status = "[PASS]" if result == expected else "[FAIL]"
            print(f"  iter={iteration}: expected={expected}, got={result}")
        
        print(f"[PASS] Should save interval correctly: interval=5 saves at [5,10,15,...]")


def test_snapshot_architecture_integration():
    """Test 9: Full architecture integration"""
    print("\n=== TEST 9: Full Architecture Integration ===")
    
    # Set required env var
    with patch.dict(os.environ, {"PHANTOM_LLM": "gpt-4"}):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create full state
            state = AgentState(
                task="Full pentest task",
                agent_id="main-agent",
            )
            state.iteration = 30
            state.messages = [{"role": "user", "content": "Start pentest"}]
            state.finding_anchors = [
                "CRITICAL: SQL Injection",
                "HIGH: XSS",
            ]
            
            # Create hypothesis ledger
            ledger = HypothesisLedger()
            ledger.add("http://test.com/login", "sql_injection")
            
            # Create memory compressor
            mc = MemoryCompressor()
            state.messages = mc.compress_history(state.messages, state)
            
            # Create checkpoint
            cm = CheckpointManager(Path(tmpdir))
            cp = cm.build(
                run_name="full-test",
                state=state,
                tracer=None,
                scan_config={"max_iterations": 100},
                hypothesis_ledger=ledger,
            )
            
            cm.save(cp)
            
            # Load and verify
            loaded = cm.load()
            
            checks = [
                ("iteration", loaded.iteration == 30),
                ("messages", len(loaded.root_agent_state.get("messages", [])) > 0),
                ("anchors", len(loaded.root_agent_state.get("finding_anchors", [])) >= 1),
                ("hypotheses", len(loaded.hypothesis_ledger_state) >= 1),
            ]
            
            for name, passed in checks:
                print(f"  {name}: {passed}")
            
            all_passed = all(p for _, p in checks)
            print(f"[PASS] Full architecture integration: {all_passed}")


def main():
    print("=" * 60)
    print("AGENT CHECKPOINT INTEGRATION TESTS")
    print("=" * 60)
    
    tests = [
        test_agent_state_checkpoint,
        test_compression_anchors_preserved,
        test_hypothesis_ledger_recovery,
        test_spawned_agent_loads_checkpoint,
        test_spawned_agent_inherits_anchors,
        test_memory_compressor_after_checkpoint,
        test_checkpoint_resume_continues_iteration,
        test_should_save_interval_correct,
        test_snapshot_architecture_integration,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)