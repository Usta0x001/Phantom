import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("CHECKPOINT SYSTEM - COMPREHENSIVE AUDIT")
print("=" * 70)

from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
from phantom.checkpoint.models import CheckpointData
from phantom.agents.state import AgentState
from phantom.agents.hypothesis_ledger import HypothesisLedger
from datetime import datetime, UTC

print("\n" + "=" * 70)
print("PART 1: CHECKPOINT INTERVAL & TRIGGER")
print("=" * 70)

print(f"""
CHECKPOINT_INTERVAL: {CHECKPOINT_INTERVAL} iterations

Trigger formula (line 129):
  return iteration > 0 and iteration % self._interval == 0

So saves at: 5, 10, 15, 20, 25... (not at iteration 1)
""")

# Verify should_save logic
with tempfile.TemporaryDirectory() as tmpdir:
    cp = CheckpointManager(Path(tmpdir))
    
    print(f"\n[TEST] Checkpoint should_save logic:")
    for i in [0, 1, 2, 5, 10, 15, 20]:
        result = cp.should_save(i)
        print(f"  iteration={i}: should_save={result}")


print("\n" + "=" * 70)
print("PART 2: CHECKPOINT DATA MODEL")
print("=" * 70)

print("""
CheckpointData contains (from models.py):

CORE ( REQUIRED):
- version: str = "1"
- run_name: str  
- status: str = "in_progress" | "interrupted" | "completed" | "crashed"
- iteration: int = 0

PROGRESS:
- root_agent_state: dict  <- Full messages + anchors + hypotheses
- sub_agent_states: dict <- FIX#6: sub-agents at checkpoint

FINDINGS:
- vulnerability_reports: list
- final_result: dict

STATS:
- llm_stats_at_checkpoint: dict
- per_model_stats: dict
- compression_calls: int
- agent_calls: int
- error_calls: int

EXTRAS:
- conversation_summary: list (last N messages)
- saved_at: timestamp

TRACKING (FIX #5):
- hypothesis_ledger_state: dict <- FIX
- coverage_tracker_state: dict
- correlation_engine_state: dict
- attack_graph_state: dict <- FIX
""")


print("\n" + "=" * 70)
print("PART 3: ATOMIC WRITE PROCESS")
print("=" * 70)

print("""
ATOMIC WRITE STRATEGY (lines 134-148):

1. Write to .tmp file first
2. Atomic rename to .json
3. Write HMAC to .tmp.hmac
4. Atomic rename to .json.hmac

Code:
  tmp = self.checkpoint_file.with_suffix(".tmp")
  tmp.write_bytes(json_bytes)
  tmp.replace(self.checkpoint_file)   # atomic on POSIX
  
  hmac_tmp = self._hmac_file.with_suffix(".tmp")
  hmac_tmp.write_text(sig, encoding="utf-8")
  hmac_tmp.replace(self._hmac_file)

This prevents corruption if process killed mid-write!
""")


print("\n" + "=" * 70)
print("PART 4: HMAC INTEGRITY CHECK")
print("=" * 70)

print("""
HMAC VERIFICATION (lines 158-186):

- Uses SHA256 with PHANTOM_CHECKPOINT_KEY or machine ID
- Stored in: checkpoint.json.hmac
- On load: verifies HMAC matches
- If mismatch: logs warning and ignores checkpoint

Purpose: Detect tampering/corruption
""")

from phantom.checkpoint.checkpoint import _get_hmac_key
key = _get_hmac_key()
print(f"\n[HMAC KEY] First 20 bytes: {key[:20]}...")


print("\n" + "=" * 70)
print("PART 5: LOAD/RESTORE PROCESS")
print("=" * 70)

print("""
LOAD PROCESS (lines 158-186):

1. Check if checkpoint_file.exists()
2. Read raw bytes
3. Verify HMAC signature
4. Parse JSON with pydantic
5. If ANY fail: return None

RESTORE PROCESS (cli.py lines 59-70):

1. CheckpointManager.load()
2. If exists:
   - Restore root_agent_state -> AgentState
   - Restore hypothesis_ledger_state -> HypothesisLedger
   - Restore coverage_tracker_state
   - Restore correlation_engine_state  
   - Restore attack_graph_state
   - Restore sub_agent_states (FIX #6)
""")


print("\n" + "=" * 70)
print("PART 6: IDENTIFIED WEAKNESSES")
print("=" * 70)

weaknesses = [
    ("1", "Large checkpoint files", "Saves ALL messages + state", "Can be huge"),
    ("2", "No selective save", "Always saves full state", "Wastes space"),
    ("3", "Sub-agent state size", "sub_agent_states can be large", "Memory issue"),
    ("4", "HMAC key exposure", "Uses machine ID fallback", "Less secure if key stolen"),
    ("5", "No compression before save", "Raw messages saved", "Larger files"),
    ("6", "No incremental save", "Full copy each time", "Slow on large scans"),
]

for num, issue, desc, impact in weaknesses:
    print(f"  {num}. {issue}")
    print(f"     DESC: {desc}")
    print(f"     IMPACT: {impact}")


print("\n" + "=" * 70)
print("PART 7: TEST SAVE/LOAD PROCESS")
print("=" * 70)

# Create test checkpoint
with tempfile.TemporaryDirectory() as tmpdir:
    cp_mgr = CheckpointManager(Path(tmpdir))
    
    # Create sample data
    test_state = AgentState(agent_id="test")
    test_state.add_message("user", "Test task")
    test_state.add_message("assistant", "Test result")
    test_state.add_finding_anchor({
        "text": "Found SQLi in /login",
        "key": "find1"
    })
    
    # Create hypothesis
    ledger = HypothesisLedger()
    hyp_id = ledger.add("/api/login", "sqli")
    ledger.record_payload(hyp_id, "' OR '1'='1 --")
    
    # Create checkpoint data
    cp_data = CheckpointData(
        run_name="test_run",
        iteration=10,
        status="in_progress",
        root_agent_state=test_state.model_dump(),
        hypothesis_ledger_state={hyp_id: ledger._hypotheses[hyp_id].to_dict()},
    )
    cp_data.saved_at = datetime.now(UTC).isoformat()
    
    print(f"\n[BEFORE SAVE]")
    print(f"  Iteration: {cp_data.iteration}")
    print(f"  State messages: {len(test_state.messages)}")
    print(f"  Anchors: {len(test_state.finding_anchors)}")
    print(f"  Hypotheses: {len(test_state.messages)}")
    
    # Save
    cp_mgr.save(cp_data)
    
    # Verify files created
    checkpoint_file = Path(tmpdir) / "checkpoint.json"
    hmac_file = Path(tmpdir) / "checkpoint.json.hmac"
    
    print(f"\n[FILES CREATED]")
    print(f"  checkpoint.json: {checkpoint_file.exists()} ({checkpoint_file.stat().st_size} bytes)")
    print(f"  checkpoint.json.hmac: {hmac_file.exists()}")
    
    # Load back
    loaded = cp_mgr.load()
    
    print(f"\n[AFTER LOAD]")
    print(f"  iteration: {loaded.iteration}")
    print(f"  status: {loaded.status}")
    print(f"  has state: {'root_agent_state' in loaded.model_dump()}")


print("\n" + "=" * 70)
print("PART 8: KEY WEAKNESS - MESSAGE BLOAT")
print("=" * 70)

print("""
ISSUE: Full messages saved every checkpoint!

Code: root_agent_state: dict = Field(default_factory=dict)
      This saves ALL messages, not just summary!

With 1000 messages:
- Each message ~500 chars
- = 500KB per checkpoint  
- Every 5 iterations = 100KB extra writes

PROBLEM: Large conversation = huge checkpoint files
SOLUTION: Should save only last N messages + summarize

Our fix would be:
- Keep last 50 messages
- Save conversation_summary (last N truncated)
- Restore: load + continue from history
""")


print("\n" + "=" * 70)
print("AUDIT COMPLETE - WEAKNESSES IDENTIFIED")
print("=" * 70)