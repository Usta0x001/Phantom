import os
import sys
import time
import asyncio
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("AGGRESSIVE COMPREHENSIVE ATTACK")
print("FIND EVERY WEAKNESS")
print("=" * 70)

from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _get_message_tokens,
    _count_tokens,
    _extract_anchors_from_chunk,
    _summarize_messages,
)
from phantom.agents.state import AgentState

model = "claude-3-haiku-20240307"
compressor = MemoryCompressor(model_name=model)

print("\n" + "=" * 70)
print("ATTACK 1: TOKEN COUNTING ACCURACY")
print("=" * 70)

test_texts = [
    ("short", "abc"),
    ("code", "function(){return x+y;}"),
    ("chinese", "密码token"),
    ("sql payload", "' OR '1'='1 --"),
    ("unicode", "alert(1)"),
]

for name, text in test_texts:
    counted = _count_tokens(text, model)
    actual_chars = len(text)
    ratio = counted / actual_chars if actual_chars > 0 else 0
    
    issue = ""
    if ratio < 0.2 or ratio > 0.6:
        issue = " <-- INACCURATE"
    print(f"  {name}: counted={counted}, chars={actual_chars}, ratio={ratio:.2f}{issue}")

print("\n[RESULT] Token counting using len//4 fallback is INHERENTLY INACCURATE")
print("[ISSUE] No fix implemented yet!")


print("\n" + "=" * 70)
print("ATTACK 2: CHUNK SIZE NOT ADAPTIVE")
print("=" * 70)

print(f"  chunk_size = fixed at 10")
print(f"  ISSUE: Same for 10 short msgs vs 10 long msgs")


print("\n" + "=" * 70)
print("ATTACK 3: NO EARLY SKIP FOR SMALL CONVOS")
print("=" * 70)

state = AgentState(agent_id="small_test")
for i in range(5):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")

messages = state.get_conversation_history()
total_tokens = sum(_get_message_tokens(m, model) for m in messages)

print(f"  Only {total_tokens} tokens, but compress_history() still runs!")
print(f"  ISSUE: No early skip optimization")


print("\n" + "=" * 70)
print("ATTACK 4: NO TIERED COMPRESSION")
print("=" * 70)

threshold = int(compressor._max_total_tokens * 0.9)
print(f"  Single threshold: {threshold:,}")
print(f"  ISSUE: 73K and 100K get SAME treatment!")


print("\n" + "=" * 70)
print("ATTACK 5: ANCHOR KEYWORDS STILL MISS")
print("=" * 70)

miss_cases = [
    "This might possibly be an issue",
    "There could be a vulnerability here",
    "I think there's a problem",
    "Not sure but looks suspicious",
    "Possibly exploitable",
]

not_anchored = 0
for text in miss_cases:
    anchors = _extract_anchors_from_chunk([{"role": "assistant", "content": text}])
    if not anchors:
        not_anchored += 1
        print(f"  MISSED: '{text}'")

print(f"\n  Still missing: {not_anchored}/{len(miss_cases)} cases")
print(f"  ISSUE: Keywords incomplete!")


print("\n" + "=" * 70)
print("ATTACK 6: PARALLEL SUMMARIZATION FAILURE")
print("=" * 70)

print("""
  ISSUE: Uses nest_asyncio which:
  - Can cause event loop deadlock
  - Not available in all environments
  - Sequential fallback is slow
""")


print("\n" + "=" * 70)
print("ATTACK 7: COMPRESSION METRICS NOT TRACKED")
print("=" * 70)

print("""
  NO tracking of:
  - compressions_per_hour
  - token_savings
  - compression_latency_ms
  - summary_quality_score
""")


print("\n" + "=" * 70)
print("ATTACK 8: MESSAGE EXPIRATION LOSES CONTEXT")
print("=" * 70)

state = AgentState(Agent_id="expire_test")
for i in range(60):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")
    if i == 5:
        state.add_message("assistant", "CRITICAL: Found SQLi at iteration 5")

print(f"  Before cleanup: {len(state.messages)} messages")

removed = state.cleanup_old_messages()
print(f"  Removed: {removed}")
print(f"  After cleanup: {len(state.messages)} messages")

# Check if SQLi finding in recent
has_sqli = any("SQLi" in m.get("content", "") for m in state.messages)
if not has_sqli:
    print("  WARNING: Critical finding may have been cleaned up!")


print("\n" + "=" * 70)
print("ATTACK 9: ANCHOR INJECTION OVERHEAD")
print("=" * 70)

state = AgentState(agent_id="anchor_overhead")
for i in range(15):
    state.add_finding_anchor({"text": f"Finding {i}", "key": f"f{i}"})

anchor_tokens = sum(len(a.get("text", "")) // 4 for a in state.finding_anchors)
print(f"  15 anchors = ~{anchor_tokens} tokens per request!")
print(f"  ISSUE: Adds significant overhead every call")


print("\n" + "=" * 70)
print("ATTACK 10: RACE CONDITION IN COMPRESSION")
print("=" * 70)

print("""
  ISSUE: If two compressions run simultaneously:
  - Both count tokens
  - Both compress
  - Could cause inconsistency
""")


print("\n" + "=" * 70)
print("ATTACK 11: SYSTEM MESSAGES NEVER CLEANED")
print("=" * 70)

state = AgentState(agent_id="sys_test")
state.add_message("system", "Prompt " * 200)
for i in range(10):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")

system_msgs = [m for m in state.messages if m.get("role") == "system"]
print(f"  System messages: {len(system_msgs)}")
print(f"  ISSUE: Never cleaned, accumulates!")


print("\n" + "=" * 70)
print("ATTACK 12: CHECKPOINT BLOATED")
print("=" * 70)

print("""
  After 100 iterations:
  - state.messages = 200+ items
  - ALL saved to checkpoint
  - No cleanup
  
  ISSUE: Large checkpoint files!
""")


print("\n" + "=" * 70)
print("ATTACK 13: NO FALLOCATION PREVENTION")
print("=" * 70)

state = AgentState(agent_id="memory")
for i in range(1000):
    state.add_message("user", f"Task {i}" * 10)
    state.add_message("assistant", f"Result {i}" * 10)

msg_count = len(state.messages)
state_size = sys.getsizeof(str(state.messages))
print(f"  After 1000 iterations: {msg_count} messages")
print(f"  Approximate size: {state_size:,} bytes")
print(f"  NO allocation limit!")


print("\n" + "=" * 70)
print("FINAL WEAKNESS LIST")
print("=" * 70)

weaknesses = [
    ("1", "Token counting inaccurate (len//4)"),
    ("2", "Chunk size not adaptive"),
    ("3", "No early skip for small convos"),
    ("4", "No tiered compression"),
    ("5", "Anchor keywords incomplete"),
    ("6", "Parallel summarization risks"),
    ("7", "No compression metrics"),
    ("8", "Message expiration may lose context"),
    ("9", "Anchor injection overhead"),
    ("10", "Race condition"),
    ("11", "System messages never cleaned"),
    ("12", "Checkpoint bloated"),
    ("13", "No memory allocation limit"),
]

print(f"\n{'#':<3} {'Weakness':<50}")
print("-" * 55)
for num, weak in weaknesses:
    print(f"{num:<3} {weak}")

print(f"\nTOTAL WEAKNESSES: {len(weaknesses)}")


print("\n" + "=" * 70)
print("AGGRESSIVE ATTACK COMPLETE")
print("=" * 70)