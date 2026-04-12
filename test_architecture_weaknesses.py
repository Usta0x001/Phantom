import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("COMPREHENSIVE ARCHITECTURE ANALYSIS")
print("ALL WEAKNESSES IN THE SYSTEM")
print("=" * 70)

from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _get_message_tokens,
    MIN_RECENT_MESSAGES,
)
from phantom.agents.state import AgentState
from phantom.llm.llm import LLM
from phantom.config.config import Config

model = "claude-3-haiku-20240307"

print("\n" + "=" * 70)
print("ARCHITECTURE FLOW - UNDERSTANDING THE SYSTEM")
print("=" * 70)

print("""

CURRENT ARCHITECTURE:
===================

1. MESSAGE STORAGE
   state.messages = list[]
   
   Issue: Stores ALL messages forever
   - No cleanup
   - Grows infinitely
   - Checkpoint saves all

2. LLM CALL FLOW
   agent.execute() 
      -> state.add_message(user, task)
      -> state.get_conversation_history() -> messages
      -> LLM.generate(messages)
      -> _prepare_messages()
         -> compress_history() on EVERY call
         -> INJECT anchors
      -> Send to LLM API

3. COMPRESSION TRIGGER
   Every call: Count tokens -> Compare to 72K threshold
   Issue: Token counting is inaccurate (len//4 fallback)

4. COMPRESSION PROCESS
   - Split into chunks of 10
   - Summarize each chunk via LLM
   - Keep recent 15
   
5. ANCHOR SYSTEM
   - Extract before compression
   - Re-inject into every prompt
   
   Issue: Keywords may miss certain findings

6. STATE PERSISTENCE
   - Save full state to checkpoint
   - Issue: Grows very large
""")

print("\n" + "=" * 70)
print("WEAKNESS 1: MESSAGE STORAGE")
print("=" * 70)

state = AgentState(agent_id="msg_test")
for i in range(100):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")

conv = state.get_conversation_history()
total_tokens = sum(_get_message_tokens(m, model) for m in conv)

print(f"""
[WEAKNESS] state.messages stores ALL messages forever

Current after 100 iterations: 
- Messages: {len(conv)}
- Tokens: {total_tokens:,}

PROBLEMS:
1. No maximum limit - grows infinitely
2. Checkpoint saves all (large files)
3. Token count keeps growing
4. Memory usage linear with iterations
""")
# Demonstrate no cleanup
add_msg_size = len(str(state.messages))
print(f"  Approximate state size: {add_msg_size:,} bytes")


print("\n" + "=" * 70)
print("WEAKNESS 2: EVERY CALL REBUILDS MESSAGES")
print("=" * 70)

print("""
[WEAKNESS] Every LLM call rebuilds the full messages array

Current flow:
  _prepare_messages() does:
    1. Create [system_prompt]
    2. Add agent_identity
    3. Call compress_history() - counts ALL tokens
    4. Update conversation in-place
    5. Inject anchors
    6. Add to messages
    7. Add <meta>Continue</meta>

PROBLEM: 
- This happens on EVERY call, even when not needed
- Token counting done every single time
- Even if conversation is small
- No optimization for small conversations
""")


print("\n" + "=" * 70)
print("WEAKNESS 3: TOKEN COUNTING")
print("=" * 70)

# Show inaccurate counting
state_token = AgentState(agent_id="token_test")
for i in range(50):
    state_token.add_message("user", f"Test {i}")
    state_token.add_message("assistant", f"Result {i}")

messages = state_token.get_conversation_history()
token_count = sum(_get_message_tokens(m, model) for m in messages)
actual_chars = sum(len(m.get("content", "")) for m in messages)

print(f"""
[WEAKNESS] Token counting uses len(text) // 4 fallback

Counted tokens: {token_count:,}
Total chars: {actual_chars:,}
Ratio: {token_count/actual_chars:.2f} (expected ~0.25)

PROBLEM:
- len//4 is VERY inaccurate for code/payloads
- May trigger compression prematurely (false positive)
- May miss compression (false negative)
""")


print("\n" + "=" * 70)
print("WEAKNESS 4: COMPRESSION ALWAYS RUNS")
print("=" * 70)

print(f"""
[WEAKNESS] compress_history() called on EVERY LLM request

CODE: llm.py line 609-614
  compressed = await asyncio.to_thread(
      self.memory_compressor.compress_history, conversation_history, _state
  )

Called even when:
- Conversation is small (< 1000 tokens)
- No compression needed
- Wastes CPU cycles

PROBLEM:
- Can't skip if tokens < threshold
- Still counts tokens every time
- Thread creation overhead
""")


print("\n" + "=" * 70)
print("WEAKNESS 5: CHUNK SIZE FIXED AT 10")
print("=" * 70)

print(f"""
[WEAKNESS] chunk_size = 10 (hardcoded default)

CONFIG: phantom_compressor_chunk_size = "10"

PROBLEM:
- Not adaptive to message length
- Short messages: 10 * 10 = 100 tokens per chunk
- Long messages: 10 * 1000 = 10000 tokens per chunk
- Same compression quality?

NOT OPTIMIZED for different scenarios
""")


print("\n" + "=" * 70)
print("WEAKNESS 6: RECENT MESSAGES LIMIT")
print("=" * 70)

print(f"""
[WEAKNESS] Only {MIN_RECENT_MESSAGES} recent messages kept

PROBLEM:
- Finding at position 16-30 gets summarized
- Loses exact payload details
- Agent must re-inject anchors to know

NO FLEXIBILITY:
- Small conversation: keep all raw
- Large conversation: still only 15 recent
""")


print("\n" + "=" * 70)
print("WEAKNESS 7: ANCHOR EXTRACTION")
print("=" * 70)

from phantom.llm.memory_compressor import _extract_anchors_from_chunk

# Show what gets missed
missed_cases = [
    "The endpoint might be vulnerable",
    "I suspect SQLi but unsure", 
    "There appears to be an issue",
    "Consider testing this payload",
]

print(f"[WEAKNESS] Anchor keywords miss nuanced language")
count = 0
for text in missed_cases:
    anchors = _extract_anchors_from_chunk([{"role": "assistant", "content": text}])
    if anchors:
        count += 1
    print(f"  '{text[:30]}...' -> anchored: {bool(anchors)}")

print(f"\n  Anchored: {count}/{len(missed_cases)}")
print(f"PROBLEM: Keywords don't catch all findings")


print("\n" + "=" * 70)
print("WEAKNESS 8: ANCHOR INJECTION EVERY TIME")
print("=" * 70)

print("""
[WEAKNESS] Anchors injected on EVERY call after compression

CODE: llm.py line 619-648
  if _has_anchors:
      if not _already_injected:
          anchor_lines = []
          for anchor in _state.finding_anchors[:15]:
              ...

PROBLEM:
- Adds tokens to every request
- If anchors already in last 5, still checks
- No caching of anchor injection status
""")


print("\n" + "=" * 70)
print("WEAKNESS 9: NO TIERED COMPRESSION")
print("=" * 70)

compressor = MemoryCompressor(model_name=model)

print(f"""
[WEAKNESS] Single threshold: {int(compressor._max_total_tokens * 0.9):,}

IF tokens > 72K:
  - FULL compression (same for 73K or 100K)

NO TIERED APPROACH:
- 50K: Might not need compression
- 72K: Normal compression  
- 90K: Might need more aggressive
- 100K+: Force compress

ALL OR NOTHING!
""")


print("\n" + "=" * 70)
print("WEAKNESS 10: STATE NEVER CLEANED")
print("=" * 70)

state_clean = AgentState(agent_id="clean_test")
state_clean.add_message("system", "System " * 100)
for i in range(50):
    state_clean.add_message("user", f"Task {i}")
    state_clean.add_message("assistant", f"Result {i}")
    if i % 10 == 0:
        state_clean.add_message("assistant", f"Found issue {i}")

system_msgs = [m for m in state_clean.messages if m.get("role") == "system"]
total_msgs = len(state_clean.messages)

print(f"""
[WEAKNESS] No cleanup mechanism

System messages accumulated: {len(system_msgs)}
Total messages: {total_msgs}

PROBLEMS:
1. Old system prompts never removed
2. Old iterations never cleaned
3. Failed tasks still stored
4. No "archive old completed iterations"
""")


print("\n" + "=" * 70)
print("WEAKNESS 11: NO CHECKPOINT CLEANUP")
print("=" * 70)

state_cp = AgentState(agent_id="cp_test")
for i in range(200):
    state_cp.add_message("user", f"Task {i}")
    state_cp.add_message("assistant", f"Result {i}")

msg_count = len(state_cp.messages)
print(f"""
[WEAKNESS] After 200 iterations: {msg_count} messages

If we save checkpoint every iteration:
- 200 checkpoints with growing size
- Each checkpoint larger than previous
- No cleanup old checkpoints
""")


print("\n" + "=" * 70)
print("WEAKNESS 12: PARALLEL SUMMARIZATION")
print("=" * 70)

parallel_enabled = (Config.get("phantom_compressor_parallel") or "true").lower() in ("true", "1", "yes")

print(f"""
[WEAKNESS] Uses nest_asyncio for parallel

Current setting: {parallel_enabled}

PROBLEMS:
1. nest_asyncio can cause event loop issues
2. Not available in all environments  
3. Requires try/except fallback
4. Sequential fallback is MUCH slower
""")


print("\n" + "=" * 70)
print("WEAKNESS 13: NO FAILED COMPRESSION RECOVERY")
print("=" * 70)

print("""
[WEAKNESS] No proper error handling

Current fallback:
1. Try LLM summarize
2. If fail: text truncation (8000 chars)
3. If still over: ??? Nothing!

PROBLEM:
If still over after truncation:
- LLM will fail
- Task fails completely
- No graceful degradation
""")


print("\n" + "=" * 70)
print("WEAKNESS 14: COMPRESSION METRICS NOT TRACKED")
print("=" * 70)

print("""
[WEAKNESS] No metrics tracking

Not tracked:
- How often compression occurs
- Token savings achieved
- Latency impact
- Summary quality
- Failed compressions

Makes optimization impossible!
""")


print("\n" + "=" * 70)
print("SUMMARY - ALL 14 WEAKNESSES")
print("=" * 70)

weaknesses = [
    ("W1", "Message storage - infinite growth"),
    ("W2", "Every call rebuilds messages array"),
    ("W3", "Token counting inaccurate"),
    ("W4", "Compression always runs, not skippable"),
    ("W5", "Chunk size fixed at 10"),
    ("W6", "Recent messages limited to 15"),
    ("W7", "Anchor extraction misses findings"),
    ("W8", "Anchor injection every call"),
    ("W9", "No tiered compression"),
    ("W10", "State never cleaned"),
    ("W11", "No checkpoint cleanup"),
    ("W12", "Parallel summarization issues"),
    ("W13", "No failed compression recovery"),
    ("W14", "No compression metrics"),
]

print(f"\n{'ID':<4} {'Weakness':<45} {'Location'}")
print("-" * 60)
for id, weak in weaknesses:
    print(f"{id:<4} {weak:<45}")

print("\n" + "=" * 70)
print("ARCHITECTURE ANALYSIS COMPLETE")
print("=" * 70)