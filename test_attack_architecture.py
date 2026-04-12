import os
import sys
import time
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("COMPREHENSIVE ARCHITECTURE ATTACK ANALYSIS")
print("=" * 70)

print("""

=============================================================
ARCHITECTURE OVERVIEW
=============================================================

The current compression system:

1. state.messages (persistent list)
2. compress_history() -> MemoryCompressor
3. Splits old messages into chunks of 10
4. Calls LLM to summarize each chunk
5. Returns: system + summaries + recent15

POTENTIAL ISSUES TO ATTACK:
1. Token counting accuracy
2. Chunk size optimization
3. Summary quality
4. Latency (multiple LLM calls)
5. Context loss
6. Anchor extraction
7. Edge cases
8. Parallel processing
9. Memory usage
10. Model switching

""")

from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _get_message_tokens,
    _count_tokens,
    _summarize_messages,
    MIN_RECENT_MESSAGES,
    COMPRESSOR_MAX_TOKENS,
)
from phantom.agents.state import AgentState

model = "claude-3-haiku-20240307"

print("\n" + "=" * 70)
print("ATTACK 1: TOKEN COUNTING INACCURACY")
print("=" * 70)

test_cases = [
    "short",
    "a" * 100,  # 100 chars
    "ABC" * 100,  # 300 chars
    "payload=' OR '1'='1 --",  # SQLi payload
]

print("\n[Test token counting accuracy]")
for text in test_cases:
    try:
        counted = _count_tokens(text, model)
    except:
        counted = len(text) // 4
    
    print(f"  '{text[:20]}...' -> counted={counted}, chars={len(text)}")

print("""
WEAKNESS: 
- len(text)//4 fallback can be 2-3x off
- Compression might trigger at wrong threshold
- May cause unneeded compression or missed compression
""")


print("\n" + "=" * 70)
print("ATTACK 2: CHUNK SIZE FIXED AT 10")
print("=" * 70)

print(f"""
Current: chunk_size = 10 (hardcoded default)
ISSUE: Not optimized for different:
  - Message lengths (short vs long)
  - Model context windows
  - Compression quality vs speed

Example:
  - Short messages (50 tokens each): 10 * 50 = 500 tokens/chunk
  - Long messages (500 tokens each): 10 * 500 = 5000 tokens/chunk
  - Same chunk size, very different compression!
""")


print("\n" + "=" * 70)
print("ATTACK 3: SUMMARY QUALITY UNCERTAIN")
print("=" * 70)

compressor = MemoryCompressor(model_name=model)

print(f"""
COMPRESSOR_MAX_TOKENS = {COMPRESSOR_MAX_TOKENS}
This limits summary length!

But:
- Important details may be cut
- URLs might be truncated
- Payloads might be shortened
- Finding context may be lost
""")


print("\n" + "=" * 70)
print("ATTACK 4: LATENCY - MULTIPLE LLM CALLS")
print("=" * 70)

print("""
For 30 messages:
  - Main task call: ~2-5 seconds
  - 2 summary calls: ~2-10 seconds each
  - Total: ~6-25 seconds EXTRA latency!

For parallel=True:
  - Summaries run in parallel (faster)
  - But still requires multiple API calls
  - More expensive (more tokens used)
""")


print("\n" + "=" * 70)
print("ATTACK 5: RECENT MESSAGES LIMIT")
print("=" * 70)

state = AgentState(agent_id="test")
compressor = MemoryCompressor(model_name=model)

print(f"""
MIN_RECENT_MESSAGES = {MIN_RECENT_MESSAGES}

Scenario:
  - 30 messages in history
  - Only 15 kept as-is
  - Messages 15-30 are summarized
  - Exact context from messages 15-30 may be lost!

Finding at message #20 gets summarized!
Only messages 15-30 kept raw.
""")


print("\n" + "=" * 70)
print("ATTACK 6: ANCHOR EXTRACTION")
print("=" * 70)

from phantom.llm.memory_compressor import _extract_anchors_from_chunk

test_msgs = [
    {"role": "assistant", "content": "Testing SQLi in /login"},
    {"role": "assistant", "content": "Found SQLi vulnerability"},
    {"role": "assistant", "content": "XSS confirmed in /search"},
]

anchors = _extract_anchors_from_chunk(test_msgs)

print(f"""
Messages: {len(test_msgs)}
Anchors extracted: {len(anchors)}
""")

for a in anchors:
    print(f"  - {a['text'][:40]}...")

print("""
WEAKNESS:
- Keywords match "Testing" but might miss nuanced findings
- "Found" captures findings but could include false positives
- Some genuine findings might not have anchor keywords
""")


print("\n" + "=" * 70)
print("ATTACK 7: EMPTY/FAILED COMPRESSION")
print("=" * 70)

print("""
If LLM summary fails:
  - Falls back to simple text truncation (8000 chars)
  - If still over threshold: no recovery!
  - Could fail the entire task

Fallback chain:
  1. LLM summarize
  2. Text truncation
  3. ? Nothing - may overflow
""")


print("\n" + "=" * 70)
print("ATTACK 8: PARALLEL PROCESSING ISSUES")
print("=" * 70)

print("""
Uses nest_asyncio for parallel:
  - Can cause event loop issues
  - Not supported in all environments
  - Fallback is sequential (slower)

Code shows:
  try:
    import nest_asyncio
    nest_asyncio.apply()
  except ImportError:
    # Sequential fallback
""")


print("\n" + "=" * 70)
print("ATTACK 9: NO TIERED COMPRESSION")
print("=" * 70)

print("""
Current: Single compression strategy
  - threshold = 72K tokens
  - Either compress or not

Better: Tiered compression
  - 50K tokens: Light compression (older messages)
  - 72K tokens: Full compression
  - 90K tokens: Aggressive compression
  - 100K tokens: Force compress
""")


print("\n" + "=" * 70)
print("ATTACK 10: NO COMPRESSION METRICS")
print("=" * 70)

print("""
The system doesn't track:
  - How often compression occurs
  - Summary quality (did key details persist?)
  - Token savings achieved
  - Latency impact
  - Failed compressions

This makes optimization difficult!
""")


print("\n" + "=" * 70)
print("ATTACK 11: SUMMARY TEMPLATE LIMITATIONS")
print("=" * 70)

from phantom.llm.memory_compressor import SUMMARY_PROMPT_TEMPLATE

print(f"""
Summary prompt:
{SUMMARY_PROMPT_TEMPLATE[:300]}...

This tells LLM to preserve:
- URLs with signals
- Parameter names
- Payloads
- Tokens/credentials
- Tool names/commands

But LLM might:
- Paraphrase instead of copy verbatim
- Skip "obvious" details
- Miss context
""")


print("\n" + "=" * 70)
print("ATTACK 12: STATE PERSISTENCE ISSUES")
print("=" * 70)

state = AgentState(agent_id="test")

for i in range(100):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")

messages = state.get_conversation_history()

print(f"""
After 100 iterations:
  Messages: {len(messages)}
  
Issues:
  - List grows indefinitely (memory)
  - No cleanup of old system messages
  - Checkpoint saves full list every time
  - Large state files!
""")


print("\n" + "=" * 70)
print("SUMMARY OF ALL ATTACKS")
print("=" * 70)

attacks = [
    ("Attack 1", "Token counting inaccurate"),
    ("Attack 2", "Fixed chunk size not optimized"),
    ("Attack 3", "Summary quality uncertain"),
    ("Attack 4", "High latency"),
    ("Attack 5", "Recent messages limit losing context"),
    ("Attack 6", "Anchor extraction may miss"),
    ("Attack 7", "Failed compression recovery"),
    ("Attack 8", "Parallel processing issues"),
    ("Attack 9", "No tiered compression"),
    ("Attack 10", "No compression metrics"),
    ("Attack 11", "Summary template limitations"),
    ("Attack 12", "State persistence bloat"),
]

for name, desc in attacks:
    print(f"  {name}: {desc}")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)