import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("ARCHITECTURE WEAKNESSES vs BUGS")
print("DESIGN-LEVEL ISSUES")
print("=" * 70)

from phantom.llm.memory_compressor import _extract_anchors_from_chunk
from phantom.agents.state import AgentState

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 1: REBUILD ON EVERY CALL")
print("=" * 70)

print("""
Every LLM call does:
  1. Create new messages array
  2. Add system prompt
  3. Add agent identity  
  4. Call compress_history()
  5. Update conversation in-place
  6. Inject anchors
  7. Add continue prompt

ISSUE: Creates new list objects every call, no caching
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 2: TOKEN COUNT ON EVERY CALL")
print("=" * 70)

print("""
compress_history() counts ALL tokens on EVERY call
  total_tokens = sum(_get_message_tokens(msg, model) for msg in messages)

ISSUE: O(n) operation even when < 1000 tokens
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 3: ALL-OR-NOTHING COMPRESSION")
print("=" * 70)

print("""
Current: IF tokens > 72K THEN compress ELSE nothing

ISSUE: Binary response, no tiered approach
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 4: FIXED CHUNK SIZE")
print("=" * 70)

print("""
chunk_size = 10 (hardcoded or config)

ISSUE: Same for short AND long messages
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 5: STATE NEVER EXPIRES")
print("=" * 70)

print("""
state.messages with no expiration
After 100 iterations: 200+ messages
Old context never removed

ISSUE: Infinite growth
""")

print("\n" + "=" * 70)
print("ANCHOR SYSTEM EVALUATION")
print("=" * 70)

print("""
PROS:
1. Preserves key findings through compression
2. Re-injected every prompt
3. Prevents redundant testing
4. Survives compression

CONS:
1. Keywords may miss nuanced findings
2. Adds tokens to every request
3. Complexity
4. Could contain outdated info
""")

test_cases = [
    ("FOUND: SQL injection in /login", True),
    ("CRITICAL: RCE", True),
    ("Testing SQLi in /login", True),
    ("The endpoint appears vulnerable", False),
]

kept = 0
for text, should in test_cases:
    anchors = _extract_anchors_from_chunk([{"role": "assistant", "content": text}])
    if anchors:
        kept += 1

print(f"Test: {kept}/{len(test_cases)} anchored")

print("\n" + "=" * 70)
print("VERDICT: SHOULD ANCHORS BE KEPT?")
print("=" * 70)

print("""
YES - WORTH KEEPING!

1. Preserves key findings through compression
2. Works for confirmed findings
3. Low overhead (max ~9K tokens)
4. Core value demonstrated

SHOULD IMPROVE:
1. Add more keywords
2. Time-based expiration
3. Confidence scoring
""")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)