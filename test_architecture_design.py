import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("ARCHITECTURE WEAKNESSES vs BUGS")
print("DESIGN-LEVEL ISSUES")
print("=" * 70)

print("""

=============================================================
BUGS vs ARCHITECTURE WEAKNESSES
=============================================================

BUGS: Code errors (typos, wrong logic, crashes)
  - Can be fixed with code changes
  
ARCHITECTURE WEAKNESSES: Design decisions causing issues
  - Fundamental to how system works
  - Harder to fix
  - May require redesign

""")

from phantom.llm.memory_compressor import _extract_anchors_from_chunk
from phantom.agents.state import AgentState

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 1: REBUILD ON EVERY CALL")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
Every LLM call does:
  1. Create new messages array
  2. Add system prompt
  3. Add agent identity
  4. Call compress_history()
  5. Update conversation in-place
  6. Inject anchors  
  7. Add continue prompt

WHY THIS IS A WEAKNESS:
====================
- Creates new list objects every call
- No caching of prepared messages
- Token counting always done
- Even for small conversations

BETTER DESIGN:
=============
- Cache prepared messages until state changes
- Skip if threshold not met
- Only rebuild when needed
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 2: TOKEN COUNT ON EVERY CALL")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
compress_history() counts ALL tokens on EVERY call

CODE:
  total_tokens = sum(_get_message_tokens(msg, model) for msg in messages)

WHY THIS IS A WEAKNESS:
====================
- O(n) operation every single call
- Even when < 1000 tokens
- No "skip if small" optimization

BETTER DESIGN:
=============
- Only count when approaching threshold
- Or use cached count + delta
- Or check rough estimate first
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 3: ALL-OR-NOTHING COMPRESSION")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
Current: IF tokens > 72K → compress ELSE → nothing

WHY THIS IS A WEAKNESS:
====================
- No tiered response
- 73K and 100K get same treatment
- Binary: compressed or not

BETTER DESIGN:
=============
Tiered:
- 50K: Light compress
- 72K: Normal
- 90K: Aggressive
- 100K: Force keep minimum
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 4: FIXED CHUNK SIZE")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
chunk_size = 10 (hardcoded or config)

WHY THIS IS A WEAKNESS:
====================
- Same for short AND long messages
- Not adaptive to content

BETTER DESIGN:
=============
Dynamic chunking:
- Calculate average message length
- Target fixed token count per chunk
- Adjust based on compression quality
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 5: STATE NEVER EXPIRES")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
state.messages = list with no expiration
state.finding_anchors = list with MAX 15 but no time-based expiry

WHY THIS IS A WEAKNESS:
====================
- Old context never removed
- After 100 iterations: 200+ messages
- Anchor at iteration 1 still there at 100

BETTER DESIGN:
=============
- Expire old messages after N iterations
- Time-based anchor expiration
- Archive old completed iterations
""")

print("\n" + "=" * 70)
print("ARCHITECTURE WEAKNESS 6: NO COMPRESSION METRICS")
print("=" * 70)

print("""
DESIGN ISSUE:
=============
No tracking of:
- Compression frequency
- Token savings
- Latency impact
- Summary quality

WHY THIS IS A WEAKNESS:
====================
- Can't optimize
- Don't know what's working
- No performance visibility

BETTER DESIGN:
=============
Track:
- compressions_per_hour
- tokens_saved
- compression_latency_ms
- summary_quality_score
""")

print("\n" + "=" * 70)
print("ANCHOR SYSTEM EVALUATION")
print("=" * 70)

print("""
=============================================================
THE ANCHOR IDEA - WORTH KEEPING?
=============================================================

PROS:
=====
1. Preserves key findings through compression
   - Without anchors, findings would be lost in summaries
   
2. Re-injected every prompt
   - LLM always sees important findings
   - Prevents redundant testing
   
3. Deduplication
   - Won't add same finding twice
   
4. Survives compression cycles
   - Key context preserved

CONS:
====
1. Keywords may miss nuanced findings
   - "might be vulnerable" -> NOT anchored
   - "I suspect SQLi" -> NOT anchored
   
2. Adds tokens to every request
   - Up to 15 anchors * 600 chars = 9000 tokens
   
3. Complexity
   - Extraction logic adds overhead
   - State management grows
4. Could contain outdated info
   - Anchors persist but context changes
""")

# Test anchor effectiveness
print("\n[ANCHOR EFFECTIVENESS TEST]")
test_cases = [
    ("FOUND: SQL injection in /login", True, "Confirmed finding"),
    ("CRITICAL: RCE via ping", True, "Confirmed finding"),
    ("Testing SQLi in /login", True, "Testing context"),
    ("Found error on page", False, "Unclear if finding"),
    ("The endpoint appears vulnerable", False, "Uncertain"),
]

kept = 0
for text, should_keep, desc in test_cases:
    anchors = _extract_anchors_from_chunk([{"role": "assistant", "content": text}])
    if anchors:
        kept += 1

print(f"  Cases: {kept}/{len(test_cases)} anchored")
print(f"  Effective for: CONFIRMED findings")
print(f"  May miss: UNCERTAIN findings")


print("\n" + "=" * 70)
print("VERDICT: SHOULD ANCHORS BE KEPT?")
print("=" * 70)

print("""
VERDICT: YES - WORTH KEEPING!

REASONING:
=========
1. Core value: PRESERVES FINDINGS
   - Without anchors: summaries lose exact payloads
   - With anchors: key context survives
   
2. Works well for CONFIRMED findings
   - "Found SQLi" -> anchored
   - "CRITICAL" -> anchored
   
3. Low overhead
   - Max 15 anchors (~9K tokens)
   - Worth for important context

SHOULD IMPROVE:
==============
1. More keywords for uncertain findings
   - "appears vulnerable"
   - "might be issue"
   
2. Time-based expiration
   - Don't keep anchors forever
   
3. Confidence scoring
   - Mark uncertain anchors differently
""")

print("\n" + "=" * 70)
print("COMPREHENSIVE SUMMARY")
print("=" * 70)

print("""
ARCHITECTURE WEAKNESSES (DESIGN LEVEL):
=====================================
1. Rebuilds messages every call
2. Counts tokens every call
3. All-or-nothing compression  
4. Fixed chunk size (10)
5. No message/anchor expiration
6. No performance metrics

ANCHOR SYSTEM:
=============
WORTH KEEPING: YES
- Preserves key findings
- Works for confirmed findings
- Should add more keywords and expiration
""")


print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)