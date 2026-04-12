import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("HARDCODED VALUES - FIND & FIX")
print("=" * 70)

from phantom.llm.memory_compressor import (
    MAX_TOTAL_TOKENS,
    MAX_CONTEXT_CEILING,
    MIN_RECENT_MESSAGES,
    COMPRESSOR_MAX_TOKENS,
)
from phantom.config.config import Config
from phantom.agents.state import AgentState
from phantom.agents.hypothesis_ledger import HypothesisLedger

print("\n" + "=" * 70)
print("PART 1: COMPRESSION SYSTEM VALUES")
print("=" * 70)

print(f"""
CURRENT VALUES (HARDCODED OR DEFAULTS):
========================================

1. MAX_TOTAL_TOKENS = {MAX_TOTAL_TOKENS:,}
   - Used as: base for compression threshold
   - Formula: threshold = MAX_TOTAL_TOKENS * 0.9 = {int(MAX_TOTAL_TOKENS * 0.9):,}
   - Environment: PHANTOM_MAX_TOTAL_TOKENS (if set)

2. MAX_CONTEXT_CEILING = {MAX_CONTEXT_CEILING:,}
   - Hard ceiling regardless of model
   - Environment: phantom_max_context_ceiling

3. MIN_RECENT_MESSAGES = {MIN_RECENT_MESSAGES}
   - Recent messages kept raw after compression
   - Changed to: {MIN_RECENT_MESSAGES} (our fix)

4. COMPRESSOR_MAX_TOKENS = {COMPRESSOR_MAX_TOKENS:,}
   - Max tokens for summary output
   - Environment:phantom_compressor_max_tokens

5. Chunk fill ratios:
   - Model 100K+: 0.65 (compress at 65%)
   - Model 32K+: 0.50 (compress at 50%)
   - Model <32K: 0.40 (compress at 40%)

6. CHUNK_SIZE = 10 (configurable)
   - Environment: phantom_compressor_chunk_size

7. MIN_RECENT_MESSAGES hardcoded at 15 (from our fix)
""")

print("\n" + "=" * 70)
print("PART 2: STATE VALUES")
print("=" * 70)

state = AgentState(agent_id="test")

print(f"""
1. MAX_FINDING_ANCHORS = {state.MAX_FINDING_ANCHORS}
   - Changed to: {state.MAX_FINDING_ANCHORS} (our fix - was 15)

2. MAX_ANCHOR_AGE_CYCLES = {state.MAX_ANCHOR_AGE_CYCLES}
   - Anchor expiration after N compression cycles

3. MAX_MESSAGES_BEFORE_CLEANUP = {state.MAX_MESSAGES_BEFORE_CLEANUP}
   - Our fix: max messages before cleanup
""")


print("\n" + "=" * 70)
print("PART 3: HOW TO CHANGE VALUES")
print("=" * 70)

print("""
METHOD 1: Environment Variables
==============================
export PHANTOM_MAX_TOTAL_TOKENS=100000
export PHANTOM_MAX_CONTEXT_CEILING=80000  
export PHANTOM_COMPRESSOR_CHUNK_SIZE=15
export phantom_compressor_chunk_size=15

METHOD 2: Config Class
===================
from phantom.config import Config
Config.set("phantom_compressor_chunk_size", "15")
Config.set("phantom_max_context_ceiling", "80000")

METHOD 3: Direct Code Change (NOT RECOMMENDED)
==============================================
Edit memory_compressor.py line 22:
  MIN_RECENT_MESSAGES = 15  # Change directly
""")


print("\n" + "=" * 70)
print("PART 4: RECOMMENDED VALUES")
print("=" * 70)

print("""
FOR EXPERT SYSTEM:

1. Token threshold:
   - 72000 is good (90% of 80K)
   - Can increase to 100000 for large models
   - Recommended: 100000 for GPT-4 class

2. Recent messages:
   - 15 is good (our fix)
   - Can increase to 20 for better context
   - Recommended: 20

3. Chunk size:
   - 10 is default
   - 15 for longer messages
   - 5 for short messages
   - Recommended: 15

4. Anchors:
   - 5 is optimal (reduced from 15)
   - Recommended: 5 (our fix)

5. Max messages:
   - 50-100 is reasonable
   - Recommended: 100
""")


print("\n" + "=" * 70)
print("CURRENT VALUES ARE:")
print("=" * 70)

current_values = [
    ("MAX_TOTAL_TOKENS", MAX_TOTAL_TOKENS, "Base for threshold"),
    ("MAX_CONTEXT_CEILING", MAX_CONTEXT_CEILING, "Hard cap"),
    ("MIN_RECENT_MESSAGES", MIN_RECENT_MESSAGES, "Recent kept raw"),
    ("COMPRESSOR_MAX_TOKENS", COMPRESSOR_MAX_TOKENS, "Summary max"),
    ("MAX_FINDING_ANCHORS", state.MAX_FINDING_ANCHORS, "Anchor limit"),
    ("MAX_ANCHOR_AGE_CYCLES", state.MAX_ANCHOR_AGE_CYCLES, "Anchor expiry"),
    ("CHUNK_SIZE", 10, "Messages per chunk"),
]

for name, value, desc in current_values:
    print(f"  {name}: {value} ({desc})")

print("\n" + "=" * 70)
print("TO CHANGE VALUES:")
print("=" * 70)
print("""
Run Python:
from phantom.config import Config
Config.set("phantom_compressor_chunk_size", "15")
Config.set("phantom_max_context_ceiling", "100000")
""")

print("\n" + "=" * 70)
print("VALUES LISTED - READY TO CHANGE")
print("=" * 70)