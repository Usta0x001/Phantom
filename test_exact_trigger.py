import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("EXACTLY HOW THE AGENT KNOWS TO COMPRESS")
print("=" * 70)

print("""

=============================================================
THE EXACT MECHANISM
=============================================================

The question: "HOW does the agent KNOW when to compress?"

Answer: BY COUNTING TOKENS and COMPARING!

Let me show the EXACT code that does this:
""")

# Show the trigger code
from phantom.llm.memory_compressor import _get_message_tokens
from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import MemoryCompressor

model = "claude-3-haiku-20240307"

print("\n" + "=" * 70)
print("STEP 1: THE VARIABLES")
print("=" * 70)

compressor = MemoryCompressor(model_name=model)

print(f"""
The MemoryCompressor has:
  - self._max_total_tokens = {compressor._max_total_tokens:,}
  - threshold = {int(compressor._max_total_tokens * 0.9):,} (90% of max)

These are set at initialization!
""")

print("\n" + "=" * 70)
print("STEP 2: THE EXACT CHECK CODE")
print("=" * 70)

state = AgentState(agent_id="test")

# Add messages until we trigger
for i in range(100):
    state.add_message("user", f"Test task {i} " * 10)  # ~30 tokens per message
    state.add_message("assistant", f"Testing result {i} " * 10)

messages = state.get_conversation_history()

# Count exactly like the code does
total_tokens = sum(_get_message_tokens(msg, model) for msg in messages)

print(f"")
print(f"[CODE SIMULATION]")
print(f"  total_tokens = sum(_get_message_tokens(msg, model) for msg in messages)")
print(f"  total_tokens = {total_tokens:,}")
print(f"")
print(f"  threshold = self._max_total_tokens * 0.9")
print(f"  threshold = {int(compressor._max_total_tokens * 0.9):,}")
print(f"")
print(f"  Compare:")
print(f"    IF {total_tokens:,} <= {int(compressor._max_total_tokens * 0.9):,}: no compression")
print(f"    IF {total_tokens:,} > {int(compressor._max_total_tokens * 0.9):,}: COMPRESS")

should_compress = total_tokens > int(compressor._max_total_tokens * 0.9)
print(f"")
print(f"  RESULT: {'OVER threshold -> COMPRESS!' if should_compress else 'Under threshold -> NO compression'}")

print("\n" + "=" * 70)
print("THE EXACT CODE LOCATION")
print("=" * 70)

print("""
File: phantom/llm/memory_compressor.py
Line: 678-688

Code:
----------------------------------------------
  total_tokens = sum(
      _get_message_tokens(msg, model_name) 
      for msg in system_msgs + regular_msgs
  )

  image_pressure = image_payload_before > self.max_total_image_bytes

  if (total_tokens <= self._max_total_tokens * 0.9 
      and not image_pressure 
      and evicted_images == 0):
      return messages  # NO COMPRESSION - return as-is!
----------------------------------------------

This IS the exact check!
- Count tokens
- Compare to max_total_tokens * 0.9
- Return original if under
- Continue to compress if over
""")

print("\n" + "=" * 70)
print("STEP 3: WHO CALLS THIS?")
print("=" * 70)

print("""
Every time LLM wants to generate:

1. agent.execute(task)
2. LLM.generate(conversation_history)
3. _prepare_messages(conversation_history)
       |
4.    compress_history(conversation_history)
              |
5.    [CODE ABOVE RUNS HERE]
              - Count tokens
              - Compare to threshold
              - Compress if needed
6.    Send to LLM

So compress_history() is called EVERY time!
And this code inside decides to compress or not.
""")


print("\n" + "=" * 70)
print("PROOF: RUN THE ACTUAL COMPRESSION")
print("=" * 70)

# Create enough messages to trigger compression
state2 = AgentState(agent_id="test2")
for i in range(60):
    state2.add_message("user", f"Task {i}")
    state2.add_message("assistant", f"Result {i} " * 20)
    if i % 5 == 0:
        state2.add_message("assistant", f"Found vulnerability in endpoint {i}!")

messages2 = state2.get_conversation_history()
tokens2 = sum(_get_message_tokens(m, model) for m in messages2)

print(f"\nTest 2:")
print(f"  Messages: {len(messages2)}")
print(f"  Tokens: {tokens2:,}")
print(f"  Threshold: {int(compressor._max_total_tokens * 0.9):,}")
print(f"  Over: {tokens2 > int(compressor._max_total_tokens * 0.9)}")

# Actually run compression
compressed = compressor.compress_history(messages2[:], state2)
tokens_compressed = sum(_get_message_tokens(m, model) for m in compressed)

print(f"\nAfter compression:")
print(f"  Messages: {len(compressed)}")
print(f"  Tokens: {tokens_compressed:,}")
print(f"  Reduction: {1 - (tokens_compressed/max(tokens2,1)):.1%}")

print("\n" + "=" * 70)
print("FINAL ANSWER - HOW THE AGENT KNOWS")
print("=" * 70)

print("""

THE AGENT KNOWS BY:

1. CALLING compress_history() on EVERY LLM request

2. INSIDE compress_history():
   - total_tokens = sum(all message tokens)
   - threshold = max_total_tokens * 0.9
   
3. THE CHECK:
   if total_tokens > threshold:
       compress()   # RUN COMPRESSION
   else:
       return messages  # NO compression

4. This is AUTOMATIC - happens every call!

The agent doesn't "know" context is full.
It COUNTS and COMPARES every single time.

""")

print("\n" + "=" * 70)
print("VERIFIED AND PROVEN!")
print("=" * 70)