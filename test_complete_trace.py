import os
import sys
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("COMPLETE TRACE: CONTEXT WINDOW -> COMPRESSION -> HISTORY")
print("=" * 70)


print("""
=============================================================
QUESTION 1: WHAT IS THE CONTEXT WINDOW?
=============================================================

- LLM has a maximum token limit it can accept in ONE request
- This limit is the "context window" 
- Claude 3 Opus: 200,000 tokens
- Claude 3 Haiku: 100,000 tokens  
- GPT-4o: 128,000 tokens

When conversation exceeds this limit, LLM returns error:
"400 - context_length_exceeded"
Or similar error messages
""")


print("\n" + "=" * 70)
print("STEP 1: Trace where context is counted")
print("=" * 70)

from phantom.llm.memory_compressor import (
    _get_message_tokens,
    _count_tokens,
    _get_model_context_window,
    MAX_TOTAL_TOKENS,
    MAX_CONTEXT_CEILING,
)

model = "claude-3-haiku-20240307"
ctx_window = _get_model_context_window(model)

print(f"\n[CONFIG for model: {model}]")
print(f"  Model context window: {ctx_window:,} tokens")
print(f"  MAX_TOTAL_TOKENS (fallback): {MAX_TOTAL_TOKENS:,}")
print(f"  MAX_CONTEXT_CEILING: {MAX_CONTEXT_CEILING:,}")
print(f"  Compression threshold: {min(MAX_CONTEXT_CEILING, ctx_window):,}")


print("\n" + "=" * 70)
print("STEP 2: Create conversation and count tokens")
print("=" * 70)

from phantom.agents.state import AgentState

state = AgentState(agent_id="test")

print(f"\n[Create sample conversation]")
for i in range(5):
    state.add_message("user", f"Task {i}: Test /api/endpoint{i} for SQLi")
    state.add_message("assistant", f"Testing SQLi in /api/endpoint{i}")

messages = state.get_conversation_history()
total_tokens = sum(_get_message_tokens(m, model) for m in messages)

print(f"  Messages: {len(messages)}")
print(f"  Total tokens: {total_tokens}")


print("\n" + "=" * 70)
print("STEP 3: What IS the 'history'?")
print("=" * 70)

print(f"\n[state.messages is a LIST]")
print(f"  Type: {type(state.messages)}")
print(f"  Location: phantom/agents/state.py line 42")
print(f"")
print(f"  Each message has:")
print(f"    - role: 'user' OR 'assistant'")
print(f"    - content: 'the actual text'")
print(f"")

print(f"\n[Example messages in state.messages]")
for i, msg in enumerate(messages[:4]):
    print(f"  [{i}] role='{msg['role']}', content='{msg['content'][:30]}...'")


print("\n" + "=" * 70)
print("STEP 4: How is 'history' passed to LLM?")
print("=" * 70)

print("""
[CODE FLOW from agent to LLM:]

1. agent.execute(task)
       |
2.   state.add_message("user", task)
       |        -> adds to state.messages
3.   conversation = state.get_conversation_history()
       |        -> returns state.messages
4.   LLM.generate(conversation)
       |        -> receives full history
5.   _prepare_messages(conversation)
       |        -> compresses if needed
6.   Send to LLM API
       |
7.   response = LLM returns
8.   state.add_message("assistant", response)
       |        -> adds response to state.messages
9.   Repeat from step 1
""")


print("\n" + "=" * 70)
print("STEP 5: When does compression happen?")
print("=" * 70)

from phantom.llm.memory_compressor import MemoryCompressor, MIN_RECENT_MESSAGES

compressor = MemoryCompressor(model_name=model)
threshold = int(compressor._max_total_tokens * 0.9)

print(f"\n[Compression TRIGGER]")
print(f"  Threshold: {threshold:,} tokens (90% of {compressor._max_total_tokens:,})")
print(f"")
print(f"  If tokens > {threshold:,}:")
print(f"    1. OLD messages (0 to {len(messages)-MIN_RECENT_MESSAGES-1}) -> SUMMARIZED")
print(f"    2. RECENT messages ({len(messages)-MIN_RECENT_MESSAGES} to {len(messages)-1}) -> KEPT AS-IS")
print(f"    3. Summaries -> Replace old messages")


print("\n" + "=" * 70)
print("STEP 6: What's 'compressed'?")
print("=" * 70)

print("""
[BEFORE COMPRESSION - say 30 messages:]
  [
    {role: 'user', content: 'Task 0'},
    {role: 'assistant', content: 'Result 0'},
    {role: 'user', content: 'Task 1'},
    {role: 'assistant', content: 'Result 1'},
    ... (30 total)
  ]

[AFTER COMPRESSION - say 12 messages:]
  [
    {role: 'system', content: 'System prompt'},    <- ALWAYS kept
    {role: 'user', content: '<context_summary>Tasks 0-9 summarized...</context_summary>'},
    {role: 'user', content: '<context_summary>Tasks 10-19 summarized...</context_summary>'},
    {role: 'user', content: '<context_summary>Tasks 20-29 summarized...</context_summary>'},
    {role: 'user', content: 'Task 20'},                  <- Recent 15 kept
    {role: 'assistant', content: 'Result 20'},
    {role: 'user', content: 'Task 21'},
    {role: 'assistant', content: 'Result 21'},
    ... (15 recent messages)
  ]
""")


print("\n" + "=" * 70)
print("STEP 7: Who does the compression?")
print("=" * 70)

print("""
[COMPRESSION DONE BY: MemoryCompressor class]

Location: phantom/llm/memory_compressor.py

Function: compress_history(messages, agent_state)
  - Called by LLM._prepare_messages()
  - Splits messages into chunks of 10
  - Calls _summarize_messages() on each chunk via LLM
  - Returns: system + summaries + recent
""")


print("\n" + "=" * 70)
print("STEP 8: What are 'chunks'?")
print("=" * 70)

print(f"""
[CHUNKS = groups of 10 messages]

Messages: 0-9   -> Chunk 1 -> Summarized to 1 message
Messages: 10-19 -> Chunk 2 -> Summarized to 1 message  
Messages: 20-29 -> Chunk 3 -> Summarized to 1 message
Messages: 30+   -> More chunks...

This is why chunk_size = 10 (configurable)
""")


print("\n" + "=" * 70)
print("STEP 9: Run REAL compression and show")
print("=" * 70)

state2 = AgentState(agent_id="test2")
compressor2 = MemoryCompressor(model_name=model)

print(f"\n[Create 30 messages with findings]")
for i in range(25):
    state2.add_message("user", f"Task {i}: Test endpoint {i}")
    state2.add_message("assistant", f"Testing in endpoint {i}")
    if i % 5 == 0:
        state2.add_message("assistant", f"CRITICAL: Found SQLi in endpoint {i}")

messages2 = state2.get_conversation_history()
tokens_before = sum(_get_message_tokens(m, model) for m in messages2)

print(f"  Before: {len(messages2)} messages, {tokens_before} tokens")
print(f"  Threshold: {int(compressor2._max_total_tokens * 0.9):,}")

# Force compression by creating many messages
for i in range(50):
    state2.add_message("user", f"More task {i}")
    state2.add_message("assistant", f"More result {i}")

messages3 = state3 = state2.get_conversation_history()
tokens3 = sum(_get_message_tokens(m, model) for m in messages3)

if tokens3 > compressor2._max_total_tokens * 0.9:
    print(f"\n[Running compression...]")
    compressed = compressor2.compress_history(messages3, state2)
    tokens_after = sum(_get_message_tokens(m, model) for m in compressed)
    print(f"  After: {len(compressed)} messages, {tokens_after} tokens")
    print(f"  Reduction: {1-(tokens_after/max(tokens3,1)):.1%}")
else:
    print(f"  Not enough tokens for compression")


print("\n" + "=" * 70)
print("COMPLETE FLOW SUMMARY")
print("=" * 70)

print("""
=============================================================
THE COMPLETE FLOW
=============================================================

1. USER INPUT
   agent.add_message("user", "test /login")

2. STATE.MESSAGES (list)
   - Grows with each user + assistant message
   - This is "the conversation history"

3. EVERY LLM CALL:
   a. agent.get_conversation_history() -> returns list
   b. LLM.generate(conversation_list)
   c. inside LLM: _prepare_messages(list)
   d. compress_history(list) if tokens > threshold
      - Split OLD messages into chunks (10 at a time)
      - Summarize each chunk via LLM
      - Keep RECENT 15 messages as-is
   e. Send to LLM API

4. LLM RESPONSE
   agent.add_message("assistant", response)

5. REPEAT from step 1

=============================================================
KEY FILES
=============================================================
- state.py:42         -> messages list storage
- llm.py:588-659    -> _prepare_messages() 
- memory_compressor.py:598 -> compress_history()
=============================================================
""")


print("\n" + "=" * 70)
print("VERIFICATION COMPLETE")
print("=" * 70)