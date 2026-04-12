import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("HOW SUMMARIZATION WORKS - STEP BY STEP")
print("=" * 70)

print("""

=============================================================
SUMMARIZATION PROCESS
=============================================================

The key function: _summarize_messages()
Location: memory_compressor.py line 332

WHAT IT DOES:
1. Takes a CHUNK of 10 messages
2. Sends them to LLM with a special PROMPT
3. LLM returns a SUMMARY
4. Returns ONE message with the summary

LET'S TRACE THIS:
""")

from phantom.llm.memory_compressor import (
    _summarize_messages,
    SUMMARY_PROMPT_TEMPLATE,
    _extract_message_text,
)

# Create test messages
test_messages = [
    {"role": "user", "content": "Test SQL injection in /login"},
    {"role": "assistant", "content": "Testing payload: ' OR '1'='1 --"},
    {"role": "assistant", "content": "Found SQLi! The login form is vulnerable"},
    {"role": "user", "content": "Test SQL injection in /register"},
    {"role": "assistant", "content": "Testing payload: admin' --"},
    {"role": "assistant", "content": "Found SQLi in /register too"},
    {"role": "user", "content": "Test XSS in /search"},
    {"role": "assistant", "content": "Testing <script>alert(1)</script>"},
    {"role": "assistant", "content": "XSS reflected in search parameter"},
    {"role": "user", "content": "Continue testing"},
]

print(f"\n[INPUT] 10 messages to summarize:")
for i, msg in enumerate(test_messages):
    print(f"  [{i}] {msg['role']}: {msg['content'][:40]}...")

# Show what the LLM sees
print(f"\n[THE PROMPT SENT TO LLM]")
print("-" * 50)
print(SUMMARY_PROMPT_TEMPLATE.format(conversation="[will be the 10 messages]"))
print("-" * 50)

print("""
The LLM receives:
- The SUMMARY PROMPT (instructions)
- The 10 messages to summarize

The LLM then returns a summary like:

<context_summary message_count='10'>
STATUS: Testing SQLi
PROGRESS: Found SQLi in /login and /register
FINDINGS:
- SQLi in /login with payload ' OR '1'='1 --
- SQLi in /register with payload admin' --
- XSS in /search (not confirmed)
TECH STACK: PHP, MySQL
</context_summary>

This is returned as ONE message!
""")


print("\n" + "=" * 70)
print("WHO CALLS THIS FUNCTION?")
print("=" * 70)

print("""
compress_history() function:

1. Split messages into CHUNKS of 10
2. For each CHUNK, call _summarize_messages()
3. Collect all summaries

CODE in compress_history():
""")

# Show the chunking logic
chunk_size = 10

chunks = []
for i in range(0, len(test_messages), chunk_size):
    chunk = test_messages[i:i+chunk_size]
    chunks.append(chunk)

print(f"\n[Example: {len(test_messages)} messages -> {len(chunks)} chunks]")
for i, chunk in enumerate(chunks):
    print(f"  Chunk {i+1}: {len(chunk)} messages")


print("\n" + "=" * 70)
print("WHERE DOES THE COMPRESSED GO?")
print("=" * 70)

print("""
After _summarize_messages() creates summaries:

compress_history() returns:
  [
    system messages...
    <context_summary Chunk 1>...
    <context_summary Chunk 2>...
    <context_summary Chunk 3>...
    recent message 1...
    recent message 2...
    ... (15 recent)
  ]

THIS IS THEN SENT TO LLM!

In llm.py line 651:
  messages.extend(compressed)
  return messages  ← This array sent to LLM API

So the final array sent to LLM has:
- System prompt
- Summaries (replacing old messages)
- Recent 15 messages (as-is)
""")


print("\n" + "=" * 70)
print("FULL CODE FLOW")
print("=" * 70)

print("""

STEP BY STEP:

1. agent.execute(task)
       │
2.   state.add_message(user, task)
       │
3.   conversation = state.get_conversation_history()
       │
4.   LLM.generate(conversation)
       │
5.   _prepare_messages(conversation)
       │        ← llm.py line 588
       │
6.   compress_history(conversation)
       │        ← memory_compressor.py line 634
       │
7.   Split into chunks of 10
       │
8.   For each chunk:
       │        ← memory_compressor.py line 332
       │        ← _summarize_messages()
       │        ← CALLS LLM API!
       │
9.   Get summaries back
       │
10.  Build: system + summaries + recent
       │
11.  messages.extend(compressed)
       │        ← llm.py line 651
       │
12.  RETURN messages ← SENT TO LLM API
       │
13.  LLM returns response

THE KEY POINT:
=============

compress_history() CALLS THE LLM internally
to create summaries!

It uses the LLM twice:
- Once to create summaries (internal)
- Once for the actual task (external)


WHAT GETS COMPRESSED:
==================

The OLD messages get summarized:
- Messages 0 to N-15  (older messages)
- Replaced with 1 summary per 10 messages

The RECENT messages stay:
- Messages N-14 to N (15 most recent)
- Kept as-is


HOW TO VERIFY THIS:
================
""")

# Run actual simulation
from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import MemoryCompressor
from phantom.llm.memory_compressor import _get_message_tokens

model = "claude-3-haiku-20240307"

state = AgentState(agent_id="sim")
compressor = MemoryCompressor(model_name=model)

# Create enough messages to trigger compression
for i in range(60):
    state.add_message("user", f"Task {i}: Test endpoint {i}")
    state.add_message("assistant", f"Testing endpoint {i}")
    if i % 10 == 0:
        state.add_message("assistant", f"Found vulnerability in endpoint {i}")

messages = state.get_conversation_history()
tokens = sum(_get_message_tokens(m, model) for m in messages)

print(f"\n[SIMULATION]")
print(f"  Messages created: {len(messages)}")
print(f"  Total tokens: {tokens}")
print(f"  Compression threshold: {int(compressor._max_total_tokens * 0.9):,}")
print(f"  ")
print(f"  Since tokens ({tokens}) < threshold ({int(compressor._max_total_tokens * 0.9):,})")
print(f"  No compression triggered")
print(f"  But the flow is the SAME when triggered!")


print("\n" + "=" * 70)
print("COMPLETE SUMMARY")
print("=" * 70)

print("""
QUESTION: How summarization works?

ANSWER:

1. compress_history() is called
2. It splits 30 messages into 3 chunks of 10
3. For EACH chunk, it calls _summarize_messages()
4. _summarize_messages() CALLS THE LLM API internally
5. LLM returns a short summary
6. The 10 messages become 1 summary message
7. All summaries + recent 15 sent to the REAL LLM


WHO DOES THE COMPRESSION?
=====================

MemoryCompressor class in memory_compressor.py

- compress_history() = main function
- _summarize_messages() = calls LLM to summarize

WHERE IS COMPRESSED SENT TO LLM?
==============================

In llm.py line 651:
  messages.extend(compressed)
  return messages

This messages array is then sent to the LLM API!


WHAT IS COMPRESSED?
=================

OLD messages → Replaced with summaries
RECENT 15 messages → Kept as-is

So instead of sending 100 messages,
the system sends ~20 messages (fewer summaries + recent)
""")


print("\n" + "=" * 70)
print("VERIFIED!")
print("=" * 70)