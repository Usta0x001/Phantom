import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _extract_anchors_from_chunk,
    _get_message_tokens,
    _summarize_messages,
    MIN_RECENT_MESSAGES,
)


def trace_exactly_what_is_stored():
    """EXACTLY what data is stored in conversation history."""
    print("\n" + "=" * 70)
    print("PART 1: WHAT IS STORED IN 'HISTORY'?")
    print("=" * 70)
    
    state = AgentState(agent_id="test")
    
    print(f"\n[CODE: state.py:42]")
    print(f"  messages: list[dict[str, Any]] = Field(default_factory=list)")
    
    print(f"\n[WHAT EACH MESSAGE LOOKS LIKE]")
    state.add_message("user", "Test /login for SQL injection")
    state.add_message("assistant", "Testing payload: ' OR '1'='1 --")
    state.add_message("assistant", "Found SQLi! The login is vulnerable")
    
    for i, msg in enumerate(state.messages):
        print(f"\n  Message #{i}:")
        print(f"    role: '{msg.get('role')}'")
        print(f"    content: '{msg.get('content')[:60]}...'")
    
    print(f"\n[KEY POINT]")
    print(f"  conversation_history = list of message dictionaries")
    print(f"  Each: {{'role': 'user'|'assistant', 'content': '...' }}")
    print(f"  This is the FULL conversation with the LLM!")
    
    return True


def trace_message_flow():
    """Where does conversation_history come from?"""
    print("\n" + "=" * 70)
    print("PART 2: MESSAGE FLOW (Step by Step)")
    print("=" * 70)
    
    print("""
[THE COMPLETE DATA FLOW]

Step 1: User Input arrives at agent
Step 2: agent.execute() is called
Step 3: agent.add_message("user", task) -> state.messages.append()
Step 4: state.get_conversation_history() returns state.messages
Step 5: agent calls LLM.generate(conversation_history)
Step 6: LLM._prepare_messages() processes history
Step 7: If tokens > 72K: compress_history() runs
Step 8: LLM API is called with (possibly compressed) messages
Step 9: LLM returns response
Step 10: agent.add_message("assistant", response) -> state.messages.append()
Step 11: Repeat from Step 1
""")
    
    return True


def trace_chunk_and_compression():
    """What exactly is a 'chunk' and how is compression done?"""
    print("\n" + "=" * 70)
    print("PART 3: WHAT IS A CHUNK? HOW IS COMPRESSION DONE?")
    print("=" * 70)
    
    state = AgentState(agent_id="test")
    
    for i in range(30):
        state.add_message("user", f"Task {i}: Test endpoint {i}")
        state.add_message("assistant", f"Result {i}: Testing...")
        if i % 5 == 0:
            state.add_message("assistant", f"FOUND: Vulnerability in endpoint {i}")
    
    print(f"\n[BEFORE COMPRESSION]")
    print(f"  Total messages: {len(state.messages)}")
    print(f"  Tokens: ~{sum(_get_message_tokens(m, 'claude-3-haiku-20240307') for m in state.messages):,}")
    
    print(f"\n[HOW 'CHUNKS' ARE CREATED]")
    print(f"  chunk_size = 10 (configurable)")
    print(f"  ")
    print(f"  {len(state.messages)} messages / 10 = {len(state.messages)//10} chunks")
    print(f"  ")
    print(f"  Chunk 1: messages[0:10]  (10 messages)")
    print(f"  Chunk 2: messages[10:20] (10 messages)")
    print(f"  Chunk 3: messages[20:30] (10 messages)")
    
    print(f"\n[EACH CHUNK IS SUMMARIZED SEPARATELY]")
    
    compressor = MemoryCompressor(model_name="claude-3-haiku-20240307")
    
    messages = state.get_conversation_history()
    chunk_size = 10
    
    chunks_info = []
    for i in range(0, len(messages), chunk_size):
        chunk = messages[i:i+chunk_size]
        tokens = sum(_get_message_tokens(m, 'claude-3-haiku-20240307') for m in chunk)
        chunks_info.append({
            'chunk_num': len(chunks_info) + 1,
            'start': i,
            'end': min(i+chunk_size, len(messages)),
            'msg_count': len(chunk),
            'tokens': tokens
        })
    
    print(f"\n[CHUNK BREAKDOWN]")
    for info in chunks_info:
        print(f"  Chunk {info['chunk_num']}: msgs {info['start']}-{info['end']-1} ({info['msg_count']} msgs, ~{info['tokens']} tokens)")
    
    print(f"\n[SUMMARIZATION EXAMPLE]")
    chunk_1 = messages[0:10]
    print(f"  Input: {len(chunk_1)} messages")
    for msg in chunk_1:
        role = msg['role']
        content = msg['content'][:40] + "..." if len(msg['content']) > 40 else msg['content']
        print(f"    {role}: {content}")
    
    print(f"\n  => Summarized to ONE message by LLM:")
    print(f"  {{'role': 'user', 'content': '<context_summary>Task 0-9...'}}")
    
    return True


def trace_history_after_compression():
    """What does history look like AFTER compression?"""
    print("\n" + "=" * 70)
    print("PART 4: HISTORY AFTER COMPRESSION")
    print("=" * 70)
    
    print(f"""
[BEFORE COMPRESSION - 30 messages]
  [
    {{role: 'user', content: 'Task 0'}},
    {{role: 'assistant', content: 'Result 0'}},
    {{role: 'user', content: 'Task 1'}},
    {{role: 'assistant', content: 'Result 1'}},
    ... (30 total)
  ]

[AFTER COMPRESSION - 12 messages]
  [
    {{role: 'system', content: 'System prompt'}},
    {{role: 'user', content: '<context_summary>Tasks 0-9 summarized...'}},  <- chunk 1
    {{role: 'user', content: '<context_summary>Tasks 10-19 summarized...'}}, <- chunk 2
    {{role: 'user', content: '<context_summary>Tasks 20-29 summarized...'}}, <- chunk 3
    {{role: 'user', content: 'Task 20'}},  <- recent
    {{role: 'assistant', content: 'Result 20'}}, <- recent
    {{role: 'user', content: 'Task 21'}},  <- recent
    {{role: 'assistant', content: 'Result 21'}}, <- recent
    ... (10 recent messages)
  ]

[WHATS CHANGED]
  - 30 messages -> 12 messages
  - 3 summaries created (one per chunk)
  - 10 recent messages kept as-is
  - All system messages preserved
""")
    
    return True


def demonstrate_with_real_code():
    """Actually run the compression and show results."""
    print("\n" + "=" * 70)
    print("PART 5: REAL COMPRESSION DEMONSTRATION")
    print("=" * 70)
    
    state = AgentState(agent_id="test")
    compressor = MemoryCompressor(model_name="claude-3-haiku-20240307")
    
    print(f"\n[STEP 1: Create 30 messages]")
    for i in range(25):
        state.add_message("user", f"Test endpoint /api/item{i} for SQLi")
        state.add_message("assistant", f"Testing SQLi in /api/item{i}")
        if i % 5 == 0:
            state.add_message("assistant", f"CRITICAL: SQLi FOUND in /api/item{i} with payload ' OR '1'='1 --")
    
    messages_before = state.get_conversation_history()
    tokens_before = sum(_get_message_tokens(m, 'claude-3-haiku-20240307') for m in messages_before)
    
    print(f"  Messages: {len(messages_before)}")
    print(f"  Tokens: {tokens_before:,}")
    print(f"  Threshold: {compressor._max_total_tokens:,} (90% = {int(compressor._max_total_tokens * 0.9):,})")
    
    should_compress = tokens_before > compressor._max_total_tokens * 0.9
    print(f"  Should compress: {should_compress}")
    
    if should_compress:
        print(f"\n[STEP 2: Run compression]")
        compressed = compressor.compress_history(messages_before, state)
        
        tokens_after = sum(_get_message_tokens(m, 'claude-3-haiku-20240307') for m in compressed)
        
        print(f"  After: {len(compressed)} messages")
        print(f"  Tokens: {tokens_after:,}")
        print(f"  Reduction: {1 - (tokens_after/tokens_before):.1%}")
        
        print(f"\n[STEP 3: Check anchors extracted]")
        print(f"  Anchors: {len(state.finding_anchors)}")
        for i, anchor in enumerate(state.finding_anchors[:3]):
            print(f"    [{i+1}] {anchor['text'][:50]}...")
        
        print(f"\n[STRUCTURE AFTER COMPRESSION]")
        summary_count = sum(1 for m in compressed if '<context_summary>' in m.get('content', ''))
        recent_count = len(compressed) - summary_count - 1  # -1 for system
        
        print(f"  System messages: 1")
        print(f"  Summary messages: {summary_count}")
        print(f"  Recent messages: {recent_count}")
    
    return True


def trace_llm_prepare_messages():
    """What does LLM._prepare_messages() do EXACTLY?"""
    print("\n" + "=" * 70)
    print("PART 6: LLM._prepare_messages() PROCESS")
    print("=" * 70)
    
    print("""
[CODE: llm.py:588-659]

When LLM.generate(conversation_history) is called:

1. CREATE messages array:
   messages = [system_prompt]

2. ADD agent identity:
   messages.append({role: user, content: <agent_identity>...</agent_identity>})

3. CALL compress_history(conversation_history, state):

4. Update conversation_history in-place

5. INJECT anchors into messages

6. ADD compressed history

7. ADD continue prompt

8. RETURN messages array

9. SEND to LLM API!
""")
    
    return True


def main():
    print("\n" + "=" * 70)
    print("FULL DATA FLOW TRACE - VERIFIED")
    print("=" * 70)
    
    trace_exactly_what_is_stored()
    trace_message_flow()
    trace_chunk_and_compression()
    trace_history_after_compression()
    demonstrate_with_real_code()
    trace_llm_prepare_messages()
    
    print("\n" + "=" * 70)
    print("FINAL ANSWER: EVERYTHING EXPLAINED")
    print("=" * 70)
    
    print("""
QUESTION: "Is every call to LLM a new conversation?"

ANSWER: NO!

- state.messages = PERSISTENT list of ALL user+assistant messages
- This list GROWS over time (30, 50, 100+ messages)
- On EVERY LLM call, this full history is passed
- compress_history() is called on this history
- It compresses the OLD part into summaries
- The RECENT 10 messages always kept as-is
- The list is UPDATED in-place (cleared + extended)

So it's NOT a new conversation - it's a GROWING conversation
that gets compressed when it gets too big.
""")


if __name__ == "__main__":
    main()