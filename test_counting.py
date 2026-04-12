import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("HOW THE AGENT COUNTS TOKENS - THE EXACT FUNCTION")
print("=" * 70)

print("""

=============================================================
THE KEY FUNCTION: _get_message_tokens()
=============================================================

This is HOW it knows! The function that DO the counting!

""")

from phantom.llm.memory_compressor import _get_message_tokens, _count_tokens
from phantom.agents.state import AgentState

model = "claude-3-haiku-20240307"

state = AgentState(agent_id="test")

# Add test messages
state.add_message("user", "Test SQL injection in /login")
state.add_message("assistant", "Testing payload: ' OR '1'='1 --")
state.add_message("user", "Test XSS in /search")
state.add_message("assistant", "Testing <script>alert(1)</script>")

messages = state.get_conversation_history()

print("\n[MESSAGES]")
for i, msg in enumerate(messages):
    print(f"  [{i}] {msg['role']}: {msg['content'][:30]}...")

print("\n" + "=" * 70)
print("THE EXACT FUNCTION: _get_message_tokens()")
print("=" * 70)

print("""

Location: memory_compressor.py line 303

Code:
----------------------------------------------
def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    try:
        return int(litellm.token_counter(model=model, messages=[msg]))
    except Exception:
        pass
    # Fallback code...
    content = msg.get("content", "")
    # ...counting...
    return base
----------------------------------------------

This function:
1. TRIES to use litellm.token_counter()
2. If fails, FALLS BACK to len(text) // 4
""")

# Run the exact function
print("\n[RUNNING THE EXACT FUNCTION]")

for msg in messages:
    tokens = _get_message_tokens(msg, model)
    content = msg['content'][:25] + "..."
    print(f"  '{content}' -> {tokens} tokens")

# Sum all
total = sum(_get_message_tokens(m, model) for m in messages)
print(f"\n  TOTAL: {total} tokens")

print("\n" + "=" * 70)
print("THE FALLBACK (len(text) // 4)")
print("=" * 70)

print("""

If litellm.token_counter() FAILS:

  return len(text) // 4

Example:
  "Test SQL injection" -> 17 chars // 4 = 4 tokens

This can be INACCURATE!
But it's the fallback when primary fails.
""")

print("\n" + "=" * 70)
print("THE COMPLETE FLOW")
print("=" * 70)

print("""

compress_history() called
       |
       v
total_tokens = 0
for each message:
    tokens = _get_message_tokens(message, model)
    total_tokens += tokens
       |
       v
total_tokens = 1234 (example)
       |
       v
threshold = 72000
       |
       v
IF total_tokens > threshold:
    COMPRESS!
ELSE:
    Return original

""")

print("\n" + "=" * 70)
print("THE FUNCTION THAT DOES THE COUNTING")
print("=" * 70)

print(f"""

Function: _get_message_tokens(msg, model)

What it does:
1. Call litellm.token_counter(model=model, messages=[msg])
2. Return token count

This is how it knows!

The system calls this function for EVERY message,
then SUMS them all,
then COMPARES to threshold.

""")

print("=" * 70)
print("VERIFIED!")
print("=" * 70)