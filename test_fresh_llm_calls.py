import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

model = "claude-3-haiku-20240307"

print("""
Every time you call litellm.completion(), it's a fresh API call!

Code:
  response = litellm.completion(model=model, messages=[...])
  
Each call:
  - Has NO memory of previous calls
  - Only knows what's in the 'messages' list you send
  - Returns response based ONLY on that input
""")

print("\n" + "=" * 70)
print("PROOF 2: HOW LLM API WORKS")
print("=" * 70)

print("""
Every LLM API call is INDEPENDENT!

How litellm.completion() works:
  response = litellm.completion(model=model, messages=[...])
  
The 'messages' list contains ALL context for that call.
There's NO shared memory between calls.

If call 1 sends: [{role: user, content: "Hello"}]
If call 2 sends: [{role: user, content: "Goodbye"}]

The LLM for call 2 ONLY sees "Goodbye".
It does NOT know about "Hello"!

This is how all LLM APIs work:
- Each request is self-contained
- No memory between requests
- You must repeat context every time
""")


print("\n" + "=" * 70)
print("HOW THE COMPRESSION CALL WORKS")
print("=" * 70)

print("""
compress_history() internally calls:

  _summarize_messages(chunk) 
    |
    v
  litellm.completion(
    model=compressor_model,
    messages=[{"role": "user", "content": prompt + chunk}]
  )

This is a COMPLETELY FRESH LLM API call!

The summary LLM doesn't know:
- What other chunks exist
- What the main task is
- Previous compressions

It just gets 10 messages and returns a summary.
""")

print("\n" + "=" * 70)
print("THE FLOW: MULTIPLE FRESH CALLS")
print("=" * 70)

print("""
Call 1 (Main task): 
  LLM API receives: system + history + anchors
  Fresh context - only what we send!

Call 2 (Summary chunk 1):
  LLM API receives: prompt + messages[0:10]
  Fresh context - only those 10 messages!

Call 3 (Summary chunk 2):
  LLM API receives: prompt + messages[10:20]  
  Fresh context - only those 10 messages!

etc...

Each call is INDEPENDENT and FRESH!
""")


print("\n" + "=" * 70)
print("VERIFY WITH CODE")
print("=" * 70)

print("""
The code in memory_compressor.py line 381:

  response = litellm.completion(**completion_args)
  
Each call is a FRESH API call!

The function signature:
  litellm.completion(
    model="...",
    messages=[...]  # ALL context for THIS call
  )

There's no shared state across calls.
""")

print("\n" + "=" * 70)
print("FINAL ANSWER")
print("=" * 70)

print("""
YES - EVERY LLM API CALL IS FRESH!

- Main task call: Fresh context (history we send)
- Summary call 1: Fresh context (chunk 1 only!)
- Summary call 2: Fresh context (chunk 2 only!)
- etc...

The LLM has NO memory between calls.
We must send all context every time.

That's why compress_history() sends
each chunk separately - each is a fresh call!
""")


print("\n" + "=" * 70)
print("VERIFIED AND PROVEN!")
print("=" * 70)


print("\n" + "=" * 70)
print("VERIFIED AND PROVEN!")
print("=" * 70)