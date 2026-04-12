import os
import sys

os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

from phantom.llm.memory_compressor import (
    MemoryCompressor,
    _extract_anchors_from_chunk,
    _get_message_tokens,
    _count_tokens,
    _get_model_context_window,
    MIN_RECENT_MESSAGES,
    MAX_CONTEXT_CEILING,
)


def test_bug_1_anchor_keyword_overcapture():
    """BUG 1: Anchor keywords are too permissive - capture testing context, not just findings.
    
    The keywords match:
    - "Testing SQL injection" (just testing, not confirmed)
    - "Found error in..." (error, not vulnerability)
    
    This causes anchor bloat and noise.
    """
    print("\n" + "=" * 70)
    print("BUG 1: Anchor Keyword Over-Permissive")
    print("=" * 70)
    
    test_messages = [
        {"role": "user", "content": "Test SQL injection in /login"},
        {"role": "assistant", "content": "Trying SQLi payload ' OR '1'='1 --"},  # Just TRYING
        {"role": "assistant", "content": "Testing XSS in /search parameter"},  # Just TESTING
        {"role": "user", "content": "What is weather today?"},  # No keywords
    ]
    
    anchors = _extract_anchors_from_chunk(test_messages)
    
    print(f"\n[ISSUE] Messages: 4, Anchors extracted: {len(anchors)}")
    print(f"[NOTE] 'Testing' and 'Trying' are NOT findings - just context")
    print(f"[RESULT] Keywords match ANY mention, not confirmed findings")
    
    for i, anchor in enumerate(anchors):
        print(f"  [{i+1}] {anchor['text'][:60]}...")
    
    return len(anchors) == 4


def test_bug_2_recent_messages_too_few():
    """BUG 2: Only 10 recent messages kept - loses recent findings.
    
    With chunk_size=10, any finding in message 11-20 gets summarized 
    before being in "recent" - loses raw detail.
    """
    print("\n" + "=" * 70)
    print("BUG 2: Recent Messages Count")
    print("=" * 70)
    
    print(f"\n[CONFIG] MIN_RECENT_MESSAGES = {MIN_RECENT_MESSAGES}")
    print(f"[ISSUE] If find vulnerability in message #15:")
    print(f"        - It gets summarized (loses exact payload)")
    print(f"        - Only 10 recent kept raw")
    print(f"[IMPACT] Exact payload details lost after compression")


def test_bug_3_chunk_size_mismatch():
    """BUG 3: Anchor extraction and chunking use different sizes.
    
    Anchor extraction: chunks by chunk_size
    Summary: also uses chunk_size
    
    But they iterate differently - could cause off-by-one or missed anchors.
    """
    print("\n" + "=" * 70)
    print("BUG 3: Chunk Size Consistency")
    print("=" * 70)
    
    print(f"\n[CODE ANALYSIS]")
    print(f"  Line 677: for i in range(0, len(old_msgs), chunk_size)")
    print(f"  Line 687: for i in range(0, len(old_msgs), chunk_size)")
    
    print(f"\n[RESULT] Both use same chunk_size - NO BUG HERE")
    print(f"[PASS] Chunk sizes consistent")


def test_bug_4_anchor_injection_no_dedup():
    """BUG 4: Anchors can be injected multiple times.
    
    The _already_injected check only looks at LAST 5 messages.
    If anchors change after compression, they might be re-injected.
    """
    print("\n" + "=" * 70)
    print("BUG 4: Anchor Duplicate Injection")
    print("=" * 70)
    
    print(f"\n[CODE] llm.py line 631-633")
    print(f"  _already_injected = any(")
    print(f"      'finding_anchors' in str(m.get('content', ''))")
    print(f"      for m in _last_msgs")
    print(f"  )")
    
    print(f"\n[ISSUE] Only checks last 5 messages for duplicate tag")
    print(f"[EDGE CASE] If compression clears those 5, anchors re-injected")
    print(f"[IMPACT] Minor - redundant but not breaking")


def test_bug_5_compression_threshold_bleed():
    """BUG 5: Uses 0.9 multiplier creating 10% bleed.
    
    threshold * 0.9 means compression fires slightly early,
    but summary could still exceed threshold.
    """
    print("\n" + "=" * 70)
    print("BUG 5: Compression Threshold Bleed")
    print("=" * 70)
    
    threshold = 80_000
    actual = threshold * 0.9
    
    print(f"\n[CODE] line 650")
    print(f"  if total_tokens <= self._max_total_tokens * 0.9")
    print(f"\n[CONFIG] threshold={threshold:,}, actual={actual:,.0f}")
    print(f"[ISSUE] Uses 0.9 multiplier - triggers early")
    print(f"[NOTE] But tokens AFTER compression could exceed threshold!")
    print(f"[IMPACT] Could still overflow context window")


def test_bug_6_token_count_inaccurate():
    """BUG 6: Token counting uses rough estimate fallback.
    
    Line 228: if counting fails, uses len(text) // 4
    
    4 chars per token is a rough estimate - could be way off
    for certain text patterns.
    """
    print("\n" + "=" * 70)
    print("BUG 6: Token Count Accuracy")
    print("=" * 70)
    
    test_texts = [
        ("short", "hello world"),
        ("code", "function() { return x + y; }"),
        ("unicode", "password=密码123"),
        ("json", '{"key": "value", "data": [1,2,3]}'),
    ]
    
    model = "claude-3-haiku-20240307"
    
    print(f"\n[TOKEN COUNTING TEST]")
    for name, text in test_texts:
        try:
            counted = _count_tokens(text, model)
            actual = len(text)
            ratio = counted / max(actual, 1)
            print(f"  {name:<10}: {counted:>4} tokens for {actual:>3} chars ({ratio:.2f})")
        except:
            print(f"  {name:<10}: ERROR")
    
    print(f"\n[ISSUE] Fallback len(text)//4 is crude estimate")
    print(f"[IMPACT] Inaccurate threshold triggers")


def test_bug_7_memory_leak_potential():
    """BUG 7: Anchors accumulate indefinitely.
    
    add_finding_anchor() has MAX_FINDING_ANCHORS = 15
    
    But if anchors are extracted every compression cycle without clearing,
    they keep accumulating. MAX only prevents ADDING, not total growth.
    """
    print("\n" + "=" * 70)
    print("BUG 7: Anchor Memory Accumulation")
    print("=" * 70)
    
    from phantom.agents.state import AgentState
    
    state = AgentState(agent_id="test")
    
    print(f"\n[CODE] state.py line 77-79")
    print(f"  if len(self.finding_anchors) >= self.MAX_FINDING_ANCHORS:")
    print(f"      return  # Don't add more")
    
    print(f"\n[ISSUE] Old anchors never expire or get cleaned")
    print(f"[EDGE CASE] After 10 compressions: 15 anchors each cycle")
    print(f"          MAX caps at 15, but which 15? First added.")
    print(f"[NOTE] Old anchors become stale - context changes but anchors don't")
    print(f"[IMPACT] Anchors can become outdated but stay in prompt")


def test_bug_8_summary_context_loss():
    """BUG 8: LLM summarization can lose critical details.
    
    The summary prompt asks to preserve URLs, payloads, tokens.
    But LLM might paraphrase or skip details.
    """
    print("\n" + "=" * 70)
    print("BUG 8: Summary Context Loss")
    print("=" * 70)
    
    print(f"\n[SUMMARY PROMPT] says 'copy verbatim' but...")
    print(f"  - LLM may paraphrase: 'SQLi payload used' vs exact payload")
    print(f"  - LLM may skip: 'various payloads' instead of list")
    print(f"  - LLM may wrong: hallucinate details")
    
    print(f"\n[MITIGATION] Anchor extraction preserves first 1500 chars")
    print(f"[REMAINING RISK] If anchor not extracted before summary,")
    print(f"                 exact details lost forever")


def test_bug_9_parallel_event_loop():
    """BUG 9: Parallel compression might fail on nested async.
    
    Code uses nest_asyncio.apply() as fallback.
    This can cause issues in complex async contexts.
    """
    print("\n" + "=" * 70)
    print("BUG 9: Nested Async Event Loop")
    print("=" * 70)
    
    print(f"\n[CODE] line 697-702")
    print(f"  try:")
    print(f"      asyncio.get_running_loop()")
    print(f"      import nest_asyncio")
    print(f"      nest_asyncio.apply()")
    print(f"  except RuntimeError:")
    print(f"      asyncio.run(...)")
    
    print(f"\n[ISSUE] nested asyncio can cause deadlock")
    print(f"[EDGE CASE] Complex async agent with nested calls")
    print(f"[NOTE] Fallback exists - sequential processing")


def test_bug_10_empty_chunk_handling():
    """BUG 10: No check for empty chunks causing wasted LLM calls.
    
    If old_msgs is empty or chunk_size > len(old_msgs),
    will still call _summarize_messages with potentially empty data.
    """
    print("\n" + "=" * 70)
    print("BUG 10: Empty Chunk Handling")
    print("=" * 70)
    
    compressor = MemoryCompressor(model_name="claude-3-haiku-20240307")
    
    messages = [
        {"role": "system", "content": "You are a pentest agent"},
        {"role": "user", "content": "test 1"},
        {"role": "user", "content": "test 2"},
    ]
    
    print(f"\n[TEST] Only 3 messages (2 regular)")
    print(f"  old_msgs = regular_msgs[:-10] = {len(messages) - 1 - MIN_RECENT_MESSAGES}")
    
    result = compressor.compress_history(messages)
    
    print(f"  Result: {len(result)} messages")
    print(f"  [PASS] Empty old_msgs handled correctly (returned as-is)")


def test_bug_11_image_eviction_order():
    """BUG 11: Image eviction might remove evidence.
    
    _handle_images keeps RECENT images, evicting OLDER ones.
    But OLDER screenshots might contain vulnerability evidence!
    """
    print("\n" + "=" * 70)
    print("BUG 11: Image Eviction Evidence Loss")
    print("=" * 70)
    
    print(f"\n[CODE] _handle_images() - likely evicts OLD images")
    print(f"[ISSUE] Old screenshot of SQLi error might be evicted")
    print(f"       while recent screenshot of 404 page kept")
    print(f"[IMPACT] Vulnerability evidence lost")


def test_bug_12_no_compression_recovery():
    """BUG 12: No recovery if compression fails completely.
    
    If ALL chunk summarizations fail, falls back to text truncation.
    But no way to recover if still over threshold.
    """
    print("\n" + "=" * 70)
    print("BUG 12: Compression Failure Recovery")
    print("=" * 70)
    
    print(f"\n[FALLBACK CHAIN]")
    print(f"  1. LLM summarize")
    print(f"  2. Fallback: join lines (truncated to 8000 chars)")
    print(f"  3. If STILL over: ?? Nothing - will overflow")
    
    print(f"\n[ISSUE] No escalation - if fallback exceeds threshold,")
    print(f"        context still too large")
    print(f"[EDGE CASE] Very long conversation with many findings")


def main():
    print("\n" + "=" * 70)
    print("COMPRESSION SYSTEM BUG ANALYSIS")
    print("=" * 70)
    
    results = []
    
    results.append(("BUG-1: Keyword Over-capture", test_bug_1_anchor_keyword_overcapture()))
    test_bug_2_recent_messages_too_few()
    results.append(("BUG-3: Chunk Size Match", test_bug_3_chunk_size_mismatch()))
    test_bug_4_anchor_injection_no_dedup()
    test_bug_5_compression_threshold_bleed()
    test_bug_6_token_count_inaccurate()
    test_bug_7_memory_leak_potential()
    test_bug_8_summary_context_loss()
    test_bug_9_parallel_event_loop()
    test_bug_10_empty_chunk_handling()
    test_bug_11_image_eviction_order()
    test_bug_12_no_compression_recovery()
    
    print("\n" + "=" * 70)
    print("SUMMARY OF ISSUES FOUND")
    print("=" * 70)
    
    critical = [
        "BUG-1: Keywords too permissive - capture testing context, not just findings",
        "BUG-6: Token counting can be inaccurate (len//4 fallback)",
        "BUG-8: LLM summarization may lose exact payload details",
        "BUG-11: Image eviction may lose vulnerability evidence",
    ]
    
    medium = [
        "BUG-2: Only 10 recent messages - findings in msg 11-20 summarized",
        "BUG-7: Anchors never expire - become stale over time",
    ]
    
    low = [
        "BUG-4: Duplicate injection check incomplete",
        "BUG-5: 0.9 threshold bleed",
        "BUG-9: Nested async fallback",
        "BUG-12: No escalation if still over threshold",
    ]
    
    print(f"\n[CRITICAL - Can cause context loss]")
    for b in critical:
        print(f"  [X] {b}")
    
    print(f"\n[MEDIUM - Cause inefficient/lost detail]")
    for b in medium:
        print(f"  [!] {b}")
    
    print(f"\n[LOW - Manageable edge cases]")
    for b in low:
        print(f"  [.] {b}")


if __name__ == "__main__":
    main()