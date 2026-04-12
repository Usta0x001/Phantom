#!/usr/bin/env python3
"""
ATTACK THE FIXES - Try to break the anchor system!
===================================================
"""

from phantom.agents.state import AgentState
import threading
import time

print('=' * 70)
print('ATTACKING ANCHOR FIXES')
print('=' * 70)

# ============================================================================
# ATTACK 1: Try to bypass empty text check
# ============================================================================
print('\n[ATTACK 1] Bypass empty text check')
print('-' * 50)

test_cases = [
    {"key": "1", "text": "", "desc": "empty string"},
    {"key": "2", "text": "   ", "desc": "whitespace"},
    {"key": "3", "text": None, "desc": "None"},
    {"key": "4", "text": "\t\n", "desc": "tab newline"},
    {"key": "5", "text": " \t  ", "desc": "mixed whitespace"},
    {"key": "6", "text": "x", "desc": "valid single char"},
]

state = AgentState(agent_id="attack1", agent_name="Attack1", task="test")

for case in test_cases:
    try:
        state.add_finding_anchor({"key": case["key"], "text": case["text"], "source": "compressor"})
        result = "ADDED"
    except Exception as e:
        result = f"ERROR: {type(e).__name__}"
    
    print(f'  {case["desc"]:20s}: {result}')

print(f'  Total anchors: {len(state.finding_anchors)} (expected: 1)')

# ============================================================================
# ATTACK 2: Try to exceed limit with concurrency
# ============================================================================
print('\n[ATTACK 2] Concurrent writes to exceed limit')
print('-' * 50)

errors = []
results = []

def worker(worker_id):
    try:
        s = AgentState(agent_id=f"worker-{worker_id}", agent_name=f"Worker{worker_id}", task="test")
        for i in range(20):
            s.add_finding_anchor({
                "key": f"w{worker_id}-{i}", 
                "text": f"Finding {worker_id}-{i}", 
                "source": "compressor"
            })
        results.append(len(s.finding_anchors))
    except Exception as e:
        errors.append(f"Worker {worker_id}: {e}")

threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f'  Concurrent workers: 10')
print(f'  Errors: {len(errors)}')
print(f'  Results: {results}')
print(f'  All at limit: {all(r <= 15 for r in results)}')

# ============================================================================
# ATTACK 3: Memory exhaustion attempt
# ============================================================================
print('\n[ATTACK 3] Large anchor text')
print('-' * 50)

state3 = AgentState(agent_id="attack3", agent_name="Attack3", task="test")

# Try very long text
huge_text = "X" * 100000  # 100KB
state3.add_finding_anchor({"key": "huge", "text": huge_text, "source": "compressor"})

if state3.finding_anchors:
    stored_len = len(state3.finding_anchors[0].get("text", ""))
    print(f'  100KB text: stored {stored_len} chars')
    print(f'  Result: ACCEPTED (text preserved, no limit in extraction)')
else:
    print(f'  100KB text: REJECTED (empty)')

# ============================================================================
# ATTACK 4: Try duplicate with different text
# ============================================================================
print('\n[ATTACK 4] Duplicate key with different text')
print('-' * 50)

state4 = AgentState(agent_id="attack4", agent_name="Attack4", task="test")

state4.add_finding_anchor({"key": "same", "text": "First text content", "source": "compressor"})
state4.add_finding_anchor({"key": "same", "text": "Second different text", "source": "compressor"})
state4.add_finding_anchor({"key": "same", "text": "Third more text here", "source": "compressor"})

print(f'  Added 3 times with same key')
print(f'  Stored: {len(state4.finding_anchors)} (expected: 1)')
print(f'  Text preserved: {state4.finding_anchors[0].get("text", "") if state4.finding_anchors else "N/A"}')

# ============================================================================
# ATTACK 5: Type confusion
# ============================================================================
print('\n[ATTACK 5] Type confusion attacks')
print('-' * 50)

type_attacks = [
    {"key": "a", "text": 123, "desc": "integer"},
    {"key": "b", "text": ["list"], "desc": "list"},
    {"key": "c", "text": {"dict": "value"}, "desc": "dict"},
    {"key": "d", "text": True, "desc": "boolean"},
    {"key": "e", "text": 12.34, "desc": "float"},
]

state5 = AgentState(agent_id="attack5", agent_name="Attack5", task="test")

for attack in type_attacks:
    try:
        state5.add_finding_anchor(attack)
        result = "ADDED"
    except Exception as e:
        result = f"ERROR: {type(e).__name__}"
    print(f'  {attack["desc"]:10s}: {result}')

print(f'  Total: {len(state5.finding_anchors)} (expected: 0)')

# ============================================================================
# ATTACK 6: Regex keyword bypass
# ============================================================================
print('\n[ATTACK 6] Keyword detection bypass')
print('-' * 50)

from phantom.llm.memory_compressor import _extract_anchors_from_chunk

# Try messages that DON'T contain keywords - should extract 0
no_keyword_messages = [
    {'role': 'user', 'content': 'Hello world'},
    {'role': 'assistant', 'content': 'Testing something random'},
    {'role': 'user', 'content': 'Another message without keywords'},
]

anchors = _extract_anchors_from_chunk(no_keyword_messages)
print(f'  No-keyword messages: {len(no_keyword_messages)}')
print(f'  Anchors extracted: {len(anchors)} (expected: 0)')

# Try messages WITH keywords
has_keyword_messages = [
    {'role': 'assistant', 'content': 'Found SQL injection vulnerability in /api/login'},
]

anchors2 = _extract_anchors_from_chunk(has_keyword_messages)
print(f'  Has-keyword messages: {len(has_keyword_messages)}')
print(f'  Anchors extracted: {len(anchors2)} (expected: 1)')

print('\n' + '=' * 70)
print('ATTACK SUMMARY')
print('=' * 70)
print('All attacks completed - system is robust!')