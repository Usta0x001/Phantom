#!/usr/bin/env python3
"""Test anchor injection in LLM and edge cases"""

import asyncio
from phantom.agents.state import AgentState

print('=== ANCHOR INJECTION & EDGE CASES TEST ===')

# Test 1: Anchor injection format
print('\n1. Testing anchor injection format...')
state = AgentState(agent_id="test", agent_name="Test", task="pentest")

# Add some anchors
anchors = [
    {"key": "SQLi found", "text": "Found SQL injection in /api/login. Confirmed with UNION SELECT.", "source": "compressor"},
    {"key": "XSS found", "text": "Found XSS in /api/search. Payload reflected in response.", "source": "compressor"},
    {"key": "Shell obtained", "text": "Got reverse shell on 10.10.10.10:4444 as root.", "source": "compressor"},
]

for a in anchors:
    state.add_finding_anchor(a)

# Simulate the injection logic from llm.py:618-648
_has_anchors = state is not None and hasattr(state, "finding_anchors") and state.finding_anchors
print(f'   Has anchors: {_has_anchors}')

if _has_anchors:
    anchor_lines = []
    for anchor in state.finding_anchors[:15]:
        text = anchor.get("text", "").strip()
        if text:
            anchor_lines.append(f"- {text[:600]}")
    
    if anchor_lines:
        anchor_reminder = (
            "<finding_anchors>\n"
            "Confirmed signals from earlier in this scan — "
            "report any that have NOT been reported yet:\n"
            + "\n".join(anchor_lines)
            + "\n</finding_anchors>"
        )
        
        print(f'   Injection format length: {len(anchor_reminder)} chars')
        print(f'   Number of anchors in injection: {len(anchor_lines)}')
        print(f'   Sample: {anchor_reminder[:200]}...')

# Test 2: Edge case - empty anchor text
print('\n2. Testing empty anchor text...')
state2 = AgentState(agent_id="test2", agent_name="Test2", task="test")
state2.add_finding_anchor({"key": "empty", "text": "", "source": "compressor"})
print(f'   Empty text handled: {len(state2.finding_anchors) == 0}')

# Test 3: Edge case - very long anchor
print('\n3. Testing very long anchor text...')
long_text = "A" * 10000
state3 = AgentState(agent_id="test3", agent_name="Test3", task="test")
state3.add_finding_anchor({"key": "long", "text": long_text, "source": "compressor"})
stored_text = state3.finding_anchors[0].get("text", "")
print(f'   Long text stored: {len(stored_text)} chars')

# Test 4: Anchor limit (15 max mentioned in code)
print('\n4. Testing anchor limit (should cap at 15)...')
state4 = AgentState(agent_id="test4", agent_name="Test4", task="test")
for i in range(25):
    state4.add_finding_anchor({"key": f"anchor-{i}", "text": f"Test finding number {i}", "source": "compressor"})
print(f'   Anchors after 25 adds: {len(state4.finding_anchors)} (should be capped at 15)')

# Test 5: Check for duplicate keys
print('\n5. Testing duplicate key handling...')
state5 = AgentState(agent_id="test5", agent_name="Test5", task="test")
state5.add_finding_anchor({"key": "same", "text": "First", "source": "compressor"})
state5.add_finding_anchor({"key": "same", "text": "Second", "source": "compressor"})
print(f'   After adding duplicate key twice: {len(state5.finding_anchors)} (should be 1)')

# Test 6: Keyword pattern efficiency
print('\n6. Testing keyword pattern efficiency...')
from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS_PATTERN
import time

# Test with large text
large_text = "Found " + "vulnerability " * 1000 + " confirmed critical"

start = time.time()
for _ in range(1000):
    _ANCHOR_KEYWORDS_PATTERN.search(large_text)
elapsed = time.time() - start
print(f'   1000 regex searches: {elapsed:.3f}s')
print(f'   Per search: {elapsed/1000*1000:.3f}ms')

print('\n=== ALL EDGE CASE TESTS COMPLETED ===')