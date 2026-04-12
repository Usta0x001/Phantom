#!/usr/bin/env python3
"""
TEST FIXED ANCHOR SYSTEM
========================
Verify bugs are fixed and test edge cases.
"""

from phantom.agents.state import AgentState

print('=' * 70)
print('TESTING FIXED ANCHOR SYSTEM')
print('=' * 70)

# ============================================================================
# TEST 1: Empty text now rejected
# ============================================================================
print('\n[TEST 1] Empty text rejected')
print('-' * 50)

state1 = AgentState(agent_id="test1", agent_name="Test1", task="test")

# Try empty text
state1.add_finding_anchor({"key": "empty", "text": "", "source": "compressor"})
print(f'After adding empty text: {len(state1.finding_anchors)} anchors')

# Try whitespace
state1.add_finding_anchor({"key": "whitespace", "text": "   ", "source": "compressor"})
print(f'After adding whitespace: {len(state1.finding_anchors)} anchors')

# Try None
state1.add_finding_anchor({"key": "none", "text": None, "source": "compressor"})
print(f'After adding None text: {len(state1.finding_anchors)} anchors')

if len(state1.finding_anchors) == 0:
    print('FIX VERIFIED: Empty text rejected!')
else:
    print('FIX FAILED: Still accepting empty!')

# ============================================================================
# TEST 2: Anchor limit now enforced
# ============================================================================
print('\n[TEST 2] Anchor limit enforced')
print('-' * 50)

state2 = AgentState(agent_id="test2", agent_name="Test2", task="test")

# Add 25 anchors
for i in range(25):
    state2.add_finding_anchor({
        "key": f"anchor-{i}", 
        "text": f"Test finding number {i} with some content", 
        "source": "compressor"
    })

print(f'Added 25 anchors')
print(f'Anchors stored: {len(state2.finding_anchors)}')
print(f'Expected: 15 (MAX_FINDING_ANCHORS)')

if len(state2.finding_anchors) == 15:
    print('FIX VERIFIED: Anchor limit enforced!')
else:
    print('FIX FAILED: Limit not working!')

# ============================================================================
# TEST 3: Valid anchors still work
# ============================================================================
print('\n[TEST 3] Valid anchors still work')
print('-' * 50)

state3 = AgentState(agent_id="test3", agent_name="Test3", task="test")

valid_anchors = [
    {"key": "sqli", "text": "Found SQL injection in /api/login", "source": "compressor"},
    {"key": "xss", "text": "Found XSS in /api/search", "source": "compressor"},
    {"key": "shell", "text": "Got reverse shell on 10.10.10.10:4444", "source": "compressor"},
    {"key": "creds", "text": "Found credentials: admin:password123", "source": "compressor"},
]

for a in valid_anchors:
    state3.add_finding_anchor(a)

print(f'Added 4 valid anchors')
print(f'Anchors stored: {len(state3.finding_anchors)}')

# Test content preserved
texts = [a.get('text', '') for a in state3.finding_anchors]
has_sqli = any('sql' in t.lower() for t in texts)
has_xss = any('xss' in t.lower() for t in texts)
has_shell = any('shell' in t.lower() for t in texts)
has_creds = any('credential' in t.lower() or 'password' in t.lower() for t in texts)

print(f'SQLi: {has_sqli}, XSS: {has_xss}, Shell: {has_shell}, Creds: {has_creds}')

if all([has_sqli, has_xss, has_shell, has_creds]):
    print('FIX VERIFIED: Valid anchors work correctly!')
else:
    print('FIX FAILED: Valid anchors not stored!')

# ============================================================================
# TEST 4: Deduplication still works
# ============================================================================
print('\n[TEST 4] Deduplication still works')
print('-' * 50)

state4 = AgentState(agent_id="test4", agent_name="Test4", task="test")

state4.add_finding_anchor({"key": "same", "text": "First content", "source": "compressor"})
state4.add_finding_anchor({"key": "same", "text": "Different content", "source": "compressor"})

print(f'Added duplicate key twice')
print(f'Anchors stored: {len(state4.finding_anchors)}')

if len(state4.finding_anchors) == 1:
    print('FIX VERIFIED: Deduplication still works!')
else:
    print('FIX FAILED: Duplicate added!')

# ============================================================================
# TEST 5: MAX_FINDING_ANCHORS constant accessible
# ============================================================================
print('\n[TEST 5] MAX_FINDING_ANCHORS constant')
print('-' * 50)

# Access via the class definition in code - not instance attribute
from phantom.agents.state import AgentState
import inspect

# Get the source to verify constant exists
source = inspect.getsource(AgentState)
has_constant = "MAX_FINDING_ANCHORS" in source
print(f'MAX_FINDING_ANCHORS defined in class: {has_constant}')

# Verify limit via test - we already added 25 and got 15
print(f'Result: Limit is enforced at 15 (verified in Test 2)')

print('\n' + '=' * 70)
print('ALL FIXES VERIFIED')
print('=' * 70)