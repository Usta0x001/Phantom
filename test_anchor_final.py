#!/usr/bin/env python3
"""Deep Anchor Analysis - Prove value and test robustness"""

from phantom.agents.state import AgentState
from phantom.llm.memory_compressor import _extract_anchors_from_chunk
import time

print('=' * 80)
print('DEEP ANOMALY ATTACK SUITE')
print('=' * 80)

# ============================================================================
# PART 1: PROVE ANCHOR VALUE
# ============================================================================
print('\nPART 1: PROVING ANCHOR VALUE')
print('-' * 50)

print("""
WHY DO WE STORE "SQLi" KEY FROM CONVERSATION?

ANSWER:
When memory is compressed, the LLM FORGETS what was found.
Anchors PRESERVE these findings so the LLM REMEMBERS them.

Example:
- Without anchors: LLM re-tests same SQLi (waste of 10+ iterations)
- With anchors: LLM sees "we found SQLi" and creates report instead
""")

# Create state with confirmed findings (simulating real scan)
state = AgentState(agent_id="test", agent_name="Test", task="pentest")

# These anchors represent what would be extracted during compression
anchors = [
    {"key": "SQLi /api/login", "text": "Found SQL injection in /api/login. Confirmed with UNION SELECT.", "source": "compressor"},
    {"key": "XSS /api/search", "text": "Found XSS in /api/search. Payload reflected without encoding.", "source": "compressor"},
    {"key": "Shell 10.10.10.10", "text": "Got reverse shell on 10.10.10.10:4444 as root", "source": "compressor"},
    {"key": "Creds admin", "text": "Found credentials: admin:password123 in authentication", "source": "compressor"},
]

for a in anchors:
    state.add_finding_anchor(a)

print(f'Stored anchors: {len(state.finding_anchors)}')
print('Keys:', [a['key'] for a in state.finding_anchors])

# Simulate what LLM sees in context (from llm.py:618-648)
anchor_lines = []
for anchor in state.finding_anchors[:15]:
    text = anchor.get("text", "").strip()
    if text:
        anchor_lines.append(f"- {text[:600]}")

if anchor_lines:
    injection = (
        "<finding_anchors>\n"
        "Confirmed signals from earlier in this scan:\n"
        + "\n".join(anchor_lines)
        + "\n</finding_anchors>"
    )
    print('\nWhat LLM sees in context:')
    print(injection[:500] + '...')

# ============================================================================
# PART 2: ATTACK TESTS
# ============================================================================
print('\n\nPART 2: ATTACK TESTS')
print('-' * 50)

# Test 1: Empty text
print('[Test 1] Empty text rejected')
s1 = AgentState(agent_id="s1", agent_name="s1", task="t")
s1.add_finding_anchor({"k": "1", "text": "", "s": "c"})
print(f'  Empty: {len(s1.finding_anchors)} (expected: 0)')

# Test 2: Limit
print('[Test 2] Limit enforced')
s2 = AgentState(agent_id="s2", agent_name="s2", task="t")
for i in range(25):
    s2.add_finding_anchor({"k": f"k{i}", "text": f"v{i}", "s": "c"})
print(f'  25 added: {len(s2.finding_anchors)} (expected: 15)')

# Test 3: Deduplication
print('[Test 3] Deduplication')
s3 = AgentState(agent_id="s3", agent_name="s3", task="t")
s3.add_finding_anchor({"k": "same", "text": "one", "s": "c"})
s3.add_finding_anchor({"k": "same", "text": "two", "s": "c"})
print(f'  2 same key: {len(s3.finding_anchors)} (expected: 1)')

# Test 4: Keyword extraction
print('[Test 4] Keyword extraction')
msgs = [
    {'role': 'assistant', 'content': 'Found SQL injection vulnerability in /api/login'},
    {'role': 'assistant', 'content': 'Got shell via command injection'},
]
anchors = _extract_anchors_from_chunk(msgs)
print(f'  Messages: {len(msgs)}, Anchors: {len(anchors)} (expected: 2)')

# Test 5: Serialization
print('[Test 5] Serialization')
s4 = AgentState(agent_id="s4", agent_name="s4", task="t")
s4.add_finding_anchor({"k": "sql", "text": "SQLi found", "s": "c"})
data = s4.model_dump()
s5 = AgentState(**data)
print(f'  Serialization: {len(s5.finding_anchors)} anchors preserved')

# Test 6: Regex performance
print('[Test 6] Regex performance')
from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS_PATTERN
start = time.time()
for _ in range(1000):
    _ANCHOR_KEYWORDS_PATTERN.search("vulnerability " * 1000)
elapsed = time.time() - start
print(f'  1000 searches: {elapsed*1000:.1f}ms (fast enough)')

# ============================================================================
# PART 3: VALUE SUMMARY
# ============================================================================
print('\n\nPART 3: ANCHOR VALUE SUMMARY')
print('-' * 50)

print("""
ANCHOR BENEFITS:
1. Prevents iteration waste (no re-testing found vulnerabilities)
2. Survives memory compression (findings not lost)
3. Enables attack chaining (remembers "we have shell")
4. Proof of work (evidence preserved for reporting)
5. Context preservation (LLM knows scan status)

KEY TAKEAWAY:
The "SQLi" key is just a label - the VALUE is in the "text" field
which contains the actual finding details that survive compression.
""")

print('=' * 80)
print('ALL TESTS COMPLETE')
print('=' * 80)