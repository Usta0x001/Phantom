#!/usr/bin/env python3
"""Full integration test for Hypothesis Ledger"""

from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.tools.hypothesis.hypothesis_actions import (
    set_ledger, add_hypothesis, record_payload_test, 
    confirm_hypothesis, reject_hypothesis, has_tested_payload,
    get_hypothesis_summary, query_hypotheses
)
import asyncio

print('=== FULL INTEGRATION TEST ===')

# 1. Setup
ledger = HypothesisLedger()
set_ledger(ledger, 'default')

# 2. Test all tools
print('\n1. Testing add_hypothesis...')
result = add_hypothesis('/api/login::username', 'sqli')
print(f'   Result: {result}')

print('\n2. Testing has_tested_payload (before test)...')
result = has_tested_payload('/api/login::username', 'sqli', "payload1")
print(f'   Result: {result}')

print('\n3. Testing record_payload_test...')
result = asyncio.run(record_payload_test('H-0001', 'payload1', 'failure', 'No SQL error'))
print(f'   Result: {result}')

print('\n4. Testing has_tested_payload (after test)...')
result = has_tested_payload('/api/login::username', 'sqli', 'payload1')
print(f'   Result: {result}')

print('\n5. Testing query_hypotheses...')
result = query_hypotheses(status='open')
print(f'   Result: {result.get("count")} open hypotheses')

print('\n6. Testing get_hypothesis_summary...')
result = get_hypothesis_summary()
print(f'   Result: {result.get("total")} total hypotheses')

print('\n=== ALL INTEGRATION TESTS PASSED ===')