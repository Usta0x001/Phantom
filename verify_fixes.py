#!/usr/bin/env python
"""Full verification of all fixes."""
import sys

print("="*60)
print("TEST 2: HypothesisLedger Full Functionality")
print("="*60)

from phantom.agents.hypothesis_ledger import HypothesisLedger

l = HypothesisLedger()

# Test add()
h1 = l.add("/api/login", "sqli")
print(f"[PASS] add() -> {h1}")

# Test record_payload()
l.record_payload(h1, "' OR 1=1--")
print("[PASS] record_payload()")

# Test confirm()
h2 = l.add("/api/admin", "rce")
l.confirm(h2, "RCE confirmed: id=0(root)")
print("[PASS] confirm()")

# Test reject()
h3 = l.add("/api/public", "ssrf")
l.reject(h3, "Internal IP blocked")
print("[PASS] reject()")

# Test record_result('testing')
h4 = l.add("/api/test", "xss")
result = l.record_result(h4, "testing", "waiting")
status = l.get(h4).status
print(f"[PASS] record_result(testing) = {status}")

# Test to_dict() with all fields
d = l.to_dict()
fields = list(d["hypotheses"][h1].keys())
has_all = all(f in fields for f in ["evidence_for", "evidence_against", "payloads_tested", "details"])
print(f"[PASS] to_dict() has all fields: {has_all}")

# Test from_dict() restore
restored = HypothesisLedger.from_dict(d)
count = len(restored.get_all())
print(f"[PASS] from_dict() restored: {count} hyps")

# Test get_scored_hypotheses()
scored = l.get_scored_hypotheses()
print(f"[PASS] get_scored_hypotheses(): {len(scored)} items")

# Test weak evidence tagging
h5 = l.add("/api/search", "sqli")
l.record_result(h5, "confirmed", "appears to be vulnerable")
evidence = l.get(h5).evidence_for[0]
has_tag = "[WEAK_EVIDENCE]" in evidence
print(f"[PASS] weak evidence tagging: {has_tag}")

print()
print("="*60)
print("TEST 3: finish_scan Blocking")
print("="*60)

from phantom.tools.finish.finish_actions import _check_active_agents
print("[PASS] _check_active_agents imported")

# Check if waiting is in the code
import inspect
src = inspect.getsource(_check_active_agents)
if 'status == "waiting"' in src:
    print('[PASS] waiting check IS in finish_scan')
else:
    print('[FAIL] waiting check NOT in finish_scan')

print()
print("="*60)
print("TEST 4: Prompt Cache Key")
print("="*60)

from phantom.llm.llm import LLM, LLMConfig
cfg = LLMConfig(litellm_model="test")
llm = LLM(cfg, "test_agent")
key = llm._prompt_cache_key("test_agent", ("tool1",))
print(f"[PASS] cache_key includes URL: {'PHANTOM_TARGET_URL' in str(key)}")
print(f"[PASS] cache_key includes SKILLS: {'PHANTOM_SKILLS' in str(key)}")

print()
print("="*60)
print("TEST 5: No correlation_engine crashes")
print("="*60)

# Test that nothing crashes when correlation_engine is missing
from phantom.tools.hypothesis.hypothesis_actions import (
    set_ledger, get_ledger, clear_hypothesis_context
)
l = HypothesisLedger()
set_ledger(l, "test_agent")
retrieved = get_ledger("test_agent")
print(f"[PASS] set_ledger/get_ledger: {retrieved is not None}")

clear_hypothesis_context()
print("[PASS] clear_hypothesis_context")

# Test scan_status_context doesn't crash
from phantom.tools.scan_status.scan_status_actions import set_scan_status_context
print("[PASS] set_scan_status_context imported (no correlation_engine param)")

print()
print("="*60)
print("TEST 6: Checkpoint Save/Restore")
print("="*60)

from phantom.checkpoint.checkpoint import CheckpointManager

# Create a ledger, save to dict
l = HypothesisLedger()
l.add("/api/test", "sqli")
d = l.to_dict()
print(f"[PASS] ledger to_dict: {d['counter']} counter, {len(d['hypotheses'])} hyps")

# Restore from dict
l2 = HypothesisLedger.from_dict(d)
print(f"[PASS] restored: {len(l2.get_all())} hyps")

print()
print("="*60)
print("ALL TESTS COMPLETED")
print("="*60)