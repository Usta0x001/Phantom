#!/usr/bin/env python
"""Full system attack - find all weaknesses, flaws, errors, bugs."""
import sys
import traceback
import asyncio

tests_passed = 0
tests_failed = 0
weaknesses = []

def test(name, func):
    global tests_passed, tests_failed
    try:
        result = func()
        if result is False:
            raise Exception("returned False")
        tests_passed += 1
        print(f"[PASS] {name}")
    except Exception as e:
        tests_failed += 1
        weaknesses.append((name, str(e)))
        print(f"[WEAK] {name}: {e}")

print("="*70)
print("ATTACK PHASE 1: Import Chain")
print("="*70)

def test_import_hypothesis_ledger():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    return HypothesisLedger is not None

def test_import_coverage_tracker():
    from phantom.agents.coverage_tracker import CoverageTracker
    return CoverageTracker is not None

def test_import_finish():
    from phantom.tools.finish.finish_actions import finish_scan
    return finish_scan is not None

def test_import_scan_status():
    from phantom.tools.scan_status.scan_status_actions import get_scan_status
    return get_scan_status is not None

def test_import_hypothesis_actions():
    from phantom.tools.hypothesis.hypothesis_actions import set_ledger, get_ledger
    return set_ledger and get_ledger

def test_import_llm():
    from phantom.llm.llm import LLM
    return LLM is not None

def test_import_executor():
    from phantom.tools.executor import execute_tool
    return execute_tool is not None

def test_import_checkpoint():
    from phantom.checkpoint.checkpoint import CheckpointManager
    return CheckpointManager is not None

def test_import_attack_graph():
    from phantom.core.attack_graph import AttackGraph
    return AttackGraph is not None

def test_import_registry():
    from phantom.tools.registry import get_tool_names
    return len(get_tool_names()) > 0

test("import hypothesis_ledger", test_import_hypothesis_ledger)
test("import coverage_tracker", test_import_coverage_tracker)
test("import finish_actions", test_import_finish)
test("import scan_status", test_import_scan_status)
test("import hypothesis_actions", test_import_hypothesis_actions)
test("import llm", test_import_llm)
test("import executor", test_import_executor)
test("import checkpoint", test_import_checkpoint)
test("import attack_graph", test_import_attack_graph)
test("import registry", test_import_registry)

print()
print("="*70)
print("ATTACK PHASE 2: Hypothesis Ledger Edge Cases")
print("="*70)

def test_ledger_add_duplicate():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    h1 = l.add("/api/login", "sqli")
    h2 = l.add("/api/login", "sqli")
    return h1 == h2  # Should dedup

def test_ledger_case_sensitivity():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    h1 = l.add("/api/login", "SQLI")
    h2 = l.add("/api/login", "sqli")
    return h1 == h2  # Should normalize

def test_ledger_payload_dedup():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    h = l.add("/api/login", "sqli")
    l.record_payload(h, "' OR 1=1--")
    l.record_payload(h, "' OR 1=1--")  # Duplicate
    return l.get(h).payloads_tested.count("' OR 1=1--") == 1

def test_ledger_confirm_missing():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    return l.confirm("H-9999", "evidence") == False  # Missing hyp

def test_ledger_reject_missing():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    return l.reject("H-9999", "reason") == False  # Missing hyp

def test_ledger_record_result_invalid():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    h = l.add("/api/login", "sqli")
    return l.record_result(h, "invalid_status", "evidence") == False

def test_ledger_find_missing():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    return l.find_by_surface_and_class("/nonexistent", "sqli") is None

def test_ledger_to_dict_empty():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    d = l.to_dict()
    return "counter" in d and "hypotheses" in d

def test_ledger_from_dict_malformed():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    try:
        l = HypothesisLedger.from_dict({"counter": "bad", "hypotheses": []})
        return True
    except Exception:
        return False  # FIXED: Use specific exception, not bare except:

def test_ledger_get_scored_empty():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    return l.get_scored_hypotheses() == []

test("ledger add duplicate", test_ledger_add_duplicate)
test("ledger case sensitivity", test_ledger_case_sensitivity)
test("ledger payload dedup", test_ledger_payload_dedup)
test("ledger confirm missing", test_ledger_confirm_missing)
test("ledger reject missing", test_ledger_reject_missing)
test("ledger record_result invalid", test_ledger_record_result_invalid)
test("ledger find missing", test_ledger_find_missing)
test("ledger to_dict empty", test_ledger_to_dict_empty)
test("ledger from_dict malformed", test_ledger_from_dict_malformed)
test("ledger get_scored empty", test_ledger_get_scored_empty)

print()
print("="*70)
print("ATTACK PHASE 3: Coverage Tracker Edge Cases")
print("="*70)

def test_coverage_basic():
    from phantom.agents.coverage_tracker import CoverageTracker
    c = CoverageTracker()
    sid = c.discover_surface("/api", "endpoint")
    c.record_test(sid, "endpoint", "sqli")
    return c.has_been_tested("/api", "endpoint", "sqli")

def test_coverage_case():
    from phantom.agents.coverage_tracker import CoverageTracker
    c = CoverageTracker()
    sid = c.discover_surface("/api", "endpoint")
    c.record_test(sid, "endpoint", "SQLI")
    return c.has_been_tested("/api", "endpoint", "sqli")

def test_coverage_vuln_class_normalized():
    from phantom.agents.coverage_tracker import CoverageTracker
    c = CoverageTracker()
    c.record_test("/api", "endpoint", "XSS")
    return c.has_been_tested("/api", "endpoint", "xss")

def test_coverage_failure():
    from phantom.agents.coverage_tracker import CoverageTracker
    c = CoverageTracker()
    sid = c.discover_surface("/api", "endpoint")
    c.record_failure(sid, "endpoint", "WAF_BLOCKED", "sqli")
    return not c.has_been_tested("/api", "endpoint", "sqli")

test("coverage basic", test_coverage_basic)
test("coverage case insensitive", test_coverage_case)
test("coverage vuln class normalized", test_coverage_vuln_class_normalized)
test("coverage failure tracking", test_coverage_failure)

print()
print("="*70)
print("ATTACK PHASE 4: Hypothesis Actions Tools")
print("="*70)

def test_set_get_ledger():
    from phantom.tools.hypothesis.hypothesis_actions import set_ledger, get_ledger
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    set_ledger(l, "test")
    return get_ledger("test") is l

def test_get_ledger_missing():
    from phantom.tools.hypothesis.hypothesis_actions import get_ledger
    return get_ledger("nonexistent") is None

def test_clear_context():
    from phantom.tools.hypothesis.hypothesis_actions import set_ledger, get_ledger, clear_hypothesis_context
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    set_ledger(l, "test")
    clear_hypothesis_context("test")
    return get_ledger("test") is None

def test_clear_all():
    from phantom.tools.hypothesis.hypothesis_actions import set_ledger, get_ledger, clear_hypothesis_context
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    l = HypothesisLedger()
    set_ledger(l, "test1")
    set_ledger(l, "test2")
    clear_hypothesis_context()
    return get_ledger("test1") is None and get_ledger("test2") is None

test("set/get ledger", test_set_get_ledger)
test("get ledger missing", test_get_ledger_missing)
test("clear context single", test_clear_context)
test("clear context all", test_clear_all)

print()
print("="*70)
print("ATTACK PHASE 5: Finish Scan")
print("="*70)

def test_finish_check_no_agent():
    from phantom.tools.finish.finish_actions import _check_active_agents
    return _check_active_agents(None) is None

def test_finish_validate_root():
    from phantom.tools.finish.finish_actions import _validate_root_agent
    class MockState:
        parent_id = None
    return _validate_root_agent(MockState()) is None

def test_finish_validate_subagent():
    from phantom.tools.finish.finish_actions import _validate_root_agent
    class MockState:
        parent_id = "parent-123"
    result = _validate_root_agent(MockState())
    return result is not None and result["success"] is False

test("finish check no agent", test_finish_check_no_agent)
test("finish validate root", test_finish_validate_root)
test("finish validate subagent", test_finish_validate_subagent)

print()
print("="*70)
print("ATTACK PHASE 6: Attack Graph")
print("="*70)

def test_graph_basic():
    from phantom.core.attack_graph import AttackGraph
    g = AttackGraph()
    g.add_vulnerability("V1", "SQLi", "high")
    return "V1" in g._nodes

def test_graph_add_edge():
    from phantom.core.attack_graph import AttackGraph, AttackEdgeType
    g = AttackGraph()
    g.add_vulnerability("V1", "SQLi", "high")
    g.add_vulnerability("V2", "RCE", "critical")
    g.add_edge("V1", "V2", AttackEdgeType.ENABLES)
    return "V1" in g._edges and "V2" in g._edges.get("V1", {})

def test_graph_serialization():
    from phantom.core.attack_graph import AttackGraph
    g = AttackGraph()
    g.add_vulnerability("V1", "SQLi", "high")
    d = g.to_dict()
    g2 = AttackGraph.from_dict(d)
    return "V1" in g2._nodes

def test_graph_path_finding():
    from phantom.core.attack_graph import AttackGraph, AttackEdgeType
    g = AttackGraph()
    g.add_vulnerability("V1", "SQLi", "high", status="confirmed")
    g.add_vulnerability("V2", "RCE", "critical")
    g.add_edge("V1", "V2", AttackEdgeType.ENABLES)
    paths = g.find_paths("V1", "V2")
    return len(paths) > 0

test("graph basic", test_graph_basic)
test("graph add edge", test_graph_add_edge)
test("graph serialization", test_graph_serialization)
test("graph path finding", test_graph_path_finding)

print()
print("="*70)
print("ATTACK PHASE 7: Registry")
print("="*70)

def test_registry_tools():
    from phantom.tools.registry import get_tool_names
    names = get_tool_names()
    return len(names) > 0 and "add_hypothesis" in names

def test_registry_get():
    from phantom.tools.registry import get_tool_by_name
    tool = get_tool_by_name("add_hypothesis")
    return tool is not None

def test_registry_missing():
    from phantom.tools.registry import get_tool_by_name
    return get_tool_by_name("nonexistent_tool_xyz") is None

test("registry get tool names", test_registry_tools)
test("registry get tool", test_registry_get)
test("registry missing tool", test_registry_missing)

print()
print("="*70)
print("ATTACK PHASE 8: Config")
print("="*70)

def test_config_defaults():
    from phantom.config import Config
    model = Config.get("phantom_llm")
    return model is not None

def test_config_env():
    import os
    os.environ["PHANTOM_TEST_KEY"] = "test_value"
    from phantom.config import Config
    val = Config.get("PHANTOM_TEST_KEY")
    return val == "test_value"

test("config defaults", test_config_defaults)
test("config env override", test_config_env)

print()
print("="*70)
print("SUMMARY")
print("="*70)
print(f"Tests passed: {tests_passed}")
print(f"Weaknesses found: {tests_failed}")

if weaknesses:
    print()
    print("ALL WEAKNESSES IDENTIFIED:")
    for i, (name, error) in enumerate(weaknesses, 1):
        print(f"{i}. {name}: {error}")

# Exit with error if critical weaknesses found
if tests_failed > 0:
    print(f"\n[CRITICAL] {tests_failed} weaknesses found!")
    sys.exit(1)
else:
    print("\n[OK] No weaknesses found!")
    sys.exit(0)