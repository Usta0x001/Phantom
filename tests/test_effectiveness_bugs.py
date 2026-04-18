"""
Proves the 5 effectiveness bugs found in the audit, then verifies the fixes.
Run with:  python tests/test_effectiveness_bugs.py
"""
import sys
import os
import types
import importlib.util

if __name__ != "__main__" and "pytest" in sys.modules:
    import pytest

    pytest.skip("standalone verification script", allow_module_level=True)

# ── Root path ────────────────────────────────────────────────────────────────
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AGENTS_DIR = os.path.join(ROOT, "phantom", "agents")
sys.path.insert(0, ROOT)

# ── Minimal config stub ───────────────────────────────────────────────────────
class _FakeConfig:
    @staticmethod
    def get(key): return None

_cfg_mod = types.ModuleType("phantom.config.config")
_cfg_mod.Config = _FakeConfig
sys.modules["phantom.config.config"] = _cfg_mod

_pcfg = types.ModuleType("phantom.config")
_pcfg.Config = _FakeConfig
sys.modules["phantom.config"] = _pcfg

# ── Stub correlation_engine so hypothesis_ledger can import it ────────────────
class _FakeCorrelationEngine:
    def get_surface_success_score(self, *a): return 0.5
    def get_payload_family_success_score(self, *a): return 0.5

_corr_mod = types.ModuleType("phantom.agents.correlation_engine")
_corr_mod.CorrelationEngine = _FakeCorrelationEngine
sys.modules["phantom.agents.correlation_engine"] = _corr_mod

# ── Load hypothesis_ledger directly (bypass __init__.py chain) ─────────────────
def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_hl = _load_module(
    "phantom.agents.hypothesis_ledger",
    os.path.join(AGENTS_DIR, "hypothesis_ledger.py"),
)
_ct = _load_module(
    "phantom.agents.coverage_tracker",
    os.path.join(AGENTS_DIR, "coverage_tracker.py"),
)

HypothesisLedger = _hl.HypothesisLedger
CoverageTracker  = _ct.CoverageTracker



# ─────────────────────────────────────────────────────────────────────────────
# BUG 1 — Dedup misses parameterised URLs
# Expected: /api/user/1 and /api/user/2 should map to same hypothesis (same template)
# Actual (before fix): two separate hypothesis IDs created
# ─────────────────────────────────────────────────────────────────────────────
def test_bug1_dedup_fails_on_parameterised_urls_BEFORE_FIX():
    """Proves Bug #1: exact-string dedup treats /api/user/1 and /api/user/2 as DIFFERENT."""
    ledger = HypothesisLedger()
    id1 = ledger.add("/api/user/1", "sqli")
    id2 = ledger.add("/api/user/2", "sqli")
    # BUG: they should be the same surface pattern but are not
    assert id1 != id2, (
        "BUG NOT PRESENT — dedup already handles parameterized URLs (test premise was wrong)"
    )
    print(f"  ✗ BUG CONFIRMED: /api/user/1→{id1} /api/user/2→{id2} — treated as different hypotheses")
    print(f"    Ledger size: {len(ledger._hypotheses)} (expected 1, got 2)")


def test_bug1_dedup_AFTER_FIX():
    """Proves Bug #1 fix: /api/user/1 and /api/user/2 → same hypothesis after normalization."""
    ledger = HypothesisLedger()
    id1 = ledger.add("/api/user/1", "sqli")
    id2 = ledger.add("/api/user/2", "sqli")
    assert id1 == id2, (
        f"FIX FAILED: /api/user/1→{id1} and /api/user/2→{id2} are still separate!"
    )
    assert len(ledger._hypotheses) == 1
    print(f"  ✓ FIX VERIFIED: Both map to {id1}. Ledger size: {len(ledger._hypotheses)}")

    # Also prove has_tested respects normalization
    ledger.record_result(id1, "testing", "SQL error returned")
    assert ledger.has_tested("/api/user/99", "sqli") is True, \
        "has_tested should return True for any numeric variant of the same endpoint"
    print("  ✓ has_tested('/api/user/99', 'sqli') → True (normalized lookup works)")


# ─────────────────────────────────────────────────────────────────────────────
# BUG 3 — Scheduler default 'flat' ignores heuristic priority scoring
# Expected: /admin/login (rce) should score higher than /robots.txt (info_disclosure)
# Actual: in flat mode they score identically (belief=0.5, same exploration bonus)
# ─────────────────────────────────────────────────────────────────────────────
def test_bug3_flat_scheduler_ignores_priority_BEFORE_FIX():
    """Proves Bug #3: default 'flat' scheduler gives identical scores to admin vs robots.txt."""
    # Patch config to return 'flat' (the default)
    import phantom.config.config as cfg_mod
    original_get = cfg_mod.Config.get
    cfg_mod.Config.get = staticmethod(lambda key: "flat" if key == "phantom_scheduler_mode" else None)

    ledger = HypothesisLedger()
    ledger.add("/admin/login", "rce")          # Should be CRITICAL priority
    ledger.add("/robots.txt", "info_disclosure")  # Should be LOW priority

    scored = ledger.get_scored_hypotheses()
    assert len(scored) == 2

    admin_score  = next(s["priority"] for s in scored if "/admin" in s["surface"])
    robots_score = next(s["priority"] for s in scored if "/robots" in s["surface"])

    # In flat mode both start with belief=0.5, same tests_executed → identical priority
    diff = abs(admin_score - robots_score)
    assert diff < 0.01, f"BUG NOT PRESENT — scores differ by {diff:.4f} in flat mode"
    print(f"  ✗ BUG CONFIRMED: /admin/login={admin_score:.4f} == /robots.txt={robots_score:.4f} (flat mode)")

    cfg_mod.Config.get = original_get


def test_bug3_heuristic_scheduler_AFTER_FIX():
    """Proves Bug #3 fix: heuristic mode scores /admin/login (rce) higher than /robots.txt."""
    import phantom.config.config as cfg_mod
    original_get = cfg_mod.Config.get
    cfg_mod.Config.get = staticmethod(lambda key: "heuristic" if key == "phantom_scheduler_mode" else None)

    ledger = HypothesisLedger()
    ledger.add("/admin/login", "rce")
    ledger.add("/robots.txt", "info_disclosure")

    scored = ledger.get_scored_hypotheses()
    admin_score  = next(s["priority"] for s in scored if "/admin" in s["surface"])
    robots_score = next(s["priority"] for s in scored if "/robots" in s["surface"])

    assert admin_score > robots_score, (
        f"FIX FAILED: /admin score ({admin_score:.4f}) should exceed /robots ({robots_score:.4f})"
    )
    print(f"  ✓ FIX VERIFIED: /admin/login={admin_score:.4f} > /robots.txt={robots_score:.4f}")
    cfg_mod.Config.get = original_get


# ─────────────────────────────────────────────────────────────────────────────
# BUG 6 — Weak evidence tag doesn't gate confirmation
# Expected: record_result("confirmed", weak_evidence) should NOT set status=confirmed
# Actual: status is set to "confirmed" regardless of evidence quality
# ─────────────────────────────────────────────────────────────────────────────
def test_bug6_weak_evidence_does_not_gate_BEFORE_FIX():
    """Proves Bug #6: 'confirmed' status accepted even with vague evidence."""
    ledger = HypothesisLedger()
    hid = ledger.add("/api/search", "sqli")
    weak_evidence = "appears to be vulnerable"
    ledger.record_result(hid, "confirmed", weak_evidence)

    hyp = ledger._hypotheses[hid]
    assert hyp.status == "confirmed", "BUG NOT PRESENT — status NOT set to confirmed"
    # Verify the evidence was tagged weak
    ev = hyp.evidence_for[0] if hyp.evidence_for else ""
    print(f"  ✗ BUG CONFIRMED: status='{hyp.status}' despite weak evidence.")
    print(f"    evidence_for[0] = '{ev[:80]}'")
    # The tag [WEAK_EVIDENCE] is present but confirmation was NOT blocked
    assert "[WEAK_EVIDENCE]" in ev, "Expected [WEAK_EVIDENCE] tag in stored evidence"
    print("    [WEAK_EVIDENCE] tag present but did NOT block confirmation status — BUG!")


def test_bug6_weak_evidence_blocked_AFTER_FIX():
    """Proves Bug #6 fix: weak evidence for 'confirmed' is downgraded to 'testing'."""
    ledger = HypothesisLedger()
    hid = ledger.add("/api/search", "sqli")
    weak_evidence = "appears to be vulnerable"
    ledger.record_result(hid, "confirmed", weak_evidence)

    hyp = ledger._hypotheses[hid]
    assert hyp.status != "confirmed", (
        f"FIX FAILED: status is still '{hyp.status}' — weak confirmation not blocked"
    )
    assert hyp.status == "testing", f"Expected 'testing', got '{hyp.status}'"
    print(f"  ✓ FIX VERIFIED: Weak evidence downgraded status to '{hyp.status}' (not confirmed)")

    # Strong evidence should still confirm
    ledger2 = HypothesisLedger()
    hid2 = ledger2.add("/api/search", "sqli")
    strong_evidence = "response: SQL error: You have an error in your SQL syntax; uid=0(root) returned"
    ledger2.record_result(hid2, "confirmed", strong_evidence)
    assert ledger2._hypotheses[hid2].status == "confirmed", \
        "FIX BROKE strong evidence — should still confirm"
    print("  ✓ Strong evidence still confirms correctly (no regression)")


# ─────────────────────────────────────────────────────────────────────────────
# BUG 13 — Coverage tracker vuln_class not normalised (case mismatch)
# Expected: record_test("SQLi") then has_been_tested("sqli") → True
# Actual: False (separate list entries)
# ─────────────────────────────────────────────────────────────────────────────
def test_bug13_vuln_class_case_mismatch_BEFORE_FIX():
    """Proves Bug #13: 'SQLi' and 'sqli' are treated as different vuln classes."""
    tracker = CoverageTracker()
    tracker.record_test("/api/login", "endpoint", "SQLi")

    result = tracker.has_been_tested("/api/login", "endpoint", "sqli")
    assert result is False, "BUG NOT PRESENT — case already normalised"
    print("  ✗ BUG CONFIRMED: recorded 'SQLi' but has_been_tested('sqli') → False")

    # Show the gap it creates
    gaps = tracker.get_coverage_gaps(["sqli"])
    assert "/api/login" in gaps["gaps"], "Expected /api/login to show as gap due to case mismatch"
    print(f"    get_coverage_gaps(['sqli']) shows /api/login as UNTESTED — false gap!")


def test_bug13_vuln_class_normalised_AFTER_FIX():
    """Proves Bug #13 fix: 'SQLi' and 'sqli' treated identically after normalisation."""
    tracker = CoverageTracker()
    tracker.record_test("/api/login", "endpoint", "SQLi")

    result = tracker.has_been_tested("/api/login", "endpoint", "sqli")
    assert result is True, "FIX FAILED: 'SQLi' and 'sqli' still treated differently"
    print("  ✓ FIX VERIFIED: has_been_tested('sqli') → True after recording 'SQLi'")

    gaps = tracker.get_coverage_gaps(["sqli"])
    assert "/api/login" not in gaps["gaps"], \
        "FIX FAILED: /api/login still appears as gap after normalisation"
    print("  ✓ No false gap for /api/login in coverage matrix")


# ─────────────────────────────────────────────────────────────────────────────
# BUG 11 — Belief propagation: rejecting SQLi reduces belief in RCE (wrong direction)
# Expected: reject of SQLi should NOT significantly reduce RCE belief
# Actual: belief in RCE drops because chain relation (sqli, rce) is symmetric
# ─────────────────────────────────────────────────────────────────────────────
def test_bug11_chain_belief_wrong_direction_BEFORE_FIX():
    """Proves Bug #11: rejecting SQLi unfairly drops belief in RCE at the same surface."""
    ledger = HypothesisLedger()
    sqli_id = ledger.add("/api/search", "sqli")
    rce_id  = ledger.add("/api/search", "rce")

    before_rce_belief = ledger.get_belief(rce_id)  # 0.5

    ledger.record_result(sqli_id, "rejected", "No SQL error observed")

    after_rce_belief = ledger.get_belief(rce_id)

    assert after_rce_belief < before_rce_belief, "BUG NOT PRESENT — belief unchanged"
    drop = before_rce_belief - after_rce_belief
    print(f"  ✗ BUG CONFIRMED: RCE belief dropped {drop:.4f} ({before_rce_belief:.4f}→{after_rce_belief:.4f})")
    print(f"    Reason: frozenset(sqli,rce) in _CHAIN_RELATIONS causes symmetric propagation")
    print(f"    Rejecting SQLi has no logical bearing on whether RCE is possible")


def test_bug11_chain_belief_directional_AFTER_FIX():
    """Proves Bug #11 fix: rejecting SQLi does NOT reduce belief in structurally unrelated RCE."""
    ledger = HypothesisLedger()
    sqli_id = ledger.add("/api/search", "sqli")
    rce_id  = ledger.add("/api/search", "rce")

    before_rce_belief = ledger.get_belief(rce_id)
    ledger.record_result(sqli_id, "rejected", "No SQL error observed")
    after_rce_belief = ledger.get_belief(rce_id)

    assert after_rce_belief >= before_rce_belief - 0.01, (
        f"FIX FAILED: RCE belief still dropped from {before_rce_belief:.4f} to {after_rce_belief:.4f}"
    )
    print(f"  ✓ FIX VERIFIED: RCE belief unchanged after SQLi rejection ({before_rce_belief:.4f}→{after_rce_belief:.4f})")

    # Confirming SQLi SHOULD still boost RCE (chain confirmed → chain positive)
    ledger2 = HypothesisLedger()
    sqli2 = ledger2.add("/api/search", "sqli")
    rce2  = ledger2.add("/api/search", "rce")
    before = ledger2.get_belief(rce2)
    ledger2.record_result(sqli2, "confirmed", "UNION SELECT version() returned data: 8.0.32")
    after = ledger2.get_belief(rce2)
    assert after > before, "FIX REGRESSION: confirming SQLi should still boost RCE belief"
    print(f"  ✓ Confirming SQLi still boosts RCE belief ({before:.4f}→{after:.4f}) — no regression")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────
BEFORE_TESTS = [
    test_bug1_dedup_fails_on_parameterised_urls_BEFORE_FIX,
    test_bug3_flat_scheduler_ignores_priority_BEFORE_FIX,
    test_bug6_weak_evidence_does_not_gate_BEFORE_FIX,
    test_bug13_vuln_class_case_mismatch_BEFORE_FIX,
    test_bug11_chain_belief_wrong_direction_BEFORE_FIX,
]

AFTER_TESTS = [
    test_bug1_dedup_AFTER_FIX,
    test_bug3_heuristic_scheduler_AFTER_FIX,
    test_bug6_weak_evidence_blocked_AFTER_FIX,
    test_bug13_vuln_class_normalised_AFTER_FIX,
    test_bug11_chain_belief_directional_AFTER_FIX,
]

if __name__ == "__main__":
    print("\n" + "="*70)
    print("PHASE 1 — PROVING BUGS EXIST (before fixes)")
    print("="*70)
    passed = 0
    failed_unexpectedly = []
    for test in BEFORE_TESTS:
        print(f"\n[BUG PROOF] {test.__name__}")
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ! Test premise may be wrong or partially fixed: {e}")
            failed_unexpectedly.append(test.__name__)
        except Exception as e:
            print(f"  ! Unexpected error: {e}")
            failed_unexpectedly.append(test.__name__)

    print(f"\nBug proofs passed: {passed}/{len(BEFORE_TESTS)}")
    if failed_unexpectedly:
        print(f"Unexpected failures: {failed_unexpectedly}")

    print("\n" + "="*70)
    print("PHASE 2 — VERIFYING FIXES (after applying patches)")
    print("="*70)
    after_passed = 0
    after_failed = []
    for test in AFTER_TESTS:
        print(f"\n[FIX VERIFY] {test.__name__}")
        try:
            test()
            after_passed += 1
        except AssertionError as e:
            print(f"  ✗ FIX NOT YET APPLIED OR BROKEN: {e}")
            after_failed.append(test.__name__)
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            after_failed.append(test.__name__)

    print(f"\nFix verifications passed: {after_passed}/{len(AFTER_TESTS)}")
    if after_failed:
        print(f"Fixes still needed: {after_failed}")
    else:
        print("ALL FIXES VERIFIED ✓")
