"""
Comprehensive verification + adversarial test suite for all 9 effectiveness fixes.

Phases:
  1. Baseline regression  - bugs that should now be GONE
  2. Fix correctness      - the fixed behaviour works exactly right
  3. Adversarial          - attempt to break each fix with edge-cases
  4. No-regression        - things that used to work still work
  5. Attack-graph / coverage structural fixes

Run with:  python tests/test_all_fixes_verified.py
"""
import sys, os, types, importlib.util, re

if __name__ != "__main__" and "pytest" in sys.modules:
    import pytest

    pytest.skip("standalone verification script", allow_module_level=True)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AGENTS_DIR = os.path.join(ROOT, "phantom", "agents")
sys.path.insert(0, ROOT)

# ---------- minimal stubs --------------------------------------------------
class _FakeConfig:
    @staticmethod
    def get(key): return None

_cfg_mod = types.ModuleType("phantom.config.config")
_cfg_mod.Config = _FakeConfig
sys.modules["phantom.config.config"] = _cfg_mod
_pcfg = types.ModuleType("phantom.config")
_pcfg.Config = _FakeConfig
sys.modules["phantom.config"] = _pcfg

class _FakeCorrelationEngine:
    def get_surface_success_score(self, *a): return 0.5
    def get_payload_family_success_score(self, *a): return 0.5

_corr_mod = types.ModuleType("phantom.agents.correlation_engine")
_corr_mod.CorrelationEngine = _FakeCorrelationEngine
sys.modules["phantom.agents.correlation_engine"] = _corr_mod

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_hl = _load("phantom.agents.hypothesis_ledger",
            os.path.join(AGENTS_DIR, "hypothesis_ledger.py"))
_ct = _load("phantom.agents.coverage_tracker",
            os.path.join(AGENTS_DIR, "coverage_tracker.py"))

HypothesisLedger = _hl.HypothesisLedger
CoverageTracker  = _ct.CoverageTracker


# ---------- helpers --------------------------------------------------------
PASS = []
FAIL = []

def ok(name):
    PASS.append(name)
    print(f"  [PASS] {name}")

def fail(name, reason):
    FAIL.append(name)
    print(f"  [FAIL] {name}: {reason}")

def check(name, condition, reason=""):
    if condition:
        ok(name)
    else:
        fail(name, reason or "assertion false")


# ===========================================================================
# PHASE 1 — Verify bugs are GONE
# ===========================================================================
print("\n" + "="*70)
print("PHASE 1 — Bug regression: confirm bugs no longer exist")
print("="*70)

# ── B1: URL dedup ──────────────────────────────────────────────────────────
print("\n[B1] URL dedup by template")
ledger = HypothesisLedger()
id1 = ledger.add("/api/user/1", "sqli")
id2 = ledger.add("/api/user/2", "sqli")
check("B1.basic: /api/user/1 and /api/user/2 deduplicated",
      id1 == id2,
      f"Got {id1} vs {id2}  —  dedup not working")
check("B1.size: ledger has exactly 1 hypothesis",
      len(ledger._hypotheses) == 1,
      f"Got {len(ledger._hypotheses)}")

# UUID variants
id3 = ledger.add("/api/item/11111111-2222-3333-4444-555555555555/detail", "sqli")
id4 = ledger.add("/api/item/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/detail", "sqli")
check("B1.uuid: UUID path segments deduplicated",
      id3 == id4,
      f"Got {id3} vs {id4}")

# Non-numeric segments should still be different
id5 = ledger.add("/api/widget/foo", "sqli")
id6 = ledger.add("/api/widget/bar", "sqli")
check("B1.nonnumeric: /api/widget/foo and /api/widget/bar are DIFFERENT",
      id5 != id6,
      "Non-numeric segments wrongly deduplicated")


# ── B3: Default scheduler is heuristic ────────────────────────────────────
print("\n[B3] Default heuristic scheduler")
ledger3 = HypothesisLedger()
ledger3.add("/admin/login", "rce")
ledger3.add("/robots.txt", "info_disclosure")
scored = ledger3.get_scored_hypotheses()
admin  = next((s for s in scored if "/admin" in s["surface"]), None)
robots = next((s for s in scored if "/robots" in s["surface"]), None)
check("B3.keys: 'priority' key present in scored dict",
      admin is not None and "priority" in admin,
      f"Keys: {list(admin.keys()) if admin else 'no admin entry'}")
if admin and robots:
    check("B3.priority: /admin/login scored higher than /robots.txt by default",
          admin["priority"] > robots["priority"],
          f"admin={admin['priority']:.4f}  robots={robots['priority']:.4f}")


# ── B3a: 'priority' key alias ─────────────────────────────────────────────
print("\n[B3a] priority key alias")
check("B3a.alias: 'priority_score' key still present (backward compat)",
      admin is not None and "priority_score" in admin,
      "priority_score key removed — backward compat broken")
if admin:
    check("B3a.equal: priority == priority_score",
          admin["priority"] == admin["priority_score"],
          f"priority={admin.get('priority')} priority_score={admin.get('priority_score')}")


# ── B6: Weak evidence gate ─────────────────────────────────────────────────
print("\n[B6] Weak evidence gate")
ledger6 = HypothesisLedger()
hid = ledger6.add("/api/search", "sqli")
ledger6.record_result(hid, "confirmed", "appears to be vulnerable")
check("B6.weak: 'appears vulnerable' does NOT confirm hypothesis",
      ledger6._hypotheses[hid].status != "confirmed",
      f"Status is still '{ledger6._hypotheses[hid].status}'")
check("B6.status: downgraded to 'testing'",
      ledger6._hypotheses[hid].status == "testing",
      f"Status is '{ledger6._hypotheses[hid].status}'")

# Strong evidence should still confirm
ledger6b = HypothesisLedger()
hid2 = ledger6b.add("/api/search", "sqli")
ledger6b.record_result(hid2, "confirmed",
    "response: SQL error: You have an error in your SQL syntax; uid=0(root) returned")
check("B6.strong: Strong evidence still confirms",
      ledger6b._hypotheses[hid2].status == "confirmed",
      f"Strong evidence no longer confirms: status={ledger6b._hypotheses[hid2].status}")


# ── B11: Chain belief directionality ──────────────────────────────────────
print("\n[B11] Chain belief directionality")
ledger11 = HypothesisLedger()
sqli_id = ledger11.add("/api/search", "sqli")
rce_id  = ledger11.add("/api/search", "rce")
before  = ledger11.get_belief(rce_id)
ledger11.record_result(sqli_id, "rejected", "No SQL error observed")
after   = ledger11.get_belief(rce_id)
check("B11.reject: Rejecting SQLi does NOT reduce RCE belief",
      after >= before - 0.01,
      f"RCE belief dropped {before:.4f}->{after:.4f}")

# Confirming SQLi SHOULD boost RCE
ledger11b = HypothesisLedger()
sqli2 = ledger11b.add("/api/search", "sqli")
rce2  = ledger11b.add("/api/search", "rce")
before2 = ledger11b.get_belief(rce2)
ledger11b.record_result(sqli2, "confirmed",
    "UNION SELECT version() returned data: 8.0.32")
after2 = ledger11b.get_belief(rce2)
check("B11.confirm: Confirming SQLi still boosts RCE belief",
      after2 > before2,
      f"RCE belief unchanged after SQLi confirm: {before2:.4f}->{after2:.4f}")


# ── B13: vuln_class case normalisation ────────────────────────────────────
print("\n[B13] vuln_class case normalisation")
tracker = CoverageTracker()
tracker.record_test("/api/login", "endpoint", "SQLi")
check("B13.lookup_lower: has_been_tested('sqli') after record 'SQLi'",
      tracker.has_been_tested("/api/login", "endpoint", "sqli"),
      "Lowercase lookup failed")
check("B13.lookup_upper: has_been_tested('SQLI') after record 'SQLi'",
      tracker.has_been_tested("/api/login", "endpoint", "SQLI"),
      "Uppercase lookup failed")

gaps = tracker.get_coverage_gaps(["sqli"])
check("B13.no_gap: /api/login not a false gap for 'sqli'",
      "/api/login" not in gaps.get("gaps", []),
      f"False gap: {gaps.get('gaps', [])}")


# ── B-B: Double increment fix ─────────────────────────────────────────────
print("\n[B-B] tests_executed double-increment")
ledgerBB = HypothesisLedger()
hBB = ledgerBB.add("/api/x", "sqli")
ledgerBB.record_result(hBB, "testing", "some evidence")
ledgerBB.increment_iteration(hBB)  # separate call (typical agent pattern)
tests = ledgerBB._hypotheses[hBB].tests_executed
# record_result += 1, increment_iteration += iterations_spent (NOT tests_executed)
# So tests_executed should be 1
check("B-B.count: tests_executed == 1 after record_result + increment_iteration",
      tests == 1,
      f"tests_executed == {tests} (double-increment)")


# ── B-D: record_failure does not add to tested ────────────────────────────
print("\n[B-D] record_failure does not pollute tested surfaces")
trackerBD = CoverageTracker()
trackerBD.record_failure("/api/login", "endpoint", "WAF_BLOCKED", "sqli")
check("B-D.not_in_tested: WAF-failed surface does NOT appear in has_been_tested",
      not trackerBD.has_been_tested("/api/login", "endpoint"),
      "WAF-blocked surface wrongly appears as tested")
check("B-D.not_in_surfaces: WAF-failed surface not in get_tested_surfaces()",
      not any(t.surface == "/api/login" for t in trackerBD.get_tested_surfaces()),
      "WAF-blocked surface in get_tested_surfaces()")


# ===========================================================================
# PHASE 2 — Adversarial tests: try to break the fixes
# ===========================================================================
print("\n" + "="*70)
print("PHASE 2 — Adversarial: try to break every fix")
print("="*70)

# ── ADVERSARIAL B1 ─────────────────────────────────────────────────────────
print("\n[ADV-B1] URL dedup edge cases")

# /api/v2/users/123 and /api/v1/users/456 — different API versions should be different
ledgerA1 = HypothesisLedger()
a1 = ledgerA1.add("/api/v1/users/1", "sqli")
a2 = ledgerA1.add("/api/v2/users/1", "sqli")
check("ADV-B1.versions: /api/v1 and /api/v2 are DIFFERENT hypotheses",
      a1 != a2,
      "v1 and v2 wrongly collapsed")

# Same surface registered twice — should dedup, counter stays at 1
ledgerA1b = HypothesisLedger()
ax = ledgerA1b.add("/api/user/1", "sqli")
ay = ledgerA1b.add("/api/user/1", "sqli")  # exact same
check("ADV-B1.exact: exact duplicate still deduped",
      ax == ay and len(ledgerA1b._hypotheses) == 1,
      f"Exact dedup failed: {ax} vs {ay}")

# Query params — /api/user?id=1 and /api/user?id=2 should be separate
# (only path segments normalised, not query params)
ledgerA1c = HypothesisLedger()
aq = ledgerA1c.add("/api/user?id=1", "sqli")
ar = ledgerA1c.add("/api/user?id=2", "sqli")
check("ADV-B1.query: query-param only URLs are separate (not path-normalised)",
      aq != ar,
      "Query-param URLs wrongly collapsed — query params are distinct surfaces")


# ── ADVERSARIAL B6 ─────────────────────────────────────────────────────────
print("\n[ADV-B6] Weak evidence adversarial")

# Multiple weak confirmations — still should not confirm
ledgerA6 = HypothesisLedger()
hA6 = ledgerA6.add("/api/search", "sqli")
for weak in ["might be vulnerable", "suspect", "potential issue here", "appears to be vulnerable"]:
    ledgerA6.record_result(hA6, "confirmed", weak)
check("ADV-B6.multi_weak: 4 weak confirmations do NOT escalate to confirmed",
      ledgerA6._hypotheses[hA6].status != "confirmed",
      f"Status is '{ledgerA6._hypotheses[hA6].status}' after multi-weak")

# Strong evidence after weak — should finally confirm
ledgerA6b = HypothesisLedger()
hA6b = ledgerA6b.add("/api/search", "sqli")
ledgerA6b.record_result(hA6b, "confirmed", "appears to be vulnerable")  # weak
ledgerA6b.record_result(hA6b, "confirmed",
    "SQL error: You have an error in your SQL syntax returned with uid=0")  # strong
check("ADV-B6.weak_then_strong: strong evidence after weak still confirms",
      ledgerA6b._hypotheses[hA6b].status == "confirmed",
      f"Status is '{ledgerA6b._hypotheses[hA6b].status}'")


# ── ADVERSARIAL B11 ────────────────────────────────────────────────────────
print("\n[ADV-B11] Chain belief adversarial")

# Rejecting on a DIFFERENT surface should not affect unrelated surface
ledgerA11 = HypothesisLedger()
sqli_other = ledgerA11.add("/api/other", "sqli")
rce_search = ledgerA11.add("/api/search", "rce")
before11   = ledgerA11.get_belief(rce_search)
ledgerA11.record_result(sqli_other, "rejected", "No SQL error")
after11    = ledgerA11.get_belief(rce_search)
check("ADV-B11.different_surface: Rejecting SQLi on /api/other doesn't tank RCE on /api/search",
      after11 >= before11 - 0.05,
      f"Cross-surface belief drop: {before11:.4f}->{after11:.4f}")

# Confirming on same surface should boost related vuln (positive direction preserved)
ledgerA11b = HypothesisLedger()
xss  = ledgerA11b.add("/api/search", "xss")
csrf = ledgerA11b.add("/api/search", "csrf")
bXSS = ledgerA11b.get_belief(csrf)
ledgerA11b.record_result(xss, "confirmed", "XSS payload reflected: <script>alert(1)</script> returned 200")
aXSS = ledgerA11b.get_belief(csrf)
check("ADV-B11.positive: Confirming XSS boosts CSRF belief on same surface",
      aXSS > bXSS,
      f"CSRF belief unchanged after XSS confirm: {bXSS:.4f}->{aXSS:.4f}")


# ── ADVERSARIAL B13 ────────────────────────────────────────────────────────
print("\n[ADV-B13] Case normalisation adversarial")

# Mixed case recorded, various cases looked up
trackerA13 = CoverageTracker()
trackerA13.record_test("/api/login", "endpoint", "XSS")
for vc in ["xss", "XSS", "Xss", "xSs"]:
    check(f"ADV-B13.case_{vc}: has_been_tested with '{vc}' after record 'XSS'",
          trackerA13.has_been_tested("/api/login", "endpoint", vc),
          f"has_been_tested returned False for '{vc}'")


# ── ADVERSARIAL B-D ────────────────────────────────────────────────────────
print("\n[ADV-B-D] record_failure adversarial")

# Record failure, then actual test — surface should now be in tested
trackerAD = CoverageTracker()
trackerAD.record_failure("/api/login", "endpoint", "WAF_BLOCKED", "sqli")
trackerAD.record_test("/api/login", "endpoint", "sqli")  # now properly tested
check("ADV-B-D.fail_then_test: after real test, surface IS in tested",
      trackerAD.has_been_tested("/api/login", "endpoint", "sqli"),
      "Surface not in tested after record_test following record_failure")


# ── ADVERSARIAL B-E (attack graph) ─────────────────────────────────────────
print("\n[ADV-B-E] Attack graph add_edge fix")
try:
    _ag = _load("phantom.core.attack_graph",
                os.path.join(ROOT, "phantom", "core", "attack_graph.py"))
    AttackGraph    = _ag.AttackGraph
    AttackEdgeType = _ag.AttackEdgeType
    AttackNodeType = _ag.AttackNodeType

    g = AttackGraph()
    g.add_vulnerability("V1", "SQLi", "critical", "confirmed")
    g.add_vulnerability("V2", "RCE", "critical", "suspected")
    # This used to crash (add_relationship -> AttributeError, caught silently)
    # Now it must work
    try:
        g.add_edge("V1", "V2", AttackEdgeType.ENABLES)
        check("ADV-B-E.add_edge: add_edge('V1','V2',ENABLES) succeeds",
              True)
    except Exception as exc:
        fail("ADV-B-E.add_edge", str(exc))

    paths = g.find_paths("V1", "V2")
    check("ADV-B-E.path: path V1->V2 found (length 1)",
          len(paths) == 1 and paths[0] == ["V1", "V2"],
          f"paths={paths}")

except ImportError:
    print("  [SKIP] networkx not installed — ADV-B-E skipped")


# ===========================================================================
# PHASE 3 — No-regression: things that must still work
# ===========================================================================
print("\n" + "="*70)
print("PHASE 3 — No-regression: existing functionality preserved")
print("="*70)

# record_result('testing') should still work
ledgerR = HypothesisLedger()
hR = ledgerR.add("/api/search", "sqli")
ledgerR.record_result(hR, "testing", "sent test payload, waiting")
check("REG.testing: record_result('testing') sets status to testing",
      ledgerR._hypotheses[hR].status == "testing",
      f"status={ledgerR._hypotheses[hR].status}")

# rejected should still work
ledgerR2 = HypothesisLedger()
hR2 = ledgerR2.add("/api/search", "sqli")
ledgerR2.record_result(hR2, "rejected", "No SQL error, response was normal")
check("REG.rejected: record_result('rejected') sets rejected status",
      ledgerR2._hypotheses[hR2].status == "rejected",
      f"status={ledgerR2._hypotheses[hR2].status}")

# Coverage tracker: multiple vuln classes per surface
trackerR = CoverageTracker()
trackerR.record_test("/api/login", "endpoint", "sqli")
trackerR.record_test("/api/login", "endpoint", "xss")
check("REG.multi_class: two vuln classes stored per surface",
      trackerR.has_been_tested("/api/login", "endpoint", "sqli") and
      trackerR.has_been_tested("/api/login", "endpoint", "xss"),
      "Multi-class storage broken")

# get_all() still works (already existed)
ledgerR3 = HypothesisLedger()
ledgerR3.add("/api/test", "sqli")
ledgerR3.add("/api/test", "xss")
all_hyps = ledgerR3.get_all()
check("REG.get_all: get_all() returns 2 hypotheses",
      len(all_hyps) == 2,
      f"get_all returned {len(all_hyps)}")

# has_tested uses normalised lookup
ledgerR4 = HypothesisLedger()
hR4 = ledgerR4.add("/api/user/1", "sqli")
ledgerR4.record_result(hR4, "testing", "started test")
check("REG.has_tested: has_tested('/api/user/99', 'sqli') True after /user/1 tested",
      ledgerR4.has_tested("/api/user/99", "sqli"),
      "has_tested normalisation broke")


# ===========================================================================
# Summary
# ===========================================================================
print("\n" + "="*70)
total = len(PASS) + len(FAIL)
print(f"Results: {len(PASS)}/{total} passed")
if FAIL:
    print(f"\nFAILED ({len(FAIL)}):")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("\nALL TESTS PASSED - all 9 fixes verified, adversarial cases survived!")
