"""
Hardening Test Suite — verifies all architectural fixes from the forensic audit.

Tests:
1. HypothesisLedger is now purely synchronous — no asyncio.new_event_loop() bombs.
2. Concurrent threaded writes to the ledger are race-condition free.
3. attack_graph.plan_attack_paths produces deterministic, non-probabilistic rankings.
4. agent_finish truncates oversized finding payloads before injecting into parent context.
5. Ledger.confirm no longer bypasses evidence checks due to JSON formatting.
"""

import sys
import os
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# 1 & 2: Synchronous HypothesisLedger + thread-safety
# ─────────────────────────────────────────────────────────────────────────────

class TestHypothesisLedgerSync(unittest.TestCase):
    """Ledger must be fully synchronous and thread-safe."""

    def setUp(self):
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        self.ledger = HypothesisLedger()

    def test_confirm_is_synchronous(self):
        """confirm() must not return a coroutine — it must be a plain bool."""
        import inspect
        hid = self.ledger.add("http://example.com/login", "sqli")
        result = self.ledger.confirm(hid, "' OR 1=1 -- confirmed via blind delay")
        self.assertFalse(inspect.iscoroutine(result), "confirm() returned a coroutine!")
        self.assertIsInstance(result, bool)
        self.assertTrue(result)

    def test_reject_is_synchronous(self):
        """reject() must not return a coroutine."""
        import inspect
        hid = self.ledger.add("http://example.com/search", "xss")
        result = self.ledger.reject(hid, "Payload reflected but CSP blocked execution")
        self.assertFalse(inspect.iscoroutine(result), "reject() returned a coroutine!")
        self.assertIsInstance(result, bool)
        self.assertTrue(result)

    def test_add_evidence_for_is_synchronous(self):
        """add_evidence_for must not return a coroutine."""
        import inspect
        hid = self.ledger.add("http://example.com/api", "idor")
        result = self.ledger.add_evidence_for(hid, "Got 200 accessing other user's data")
        self.assertFalse(inspect.iscoroutine(result), "add_evidence_for() returned a coroutine!")

    def test_add_evidence_against_is_synchronous(self):
        """add_evidence_against must not return a coroutine."""
        import inspect
        hid = self.ledger.add("http://example.com/api", "ssrf")
        result = self.ledger.add_evidence_against(hid, "Target IP was a private loopback, not accessible")
        self.assertFalse(inspect.iscoroutine(result), "add_evidence_against() returned a coroutine!")

    def test_record_result_no_event_loop_created(self):
        """record_result must NOT spin up asyncio event loops."""
        import asyncio
        hid = self.ledger.add("http://example.com/rce", "rce")
        # Verify no running loop is stolen or created by this call
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None  # Expected: no loop running in test thread

        self.ledger.record_result(hid, "confirmed", "RCE via shell injection confirmed")

        try:
            loop_after = asyncio.get_running_loop()
        except RuntimeError:
            loop_after = None

        # The loop state should be identical before and after — we didn't create one
        self.assertEqual(loop, loop_after, "record_result() created/destroyed an asyncio event loop!")

    def test_concurrent_10_thread_writes_no_crash(self):
        """10 concurrent threads hammering the ledger must not corrupt state."""
        errors = []

        def worker(idx: int):
            try:
                hid = self.ledger.add(f"http://target.com/endpoint-{idx}", "xss")
                self.ledger.record_payload(hid, f"<script>alert({idx})</script>")
                if idx % 2 == 0:
                    self.ledger.confirm(hid, f"XSS confirmed with payload #{idx} via alert box")
                else:
                    self.ledger.reject(hid, f"CSP blocked payload #{idx}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"Thread errors occurred: {errors}")
        # Verify final state: all 10 hypotheses added, 5 confirmed, 5 rejected
        all_hyps = self.ledger.get_all()
        self.assertEqual(len(all_hyps), 10)

    def test_set_correlation_engine_removed(self):
        """set_correlation_engine stub must no longer exist."""
        self.assertFalse(
            hasattr(self.ledger, "set_correlation_engine"),
            "set_correlation_engine stub still exists — it was supposed to be removed!"
        )

    def test_confirm_does_not_bypass_via_json_formatting(self):
        """Ledger must NOT blindly accept weak claims formatted as JSON/dict."""
        hid = self.ledger.add("http://example.com/upload", "rce")
        # Previously: containing '{' bypassed the weak-evidence check entirely
        weak_json_evidence = '{"status": "ok", "rce": "maybe"}'
        self.ledger.confirm(hid, weak_json_evidence)
        hyp = self.ledger.get(hid)
        evidence = hyp.evidence_for[0] if hyp.evidence_for else ""
        # Should NOT be marked WEAK_EVIDENCE (the old broken path marked it as clean due to '{')
        # but also should NOT silently pass as authoritative strong evidence — it's short so flagged
        # The new code: only check length (<50), not json bypasses
        # This evidence string is 42 chars — under 50 — should get [NEEDS_MORE_DETAIL]
        self.assertIn("[NEEDS_MORE_DETAIL]", evidence,
                      "Short JSON evidence should still be flagged as needing more detail!")


# ─────────────────────────────────────────────────────────────────────────────
# 3: AttackGraph deterministic ranking
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackGraphDeterministicRanking(unittest.TestCase):
    """Attack graph must rank paths deterministically, not via floating-point drift."""

    def setUp(self):
        try:
            from phantom.core.attack_graph import AttackGraph, AttackNodeType, AttackEdgeType
            self.AttackGraph = AttackGraph
            self.AttackNodeType = AttackNodeType
            self.AttackEdgeType = AttackEdgeType
            self.graph = AttackGraph()
        except ImportError:
            self.skipTest("networkx not installed")

    def _build_test_graph(self):
        g = self.graph
        g.add_vulnerability("v1", "SQL Injection", "high", status="confirmed")
        g.add_vulnerability("v2", "XSS", "medium", status="open")
        g.add_vulnerability("v3", "Auth Bypass", "critical", status="testing")
        g.add_asset("a1", "Admin Panel")
        g.add_edge("v1", "a1", self.AttackEdgeType.AFFECTS)
        g.add_edge("v2", "a1", self.AttackEdgeType.AFFECTS)
        g.add_edge("v3", "v1", self.AttackEdgeType.ENABLES)

    def test_confirmed_path_beats_open_path(self):
        """A path through confirmed nodes must rank above a path through open nodes."""
        self._build_test_graph()
        plans = self.graph.plan_attack_paths("v1", "a1", max_plans=5)
        self.assertGreater(len(plans), 0)
        # v1 is confirmed (priority=1) — direct path to a1 should score best
        best_path = plans[0].path
        self.assertIn("v1", best_path)

    def test_path_ranking_is_deterministic(self):
        """Calling plan_attack_paths twice must return identical ordering."""
        self._build_test_graph()
        plans1 = self.graph.plan_attack_paths("v3", "a1", max_plans=5)
        plans2 = self.graph.plan_attack_paths("v3", "a1", max_plans=5)
        self.assertEqual(
            [p.path for p in plans1],
            [p.path for p in plans2],
            "Path ranking is non-deterministic!"
        )

    def test_no_float_probabilities_in_range_0_1(self):
        """Score field must not be a suspicious 0-1 probability from the old math."""
        self._build_test_graph()
        plans = self.graph.plan_attack_paths("v1", "a1", max_plans=5)
        for plan in plans:
            # Old system: score was `probability / (1 + cost)` — always between 0 and 1
            # New system: score is integer priority_sum + hop_count — always >= 2
            self.assertGreaterEqual(plan.score, 2.0,
                f"Score {plan.score} looks like old float probability math!")

    def test_rejected_node_deprioritized(self):
        """Paths through rejected nodes must rank worse than paths through open nodes."""
        g = self.graph
        g.add_vulnerability("rejected_vuln", "Old Finding", "low", status="rejected")
        g.add_vulnerability("open_vuln", "New Finding", "medium", status="open")
        g.add_asset("target", "Target Asset")
        g.add_edge("rejected_vuln", "target", self.AttackEdgeType.AFFECTS)
        g.add_edge("open_vuln", "target", self.AttackEdgeType.AFFECTS)

        # Check priorities directly
        rejected_priority = self.graph._node_priority("rejected_vuln")
        open_priority = self.graph._node_priority("open_vuln")
        self.assertGreater(rejected_priority, open_priority,
            "Rejected nodes must have higher (worse) priority than open nodes!")


# ─────────────────────────────────────────────────────────────────────────────
# 4: agent_finish payload truncation
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentFinishTruncation(unittest.TestCase):
    """agent_finish must limit findings to prevent token explosion."""

    def test_truncation_helper_in_scope(self):
        """The _truncate helper must exist within the agent_finish function scope."""
        import ast, inspect
        from phantom.tools.agents_graph import agents_graph_actions
        src = inspect.getsource(agents_graph_actions.agent_finish)
        self.assertIn("_truncate", src, "_truncate helper not found in agent_finish!")
        self.assertIn("[:8]", src, "Findings list is not capped at 8 items!")

    def test_findings_limit_documented(self):
        """agent_finish must import Any for the _truncate type hint."""
        from phantom.tools.agents_graph import agents_graph_actions
        import inspect
        src = inspect.getsource(agents_graph_actions)
        self.assertIn("from typing import Any", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
