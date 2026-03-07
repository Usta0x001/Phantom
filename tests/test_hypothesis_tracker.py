"""
Tests for the Hypothesis Tracker.

Validates:
- Hypothesis lifecycle: propose → test → confirm/reject
- Priority sorting
- Eviction of old rejected hypotheses
- Filtering by target/category/status
- Summary and context generation
"""

import pytest

from phantom.core.hypothesis_tracker import (
    Hypothesis,
    HypothesisStatus,
    HypothesisTracker,
)


# ── Lifecycle ──


class TestLifecycle:
    def test_propose(self):
        tracker = HypothesisTracker()
        hid = tracker.propose(
            claim="POST /login is SQLi-vulnerable",
            target="http://target/login",
            category="sqli",
        )
        assert hid.startswith("hyp-")
        pending = tracker.get_pending()
        assert len(pending) == 1
        assert pending[0].claim == "POST /login is SQLi-vulnerable"

    def test_start_testing(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("XSS at /search", "http://target/search", "xss")
        assert tracker.start_testing(hid) is True
        active = tracker.get_active()
        assert len(active) == 1
        assert active[0].status == HypothesisStatus.TESTING

    def test_confirm(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("SQLi found", "http://target/api", "sqli")
        tracker.start_testing(hid)
        assert tracker.confirm(hid, 0.9, "Exploit succeeded") is True
        confirmed = tracker.get_confirmed()
        assert len(confirmed) == 1
        assert confirmed[0].confidence == 0.9
        assert confirmed[0].result_notes == "Exploit succeeded"

    def test_reject(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("IDOR at /user", "http://target/user", "idor")
        tracker.start_testing(hid)
        assert tracker.reject(hid, "No access bypass observed") is True
        pending = tracker.get_pending()
        assert len(pending) == 0

    def test_confirm_with_evidence_ids(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("SQLi", "target", "sqli")
        tracker.confirm(hid, 0.8, evidence_ids=["ev-abc", "ev-def"])
        confirmed = tracker.get_confirmed()
        assert confirmed[0].evidence_ids == ["ev-abc", "ev-def"]


# ── Guard Conditions ──


class TestGuards:
    def test_cannot_test_already_testing(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("test", "target", "misc")
        tracker.start_testing(hid)
        # Second start_testing should fail (not in PROPOSED state)
        assert tracker.start_testing(hid) is False

    def test_confirm_nonexistent(self):
        tracker = HypothesisTracker()
        assert tracker.confirm("hyp-9999", 0.9) is False

    def test_reject_nonexistent(self):
        tracker = HypothesisTracker()
        assert tracker.reject("hyp-9999") is False

    def test_confidence_clamped(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("test", "target", "misc")
        tracker.confirm(hid, 5.0)  # Over 1.0
        confirmed = tracker.get_confirmed()
        assert confirmed[0].confidence == 1.0

    def test_negative_confidence_clamped(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("test", "target", "misc")
        tracker.confirm(hid, -1.0)
        confirmed = tracker.get_confirmed()
        assert confirmed[0].confidence == 0.0


# ── Priority Sorting ──


class TestPriority:
    def test_pending_sorted_by_priority(self):
        tracker = HypothesisTracker()
        tracker.propose("Low priority", "t", "misc", priority=10)
        tracker.propose("High priority", "t", "misc", priority=1)
        tracker.propose("Medium priority", "t", "misc", priority=5)

        pending = tracker.get_pending()
        assert pending[0].claim == "High priority"
        assert pending[1].claim == "Medium priority"
        assert pending[2].claim == "Low priority"


# ── Filtering ──


class TestFiltering:
    def test_get_by_target(self):
        tracker = HypothesisTracker()
        tracker.propose("SQLi", "http://target.com/login", "sqli")
        tracker.propose("XSS", "http://target.com/search", "xss")
        tracker.propose("IDOR", "http://other.com/api", "idor")

        results = tracker.get_by_target("target.com")
        assert len(results) == 2

    def test_get_by_category(self):
        tracker = HypothesisTracker()
        tracker.propose("SQLi 1", "t1", "sqli")
        tracker.propose("SQLi 2", "t2", "sqli")
        tracker.propose("XSS", "t3", "xss")

        results = tracker.get_by_category("sqli")
        assert len(results) == 2


# ── Eviction ──


class TestEviction:
    def test_evicts_old_rejected_when_full(self):
        tracker = HypothesisTracker()
        tracker._MAX_HYPOTHESES = 10

        # Fill with rejected hypotheses
        for i in range(10):
            hid = tracker.propose(f"Old {i}", "t", "misc")
            tracker.reject(hid)

        # Should evict some rejected to make room
        new_hid = tracker.propose("New one", "t", "misc")
        assert new_hid is not None
        # The new one should be accessible
        pending = tracker.get_pending()
        assert any(h.claim == "New one" for h in pending)


# ── Claim Truncation ──


class TestTruncation:
    def test_long_claim_truncated(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("x" * 1000, "target", "misc")
        h = tracker._hypotheses[hid]
        assert len(h.claim) <= 500


# ── Summary ──


class TestSummary:
    def test_empty_summary(self):
        tracker = HypothesisTracker()
        s = tracker.get_summary()
        assert s["total"] == 0
        assert s["confirmation_rate"] == 0.0

    def test_summary_with_data(self):
        tracker = HypothesisTracker()
        h1 = tracker.propose("SQLi", "t", "sqli")
        h2 = tracker.propose("XSS", "t", "xss")
        tracker.confirm(h1, 0.9)
        
        s = tracker.get_summary()
        assert s["total"] == 2
        assert s["by_status"]["confirmed"] == 1
        assert s["by_status"]["proposed"] == 1
        assert s["by_category"]["sqli"] == 1
        assert s["by_category"]["xss"] == 1


# ── Context String ──


class TestContextString:
    def test_empty_context(self):
        tracker = HypothesisTracker()
        assert tracker.to_context_string() == ""

    def test_context_with_active(self):
        tracker = HypothesisTracker()
        hid = tracker.propose("SQLi at /login", "http://t/login", "sqli")
        tracker.start_testing(hid)
        ctx = tracker.to_context_string()
        assert "ACTIVE HYPOTHESES" in ctx
        assert "SQLi at /login" in ctx

    def test_context_with_pending(self):
        tracker = HypothesisTracker()
        tracker.propose("SQLi", "t", "sqli")
        ctx = tracker.to_context_string()
        assert "PENDING" in ctx
