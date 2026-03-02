"""Tests for the vuln-class rotation engine."""

import pytest
from phantom.core.vuln_class_rotation import VulnClassTracker, VULN_CLASSES


class TestVulnClassTracker:
    """Test the vuln-class rotation engine."""

    def test_initial_state(self):
        tracker = VulnClassTracker(max_iters_per_class=5)
        assert tracker.current_class_idx == 0
        assert tracker.current_class_iters == 0
        assert len(tracker.completed_classes) == 0

    def test_tick_increments_counter(self):
        tracker = VulnClassTracker(max_iters_per_class=10)
        msg = tracker.tick()
        assert msg is None  # No rotation needed yet
        assert tracker.current_class_iters == 1
        assert tracker.total_iterations == 1

    def test_rotation_after_budget_exhausted(self):
        tracker = VulnClassTracker(max_iters_per_class=3)
        # Tick 3 times — should trigger rotation on the 3rd
        for _ in range(2):
            msg = tracker.tick()
            assert msg is None
        msg = tracker.tick()
        assert msg is not None
        assert "MANDATORY ROTATION" in msg
        assert "SQL Injection" in msg  # Just completed
        assert "XSS" in msg or "Cross-Site Scripting" in msg  # Next class
        assert tracker.current_class_idx == 1
        assert tracker.current_class_iters == 0
        assert "sqli" in tracker.completed_classes

    def test_full_rotation_cycle(self):
        tracker = VulnClassTracker(max_iters_per_class=2)
        total_classes = len(VULN_CLASSES)
        for _ in range(total_classes * 2):
            tracker.tick()
        # All classes should be completed
        assert len(tracker.completed_classes) == total_classes

    def test_get_current_directive(self):
        tracker = VulnClassTracker(max_iters_per_class=10)
        directive = tracker.get_current_directive()
        assert "SQL Injection" in directive
        assert "10 iterations remaining" in directive

    def test_get_current_directive_after_all_done(self):
        tracker = VulnClassTracker(max_iters_per_class=1)
        for _ in range(len(VULN_CLASSES)):
            tracker.tick()
        directive = tracker.get_current_directive()
        assert "All vulnerability classes have been tested" in directive

    def test_record_finding(self):
        tracker = VulnClassTracker(max_iters_per_class=10)
        tracker.tick()  # activate sqli
        tracker.record_finding()
        assert tracker.class_findings.get("sqli") == 1
        tracker.record_finding("xss")
        assert tracker.class_findings.get("xss") == 1

    def test_force_check_low_diversity(self):
        tracker = VulnClassTracker(max_iters_per_class=50)
        # Simulate 30 iterations on one class
        for _ in range(30):
            tracker.tick()
        msg = tracker.force_check(30)
        assert msg is not None
        assert "DIVERSITY CHECK" in msg

    def test_force_check_no_spam(self):
        tracker = VulnClassTracker(max_iters_per_class=50)
        for _ in range(30):
            tracker.tick()
        msg1 = tracker.force_check(30)
        assert msg1 is not None
        # Calling again within 8 iterations should return None
        msg2 = tracker.force_check(35)
        assert msg2 is None

    def test_progress_summary(self):
        tracker = VulnClassTracker(max_iters_per_class=3)
        for _ in range(3):
            tracker.tick()
        summary = tracker.get_progress_summary()
        assert "Done" in summary
        assert "Active" in summary or "Pending" in summary
        assert "SQL Injection" in summary

    def test_vuln_classes_have_required_fields(self):
        """Ensure all VULN_CLASSES have the required fields."""
        for vc in VULN_CLASSES:
            assert "id" in vc
            assert "name" in vc
            assert "tools" in vc
            assert "description" in vc

    def test_vuln_classes_unique_ids(self):
        """Ensure all VULN_CLASSES have unique IDs."""
        ids = [vc["id"] for vc in VULN_CLASSES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {ids}"

    def test_at_least_8_vuln_classes(self):
        """Ensure we have enough vuln classes for diversity."""
        assert len(VULN_CLASSES) >= 8
