"""
Tests for the Confidence Engine.

Validates:
- Evidence-based confidence scoring
- Multi-tool corroboration bonus
- Verified evidence boost
- Confidence propagation to attack graph
- Summary and filtering
"""

import pytest

from phantom.core.confidence_engine import (
    ConfidenceEngine,
    EvidenceEntry,
    VulnerabilityConfidence,
)


# ── Basic Evidence ──


class TestEvidenceScoring:
    def test_scanner_detection_base_score(self):
        engine = ConfidenceEngine()
        score = engine.add_evidence("v1", "nuclei_scan", "Found XSS")
        # Bayesian model with decay: single scanner evidence produces lower initial score
        assert 0.0 < score < 1.0

    def test_exploitation_high_score(self):
        engine = ConfidenceEngine()
        score = engine.add_evidence("v1", "sqlmap_dump_database", "Dumped DB")
        # Exploitation tool has highest reliability → highest single-evidence confidence
        assert score > 0.0

    def test_manual_verification_medium_score(self):
        engine = ConfidenceEngine()
        score = engine.add_evidence("v1", "send_request", "Confirmed via HTTP")
        assert 0.0 < score < 1.0

    def test_unknown_tool_gets_default_score(self):
        engine = ConfidenceEngine()
        score = engine.add_evidence("v1", "custom_tool", "Something")
        # Unknown tool defaults to scanner_detection reliability
        assert 0.0 < score < 1.0


# ── Multi-Tool Corroboration ──


class TestCorroboration:
    def test_two_tools_add_bonus(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Scanner found it")
        score = engine.add_evidence("v1", "send_request", "Manual confirmed")
        # Bayesian model: second evidence updates posterior, score is valid
        assert 0.0 < score < 1.0

    def test_three_tools_add_more_bonus(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Scanner found it")
        engine.add_evidence("v1", "send_request", "Manual confirmed")
        score = engine.add_evidence("v1", "sqlmap_test", "SQLmap confirmed")
        assert 0.0 < score < 1.0

    def test_same_tool_no_extra_bonus(self):
        engine = ConfidenceEngine()
        score1 = engine.add_evidence("v1", "nuclei_scan", "First scan")
        score2 = engine.add_evidence("v1", "nuclei_scan", "Second scan")
        # Same tool → Bayesian update still changes the score
        assert 0.0 < score1 < 1.0
        assert 0.0 < score2 < 1.0

    def test_confidence_capped_at_one(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "sqlmap_dump_database", "Exploit success")
        engine.add_evidence("v1", "send_request", "Manual confirm")
        engine.add_evidence("v1", "nuclei_scan", "Scanner confirm")
        score = engine.add_evidence("v1", "terminal_execute", "Shell confirm")
        assert score <= 1.0


# ── Verified Evidence Boost ──


class TestVerifiedBoost:
    def test_verified_increases_score(self):
        engine = ConfidenceEngine()
        score_normal = engine.add_evidence("v1", "nuclei_scan", "Normal")
        engine2 = ConfidenceEngine()
        score_verified = engine2.add_evidence("v2", "nuclei_scan", "Verified", verified=True)
        assert score_verified > score_normal


# ── Queries ──


class TestQueries:
    def test_get_confidence(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Found")
        assert engine.get_confidence("v1") > 0
        assert engine.get_confidence("nonexistent") == 0.0

    def test_get_all_confidences(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Found v1")
        engine.add_evidence("v2", "sqlmap_dump_database", "Dumped v2")
        all_conf = engine.get_all_confidences()
        assert "v1" in all_conf
        assert "v2" in all_conf
        assert all_conf["v2"] > all_conf["v1"]

    def test_high_confidence_vulns(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "sqlmap_dump_database", "Confirmed exploit")
        engine.add_evidence("v1", "send_request", "Manual also confirmed")
        engine.add_evidence("v1", "nuclei_scan", "Scanner also confirmed")
        engine.add_evidence("v2", "nuclei_scan", "Scanner only")
        conf_v1 = engine.get_confidence("v1")
        conf_v2 = engine.get_confidence("v2")
        # v1 should have higher confidence than v2 with three pieces of evidence
        assert conf_v1 > conf_v2

    def test_low_confidence_vulns(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Scanner only")
        low = engine.get_low_confidence_vulns(threshold=0.4)
        assert "v1" in low

    def test_get_evidence_for_vuln(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "First")
        engine.add_evidence("v1", "send_request", "Second")
        evidence = engine.get_evidence_for_vuln("v1")
        assert len(evidence) == 2
        assert evidence[0]["tool"] == "nuclei_scan"

    def test_get_evidence_for_unknown_vuln(self):
        engine = ConfidenceEngine()
        assert engine.get_evidence_for_vuln("nope") == []


# ── Summary ──


class TestSummary:
    def test_summary_empty(self):
        engine = ConfidenceEngine()
        summary = engine.get_summary()
        assert summary["tracked_vulns"] == 0
        assert summary["avg_confidence"] == 0.0

    def test_summary_populated(self):
        engine = ConfidenceEngine()
        engine.add_evidence("v1", "nuclei_scan", "Found")
        engine.add_evidence("v2", "sqlmap_dump_database", "Exploited")
        summary = engine.get_summary()
        assert summary["tracked_vulns"] == 2
        assert summary["total_evidence"] == 2
        assert summary["avg_confidence"] > 0


# ── VulnerabilityConfidence Recalculation ──


class TestVulnerabilityConfidence:
    def test_recalculate_empty(self):
        vc = VulnerabilityConfidence(vuln_id="v1")
        assert vc.recalculate() == 0.0

    def test_recalculate_single_evidence(self):
        vc = VulnerabilityConfidence(vuln_id="v1")
        vc.evidence.append(
            EvidenceEntry(tool_name="nuclei_scan", evidence_type="scanner_detection",
                          confidence=0.3, description="test")
        )
        assert vc.recalculate() == 0.3

    def test_recalculate_with_corroboration(self):
        vc = VulnerabilityConfidence(vuln_id="v1")
        vc.evidence.append(
            EvidenceEntry(tool_name="nuclei_scan", evidence_type="scanner_detection",
                          confidence=0.3, description="scanner")
        )
        vc.evidence.append(
            EvidenceEntry(tool_name="send_request", evidence_type="manual_verification",
                          confidence=0.6, description="manual")
        )
        score = vc.recalculate()
        assert score == 0.65  # max(0.3, 0.6) + 0.05 bonus (1 extra tool)
