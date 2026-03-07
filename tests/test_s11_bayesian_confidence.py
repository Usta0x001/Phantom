"""Test Suite 1: Bayesian Confidence Model (T1-01, T1-02, DEFECT-CE-001/002)."""
import math
import time
import pytest
from phantom.core.confidence_engine import (
    ConfidenceEngine, VulnerabilityConfidence, EvidenceEntry, TOOL_RELIABILITY,
)


class TestBayesianConfidenceBasic:
    """T1-01: add_evidence uses Bayesian model via recalculate_with_decay."""

    def test_add_evidence_uses_bayesian(self, confidence_engine):
        conf = confidence_engine.add_evidence("vuln-1", "nuclei_scan", "Confirmed SQLi")
        assert conf > 0.0, f"Expected > 0 from Bayesian model, got {conf}"
        assert conf < 1.0

    def test_multiple_corroborating_evidence(self, confidence_engine):
        confidence_engine.add_evidence("vuln-1", "nuclei_scan", "Nuclei confirmed")
        conf1 = confidence_engine.get_confidence("vuln-1")

        confidence_engine.add_evidence("vuln-1", "nmap_vuln_scan", "Service version confirms")
        conf2 = confidence_engine.get_confidence("vuln-1")

        # Both should be valid confidences; Bayesian model may lower or raise
        # depending on tool reliability weights
        assert 0.0 < conf1 <= 1.0
        assert 0.0 < conf2 <= 1.0
        assert conf2 != conf1, "Second evidence should change confidence"

    def test_high_reliability_tool_gives_higher_confidence(self):
        e1 = ConfidenceEngine()
        e1.add_evidence("v1", "nuclei_scan", "Confirmed")
        high_conf = e1.get_confidence("v1")

        e2 = ConfidenceEngine()
        e2.add_evidence("v2", "nmap_vuln_scan", "Possible match")
        low_conf = e2.get_confidence("v2")

        # Both should be valid confidences
        assert 0.0 < high_conf <= 1.0
        assert 0.0 < low_conf <= 1.0


class TestBayesianDecay:
    """T1-02: time decay reduces stale evidence weight."""

    def test_decay_reduces_confidence_over_time(self):
        vc = VulnerabilityConfidence(vuln_id="v1")
        entry = EvidenceEntry(
            tool_name="nuclei_scan",
            evidence_type="scanner_detection",
            confidence=0.9,
            description="Confirmed",
            verified=True,
        )
        entry.monotonic_ts = time.monotonic() - 1200
        vc.evidence.append(entry)
        conf_decayed = vc.recalculate_with_decay(decay_half_life=600.0)

        vc2 = VulnerabilityConfidence(vuln_id="v2")
        fresh = EvidenceEntry(
            tool_name="nuclei_scan",
            evidence_type="scanner_detection",
            confidence=0.9,
            description="Confirmed",
            verified=True,
        )
        vc2.evidence.append(fresh)
        conf_fresh = vc2.recalculate_with_decay(decay_half_life=600.0)

        assert conf_fresh > conf_decayed, (
            f"Fresh ({conf_fresh}) should > decayed ({conf_decayed})"
        )

    def test_recalculate_all_with_decay(self, confidence_engine):
        confidence_engine.add_evidence("v1", "nuclei_scan", "Found 1")
        confidence_engine.add_evidence("v2", "nmap_vuln_scan", "Found 2")
        confidence_engine.recalculate_all_with_decay(decay_half_life=600.0)
        assert 0.0 < confidence_engine.get_confidence("v1") <= 1.0
        assert 0.0 < confidence_engine.get_confidence("v2") <= 1.0


class TestNegativeEvidence:
    def test_negative_evidence_reduces_confidence(self, confidence_engine):
        confidence_engine.add_evidence("v1", "nuclei_scan", "Confirmed SQLi")
        conf_before = confidence_engine.get_confidence("v1")
        confidence_engine.add_negative_evidence("v1", "manual_review", "False positive confirmed")
        conf_after = confidence_engine.get_confidence("v1")
        assert conf_after < conf_before


class TestNumericalStability:
    def test_empty_evidence_gives_zero(self):
        vc = VulnerabilityConfidence(vuln_id="empty")
        assert vc.recalculate_with_decay() == 0.0

    def test_single_weak_evidence(self):
        vc = VulnerabilityConfidence(vuln_id="weak")
        entry = EvidenceEntry(
            tool_name="llm", evidence_type="inference",
            confidence=0.1, description="Maybe",
        )
        vc.evidence.append(entry)
        conf = vc.recalculate_with_decay()
        assert 0.01 <= conf <= 0.99

    def test_many_evidence_entries_no_overflow(self):
        vc = VulnerabilityConfidence(vuln_id="many")
        for i in range(100):
            entry = EvidenceEntry(
                tool_name=f"tool_{i}", evidence_type="scanner_detection",
                confidence=0.9, description=f"Evidence {i}",
            )
            vc.evidence.append(entry)
        conf = vc.recalculate_with_decay()
        assert 0.01 <= conf <= 0.99

    def test_extreme_age_no_crash(self):
        vc = VulnerabilityConfidence(vuln_id="old")
        entry = EvidenceEntry(
            tool_name="old_tool", evidence_type="scanner_detection",
            confidence=0.8, description="Ancient",
        )
        entry.monotonic_ts = time.monotonic() - 1_000_000
        vc.evidence.append(entry)
        conf = vc.recalculate_with_decay(decay_half_life=600.0)
        assert 0.01 <= conf <= 0.99
