"""Test Suite 9: Confidence Engine Serialization (T2-07, DEFECT-CE-002)."""
import pytest
from phantom.core.confidence_engine import ConfidenceEngine


class TestEmptyEngineRoundtrip:
    def test_to_dict_from_dict_empty(self):
        engine = ConfidenceEngine()
        data = engine.to_dict()
        assert isinstance(data, dict)

        restored = ConfidenceEngine.from_dict(data)
        assert isinstance(restored, ConfidenceEngine)

    def test_empty_engine_has_expected_keys(self):
        engine = ConfidenceEngine()
        data = engine.to_dict()
        assert isinstance(data, dict)


class TestPopulatedEngineRoundtrip:
    def test_confidence_preserved_after_roundtrip(self):
        engine = ConfidenceEngine()
        engine.add_evidence("vuln-001", "nuclei", "SQL injection detected")
        engine.add_evidence("vuln-001", "sqlmap", "Confirmed SQLi via time-based")
        engine.add_evidence("vuln-002", "nmap", "Port 22 open")

        c1_before = engine.get_confidence("vuln-001")
        c2_before = engine.get_confidence("vuln-002")

        data = engine.to_dict()
        restored = ConfidenceEngine.from_dict(data)

        c1_after = restored.get_confidence("vuln-001")
        c2_after = restored.get_confidence("vuln-002")

        assert c1_after == pytest.approx(c1_before, abs=0.001), (
            f"vuln-001 confidence drifted: {c1_before} → {c1_after}"
        )
        assert c2_after == pytest.approx(c2_before, abs=0.001), (
            f"vuln-002 confidence drifted: {c2_before} → {c2_after}"
        )

    def test_negative_evidence_survives_roundtrip(self):
        engine = ConfidenceEngine()
        engine.add_evidence("vuln-003", "nuclei", "XSS detected")
        engine.add_negative_evidence("vuln-003", "manual_review", "False positive confirmed")

        c_before = engine.get_confidence("vuln-003")
        data = engine.to_dict()
        restored = ConfidenceEngine.from_dict(data)
        c_after = restored.get_confidence("vuln-003")

        assert c_after == pytest.approx(c_before, abs=0.001)

    def test_many_vulns_roundtrip(self):
        engine = ConfidenceEngine()
        for i in range(100):
            engine.add_evidence(
                f"vuln-{i:04d}",
                "scanner",
                f"Finding {i}",
            )

        data = engine.to_dict()
        restored = ConfidenceEngine.from_dict(data)

        for i in range(100):
            vid = f"vuln-{i:04d}"
            assert restored.get_confidence(vid) == pytest.approx(
                engine.get_confidence(vid), abs=0.001
            )
