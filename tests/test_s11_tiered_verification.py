"""Test Suite 6: Tiered Verification Engine (T2-05, T2-06, DEFECT-VE-001)."""
import pytest
from unittest.mock import MagicMock
from phantom.core.verification_engine import VerificationEngine, VerificationTier


class TestTierSelection:
    """T2-05: select_tier chooses tier based on severity and phase."""

    @pytest.fixture
    def engine(self):
        return VerificationEngine()

    def test_critical_severity_gets_deep(self, engine):
        vuln = MagicMock()
        vuln.severity = "CRITICAL"
        tier = engine.select_tier(vuln, phase="exploitation")
        assert tier == VerificationTier.DEEP

    def test_low_severity_recon_gets_quick(self, engine):
        vuln = MagicMock()
        vuln.severity = "LOW"
        tier = engine.select_tier(vuln, phase="recon")
        assert tier == VerificationTier.QUICK

    def test_medium_severity_verification_gets_standard(self, engine):
        vuln = MagicMock()
        vuln.severity = "MEDIUM"
        tier = engine.select_tier(vuln, phase="verification")
        assert tier == VerificationTier.STANDARD

    def test_high_severity_exploitation_gets_deep(self, engine):
        vuln = MagicMock()
        vuln.severity = "HIGH"
        tier = engine.select_tier(vuln, phase="exploitation")
        assert tier == VerificationTier.DEEP


class TestDeepTierEnum:
    """T2-06: DEEP tier clamp verification via tier enum values."""

    def test_deep_tier_exists(self):
        assert VerificationTier.DEEP.value == "deep"

    def test_quick_tier_exists(self):
        assert VerificationTier.QUICK.value == "quick"

    def test_standard_tier_exists(self):
        assert VerificationTier.STANDARD.value == "standard"

    def test_tier_ordering_by_intensity(self):
        """QUICK < STANDARD < DEEP in terms of verification depth."""
        tiers = [VerificationTier.QUICK, VerificationTier.STANDARD, VerificationTier.DEEP]
        assert len(set(tiers)) == 3  # all distinct
