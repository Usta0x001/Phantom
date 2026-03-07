"""
Tests for the Adversarial Critic (BUG-005 FIX).

Validates:
- Phase compliance enforcement
- Evidence requirement checks
- Verification gates
- Duplicate test detection
- CriticVerdict output
"""

from unittest.mock import MagicMock

import pytest

from phantom.core.adversarial_critic import (
    AdversarialCritic,
    CriticVerdict,
)


# ── Fixtures ──


def _make_state(**overrides):
    state = MagicMock()
    state.vulnerabilities = overrides.get("vulnerabilities", {})
    state.verified_vulns = overrides.get("verified_vulns", [])
    state.false_positives = overrides.get("false_positives", [])
    state.findings_ledger = overrides.get("findings_ledger", [])
    state.tested_endpoints = overrides.get("tested_endpoints", {})
    state.pending_verification = overrides.get("pending_verification", [])
    # Provide a mock attack_graph with proper int node_count for graph feasibility check
    mock_graph = MagicMock()
    mock_graph.node_count = overrides.get("node_count", 5)
    state.attack_graph = overrides.get("attack_graph", mock_graph)
    return state


def _make_phase(value: str):
    phase = MagicMock()
    phase.value = value
    return phase


def _make_vuln(severity: str = "high"):
    v = MagicMock()
    v.severity.value = severity
    return v


# ── Phase Compliance ──


class TestPhaseCompliance:
    def test_sqlmap_blocked_during_recon(self):
        critic = AdversarialCritic()
        state = _make_state()
        phase = _make_phase("reconnaissance")
        verdict = critic.review_action("sqlmap_test", {}, state, phase)
        assert len(verdict.issues) > 0
        assert "not appropriate" in verdict.issues[0]

    def test_nmap_blocked_during_reporting(self):
        critic = AdversarialCritic()
        state = _make_state()
        phase = _make_phase("reporting")
        verdict = critic.review_action("nmap_scan", {}, state, phase)
        assert len(verdict.issues) > 0

    def test_nmap_allowed_during_recon(self):
        critic = AdversarialCritic()
        state = _make_state()
        phase = _make_phase("reconnaissance")
        verdict = critic.review_action("nmap_scan", {}, state, phase)
        assert verdict.allowed
        assert len(verdict.issues) == 0

    def test_finish_allowed_during_reporting(self):
        critic = AdversarialCritic()
        state = _make_state()
        phase = _make_phase("reporting")
        verdict = critic.review_action("finish_scan", {}, state, phase)
        # finish_scan during reporting is phase-appropriate
        phase_issues = [i for i in verdict.issues if "not appropriate" in i]
        assert len(phase_issues) == 0


# ── Evidence Requirements ──


class TestEvidenceRequirements:
    def test_sqlmap_without_evidence_warns(self):
        critic = AdversarialCritic()
        state = _make_state(findings_ledger=[])
        phase = _make_phase("exploitation")
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://target/login"}, state, phase,
        )
        assert any("requires prior evidence" in i for i in verdict.issues)

    def test_sqlmap_with_evidence_passes(self):
        critic = AdversarialCritic()
        state = _make_state(
            findings_ledger=["Found SQL injection error at http://target/login"],
        )
        phase = _make_phase("exploitation")
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://target/login"}, state, phase,
        )
        evidence_issues = [i for i in verdict.issues if "requires prior evidence" in i]
        assert len(evidence_issues) == 0

    def test_sqlmap_dump_requires_confirmed_sqli(self):
        critic = AdversarialCritic()
        state = _make_state(findings_ledger=[])
        phase = _make_phase("exploitation")
        verdict = critic.review_action(
            "sqlmap_dump_database", {"url": "http://target/api"}, state, phase,
        )
        assert any("requires prior evidence" in i for i in verdict.issues)


# ── Verification Gates ──


class TestVerificationGates:
    def test_finish_blocked_with_unverified_crit(self):
        critic = AdversarialCritic()
        state = _make_state(
            vulnerabilities={"v1": _make_vuln("critical")},
            verified_vulns=[],
            false_positives=[],
        )
        phase = _make_phase("reporting")
        verdict = critic.review_action("finish_scan", {}, state, phase)
        assert any("unverified" in i.lower() for i in verdict.issues)

    def test_finish_allowed_when_all_verified(self):
        critic = AdversarialCritic()
        state = _make_state(
            vulnerabilities={"v1": _make_vuln("critical")},
            verified_vulns=["v1"],
        )
        phase = _make_phase("reporting")
        verdict = critic.review_action("finish_scan", {}, state, phase)
        verification_issues = [i for i in verdict.issues if "unverified" in i.lower()]
        assert len(verification_issues) == 0

    def test_finish_allowed_when_fp_dismissed(self):
        critic = AdversarialCritic()
        state = _make_state(
            vulnerabilities={"v1": _make_vuln("high")},
            verified_vulns=[],
            false_positives=["v1"],
        )
        phase = _make_phase("reporting")
        verdict = critic.review_action("finish_scan", {}, state, phase)
        verification_issues = [i for i in verdict.issues if "unverified" in i.lower()]
        assert len(verification_issues) == 0


# ── Strict Mode ──


class TestStrictMode:
    def test_strict_blocks(self):
        critic = AdversarialCritic(strict=True)
        state = _make_state()
        phase = _make_phase("reconnaissance")
        verdict = critic.review_action("sqlmap_test", {}, state, phase)
        assert not verdict.allowed

    def test_non_strict_warns(self):
        """v0.9.40: strict flag no longer affects verdict — issues always block."""
        critic = AdversarialCritic(strict=False)
        state = _make_state()
        phase = _make_phase("reconnaissance")
        verdict = critic.review_action("sqlmap_test", {}, state, phase)
        assert not verdict.allowed  # v0.9.40: blocked regardless of strict
        assert len(verdict.issues) > 0


# ── CriticVerdict ──


class TestCriticVerdict:
    def test_warning_text_empty_when_no_issues(self):
        v = CriticVerdict(tool_name="nmap_scan", allowed=True, issues=[], phase="recon")
        assert v.warning_text == ""

    def test_warning_text_contains_issues(self):
        v = CriticVerdict(
            tool_name="sqlmap_test", allowed=False,
            issues=["Phase violation", "Evidence missing"],
            phase="recon",
        )
        text = v.warning_text
        assert "CRITIC WARNING" in text
        assert "Phase violation" in text
        assert "Evidence missing" in text

    def test_to_dict(self):
        v = CriticVerdict(tool_name="nmap", allowed=True, issues=[], phase="recon")
        d = v.to_dict()
        assert d["tool_name"] == "nmap"
        assert d["allowed"] is True
        assert d["phase"] == "recon"


# ── Verification Report ──


class TestVerificationReport:
    def test_report_counts(self):
        critic = AdversarialCritic()
        state = _make_state(
            vulnerabilities={
                "v1": _make_vuln("critical"),
                "v2": _make_vuln("high"),
                "v3": _make_vuln("medium"),
            },
            verified_vulns=["v1"],
            false_positives=["v3"],
        )
        report = critic.get_verification_report(state)
        assert report["total_findings"] == 3
        assert report["verified"] == 1
        assert report["false_positives"] == 1
        assert report["unverified"] == 1  # v2
        assert report["unverified_high_crit"] == 1  # v2 is high


# ── Review Log ──


class TestReviewLog:
    def test_review_log_recorded(self):
        critic = AdversarialCritic()
        state = _make_state()
        phase = _make_phase("reconnaissance")
        critic.review_action("nmap_scan", {}, state, phase)
        critic.review_action("sqlmap_test", {}, state, phase)
        log = critic.get_review_log()
        assert len(log) == 2
