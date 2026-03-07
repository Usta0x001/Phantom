"""
Tests for the Scan State Machine (BUG-003 FIX).

Validates:
- Deterministic state transitions
- Guard condition enforcement
- Invalid transition rejection
- Phase metrics tracking
- Thread safety of state access
- Auto-advance logic
"""

import threading
from unittest.mock import MagicMock

import pytest

from phantom.core.scan_state_machine import (
    GuardConditionNotMetError,
    InvalidTransitionError,
    PhaseMetrics,
    ScanState,
    ScanStateMachine,
)


# ── Fixtures ──


def _make_state(**overrides):
    """Create a mock EnhancedAgentState with configurable fields."""
    state = MagicMock()
    state.sandbox_id = overrides.get("sandbox_id", "sandbox-1")
    state.hosts = overrides.get("hosts", {})
    state.subdomains = overrides.get("subdomains", [])
    state.endpoints = overrides.get("endpoints", [])
    state.vulnerabilities = overrides.get("vulnerabilities", {})
    state.vuln_stats = overrides.get("vuln_stats", {"total": 0})
    state.pending_verification = overrides.get("pending_verification", [])
    state.verified_vulns = overrides.get("verified_vulns", [])
    state.false_positives = overrides.get("false_positives", [])
    return state


# ── Init & Basic State ──


class TestScanStateMachineInit:
    def test_initial_state_is_init(self):
        fsm = ScanStateMachine()
        assert fsm.current_state == ScanState.INIT

    def test_phase_metrics_initialized(self):
        fsm = ScanStateMachine()
        metrics = fsm.phase_metrics
        assert ScanState.INIT in metrics
        assert metrics[ScanState.INIT].started_at is not None

    def test_custom_phase_budgets(self):
        custom = {ScanState.RECONNAISSANCE: 0.5}
        fsm = ScanStateMachine(phase_budgets=custom)
        state = _make_state()
        fsm.transition(ScanState.RECONNAISSANCE, state)
        assert fsm.get_phase_budget(100) == 50


# ── Valid Transitions ──


class TestValidTransitions:
    def test_init_to_recon(self):
        fsm = ScanStateMachine()
        state = _make_state()
        assert fsm.transition(ScanState.RECONNAISSANCE, state) is True
        assert fsm.current_state == ScanState.RECONNAISSANCE

    def test_recon_to_enum_with_hosts(self):
        fsm = ScanStateMachine()
        state = _make_state(hosts={"10.0.0.1": MagicMock()})
        fsm.transition(ScanState.RECONNAISSANCE, state)
        assert fsm.transition(ScanState.ENUMERATION, state) is True
        assert fsm.current_state == ScanState.ENUMERATION

    def test_recon_to_enum_with_subdomains(self):
        fsm = ScanStateMachine()
        state = _make_state(subdomains=["sub.example.com"])
        fsm.transition(ScanState.RECONNAISSANCE, state)
        assert fsm.transition(ScanState.ENUMERATION, state) is True

    def test_full_progression(self):
        """Walk through all phases sequentially."""
        fsm = ScanStateMachine()

        mock_host = MagicMock()
        mock_host.ports = [MagicMock()]

        mock_vuln = MagicMock()
        mock_vuln.severity.value = "high"
        mock_vuln.id = "v1"

        state = _make_state(
            hosts={"10.0.0.1": mock_host},
            endpoints=["/api"],
            vuln_stats={"total": 2},
            vulnerabilities={"v1": mock_vuln},
            pending_verification=["v1"],
            verified_vulns=["v1"],
            false_positives=[],
        )
        state.state_machine = fsm

        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.transition(ScanState.ENUMERATION, state)
        fsm.transition(ScanState.VULNERABILITY_SCANNING, state)
        fsm.transition(ScanState.EXPLOITATION, state)
        fsm.transition(ScanState.VERIFICATION, state)
        fsm.transition(ScanState.REPORTING, state)
        fsm.transition(ScanState.COMPLETED, state)

        assert fsm.current_state == ScanState.COMPLETED

    def test_noop_transition_same_state(self):
        fsm = ScanStateMachine()
        state = _make_state()
        fsm.transition(ScanState.RECONNAISSANCE, state)
        # Transitioning to same state is a no-op
        assert fsm.transition(ScanState.RECONNAISSANCE, state) is True

    def test_error_transition_always_allowed(self):
        fsm = ScanStateMachine()
        state = _make_state()
        fsm.transition(ScanState.RECONNAISSANCE, state)
        assert fsm.transition(ScanState.ERROR, state) is True
        assert fsm.current_state == ScanState.ERROR


# ── Invalid Transitions ──


class TestInvalidTransitions:
    def test_recon_to_enum_without_hosts(self):
        fsm = ScanStateMachine()
        state = _make_state(hosts={}, subdomains=[])
        fsm.transition(ScanState.RECONNAISSANCE, state)
        with pytest.raises(GuardConditionNotMetError):
            fsm.transition(ScanState.ENUMERATION, state)

    def test_skip_phase_not_allowed_by_default(self):
        fsm = ScanStateMachine()
        state = _make_state()
        # Cannot jump from INIT to ENUMERATION
        with pytest.raises(InvalidTransitionError):
            fsm.transition(ScanState.ENUMERATION, state)

    def test_vulnscan_to_exploit_without_vulns(self):
        fsm = ScanStateMachine()
        mock_host = MagicMock()
        mock_host.ports = [MagicMock()]
        state = _make_state(
            hosts={"10.0.0.1": mock_host},
            endpoints=["/api"],
            vuln_stats={"total": 0},
        )
        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.transition(ScanState.ENUMERATION, state)
        fsm.transition(ScanState.VULNERABILITY_SCANNING, state)
        with pytest.raises(GuardConditionNotMetError):
            fsm.transition(ScanState.EXPLOITATION, state)


# ── Force Transition ──


class TestForceTransition:
    def test_force_bypasses_guard(self):
        fsm = ScanStateMachine()
        state = _make_state()
        fsm.transition(ScanState.RECONNAISSANCE, state)
        # Force transition without meeting guard
        assert fsm.transition(ScanState.ENUMERATION, state, force=True) is True
        assert fsm.current_state == ScanState.ENUMERATION


# ── Auto-Advance ──


class TestAutoAdvance:
    def test_try_advance_from_init_not_in_progression(self):
        """INIT is not in the progression list, so try_advance returns None."""
        fsm = ScanStateMachine()
        state = _make_state()
        new_state = fsm.try_advance(state)
        assert new_state is None  # INIT not in progression

    def test_try_advance_blocked_by_guard(self):
        fsm = ScanStateMachine()
        state = _make_state(hosts={}, subdomains=[])
        fsm.transition(ScanState.RECONNAISSANCE, state)
        new_state = fsm.try_advance(state)
        assert new_state is None  # Guard blocks recon→enum

    def test_try_advance_succeeds_when_guard_met(self):
        fsm = ScanStateMachine()
        state = _make_state(hosts={"10.0.0.1": MagicMock()})
        fsm.transition(ScanState.RECONNAISSANCE, state)
        new_state = fsm.try_advance(state)
        assert new_state == ScanState.ENUMERATION


# ── Phase Budget ──


class TestPhaseBudget:
    def test_default_budget_recon(self):
        fsm = ScanStateMachine()
        state = _make_state()
        fsm.transition(ScanState.RECONNAISSANCE, state)
        budget = fsm.get_phase_budget(100)
        assert budget == 15  # 0.15 * 100

    def test_budget_minimum_is_1(self):
        fsm = ScanStateMachine()
        assert fsm.get_phase_budget(0) >= 1


# ── Thread Safety ──


class TestThreadSafety:
    def test_concurrent_reads(self):
        fsm = ScanStateMachine()
        results = []

        def read_state():
            for _ in range(100):
                results.append(fsm.current_state)

        threads = [threading.Thread(target=read_state) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(s == ScanState.INIT for s in results)

    def test_can_transition_check(self):
        fsm = ScanStateMachine()
        state = _make_state()
        assert fsm.can_transition(ScanState.RECONNAISSANCE, state) is True
        assert fsm.can_transition(ScanState.ENUMERATION, state) is False
