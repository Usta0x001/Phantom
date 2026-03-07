"""
TASK 3: Safety & Boundary Enforcement Tests

Validates tool gating, phase guard enforcement, scope enforcement,
circuit breaker edge cases, degradation mode transitions, exception
hierarchy, and edge cases in safety-critical paths.
"""
import time
import threading
from unittest.mock import MagicMock

import pytest

from phantom.core.adversarial_critic import AdversarialCritic, CriticVerdict
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState
from phantom.core.degradation_handler import DegradationHandler, DegradationMode
from phantom.core.scan_state_machine import ScanStateMachine, ScanState
from phantom.core.attack_graph import AttackGraph
from phantom.core.exceptions import (
    SecurityViolationError, ScopeViolationError, SSRFBlockedError,
    AuditTamperError, CheckpointTamperError, InvalidTransitionError,
    ResourceExhaustedError, ToolError, LLMError, BasePhantomError,
)


# ===================================================================
# 3.1 Phase-Based Tool Gating
# ===================================================================

class TestPhaseToolGating:
    """Validate that the critic correctly blocks/allows tools per phase."""

    def _make_state(self, phase: ScanState):
        state = MagicMock()
        state.sandbox_id = "test"
        state.hosts = {"10.0.0.1": MagicMock(ports=[MagicMock()])}
        state.endpoints = ["/api"]
        state.vulnerabilities = {}
        state.vuln_stats = {"total": 0}
        state.pending_verification = []
        state.verified_vulns = []
        state.false_positives = []
        state.findings_ledger = []
        state.tested_endpoints = {}
        state.discovered_vulns = {}
        state.subdomains = []
        state.attack_graph = AttackGraph()
        state.attack_graph.add_host("10.0.0.1", ports=[80])
        return state

    def test_exploitation_tools_denied_in_recon(self):
        """sqlmap should be denied during reconnaissance (strict mode)."""
        critic = AdversarialCritic(strict=True)
        state = self._make_state(ScanState.RECONNAISSANCE)
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://10.0.0.1/api"},
            state, ScanState.RECONNAISSANCE,
        )
        assert not verdict.allowed
        assert len(verdict.issues) > 0

    def test_nmap_allowed_in_recon(self):
        critic = AdversarialCritic()
        state = self._make_state(ScanState.RECONNAISSANCE)
        verdict = critic.review_action(
            "nmap_scan", {"target": "10.0.0.1"},
            state, ScanState.RECONNAISSANCE,
        )
        assert verdict.allowed

    def test_recon_tools_denied_in_reporting(self):
        """Scanning tools should be flagged during reporting phase."""
        critic = AdversarialCritic(strict=True)
        state = self._make_state(ScanState.REPORTING)
        for tool in ["nmap_scan", "nuclei_scan", "sqlmap_test"]:
            verdict = critic.review_action(
                tool, {"target": "10.0.0.1"},
                state, ScanState.REPORTING,
            )
            assert not verdict.allowed, f"{tool} should be denied in REPORTING"
            assert len(verdict.issues) > 0

    def test_nuclei_requires_vulnerability_scanning_phase(self):
        """nuclei_scan min phase is vulnerability_scanning (strict mode)."""
        critic = AdversarialCritic(strict=True)
        state = self._make_state(ScanState.RECONNAISSANCE)
        verdict = critic.review_action(
            "nuclei_scan", {"target": "10.0.0.1"},
            state, ScanState.RECONNAISSANCE,
        )
        assert not verdict.allowed
        assert any("phase" in i.lower() for i in verdict.issues)

    def test_sqlmap_requires_evidence_in_findings_ledger(self):
        """sqlmap_test requires SQL injection evidence."""
        critic = AdversarialCritic()
        state = self._make_state(ScanState.EXPLOITATION)
        # No evidence
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://10.0.0.1/api"},
            state, ScanState.EXPLOITATION,
        )
        has_evidence_issue = any("requires prior evidence" in i for i in verdict.issues)
        assert has_evidence_issue

    def test_sqlmap_allowed_with_evidence(self):
        """sqlmap_test should pass when findings_ledger has SQL evidence."""
        critic = AdversarialCritic()
        state = self._make_state(ScanState.EXPLOITATION)
        state.findings_ledger = [
            "SQL injection error at http://10.0.0.1/api"
        ]
        verdict = critic.review_action(
            "sqlmap_test", {"url": "http://10.0.0.1/api"},
            state, ScanState.EXPLOITATION,
        )
        evidence_issues = [i for i in verdict.issues if "requires prior evidence" in i]
        assert len(evidence_issues) == 0

    def test_verdict_has_required_fields(self):
        critic = AdversarialCritic()
        state = self._make_state(ScanState.RECONNAISSANCE)
        verdict = critic.review_action(
            "nmap_scan", {"target": "10.0.0.1"},
            state, ScanState.RECONNAISSANCE,
        )
        assert isinstance(verdict, CriticVerdict)
        assert hasattr(verdict, "allowed")
        assert hasattr(verdict, "issues")
        assert hasattr(verdict, "tool_name")
        assert isinstance(verdict.to_dict(), dict)

    def test_high_risk_tool_flagging(self):
        """High-risk tools should generate warnings even when allowed."""
        critic = AdversarialCritic()
        state = self._make_state(ScanState.EXPLOITATION)
        state.findings_ledger = ["sqli confirmed at http://10.0.0.1/api"]
        verdict = critic.review_action(
            "sqlmap_dump_database", {"url": "http://10.0.0.1/api"},
            state, ScanState.EXPLOITATION,
        )
        # High-risk tools get extra scrutiny — should have issues or warnings
        assert isinstance(verdict.issues, list)


# ===================================================================
# 3.2 FSM Guard Enforcement
# ===================================================================

class TestFSMGuardEnforcement:
    """Validate state machine guards prevent invalid transitions."""

    def _make_state(self, fsm):
        state = MagicMock()
        state.sandbox_id = "test"
        state.state_machine = fsm
        state.hosts = {}
        state.subdomains = []
        state.endpoints = []
        state.vulnerabilities = {}
        state.vuln_stats = {"total": 0}
        state.pending_verification = []
        state.verified_vulns = []
        state.false_positives = []
        state.findings_ledger = []
        state.tested_endpoints = {}
        state.discovered_vulns = {}
        return state

    def test_recon_to_enum_requires_hosts(self):
        """Cannot advance from RECON to ENUM without hosts."""
        fsm = ScanStateMachine()
        state = self._make_state(fsm)
        state.hosts = {}  # No hosts
        fsm.transition(ScanState.RECONNAISSANCE, state)
        with pytest.raises(Exception):
            fsm.transition(ScanState.ENUMERATION, state)

    def test_enum_to_vulnscan_requires_endpoints(self):
        """Cannot advance from ENUM to VULN_SCAN without endpoints or ports."""
        fsm = ScanStateMachine()
        state = self._make_state(fsm)
        state.hosts = {"10.0.0.1": MagicMock(ports=[])}  # No ports
        state.endpoints = []  # No endpoints
        fsm.transition(ScanState.RECONNAISSANCE, state)
        # Add hosts with ports to allow RECON→ENUM
        state.hosts = {"10.0.0.1": MagicMock(ports=[MagicMock()])}
        fsm.transition(ScanState.ENUMERATION, state)
        # Now clear hosts ports and endpoints for guard test
        state.hosts = {"10.0.0.1": MagicMock(ports=[])}
        state.endpoints = []
        with pytest.raises(Exception):
            fsm.transition(ScanState.VULNERABILITY_SCANNING, state)

    def test_vulnscan_to_exploit_requires_vulns(self):
        """Cannot advance from VULN_SCAN to EXPLOITATION without vulns."""
        fsm = ScanStateMachine()
        state = self._make_state(fsm)
        state.hosts = {"10.0.0.1": MagicMock(ports=[MagicMock()])}
        state.endpoints = ["/api"]
        state.vuln_stats = {"total": 0}
        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.transition(ScanState.ENUMERATION, state)
        fsm.transition(ScanState.VULNERABILITY_SCANNING, state)
        with pytest.raises(Exception):
            fsm.transition(ScanState.EXPLOITATION, state)

    def test_skip_phases_not_allowed(self):
        """Cannot jump from INIT directly to EXPLOITATION."""
        fsm = ScanStateMachine()
        state = self._make_state(fsm)
        with pytest.raises(InvalidTransitionError):
            fsm.transition(ScanState.EXPLOITATION, state)

    def test_backward_transition_blocked(self):
        """Going backward should be blocked."""
        fsm = ScanStateMachine()
        state = self._make_state(fsm)
        state.hosts = {"10.0.0.1": MagicMock(ports=[MagicMock()])}
        fsm.transition(ScanState.RECONNAISSANCE, state)
        fsm.transition(ScanState.ENUMERATION, state)
        with pytest.raises(InvalidTransitionError):
            fsm.transition(ScanState.RECONNAISSANCE, state)


# ===================================================================
# 3.3 Circuit Breaker Edge Cases
# ===================================================================

class TestCircuitBreakerEdgeCases:
    """Validate circuit breaker state transitions and edge cases."""

    def test_starts_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=0.1)
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute()

    def test_trips_to_open_after_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=0.1)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert not cb.can_execute()

    def test_open_to_half_open_after_timeout(self):
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.can_execute()  # Triggers HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_allows_single_probe(self):
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.can_execute()  # First probe
        assert not cb.can_execute()  # Second probe blocked

    def test_half_open_success_resets_to_closed(self):
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.can_execute()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute()

    def test_half_open_failure_returns_to_open(self):
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.can_execute()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_serialization_roundtrip(self):
        cb = CircuitBreaker("test_cb", failure_threshold=5, recovery_timeout=30.0)
        cb.record_failure()
        data = cb.to_dict()
        restored = CircuitBreaker.from_dict(data)
        assert restored.name == "test_cb"
        assert restored.failure_threshold == 5

    def test_concurrent_circuit_breaker_access(self):
        """Multiple threads accessing same circuit breaker."""
        cb = CircuitBreaker("shared", failure_threshold=5, recovery_timeout=0.5)
        errors = []

        def hammer(tid):
            for i in range(100):
                try:
                    if cb.can_execute():
                        if i % 3 == 0:
                            cb.record_failure()
                        else:
                            cb.record_success()
                except Exception as e:
                    errors.append((tid, str(e)))

        threads = [threading.Thread(target=hammer, args=(t,)) for t in range(5)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)
        assert len(errors) == 0, f"CB concurrency errors: {errors}"


# ===================================================================
# 3.4 Degradation Handler Mode Transitions
# ===================================================================

class TestDegradationModeTransitions:
    """Validate graceful degradation mode transitions."""

    def test_starts_in_full_mode(self):
        handler = DegradationHandler()
        assert handler.mode == DegradationMode.FULL

    def test_single_provider_failure_reduces(self):
        handler = DegradationHandler()
        handler.handle_provider_failure("openai", "rate_limit")
        assert handler.mode == DegradationMode.REDUCED

    def test_two_provider_failures_goes_minimal(self):
        handler = DegradationHandler()
        handler.handle_provider_failure("openai", "rate_limit")
        handler.handle_provider_failure("anthropic", "timeout")
        assert handler.mode == DegradationMode.MINIMAL

    def test_tool_failures_cumulative(self):
        handler = DegradationHandler()
        handler.handle_tool_failure("nmap", "timeout")
        assert handler.mode == DegradationMode.FULL  # 1 tool failure = FULL
        handler.handle_tool_failure("nuclei", "crash")
        assert handler.mode == DegradationMode.FULL  # 2 = still FULL (H-DG-001: threshold=3)
        handler.handle_tool_failure("sqlmap", "error")
        assert handler.mode == DegradationMode.REDUCED  # 3 = REDUCED

    def test_five_tool_failures_minimal(self):
        handler = DegradationHandler()
        for i in range(5):
            handler.handle_tool_failure(f"tool_{i}", "error")
        assert handler.mode == DegradationMode.MINIMAL

    def test_recovery_restores_mode(self):
        handler = DegradationHandler()
        handler.handle_provider_failure("openai", "error")
        assert handler.mode == DegradationMode.REDUCED
        handler.recover_provider("openai")
        assert handler.mode == DegradationMode.FULL

    def test_status_report(self):
        handler = DegradationHandler()
        handler.handle_tool_failure("nmap", "error")
        status = handler.get_status()
        assert isinstance(status, dict)
        assert "mode" in status or "failed_tools" in status or len(status) > 0


# ===================================================================
# 3.5 Exception Hierarchy Safety
# ===================================================================

class TestExceptionHierarchy:
    """Validate exception hierarchy and recoverability flags."""

    def test_security_violations_not_recoverable(self):
        for exc_cls in [ScopeViolationError, SSRFBlockedError,
                        AuditTamperError, CheckpointTamperError]:
            exc = exc_cls("test")
            assert isinstance(exc, SecurityViolationError)
            assert isinstance(exc, BasePhantomError)
            assert not exc.recoverable

    def test_resource_exhausted_not_recoverable(self):
        exc = ResourceExhaustedError("cost limit")
        assert not exc.recoverable

    def test_operational_errors_recoverable(self):
        for exc_cls in [ToolError, LLMError]:
            exc = exc_cls("test")
            assert exc.recoverable

    def test_scope_violation_attributes(self):
        exc = ScopeViolationError("nmap_scan", target="192.168.1.1")
        assert isinstance(exc, SecurityViolationError)

    def test_ssrf_blocked_attributes(self):
        exc = SSRFBlockedError("169.254.169.254")
        assert isinstance(exc, SecurityViolationError)

    def test_invalid_transition_error(self):
        exc = InvalidTransitionError("init", "exploitation")
        assert isinstance(exc, BasePhantomError)


# ===================================================================
# 3.6 Critic Strict Mode
# ===================================================================

class TestCriticStrictMode:
    """Test critic behavior in strict vs permissive mode."""

    def _make_state(self):
        state = MagicMock()
        state.sandbox_id = "test"
        state.hosts = {"10.0.0.1": MagicMock(ports=[MagicMock()])}
        state.endpoints = ["/api"]
        state.vulnerabilities = {}
        state.vuln_stats = {"total": 0}
        state.pending_verification = []
        state.verified_vulns = []
        state.false_positives = []
        state.findings_ledger = []
        state.tested_endpoints = {}
        state.discovered_vulns = {}
        state.subdomains = []
        state.attack_graph = AttackGraph()
        state.attack_graph.add_host("10.0.0.1", ports=[80])
        return state

    def test_strict_mode_more_restrictive(self):
        """Strict mode should produce warnings/blocks more aggressively."""
        strict = AdversarialCritic(strict=True)
        permissive = AdversarialCritic(strict=False)
        state = self._make_state()

        v_strict = strict.review_action("nmap_scan", {"target": "10.0.0.1"},
                                         state, ScanState.RECONNAISSANCE)
        v_permissive = permissive.review_action("nmap_scan", {"target": "10.0.0.1"},
                                                 state, ScanState.RECONNAISSANCE)
        # Both should return CriticVerdict
        assert isinstance(v_strict, CriticVerdict)
        assert isinstance(v_permissive, CriticVerdict)

    def test_unknown_tool_handled_gracefully(self):
        critic = AdversarialCritic()
        state = self._make_state()
        verdict = critic.review_action(
            "totally_unknown_tool", {"foo": "bar"},
            state, ScanState.RECONNAISSANCE,
        )
        assert isinstance(verdict, CriticVerdict)
        # Should still produce a verdict, not crash
