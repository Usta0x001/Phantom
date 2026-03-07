"""Test Suite 5: Circuit Breaker (T2-01, T2-02, DEFECT-CB-001)."""
import time
import pytest
from phantom.core.circuit_breaker import CircuitBreaker, CircuitState


class TestStateTransitions:
    """CLOSED → OPEN → HALF_OPEN → CLOSED full lifecycle."""

    def test_starts_closed(self, circuit_breaker):
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.can_execute() is True

    def test_opens_after_threshold_failures(self, circuit_breaker):
        for _ in range(circuit_breaker.failure_threshold):
            circuit_breaker.record_failure()
        assert circuit_breaker.state == CircuitState.OPEN
        assert circuit_breaker.can_execute() is False

    def test_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        time.sleep(0.15)
        assert cb.can_execute() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.can_execute()  # transitions to HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.can_execute()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


class TestHalfOpenProbeLimit:
    """T2-02: Only one probe allowed in HALF_OPEN state."""

    def test_second_call_blocked(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)

        assert cb.can_execute() is True  # first probe
        assert cb.can_execute() is False  # second probe blocked

    def test_probe_resets_after_success(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)

        assert cb.can_execute() is True
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_probe_resets_after_failure(self):
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)

        assert cb.can_execute() is True
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.can_execute() is True  # new probe window


class TestCircuitBreakerSerialization:
    """Roundtrip serialization."""

    def test_roundtrip(self):
        cb = CircuitBreaker(name="test_ser", failure_threshold=5, recovery_timeout=30.0)
        cb.record_failure()
        cb.record_failure()

        data = cb.to_dict()
        restored = CircuitBreaker.from_dict(data)
        assert restored.state == cb.state
        assert restored._failure_count == cb._failure_count
        assert restored.failure_threshold == cb.failure_threshold
