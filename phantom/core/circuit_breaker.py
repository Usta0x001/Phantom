"""
Circuit Breaker Module

Architecture Improvement 9.2: Standalone circuit breaker pattern for
external calls (tools, LLM providers, HTTP targets).

States:
    CLOSED  → normal operation, failures counted
    OPEN    → calls rejected immediately, cooldown timer running
    HALF_OPEN → single probe call allowed to test recovery

The executor's inline ``_circuit_breaker`` dict can be migrated to use
this class for richer state handling (serialisation, metrics hooks).
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Any

_logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-resource circuit breaker.

    Args:
        name: Human-readable name (tool name or provider).
        failure_threshold: Consecutive failures before tripping to OPEN.
        recovery_timeout: Seconds to wait in OPEN before moving to HALF_OPEN.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._lock = threading.Lock()  # CRIT-09 FIX: Thread safety
        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.monotonic()
        self._half_open_probe_sent: bool = False  # T2-02: single-probe guard

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._maybe_transition()
            return self._state

    def can_execute(self) -> bool:
        """Return True if a call should be allowed."""
        with self._lock:
            self._maybe_transition()
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.HALF_OPEN:
                # T2-02: Allow exactly one probe in HALF_OPEN
                if not self._half_open_probe_sent:
                    self._half_open_probe_sent = True
                    return True
                return False  # Block subsequent calls until result recorded
            return False  # OPEN → reject

    def record_success(self) -> None:
        """Record a successful call — resets the breaker to CLOSED."""
        with self._lock:
            if self._state != CircuitState.CLOSED:
                _logger.info("CircuitBreaker[%s]: recovered → CLOSED", self.name)
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_probe_sent = False
            self._last_state_change = time.monotonic()

    def record_failure(self) -> None:
        """Record a failed call — may trip the breaker to OPEN."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    _logger.warning(
                        "CircuitBreaker[%s]: tripped → OPEN after %d failures (cooldown %ds)",
                        self.name, self._failure_count, self.recovery_timeout,
                    )
                self._state = CircuitState.OPEN
                self._half_open_probe_sent = False
                self._last_state_change = time.monotonic()

    # ------------------------------------------------------------------
    # Serialisation (for checkpoint persistence, bypass-C mitigation)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "last_failure_time": self._last_failure_time,
                "last_state_change": self._last_state_change,
                "half_open_probe_sent": self._half_open_probe_sent,
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CircuitBreaker":
        cb = cls(
            name=data["name"],
            failure_threshold=data.get("failure_threshold", 3),
            recovery_timeout=data.get("recovery_timeout", 60.0),
        )
        cb._state = CircuitState(data.get("state", "closed"))
        cb._failure_count = data.get("failure_count", 0)
        cb._last_failure_time = data.get("last_failure_time", 0.0)
        # HIGH-25/26 FIX: Restore serialized fields
        cb._last_state_change = data.get("last_state_change", time.monotonic())
        cb._half_open_probe_sent = data.get("half_open_probe_sent", False)
        return cb

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _maybe_transition(self) -> None:
        """Auto-transition from OPEN → HALF_OPEN after recovery_timeout."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_state_change
            if elapsed >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                _logger.info(
                    "CircuitBreaker[%s]: cooldown elapsed → HALF_OPEN",
                    self.name,
                )

    def __repr__(self) -> str:
        return (
            f"CircuitBreaker(name={self.name!r}, state={self._state.value}, "
            f"failures={self._failure_count}/{self.failure_threshold})"
        )
