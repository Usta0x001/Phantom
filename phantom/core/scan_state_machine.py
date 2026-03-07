"""
Scan State Machine (BUG-003 FIX)

Formal finite state machine for scan phase enforcement.
Replaces the informal boolean flags with deterministic state transitions
governed by guard conditions.

States:
    INIT → RECONNAISSANCE → ENUMERATION → VULNERABILITY_SCANNING →
    EXPLOITATION → VERIFICATION → REPORTING → COMPLETED

Each transition has a guard condition that must be satisfied.
The agent CANNOT skip phases unless explicitly allowed by the scan profile.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from phantom.agents.enhanced_state import EnhancedAgentState

_logger = logging.getLogger(__name__)


class ScanState(str, Enum):
    """Formal scan states with deterministic transitions."""
    INIT = "init"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class PhaseMetrics:
    """Metrics tracked per phase for guard evaluation and reporting."""
    phase: ScanState
    started_at: str | None = None
    completed_at: str | None = None
    iterations_used: int = 0
    tools_invoked: int = 0
    findings_count: int = 0

    @property
    def is_active(self) -> bool:
        return self.started_at is not None and self.completed_at is None


@dataclass
class TransitionRule:
    """A rule governing a state transition."""
    from_state: ScanState
    to_state: ScanState
    guard: Callable[["EnhancedAgentState"], bool]
    description: str = ""
    can_skip: bool = False  # If True, transition can be forced without guard


from phantom.core.exceptions import InvalidTransitionError


class GuardConditionNotMetError(Exception):
    """Raised when a guard condition blocks a transition."""


class ScanStateMachine:
    """
    Formal FSM for scan phase management.

    Enforces:
    - Only valid transitions are allowed
    - Guard conditions gate each transition
    - Phase metrics are tracked automatically
    - Thread-safe state access
    """

    # ── Default guard conditions ──

    @staticmethod
    def _guard_init_to_recon(state: "EnhancedAgentState") -> bool:
        """Allowed when sandbox is ready."""
        return state.sandbox_id is not None  # HIGH-09 FIX: Removed 'or True'

    @staticmethod
    def _guard_recon_to_enum(state: "EnhancedAgentState") -> bool:
        """At least 1 host or subdomain discovered."""
        return len(state.hosts) > 0 or len(state.subdomains) > 0

    @staticmethod
    def _guard_enum_to_vulnscan(state: "EnhancedAgentState") -> bool:
        """At least 1 endpoint or service enumerated."""
        return len(state.endpoints) > 0 or any(
            len(h.ports) > 0 for h in state.hosts.values()
        )

    @staticmethod
    def _guard_vulnscan_to_exploit(state: "EnhancedAgentState") -> bool:
        """At least 1 potential vulnerability identified."""
        return state.vuln_stats.get("total", 0) > 0

    @staticmethod
    def _guard_exploit_to_verify(state: "EnhancedAgentState") -> bool:
        """At least 1 finding exists that needs verification."""
        return len(state.pending_verification) > 0 or len(state.verified_vulns) > 0

    @staticmethod
    def _guard_verify_to_report(state: "EnhancedAgentState") -> bool:
        """All HIGH/CRITICAL findings verified, OR verification budget exhausted."""
        high_crit = [
            v for v in state.vulnerabilities.values()
            if v.severity.value.lower() in ("critical", "high")
            and v.id not in state.verified_vulns
            and v.id not in state.false_positives
        ]
        # FIX-P2-001: Strict guard — ALL HIGH/CRITICAL must be verified.
        # Forced advancement only after exhaustion threshold (50 iterations in VERIFY).
        if high_crit:
            verify_metrics = state.state_machine.phase_metrics.get(ScanState.VERIFICATION)
            if verify_metrics and verify_metrics.iterations_used >= 50:
                _logger.warning(
                    "Verification exhaustion: %d unverified HIGH/CRIT after 50 iterations, allowing transition",
                    len(high_crit),
                )
                return True
            return False
        return True

    @staticmethod
    def _guard_report_to_complete(state: "EnhancedAgentState") -> bool:
        """Always allowed after reporting."""
        return True

    # ── Transition table ──

    DEFAULT_TRANSITIONS: list[TransitionRule] = [
        TransitionRule(ScanState.INIT, ScanState.RECONNAISSANCE,
                       _guard_init_to_recon, "Sandbox ready"),
        TransitionRule(ScanState.RECONNAISSANCE, ScanState.ENUMERATION,
                       _guard_recon_to_enum, "At least 1 host discovered"),
        TransitionRule(ScanState.ENUMERATION, ScanState.VULNERABILITY_SCANNING,
                       _guard_enum_to_vulnscan, "At least 1 endpoint enumerated"),
        TransitionRule(ScanState.VULNERABILITY_SCANNING, ScanState.EXPLOITATION,
                       _guard_vulnscan_to_exploit, "At least 1 vulnerability found"),
        TransitionRule(ScanState.EXPLOITATION, ScanState.VERIFICATION,
                       _guard_exploit_to_verify, "Findings exist for verification"),
        TransitionRule(ScanState.VERIFICATION, ScanState.REPORTING,
                       _guard_verify_to_report, "HIGH/CRIT findings verified"),
        TransitionRule(ScanState.REPORTING, ScanState.COMPLETED,
                       _guard_report_to_complete, "Report generated"),
        # Skip transitions (allowed with can_skip=True for quick/standard profiles)
        TransitionRule(ScanState.RECONNAISSANCE, ScanState.VULNERABILITY_SCANNING,
                       _guard_recon_to_enum, "Skip enumeration", can_skip=True),
        TransitionRule(ScanState.VULNERABILITY_SCANNING, ScanState.VERIFICATION,
                       _guard_vulnscan_to_exploit, "Skip exploitation", can_skip=True),
        TransitionRule(ScanState.EXPLOITATION, ScanState.REPORTING,
                       _guard_exploit_to_verify, "Skip verification", can_skip=True),
        # Error transition from any state
    ]

    # Phase budget allocation (percentage of total iterations)
    DEFAULT_PHASE_BUDGETS: dict[ScanState, float] = {
        ScanState.RECONNAISSANCE: 0.15,
        ScanState.ENUMERATION: 0.20,
        ScanState.VULNERABILITY_SCANNING: 0.25,
        ScanState.EXPLOITATION: 0.20,
        ScanState.VERIFICATION: 0.10,
        ScanState.REPORTING: 0.10,
    }

    def __init__(
        self,
        transitions: list[TransitionRule] | None = None,
        phase_budgets: dict[ScanState, float] | None = None,
        allow_skip: bool = False,
    ) -> None:
        self._current_state = ScanState.INIT
        self._transitions = transitions or list(self.DEFAULT_TRANSITIONS)
        self._phase_budgets = phase_budgets or dict(self.DEFAULT_PHASE_BUDGETS)
        self._allow_skip = allow_skip
        self._lock = threading.RLock()  # HIGH-27 FIX: Use RLock to prevent deadlock in guards
        self._phase_metrics: dict[ScanState, PhaseMetrics] = {
            s: PhaseMetrics(phase=s) for s in ScanState
        }
        self._transition_log: list[dict[str, Any]] = []
        self._phase_metrics[ScanState.INIT].started_at = datetime.now(UTC).isoformat()

    @property
    def current_state(self) -> ScanState:
        with self._lock:
            return self._current_state

    @property
    def phase_metrics(self) -> dict[ScanState, PhaseMetrics]:
        return dict(self._phase_metrics)

    def can_transition(self, target: ScanState, state: "EnhancedAgentState") -> bool:
        """Check if transition is possible without performing it."""
        with self._lock:
            return self._find_valid_transition(target, state) is not None

    def transition(
        self,
        target: ScanState,
        state: "EnhancedAgentState",
        *,
        force: bool = False,
    ) -> bool:
        """
        Attempt a state transition.

        Args:
            target: Target state to transition to
            state: Current agent state for guard evaluation
            force: If True, bypasses guard conditions (emergency use only)

        Returns:
            True if transition succeeded

        Raises:
            InvalidTransitionError if no rule exists for this transition
            GuardConditionNotMetError if guard blocks the transition
        """
        with self._lock:
            if target == self._current_state:
                return True  # No-op

            # Error transitions are always allowed
            if target == ScanState.ERROR:
                self._perform_transition(target, "Error state forced")
                return True

            if force:
                self._perform_transition(target, "Forced transition")
                return True

            rule = self._find_valid_transition(target, state)
            if rule is None:
                valid_targets = self._get_valid_targets()
                raise InvalidTransitionError(
                    f"Cannot transition from {self._current_state.value} to "
                    f"{target.value}. Valid targets: {[t.value for t in valid_targets]}"
                )

            if not rule.guard(state):
                raise GuardConditionNotMetError(
                    f"Guard failed for {self._current_state.value} → {target.value}: "
                    f"{rule.description}"
                )

            self._perform_transition(target, rule.description)
            return True

    def try_advance(self, state: "EnhancedAgentState") -> ScanState | None:
        """
        Attempt to advance to the next natural phase.

        Returns the new state if advanced, None if no transition is possible.
        This is called by the agent loop to auto-advance phases when guards are met.
        """
        # Define natural progression order
        progression = [
            ScanState.RECONNAISSANCE,
            ScanState.ENUMERATION,
            ScanState.VULNERABILITY_SCANNING,
            ScanState.EXPLOITATION,
            ScanState.VERIFICATION,
            ScanState.REPORTING,
            ScanState.COMPLETED,
        ]

        # CRIT-08 FIX: Keep lock held across entire try_advance to prevent TOCTOU
        with self._lock:
            current_idx = -1
            for i, s in enumerate(progression):
                if s == self._current_state:
                    current_idx = i
                    break

            if current_idx < 0 or current_idx >= len(progression) - 1:
                return None

            next_state = progression[current_idx + 1]

            # Perform transition inline (without releasing lock)
            if next_state == self._current_state:
                return next_state

            rule = self._find_valid_transition(next_state, state)
            if rule is None:
                return None

            if not rule.guard(state):
                return None

            self._perform_transition(next_state, rule.description)
            return next_state

    def get_phase_budget(self, max_iterations: int) -> int:
        """Get the iteration budget for the current phase."""
        budget_pct = self._phase_budgets.get(self._current_state, 0.1)
        return max(1, int(max_iterations * budget_pct))

    def get_phase_guidance(self) -> str:
        """Get human-readable guidance for the current phase."""
        with self._lock:
            current = self._current_state
        guidance = {
            ScanState.INIT: "Initializing scan environment.",
            ScanState.RECONNAISSANCE: (
                "RECONNAISSANCE PHASE: Map the attack surface. Use nmap, DNS lookups, "
                "subdomain enumeration. Discover hosts, ports, services. Do NOT "
                "attempt exploitation yet."
            ),
            ScanState.ENUMERATION: (
                "ENUMERATION PHASE: Enumerate services and endpoints. Use directory "
                "scanning, technology fingerprinting, API discovery. Build a complete "
                "picture of the target surface."
            ),
            ScanState.VULNERABILITY_SCANNING: (
                "VULNERABILITY SCANNING PHASE: Scan for vulnerabilities using nuclei, "
                "sqlmap detection mode, and manual testing. Identify potential issues "
                "but do NOT attempt full exploitation yet."
            ),
            ScanState.EXPLOITATION: (
                "EXPLOITATION PHASE: Attempt to exploit confirmed vulnerabilities. "
                "Use sqlmap, manual payload testing, and other exploit tools. "
                "Record all findings with evidence."
            ),
            ScanState.VERIFICATION: (
                "VERIFICATION PHASE: Verify all HIGH and CRITICAL findings. "
                "Re-test exploits, confirm false positives, gather evidence. "
                "You MUST verify findings before reporting."
            ),
            ScanState.REPORTING: (
                "REPORTING PHASE: Generate the final scan report. Summarize all "
                "verified findings, provide remediation advice. Call finish_scan "
                "when complete."
            ),
            ScanState.COMPLETED: "Scan completed.",
            ScanState.ERROR: "Scan encountered an error.",
        }
        return guidance.get(current, "")

    def get_status(self) -> dict[str, Any]:
        """Get full FSM status for debugging and reporting."""
        with self._lock:
            return {
                "current_state": self._current_state.value,
                "phase_metrics": {
                    s.value: {
                        "started_at": m.started_at,
                        "completed_at": m.completed_at,
                        "iterations_used": m.iterations_used,
                        "tools_invoked": m.tools_invoked,
                        "findings_count": m.findings_count,
                    }
                    for s, m in self._phase_metrics.items()
                    if m.started_at is not None
                },
                "transition_log": self._transition_log[-20:],  # Last 20
            }

    def record_iteration(self) -> None:
        """Record that an iteration occurred in the current phase."""
        with self._lock:
            metrics = self._phase_metrics.get(self._current_state)
            if metrics:
                metrics.iterations_used += 1

    def record_tool_invocation(self) -> None:
        """Record a tool invocation in the current phase."""
        with self._lock:
            metrics = self._phase_metrics.get(self._current_state)
            if metrics:
                metrics.tools_invoked += 1

    def record_finding(self) -> None:
        """Record a finding in the current phase."""
        with self._lock:
            metrics = self._phase_metrics.get(self._current_state)
            if metrics:
                metrics.findings_count += 1

    # ── Private ──

    def _find_valid_transition(
        self, target: ScanState, state: "EnhancedAgentState"
    ) -> TransitionRule | None:
        """Find a valid transition rule for the given target."""
        for rule in self._transitions:
            if rule.from_state != self._current_state:
                continue
            if rule.to_state != target:
                continue
            if rule.can_skip and not self._allow_skip:
                continue
            return rule
        return None

    def _get_valid_targets(self) -> list[ScanState]:
        """Get all states reachable from the current state."""
        targets = set()
        for rule in self._transitions:
            if rule.from_state == self._current_state:
                if not rule.can_skip or self._allow_skip:
                    targets.add(rule.to_state)
        targets.add(ScanState.ERROR)  # Always reachable
        return sorted(targets, key=lambda s: s.value)

    def _perform_transition(self, target: ScanState, description: str) -> None:
        """Execute the transition (must be called with lock held)."""
        old_state = self._current_state

        # Close current phase metrics
        current_metrics = self._phase_metrics.get(old_state)
        if current_metrics and current_metrics.is_active:
            current_metrics.completed_at = datetime.now(UTC).isoformat()

        # Open new phase metrics
        target_metrics = self._phase_metrics.get(target)
        if target_metrics:
            target_metrics.started_at = datetime.now(UTC).isoformat()

        self._current_state = target
        self._transition_log.append({
            "from": old_state.value,
            "to": target.value,
            "description": description,
            "timestamp": datetime.now(UTC).isoformat(),
        })
        # LOW-24 FIX: Cap transition log to prevent unbounded growth
        if len(self._transition_log) > 500:
            self._transition_log = self._transition_log[-250:]

        _logger.info(
            "State transition: %s → %s (%s)",
            old_state.value, target.value, description,
        )

    # ── Serialization (FIX-P1-003 / REG-003) ──

    def to_dict(self) -> dict[str, Any]:
        """Serialize FSM state for checkpoint persistence."""
        with self._lock:
            return {
                "current_state": self._current_state.value,
                "transition_log": list(self._transition_log),
                "phase_metrics": {
                    s.value: {
                        "started_at": m.started_at,
                        "completed_at": m.completed_at,
                        "iterations_used": m.iterations_used,
                        "tools_invoked": m.tools_invoked,
                        "findings_count": m.findings_count,
                    }
                    for s, m in self._phase_metrics.items()
                },
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any], **kwargs: Any) -> "ScanStateMachine":
        """Restore FSM from checkpoint data."""
        fsm = cls(**kwargs)
        try:
            restored_state = ScanState(data["current_state"])
            # MED-37 FIX: Don't restore COMPLETED/ERROR — start from INIT
            if restored_state in (ScanState.COMPLETED, ScanState.ERROR):
                fsm._current_state = ScanState.INIT
            else:
                fsm._current_state = restored_state
        except (KeyError, ValueError):
            fsm._current_state = ScanState.INIT

        fsm._transition_log = data.get("transition_log", [])
        for s_val, metrics_data in data.get("phase_metrics", {}).items():
            try:
                state = ScanState(s_val)
                m = fsm._phase_metrics.get(state)
                if m:
                    m.started_at = metrics_data.get("started_at")
                    m.completed_at = metrics_data.get("completed_at")
                    m.iterations_used = metrics_data.get("iterations_used", 0)
                    m.tools_invoked = metrics_data.get("tools_invoked", 0)
                    m.findings_count = metrics_data.get("findings_count", 0)
            except (ValueError, AttributeError):
                continue
        return fsm

    def recover_from_error(self, state: "EnhancedAgentState") -> ScanState | None:
        """REG-003: Recover from ERROR state.

        Attempts to transition to REPORTING for partial report generation,
        or back to INIT for supervised restart.
        """
        with self._lock:
            if self._current_state != ScanState.ERROR:
                return None
            # MED-38 FIX: Reset phase metrics for the error phase
            error_metrics = self._phase_metrics.get(ScanState.ERROR)
            if error_metrics:
                error_metrics.iterations_used = 0
                error_metrics.tools_invoked = 0
                error_metrics.findings_count = 0
            # If we have findings, go to REPORTING for partial report
            if len(state.vulnerabilities) > 0:
                self._perform_transition(ScanState.REPORTING, "Error recovery → partial report")
                return ScanState.REPORTING
            # Otherwise reset to INIT
            self._perform_transition(ScanState.INIT, "Error recovery → restart")
            return ScanState.INIT
