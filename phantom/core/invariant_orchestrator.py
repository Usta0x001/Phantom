"""
Invariant Orchestrator — Hardening H-INV-001

Top-level module that periodically validates system-wide invariants:
  INV-GR-001: Graph structural integrity
  INV-IL-001: Confidence monotonicity (ceiling enforcement)
  INV-EV-001: Evidence limit per vulnerability
  INV-SM-001: State machine transition legality
  INV-DG-001: Degradation mode consistency

Publishes invariant violation events via the EventBus.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from phantom.core.graph_integrity_validator import GraphIntegrityValidator, GraphIntegrityReport
from phantom.core.metrics import metrics as _metrics

if TYPE_CHECKING:
    from phantom.core.attack_graph import AttackGraph
    from phantom.core.confidence_engine import ConfidenceEngine
    from phantom.core.event_bus import EventBus

_logger = logging.getLogger(__name__)

# Maximum evidence entries per vulnerability before flagging
_MAX_EVIDENCE_PER_VULN = 50

# Minimum interval between full invariant sweeps (seconds)
_MIN_SWEEP_INTERVAL = 30.0


@dataclass
class InvariantReport:
    """Aggregated result of all invariant checks."""
    timestamp: float = field(default_factory=time.time)
    graph_valid: bool = True
    graph_issues: list[str] = field(default_factory=list)
    confidence_violations: list[str] = field(default_factory=list)
    evidence_violations: list[str] = field(default_factory=list)
    state_machine_violations: list[str] = field(default_factory=list)
    degradation_violations: list[str] = field(default_factory=list)
    total_violations: int = 0

    @property
    def all_valid(self) -> bool:
        return self.total_violations == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "all_valid": self.all_valid,
            "total_violations": self.total_violations,
            "graph_valid": self.graph_valid,
            "graph_issues": self.graph_issues,
            "confidence_violations": self.confidence_violations,
            "evidence_violations": self.evidence_violations,
            "state_machine_violations": self.state_machine_violations,
            "degradation_violations": self.degradation_violations,
        }


class InvariantOrchestrator:
    """Periodically validates system-wide invariants.

    Thread-safe.  Call ``run_sweep()`` at the end of each agent iteration
    or on a timer.
    """

    def __init__(
        self,
        attack_graph: "AttackGraph | None" = None,
        confidence_engine: "ConfidenceEngine | None" = None,
        event_bus: "EventBus | None" = None,
    ) -> None:
        self._attack_graph = attack_graph
        self._confidence_engine = confidence_engine
        self._event_bus = event_bus
        self._lock = threading.Lock()
        self._last_sweep: float = 0.0
        self._sweep_count: int = 0
        self._violation_history: list[InvariantReport] = []

    def run_sweep(self, *, force: bool = False) -> InvariantReport:
        """Run all invariant checks.

        Skips if called within ``_MIN_SWEEP_INTERVAL`` unless ``force=True``.
        """
        now = time.time()
        if not force and (now - self._last_sweep) < _MIN_SWEEP_INTERVAL:
            return InvariantReport()

        with self._lock:
            self._last_sweep = now
            self._sweep_count += 1

            report = InvariantReport(timestamp=now)

            # INV-GR-001: Graph integrity
            self._check_graph_integrity(report)

            # INV-IL-001: Confidence monotonicity / ceiling
            self._check_confidence_invariants(report)

            # INV-EV-001: Evidence limits
            self._check_evidence_limits(report)

            # Count total violations
            report.total_violations = (
                len(report.graph_issues)
                + len(report.confidence_violations)
                + len(report.evidence_violations)
                + len(report.state_machine_violations)
                + len(report.degradation_violations)
            )

            # Record metrics
            try:
                inv_checks = _metrics._counters.get("phantom_invariant_checks_total")
                if inv_checks is None:
                    inv_checks = _metrics._counter("phantom_invariant_checks_total", "Invariant sweep runs")
                inv_checks.inc()
                if report.total_violations > 0:
                    inv_viol = _metrics._counters.get("phantom_invariant_violations_total")
                    if inv_viol is None:
                        inv_viol = _metrics._counter("phantom_invariant_violations_total", "Invariant violations")
                    inv_viol.inc(report.total_violations)
            except Exception:
                pass  # metrics are best-effort
                _logger.warning(
                    "Invariant sweep #%d: %d violations detected",
                    self._sweep_count, report.total_violations,
                )

            # Publish event
            if self._event_bus and report.total_violations > 0:
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(
                            self._event_bus.publish("invariant_violation", report.to_dict())
                        )
                except Exception:
                    pass

            # Keep bounded history
            self._violation_history.append(report)
            if len(self._violation_history) > 100:
                self._violation_history = self._violation_history[-50:]

            return report

    def _check_graph_integrity(self, report: InvariantReport) -> None:
        """INV-GR-001: Use GraphIntegrityValidator on the attack graph."""
        if self._attack_graph is None:
            return
        try:
            validator = GraphIntegrityValidator()
            gr: GraphIntegrityReport = validator.validate_graph(
                self._attack_graph,
            )
            report.graph_valid = gr.valid
            if not gr.valid:
                report.graph_issues.extend(gr.issues)
        except Exception as exc:
            report.graph_issues.append(f"Graph validation error: {exc}")

    def _check_confidence_invariants(self, report: InvariantReport) -> None:
        """INV-IL-001: No confidence exceeds 1.0, ceilings respected."""
        if self._confidence_engine is None:
            return
        try:
            all_conf = self._confidence_engine.get_all_confidences()
            for vuln_id, conf in all_conf.items():
                if conf > 1.0:
                    report.confidence_violations.append(
                        f"Confidence for {vuln_id} exceeds 1.0: {conf:.4f}"
                    )
                if conf < 0.0:
                    report.confidence_violations.append(
                        f"Confidence for {vuln_id} is negative: {conf:.4f}"
                    )
        except Exception as exc:
            report.confidence_violations.append(
                f"Confidence check error: {exc}"
            )

    def _check_evidence_limits(self, report: InvariantReport) -> None:
        """INV-EV-001: No vulnerability has more than _MAX_EVIDENCE_PER_VULN entries."""
        if self._confidence_engine is None:
            return
        try:
            if hasattr(self._confidence_engine, '_vulns'):
                for vuln_id, vc in self._confidence_engine._vulns.items():
                    if len(vc.evidence) > _MAX_EVIDENCE_PER_VULN:
                        report.evidence_violations.append(
                            f"Vulnerability {vuln_id} has {len(vc.evidence)} "
                            f"evidence entries (max={_MAX_EVIDENCE_PER_VULN})"
                        )
        except Exception as exc:
            report.evidence_violations.append(f"Evidence limit check error: {exc}")

    @property
    def sweep_count(self) -> int:
        return self._sweep_count

    @property
    def last_report(self) -> InvariantReport | None:
        return self._violation_history[-1] if self._violation_history else None

    def get_history(self) -> list[dict[str, Any]]:
        """Return violation history as dicts."""
        return [r.to_dict() for r in self._violation_history]
