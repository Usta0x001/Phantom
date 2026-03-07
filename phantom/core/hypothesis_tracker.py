"""
Hypothesis Tracker

Tracks the agent's hypotheses about the target and their validation status.
A hypothesis is a testable claim like "POST /api/login is vulnerable to SQLi".

Lifecycle:
    PROPOSED → TESTING → CONFIRMED / REJECTED / INCONCLUSIVE

This provides structured reasoning tracking that replaces the no-op think tool's
missing storage and gives the agent a formal way to track what it's investigating.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

_logger = logging.getLogger(__name__)


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Hypothesis:
    """A testable security hypothesis."""
    id: str
    claim: str                     # "POST /login param=email is SQLi-vulnerable"
    target: str                    # "http://target.com/login"
    category: str                  # "sqli", "xss", "misconfig", etc.
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.0        # 0.0-1.0
    evidence_ids: list[str] = field(default_factory=list)
    test_plan: str = ""            # How to test this hypothesis
    result_notes: str = ""         # Outcome description
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    priority: int = 5              # 1=highest, 10=lowest

    def set_testing(self) -> None:
        self.status = HypothesisStatus.TESTING
        self.updated_at = datetime.now(UTC).isoformat()

    def confirm(self, confidence: float, notes: str = "") -> None:
        self.status = HypothesisStatus.CONFIRMED
        self.confidence = min(1.0, max(0.0, confidence))
        self.result_notes = notes
        self.updated_at = datetime.now(UTC).isoformat()

    def reject(self, notes: str = "") -> None:
        self.status = HypothesisStatus.REJECTED
        self.confidence = 0.0
        self.result_notes = notes
        self.updated_at = datetime.now(UTC).isoformat()


class HypothesisTracker:
    """
    Manages the lifecycle of security hypotheses.

    Integrates with:
    - Think tool (proposing hypotheses)
    - Tool execution (testing hypotheses)
    - Evidence registry (confirming/rejecting hypotheses)
    - Confidence engine (updating confidence scores)
    """

    _MAX_HYPOTHESES = 500

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter = 0
        self._lock = threading.Lock()  # HIGH-05 FIX: Thread safety

    def propose(
        self,
        claim: str,
        target: str,
        category: str,
        *,
        test_plan: str = "",
        priority: int = 5,
    ) -> str:
        """Propose a new hypothesis.

        Returns the hypothesis ID.
        """
        with self._lock:
            if len(self._hypotheses) >= self._MAX_HYPOTHESES:
                # Evict oldest rejected hypotheses
                rejected = sorted(
                    [h for h in self._hypotheses.values()
                     if h.status == HypothesisStatus.REJECTED],
                    key=lambda h: h.created_at,
                )
                for h in rejected[:50]:
                    del self._hypotheses[h.id]

            # HIGH-04 FIX: Hard cap — only add if below limit after eviction
            if len(self._hypotheses) >= self._MAX_HYPOTHESES:
                _logger.warning("Hypothesis tracker at hard cap (%d), rejecting new proposal", self._MAX_HYPOTHESES)
                return ""  # Signal cap reached

            self._counter += 1
            hid = f"hyp-{self._counter:04d}"
            h = Hypothesis(
                id=hid,
                claim=claim[:500],
                target=target,
                category=category,
                test_plan=test_plan[:500],
                priority=priority,
            )
            self._hypotheses[hid] = h
            _logger.debug("Hypothesis proposed: %s — %s", hid, claim[:80])
            return hid

    def start_testing(self, hypothesis_id: str) -> bool:
        """Mark a hypothesis as being actively tested."""
        h = self._hypotheses.get(hypothesis_id)
        if h and h.status == HypothesisStatus.PROPOSED:
            h.set_testing()
            return True
        return False

    def confirm(
        self,
        hypothesis_id: str,
        confidence: float,
        notes: str = "",
        evidence_ids: list[str] | None = None,
    ) -> bool:
        """Confirm a hypothesis with evidence."""
        with self._lock:
            h = self._hypotheses.get(hypothesis_id)
            if not h:
                return False
            # MED-21 FIX: Only confirm if in valid state
            if h.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING):
                _logger.warning("Cannot confirm %s in state %s", hypothesis_id, h.status.value)
                return False
            h.confirm(confidence, notes)
            if evidence_ids:
                h.evidence_ids.extend(evidence_ids)
            return True

    def reject(self, hypothesis_id: str, notes: str = "") -> bool:
        """Reject a hypothesis."""
        with self._lock:
            h = self._hypotheses.get(hypothesis_id)
            if not h:
                return False
            # MED-21 FIX: Only reject if in valid state
            if h.status == HypothesisStatus.CONFIRMED:
                _logger.warning("Cannot reject confirmed hypothesis %s", hypothesis_id)
                return False
            h.reject(notes)
            return True

    def get_pending(self) -> list[Hypothesis]:
        """Get hypotheses that haven't been tested yet, sorted by priority."""
        return sorted(
            [h for h in self._hypotheses.values()
             if h.status == HypothesisStatus.PROPOSED],
            key=lambda h: h.priority,
        )

    def get_active(self) -> list[Hypothesis]:
        """Get hypotheses currently being tested."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.TESTING
        ]

    def get_confirmed(self) -> list[Hypothesis]:
        """Get confirmed hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.CONFIRMED
        ]

    def get_by_target(self, target: str) -> list[Hypothesis]:
        """Get all hypotheses for a specific target.
        
        LOW-16 FIX: Use case-insensitive containment check.
        """
        target_lower = target.lower()
        return [
            h for h in self._hypotheses.values()
            if target_lower in h.target.lower()
        ]

    def get_by_category(self, category: str) -> list[Hypothesis]:
        """Get all hypotheses of a specific category."""
        return [
            h for h in self._hypotheses.values()
            if h.category == category
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get hypothesis tracking summary."""
        status_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for h in self._hypotheses.values():
            status_counts[h.status.value] = status_counts.get(h.status.value, 0) + 1
            category_counts[h.category] = category_counts.get(h.category, 0) + 1

        return {
            "total": len(self._hypotheses),
            "by_status": status_counts,
            "by_category": category_counts,
            "confirmation_rate": (
                len(self.get_confirmed()) / max(1, len(self._hypotheses))
            ),
        }

    def to_context_string(self) -> str:
        """Generate a context string for LLM system prompt injection."""
        pending = self.get_pending()[:5]
        active = self.get_active()
        confirmed = self.get_confirmed()[:5]

        parts: list[str] = []
        if active:
            parts.append("ACTIVE HYPOTHESES:")
            for h in active:
                parts.append(f"  [{h.id}] {h.claim} (target: {h.target})")
        if pending:
            parts.append(f"PENDING: {len(pending)} hypotheses awaiting testing")
            for h in pending[:3]:
                parts.append(f"  [{h.id}] {h.claim}")
        if confirmed:
            parts.append(f"CONFIRMED: {len(confirmed)} hypotheses")

        return "\n".join(parts) if parts else ""

    def reap_stale(self, *, max_age_minutes: float = 30.0) -> int:
        """Reap stale hypotheses that have been in PROPOSED/TESTING too long (H-HT-001).

        Hypotheses stuck in PROPOSED or TESTING for longer than max_age_minutes
        are moved to INCONCLUSIVE and can be evicted to free capacity.

        Returns the number of hypotheses reaped.
        """
        reaped = 0
        cutoff = datetime.now(UTC)

        with self._lock:
            for h in list(self._hypotheses.values()):
                if h.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING):
                    continue

                try:
                    created = datetime.fromisoformat(h.created_at)
                    age_minutes = (cutoff - created).total_seconds() / 60.0
                except (ValueError, TypeError):
                    continue

                if age_minutes > max_age_minutes:
                    h.status = HypothesisStatus.INCONCLUSIVE
                    h.result_notes = f"Stale after {age_minutes:.0f}m — auto-reaped"
                    h.updated_at = datetime.now(UTC).isoformat()
                    reaped += 1

        if reaped:
            _logger.info("Hypothesis reaper: %d stale hypotheses reaped", reaped)
        return reaped
