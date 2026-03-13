"""
Hypothesis Ledger — Rec 6 (SF-005, SF-006, SF-007)

Structured external memory that lives outside the conversation history and
therefore survives every memory-compression cycle.  Agents inject a compact
summary every N iterations to maintain strategic coherence without bloating
the context window.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


_VALID_STATUSES = frozenset({"open", "testing", "confirmed", "rejected"})


@dataclass
class Hypothesis:
    id: str
    surface: str          # e.g. "/api/login::username"
    vuln_class: str       # e.g. "sqli"
    status: str = "open"  # open | testing | confirmed | rejected
    payloads_tested: list[str] = field(default_factory=list)
    iterations_spent: int = 0
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "vuln_class": self.vuln_class,
            "status": self.status,
            "payloads_tested": self.payloads_tested,
            "iterations_spent": self.iterations_spent,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Hypothesis":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class HypothesisLedger:
    """
    Thread-safe registry of hypotheses for a single scan.

    Properties:
    - Survives memory compression (stored outside conversation history)
    - Prevents redundant payload testing via `has_tested()`
    - Drives coverage tracking via `get_coverage_gaps()`
    - Injects compact TOP-N summary into LLM context (avoids token bloat)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter: int = 0

    # ── Mutations ─────────────────────────────────────────────────────────────

    def add(self, surface: str, vuln_class: str) -> str:
        """Register a new hypothesis; return its ID.  No-ops on duplicates."""
        with self._lock:
            # Dedup by surface + class
            for hyp in self._hypotheses.values():
                if hyp.surface == surface and hyp.vuln_class == vuln_class:
                    return hyp.id
            self._counter += 1
            hyp_id = f"H-{self._counter:04d}"
            self._hypotheses[hyp_id] = Hypothesis(
                id=hyp_id, surface=surface, vuln_class=vuln_class
            )
            return hyp_id

    def record_payload(self, hyp_id: str, payload: str) -> None:
        """Mark a payload as tested under this hypothesis."""
        with self._lock:
            hyp = self._hypotheses.get(hyp_id)
            if hyp and payload not in hyp.payloads_tested:
                hyp.payloads_tested.append(payload)
                hyp.iterations_spent += 1
                hyp.last_updated = datetime.now(UTC).isoformat()

    def record_result(
        self,
        hyp_id: str,
        outcome: str,
        evidence: str = "",
    ) -> None:
        """
        Update hypothesis status.
        outcome: 'confirmed' | 'rejected' | 'testing'
        """
        with self._lock:
            hyp = self._hypotheses.get(hyp_id)
            if not hyp:
                return
            if outcome in _VALID_STATUSES:
                hyp.status = outcome
            if evidence:
                if outcome == "confirmed":
                    hyp.evidence_for.append(evidence)
                elif outcome == "rejected":
                    hyp.evidence_against.append(evidence)
            hyp.last_updated = datetime.now(UTC).isoformat()

    def increment_iteration(self, hyp_id: str) -> None:
        """Increment the iterations-spent counter for a hypothesis."""
        with self._lock:
            hyp = self._hypotheses.get(hyp_id)
            if hyp:
                hyp.iterations_spent += 1
                hyp.last_updated = datetime.now(UTC).isoformat()

    # ── Queries ───────────────────────────────────────────────────────────────

    def has_tested(
        self,
        surface: str,
        vuln_class: str,
        payload: str | None = None,
    ) -> bool:
        """Return True if surface+class (optionally with specific payload) was tested."""
        with self._lock:
            for hyp in self._hypotheses.values():
                if hyp.surface != surface or hyp.vuln_class != vuln_class:
                    continue
                if payload is None:
                    # Any testing at all counts
                    return hyp.status != "open" or bool(hyp.payloads_tested)
                return payload in hyp.payloads_tested
        return False

    def get_open_hypotheses(self) -> list[Hypothesis]:
        """Return all hypotheses not yet confirmed or rejected."""
        with self._lock:
            return [h for h in self._hypotheses.values() if h.status in {"open", "testing"}]

    def get_coverage_gaps(self, known_surfaces: list[str]) -> list[str]:
        """Return surfaces that have no hypothesis registered against them."""
        with self._lock:
            tested = {h.surface for h in self._hypotheses.values()}
        return [s for s in known_surfaces if s not in tested]

    def get_stale_hypotheses(self, iteration_threshold: int = 20) -> list[Hypothesis]:
        """Return hypotheses consuming many iterations without resolution."""
        with self._lock:
            return [
                h for h in self._hypotheses.values()
                if h.status in {"open", "testing"}
                and h.iterations_spent >= iteration_threshold
            ]

    # ── Prompt Injection ──────────────────────────────────────────────────────

    def to_prompt_summary(self, top_n: int = 10) -> str:
        """
        Return a compact text summary safe to inject into the LLM prompt.

        Prioritises:
        1. Confirmed/rejected (for awareness, deduplication)
        2. Actively testing (current work)
        3. Open but untouched (highest exploration value)

        Hard limit: top_n entries to prevent token bloat.
        """
        with self._lock:
            hyps = list(self._hypotheses.values())

        if not hyps:
            return ""

        # Sort: confirmed/rejected first (compact), then by iterations desc
        def sort_key(h: Hypothesis) -> tuple[int, int]:
            status_order = {"confirmed": 0, "rejected": 1, "testing": 2, "open": 3}
            return (status_order.get(h.status, 9), -h.iterations_spent)

        hyps_sorted = sorted(hyps, key=sort_key)[:top_n]

        lines = ["[HYPOTHESIS LEDGER — current scan state]"]
        for h in hyps_sorted:
            tested_count = len(h.payloads_tested)
            ev_for = len(h.evidence_for)
            ev_against = len(h.evidence_against)
            line = (
                f"  {h.id} | {h.status.upper():10s} | {h.vuln_class:15s} | "
                f"{h.surface[:50]} | payloads={tested_count} "
                f"ev+={ev_for} ev-={ev_against} iters={h.iterations_spent}"
            )
            lines.append(line)

        open_count = sum(1 for h in hyps if h.status == "open")
        testing_count = sum(1 for h in hyps if h.status == "testing")
        confirmed_count = sum(1 for h in hyps if h.status == "confirmed")
        rejected_count = sum(1 for h in hyps if h.status == "rejected")

        lines.append(
            f"  Total: {len(hyps)} | open={open_count} testing={testing_count} "
            f"confirmed={confirmed_count} rejected={rejected_count}"
        )
        lines.append("[END LEDGER]")
        return "\n".join(lines)

    # ── Serialisation (survives compression) ──────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counter": self._counter,
                "hypotheses": {k: v.to_dict() for k, v in self._hypotheses.items()},
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HypothesisLedger":
        ledger = cls()
        ledger._counter = d.get("counter", 0)
        for k, v in d.get("hypotheses", {}).items():
            ledger._hypotheses[k] = Hypothesis.from_dict(v)
        return ledger

    def __len__(self) -> int:
        with self._lock:
            return len(self._hypotheses)
