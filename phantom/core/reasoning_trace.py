"""
Reasoning Trace — Hardening H-IL-003

Append-only log of the agent's reasoning steps per scan.

Design:
  - Each entry records: step number, phase, tool, reasoning, confidence, timestamp
  - Hard cap at 500 entries (ring buffer — evicts oldest)
  - Thread-safe with RLock
  - Exportable to JSON for post-scan analysis
  - Summary stats: steps per phase, avg confidence, tool distribution

This module powers the "reasoning transparency" requirement from the
hardening roadmap, allowing auditors to inspect the agent's decision chain.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger(__name__)

_MAX_TRACE_ENTRIES = 500


@dataclass
class ReasoningStep:
    """A single reasoning step in the agent trace."""
    step_number: int
    phase: str
    tool_name: str
    reasoning: str
    confidence: float
    outcome: str = ""  # success | failure | blocked | skipped
    evidence_ids: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "phase": self.phase,
            "tool": self.tool_name,
            "reasoning": self.reasoning[:500],  # truncate long reasoning
            "confidence": round(self.confidence, 4),
            "outcome": self.outcome,
            "evidence_ids": self.evidence_ids[:10],
            "timestamp": self.timestamp,
        }


class ReasoningTrace:
    """Append-only reasoning log with ring buffer and summary stats."""

    def __init__(self, *, max_entries: int = _MAX_TRACE_ENTRIES) -> None:
        self._entries: list[ReasoningStep] = []
        self._max_entries = max_entries
        self._lock = threading.RLock()
        self._step_counter = 0

    def append(
        self,
        phase: str,
        tool_name: str,
        reasoning: str,
        confidence: float,
        *,
        outcome: str = "",
        evidence_ids: list[str] | None = None,
    ) -> int:
        """Append a reasoning step. Returns the step number."""
        with self._lock:
            self._step_counter += 1
            step = ReasoningStep(
                step_number=self._step_counter,
                phase=phase,
                tool_name=tool_name,
                reasoning=reasoning,
                confidence=max(0.0, min(1.0, confidence)),
                outcome=outcome,
                evidence_ids=evidence_ids or [],
            )
            self._entries.append(step)

            # Ring buffer: evict oldest when over cap
            if len(self._entries) > self._max_entries:
                evict_count = len(self._entries) - self._max_entries
                self._entries = self._entries[evict_count:]
                _logger.debug(
                    "ReasoningTrace: evicted %d old entries", evict_count
                )

            return step.step_number

    def update_outcome(self, step_number: int, outcome: str) -> bool:
        """Update the outcome of a previously logged step."""
        with self._lock:
            for entry in reversed(self._entries):
                if entry.step_number == step_number:
                    entry.outcome = outcome
                    return True
        return False

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def total_steps(self) -> int:
        return self._step_counter

    def get_last(self, n: int = 10) -> list[ReasoningStep]:
        """Get the last N reasoning steps."""
        with self._lock:
            return list(self._entries[-n:])

    def get_by_phase(self, phase: str) -> list[ReasoningStep]:
        """Get all steps in a specific phase."""
        with self._lock:
            return [e for e in self._entries if e.phase == phase]

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics of the reasoning trace."""
        with self._lock:
            if not self._entries:
                return {"total_steps": 0, "phases": {}, "tools": {}, "outcomes": {}}

            phases = Counter(e.phase for e in self._entries)
            tools = Counter(e.tool_name for e in self._entries)
            outcomes = Counter(e.outcome for e in self._entries if e.outcome)
            confidences = [e.confidence for e in self._entries]

            return {
                "total_steps": self._step_counter,
                "entries_in_buffer": len(self._entries),
                "phases": dict(phases),
                "tools": dict(tools.most_common(15)),
                "outcomes": dict(outcomes),
                "avg_confidence": round(sum(confidences) / len(confidences), 4),
                "min_confidence": round(min(confidences), 4),
                "max_confidence": round(max(confidences), 4),
                "time_span_sec": round(
                    self._entries[-1].timestamp - self._entries[0].timestamp, 1
                ) if len(self._entries) > 1 else 0,
            }

    def export(self) -> list[dict[str, Any]]:
        """Export all entries as JSON-serializable dicts."""
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def detect_reasoning_loops(self, *, window: int = 10, threshold: int = 3) -> list[str]:
        """Detect if the agent is stuck in a reasoning loop.

        Returns list of tool names that appear >= threshold times
        in the last `window` steps.
        """
        with self._lock:
            recent = self._entries[-window:]
            if len(recent) < threshold:
                return []

            tool_counts = Counter(e.tool_name for e in recent)
            loops = [
                tool for tool, count in tool_counts.items()
                if count >= threshold
            ]
            if loops:
                _logger.warning(
                    "Reasoning loop detected: %s in last %d steps",
                    loops, window,
                )
            return loops

    def detect_confidence_collapse(self, *, window: int = 5, threshold: float = 0.3) -> bool:
        """Detect if confidence has collapsed (avg below threshold in recent window)."""
        with self._lock:
            recent = self._entries[-window:]
            if len(recent) < window:
                return False

            avg_conf = sum(e.confidence for e in recent) / len(recent)
            if avg_conf < threshold:
                _logger.warning(
                    "Confidence collapse: avg=%.3f in last %d steps",
                    avg_conf, window,
                )
                return True
            return False
