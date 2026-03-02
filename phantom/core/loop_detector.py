"""
Loop Detector (PHASE 4 — Security Control)

Detects when agents enter repetitive reasoning loops:
1. Repeated identical tool calls
2. Repeated identical LLM responses
3. Cyclic tool-call patterns
4. Stagnant progress (no new findings over N iterations)

Triggers safe termination when loops are detected.
"""

from __future__ import annotations

import hashlib
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_WINDOW_SIZE = 20         # Track last N tool calls
DEFAULT_REPEAT_THRESHOLD = 3    # Block after N identical calls
DEFAULT_RESPONSE_WINDOW = 10    # Track last N LLM responses
DEFAULT_RESPONSE_THRESHOLD = 3  # Block after N similar responses
DEFAULT_STAGNATION_WINDOW = 15  # Check for progress over N iterations (reduced from 30)


@dataclass
class LoopDetectionResult:
    """Result of a loop detection check."""
    is_loop: bool = False
    loop_type: str = ""       # "tool_repeat", "response_repeat", "stagnation", "cycle"
    details: str = ""
    confidence: float = 0.0   # 0.0 to 1.0


class LoopDetector:
    """Detects and breaks agent reasoning loops.

    Maintains a sliding window of recent tool calls and LLM responses
    to detect repetitive patterns.
    """

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        repeat_threshold: int = DEFAULT_REPEAT_THRESHOLD,
        response_window: int = DEFAULT_RESPONSE_WINDOW,
        response_threshold: int = DEFAULT_RESPONSE_THRESHOLD,
        stagnation_window: int = DEFAULT_STAGNATION_WINDOW,
    ):
        self.window_size = window_size
        self.repeat_threshold = repeat_threshold
        self.response_window = response_window
        self.response_threshold = response_threshold
        self.stagnation_window = stagnation_window

        self._tool_history: deque[str] = deque(maxlen=window_size)
        self._response_hashes: deque[str] = deque(maxlen=response_window)
        self._findings_count_history: deque[int] = deque(maxlen=stagnation_window)
        self._total_loops_detected = 0

    def record_tool_call(self, tool_name: str, args: dict[str, Any]) -> LoopDetectionResult:
        """Record a tool call and check for loops.

        Returns a LoopDetectionResult indicating whether a loop was detected.
        """
        # Create a normalized fingerprint of this tool call
        fingerprint = self._tool_fingerprint(tool_name, args)
        self._tool_history.append(fingerprint)

        # Check for repeated identical calls
        repeat_result = self._check_tool_repeat(fingerprint)
        if repeat_result.is_loop:
            self._total_loops_detected += 1
            return repeat_result

        # Check for cyclic patterns (A→B→A→B)
        cycle_result = self._check_cycle()
        if cycle_result.is_loop:
            self._total_loops_detected += 1
            return cycle_result

        return LoopDetectionResult()

    def record_response(self, response_content: str) -> LoopDetectionResult:
        """Record an LLM response and check for repetition."""
        # Hash the response for efficient comparison
        response_hash = hashlib.md5(
            response_content.strip()[:2000].encode()
        ).hexdigest()[:12]

        self._response_hashes.append(response_hash)

        # Check for repeated responses
        recent = list(self._response_hashes)
        count = recent.count(response_hash)

        if count >= self.response_threshold:
            self._total_loops_detected += 1
            return LoopDetectionResult(
                is_loop=True,
                loop_type="response_repeat",
                details=f"LLM produced the same response {count}x in last "
                        f"{len(recent)} responses",
                confidence=min(1.0, count / (self.response_threshold + 1)),
            )

        return LoopDetectionResult()

    def record_findings_count(self, count: int) -> LoopDetectionResult:
        """Record current findings count and check for stagnation."""
        self._findings_count_history.append(count)

        if len(self._findings_count_history) < self.stagnation_window:
            return LoopDetectionResult()

        # Check if findings count hasn't changed
        history = list(self._findings_count_history)
        if len(set(history[-self.stagnation_window:])) == 1:
            return LoopDetectionResult(
                is_loop=True,
                loop_type="stagnation",
                details=f"No new findings in {self.stagnation_window} iterations "
                        f"(stuck at {count})",
                confidence=0.7,
            )

        return LoopDetectionResult()

    def _tool_fingerprint(self, tool_name: str, args: dict[str, Any]) -> str:
        """Create a normalized fingerprint for a tool call."""
        # Sort args for consistent hashing
        sorted_args = sorted(
            (k, str(v)[:200]) for k, v in args.items()
            if k not in ("timeout", "timestamp")
        )
        raw = f"{tool_name}:{sorted_args}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def _check_tool_repeat(self, fingerprint: str) -> LoopDetectionResult:
        """Check if the same tool call has been made too many times recently."""
        recent = list(self._tool_history)
        count = recent.count(fingerprint)

        if count >= self.repeat_threshold:
            return LoopDetectionResult(
                is_loop=True,
                loop_type="tool_repeat",
                details=f"Identical tool call made {count}x in last "
                        f"{len(recent)} calls",
                confidence=min(1.0, count / (self.repeat_threshold + 2)),
            )

        return LoopDetectionResult()

    def _check_cycle(self) -> LoopDetectionResult:
        """Detect cyclic patterns (A→B→A→B or A→B→C→A→B→C)."""
        history = list(self._tool_history)
        if len(history) < 4:
            return LoopDetectionResult()

        # Check for 2-element cycles
        for cycle_len in (2, 3, 4):
            if len(history) < cycle_len * 2:
                continue
            pattern = history[-cycle_len:]
            prev_pattern = history[-(cycle_len * 2):-cycle_len]
            if pattern == prev_pattern:
                # Verify it repeats at least once more
                if len(history) >= cycle_len * 3:
                    prev_prev = history[-(cycle_len * 3):-(cycle_len * 2)]
                    if prev_prev == pattern:
                        return LoopDetectionResult(
                            is_loop=True,
                            loop_type="cycle",
                            details=f"Detected {cycle_len}-element cycle "
                                    f"repeating 3+ times",
                            confidence=0.9,
                        )

        return LoopDetectionResult()

    def get_stats(self) -> dict[str, Any]:
        """Get loop detection statistics."""
        return {
            "total_loops_detected": self._total_loops_detected,
            "tool_history_size": len(self._tool_history),
            "response_history_size": len(self._response_hashes),
        }

    def reset(self) -> None:
        """Reset all detection state."""
        self._tool_history.clear()
        self._response_hashes.clear()
        self._findings_count_history.clear()
        self._total_loops_detected = 0


# ── Module-level singleton ──────────────────────────────────────────
_global_detector: LoopDetector | None = None


def init_global_detector(**kwargs: Any) -> LoopDetector:
    """Create (or re-create) the module-level LoopDetector singleton."""
    global _global_detector  # noqa: PLW0603
    _global_detector = LoopDetector(**kwargs)
    return _global_detector


def get_global_detector() -> LoopDetector | None:
    """Return the global detector, or None if not yet initialized."""
    return _global_detector
