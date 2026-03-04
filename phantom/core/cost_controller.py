"""
Cost Controller (PHASE 4 — Security Control)

Tracks cumulative LLM token consumption and cost per scan.
Aborts execution when cost exceeds configurable thresholds.
Persists cost data in checkpoints for scan resume.

Prevents unbounded LLM spending from:
- Infinite agent loops
- Excessive memory compression calls
- Hallucination-driven reconnaissance spirals
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger(__name__)

# Default thresholds (can be overridden via config)
DEFAULT_MAX_COST_USD = 25.0  # M9 FIX: reduced from $50 to safer default
DEFAULT_MAX_INPUT_TOKENS = 5_000_000
DEFAULT_MAX_OUTPUT_TOKENS = 500_000
DEFAULT_WARNING_THRESHOLD = 0.8  # Warn at 80% of limit
DEFAULT_MAX_SINGLE_REQUEST_COST = 5.0  # PHT-021: Per-request ceiling
DEFAULT_MAX_COMPRESSION_CALLS = 50  # PHT-022: Prevent compression spirals


class CostLimitExceeded(Exception):
    """Raised when scan cost exceeds the configured limit."""

    def __init__(self, message: str, current_cost: float, limit: float):
        super().__init__(message)
        self.current_cost = current_cost
        self.limit = limit


@dataclass
class CostSnapshot:
    """Immutable snapshot of cost state for checkpointing."""

    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cached_tokens: int = 0
    total_cost_usd: float = 0.0
    total_requests: int = 0
    compression_calls: int = 0
    compression_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cached_tokens": self.total_cached_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_requests": self.total_requests,
            "compression_calls": self.compression_calls,
            "compression_cost_usd": round(self.compression_cost_usd, 4),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CostSnapshot:
        return cls(
            total_input_tokens=data.get("total_input_tokens", 0),
            total_output_tokens=data.get("total_output_tokens", 0),
            total_cached_tokens=data.get("total_cached_tokens", 0),
            total_cost_usd=data.get("total_cost_usd", 0.0),
            total_requests=data.get("total_requests", 0),
            compression_calls=data.get("compression_calls", 0),
            compression_cost_usd=data.get("compression_cost_usd", 0.0),
        )


class CostController:
    """Tracks and enforces LLM cost limits per scan.

    Thread-safe for concurrent agent access.
    """

    def __init__(
        self,
        max_cost_usd: float = DEFAULT_MAX_COST_USD,
        max_input_tokens: int = DEFAULT_MAX_INPUT_TOKENS,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        warning_threshold: float = DEFAULT_WARNING_THRESHOLD,
        max_single_request_cost: float = DEFAULT_MAX_SINGLE_REQUEST_COST,
        max_compression_calls: int = DEFAULT_MAX_COMPRESSION_CALLS,
    ):
        self.max_cost_usd = max_cost_usd
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.warning_threshold = warning_threshold
        self.max_single_request_cost = max_single_request_cost
        self.max_compression_calls = max_compression_calls

        self._lock = threading.Lock()
        self._state = CostSnapshot()
        self._warning_sent = False
        self._critical_warning_sent = False

    def record_usage(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_tokens: int = 0,
        cost_usd: float = 0.0,
        is_compression: bool = False,
    ) -> None:
        """Record token usage from an LLM call.

        Raises CostLimitExceeded if any limit is breached.

        PHT-044: All state mutations and limit checks are now inside the
        lock to prevent race conditions when multiple agents share the
        same cost controller.
        """
        with self._lock:
            # PHT-021: Per-request cost ceiling — reject anomalous single requests
            if cost_usd > self.max_single_request_cost:
                _logger.error(
                    "Single request cost $%.2f exceeds per-request ceiling $%.2f — rejecting",
                    cost_usd, self.max_single_request_cost,
                )
                raise CostLimitExceeded(
                    f"Single request cost ${cost_usd:.2f} exceeds ceiling ${self.max_single_request_cost:.2f}",
                    cost_usd,
                    self.max_single_request_cost,
                )

            # LOGIC-002 FIX: Check compression limit BEFORE recording any cost
            # to prevent accumulating cost for the call that exceeds the limit.
            if is_compression and self._state.compression_calls >= self.max_compression_calls:
                raise CostLimitExceeded(
                    f"Compression calls ({self._state.compression_calls}) reached limit ({self.max_compression_calls})",
                    self._state.total_cost_usd,
                    self.max_cost_usd,
                )

            self._state.total_input_tokens += input_tokens
            self._state.total_output_tokens += output_tokens
            self._state.total_cached_tokens += cached_tokens
            self._state.total_cost_usd += cost_usd
            self._state.total_requests += 1

            if is_compression:
                self._state.compression_calls += 1
                self._state.compression_cost_usd += cost_usd

            # LOGIC-001 FIX: _check_limits() now inside the lock to prevent
            # race condition where another thread could mutate state between
            # releasing the lock and checking limits.
            self._check_limits()

    def _check_limits(self) -> None:
        """Check if any cost/token limit has been exceeded."""
        state = self._state

        # Cost limit
        if state.total_cost_usd >= self.max_cost_usd:
            raise CostLimitExceeded(
                f"Scan cost ${state.total_cost_usd:.2f} exceeds limit ${self.max_cost_usd:.2f}",
                state.total_cost_usd,
                self.max_cost_usd,
            )

        # Token limits
        if state.total_input_tokens >= self.max_input_tokens:
            raise CostLimitExceeded(
                f"Input tokens {state.total_input_tokens:,} exceeds limit {self.max_input_tokens:,}",
                state.total_cost_usd,
                self.max_cost_usd,
            )

        if state.total_output_tokens >= self.max_output_tokens:
            raise CostLimitExceeded(
                f"Output tokens {state.total_output_tokens:,} exceeds limit {self.max_output_tokens:,}",
                state.total_cost_usd,
                self.max_cost_usd,
            )

        # Warnings
        cost_ratio = state.total_cost_usd / self.max_cost_usd if self.max_cost_usd > 0 else 0

        if cost_ratio >= 0.95 and not self._critical_warning_sent:
            self._critical_warning_sent = True
            _logger.warning(
                "CRITICAL: Scan cost at %.0f%% of limit ($%.2f / $%.2f). "
                "Scan will abort if limit is reached.",
                cost_ratio * 100,
                state.total_cost_usd,
                self.max_cost_usd,
            )

        elif cost_ratio >= self.warning_threshold and not self._warning_sent:
            self._warning_sent = True
            _logger.warning(
                "WARNING: Scan cost at %.0f%% of limit ($%.2f / $%.2f)",
                cost_ratio * 100,
                state.total_cost_usd,
                self.max_cost_usd,
            )

    def get_snapshot(self) -> CostSnapshot:
        """Get a snapshot of the current cost state."""
        with self._lock:
            return CostSnapshot(
                total_input_tokens=self._state.total_input_tokens,
                total_output_tokens=self._state.total_output_tokens,
                total_cached_tokens=self._state.total_cached_tokens,
                total_cost_usd=self._state.total_cost_usd,
                total_requests=self._state.total_requests,
                compression_calls=self._state.compression_calls,
                compression_cost_usd=self._state.compression_cost_usd,
            )

    def restore_from_checkpoint(self, data: dict[str, Any]) -> None:
        """Restore cost state from a checkpoint."""
        with self._lock:
            self._state = CostSnapshot.from_dict(data)
            _logger.info(
                "Cost controller restored: $%.2f spent, %d requests",
                self._state.total_cost_usd,
                self._state.total_requests,
            )

    def get_remaining_budget(self) -> dict[str, Any]:
        """Get remaining budget information."""
        with self._lock:
            state = self._state
            return {
                "remaining_cost_usd": round(self.max_cost_usd - state.total_cost_usd, 4),
                "remaining_input_tokens": self.max_input_tokens - state.total_input_tokens,
                "remaining_output_tokens": self.max_output_tokens - state.total_output_tokens,
                "usage_percentage": round(
                    (state.total_cost_usd / self.max_cost_usd * 100)
                    if self.max_cost_usd > 0 else 0, 1
                ),
            }

    def get_cost_summary(self) -> str:
        """Get a human-readable cost summary."""
        with self._lock:
            state = self._state
            return (
                f"Cost: ${state.total_cost_usd:.2f} / ${self.max_cost_usd:.2f} "
                f"({state.total_requests} requests, "
                f"{state.total_input_tokens:,} in + {state.total_output_tokens:,} out tokens, "
                f"{state.compression_calls} compressions)"
            )


# Global instance
_global_cost_controller: CostController | None = None


def get_cost_controller() -> CostController | None:
    return _global_cost_controller


def set_cost_controller(controller: CostController) -> None:
    global _global_cost_controller  # noqa: PLW0603
    _global_cost_controller = controller


def init_cost_controller(**kwargs: Any) -> CostController:
    """Initialize and set the global cost controller."""
    controller = CostController(**kwargs)
    set_cost_controller(controller)
    return controller
