"""
Event Bus (Architecture Improvement)

Typed async event bus for decoupling Phantom components.
Enables intelligence components to react independently to scan events
without tight coupling in the agent loop.

Event Types:
- ToolRequested: Tool invocation requested (pre-execution)
- ToolExecuted: Tool completed execution
- FindingCreated: New vulnerability finding discovered
- EvidenceAdded: Evidence added to registry
- PhaseTransition: Scan phase changed
- ConfidenceUpdated: Confidence score recalculated
- VerificationCompleted: Finding verification finished

Usage:
    bus = EventBus()
    bus.subscribe(ToolExecuted, my_handler)
    await bus.publish(ToolExecuted(tool_name="nmap", success=True))
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, TypeVar

_logger = logging.getLogger(__name__)

# Type for event handlers
T = TypeVar("T", bound="Event")
EventHandler = Callable[[Any], Coroutine[Any, Any, None] | None]


@dataclass(frozen=True)
class Event:
    """Base event class. All events must be immutable (frozen=True)."""
    
    timestamp: float = field(default_factory=time.monotonic)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize event to dictionary."""
        return {
            "event_type": self.__class__.__name__,
            "timestamp": self.timestamp,
            **{k: v for k, v in self.__dict__.items() if k != "timestamp"},
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ToolRequested(Event):
    """Emitted before a tool is executed."""
    tool_name: str = ""
    kwargs: dict = field(default_factory=dict, hash=False)
    phase: str = ""
    iteration: int = 0


@dataclass(frozen=True)
class ToolExecuted(Event):
    """Emitted after a tool completes execution."""
    tool_name: str = ""
    kwargs: dict = field(default_factory=dict, hash=False)
    result: Any = field(default=None, hash=False)
    duration_ms: float = 0.0
    success: bool = True
    error_message: str = ""


@dataclass(frozen=True)
class ToolBlocked(Event):
    """Emitted when a tool invocation is blocked by critic/scope."""
    tool_name: str = ""
    reason: str = ""
    blocker: str = ""  # "critic", "scope_validator", "circuit_breaker"


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FindingCreated(Event):
    """Emitted when a new vulnerability finding is discovered."""
    finding_id: str = ""
    severity: str = ""
    target: str = ""
    tool: str = ""
    description: str = ""
    confidence: float = 0.0


@dataclass(frozen=True)
class FindingUpdated(Event):
    """Emitted when a finding is modified."""
    finding_id: str = ""
    field_changed: str = ""
    old_value: Any = None
    new_value: Any = None


@dataclass(frozen=True)
class FindingVerified(Event):
    """Emitted when a finding passes verification."""
    finding_id: str = ""
    method: str = ""
    confidence_boost: float = 0.0


@dataclass(frozen=True)
class FindingRejected(Event):
    """Emitted when a finding fails verification (false positive)."""
    finding_id: str = ""
    reason: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# EVIDENCE EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class EvidenceAdded(Event):
    """Emitted when evidence is added to the registry."""
    evidence_id: str = ""
    finding_id: str = ""
    evidence_type: str = ""
    tool: str = ""
    confidence: float = 0.0


@dataclass(frozen=True)
class EvidenceInvalidated(Event):
    """Emitted when evidence is invalidated/expired."""
    evidence_id: str = ""
    reason: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# STATE MACHINE EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PhaseTransition(Event):
    """Emitted when the scan state machine changes phase."""
    from_phase: str = ""
    to_phase: str = ""
    reason: str = ""
    iteration: int = 0


@dataclass(frozen=True)
class ScanStarted(Event):
    """Emitted when a scan begins."""
    scan_id: str = ""
    targets: tuple[str, ...] = ()
    profile: str = ""


@dataclass(frozen=True)
class ScanCompleted(Event):
    """Emitted when a scan finishes."""
    scan_id: str = ""
    total_findings: int = 0
    verified_findings: int = 0
    duration_s: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIDENCE EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ConfidenceUpdated(Event):
    """Emitted when confidence score changes for a finding."""
    finding_id: str = ""
    old_confidence: float = 0.0
    new_confidence: float = 0.0
    reason: str = ""  # "evidence_added", "decay", "verification"


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICATION EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class VerificationRequested(Event):
    """Emitted when verification is requested for a finding."""
    finding_id: str = ""
    tier: str = ""  # "quick", "standard", "deep"


@dataclass(frozen=True)
class VerificationCompleted(Event):
    """Emitted when verification completes."""
    finding_id: str = ""
    status: str = ""  # "verified", "not_confirmed", "false_positive"
    method: str = ""
    confidence_adjustment: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class GraphNodeAdded(Event):
    """Emitted when a node is added to the attack graph."""
    node_id: str = ""
    node_type: str = ""
    label: str = ""


@dataclass(frozen=True)
class GraphEdgeAdded(Event):
    """Emitted when an edge is added to the attack graph."""
    source_id: str = ""
    target_id: str = ""
    edge_type: str = ""


@dataclass(frozen=True)
class AttackChainDiscovered(Event):
    """Emitted when a new attack chain is inferred."""
    chain_id: str = ""
    nodes: tuple[str, ...] = ()
    risk_score: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# EVENT BUS IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

class EventBus:
    """
    Typed async event bus with ordered delivery.
    
    Features:
    - Type-safe subscriptions (subscribe to specific event types)
    - Async handler support (awaits coroutine handlers)
    - Event history (last N events stored for debugging)
    - Error isolation (handler exceptions don't crash the bus)
    - Storm detection (H-EB-001): alerts when event rate exceeds threshold
    """
    
    # Storm detection: max events per second before triggering alert
    _STORM_THRESHOLD = 100
    _STORM_WINDOW_SEC = 5.0
    
    def __init__(self, max_history: int = 1000) -> None:
        self._lock = threading.Lock()  # HIGH-17 FIX: Thread safety
        self._handlers: dict[type, list[EventHandler]] = defaultdict(list)
        self._history: list[Event] = []
        self._max_history = max_history
        self._stats: dict[str, int] = defaultdict(int)
        # H-EB-001: Storm detection state
        self._storm_window: list[float] = []
        self._storm_active = False
        self._storm_count = 0
    
    def subscribe(
        self,
        event_type: type[T],
        handler: Callable[[T], Coroutine[Any, Any, None] | None],
    ) -> Callable[[], None]:
        """
        Register a handler for a specific event type.
        
        Args:
            event_type: The event class to subscribe to
            handler: Callback function (sync or async)
            
        Returns:
            Unsubscribe function
        """
        with self._lock:
            self._handlers[event_type].append(handler)
        
        def unsubscribe() -> None:
            with self._lock:
                self._handlers[event_type].remove(handler)
        
        return unsubscribe
    
    async def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribed handlers.
        
        Handlers are called in subscription order.
        Exceptions in handlers are logged but don't stop delivery.
        H-EB-001: Storm detection drops events if rate exceeds threshold.
        """
        # H-EB-001: Storm detection
        now = time.monotonic()
        with self._lock:
            # Prune old timestamps from storm window
            cutoff = now - self._STORM_WINDOW_SEC
            self._storm_window = [t for t in self._storm_window if t > cutoff]
            self._storm_window.append(now)
            
            rate = len(self._storm_window) / self._STORM_WINDOW_SEC
            if rate > self._STORM_THRESHOLD:
                if not self._storm_active:
                    self._storm_active = True
                    _logger.warning(
                        "EVENT STORM DETECTED: %.1f events/sec (threshold=%d). "
                        "Dropping non-critical events.",
                        rate, self._STORM_THRESHOLD,
                    )
                self._storm_count += 1
                # During storm, only deliver critical event types
                event_name = event.__class__.__name__
                critical_events = {"ScanCompleted", "PhaseTransition", "ToolBlocked"}
                if event_name not in critical_events:
                    self._stats["storm_dropped"] = self._stats.get("storm_dropped", 0) + 1
                    return
            elif self._storm_active:
                self._storm_active = False
                _logger.info(
                    "Event storm subsided. Dropped %d events during storm.",
                    self._storm_count,
                )
                self._storm_count = 0

        # Record in history
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            
            # Track stats
            event_name = event.__class__.__name__
            self._stats[event_name] += 1
            self._stats["total"] += 1
            
            # Copy handlers to avoid holding lock during execution
            handlers = list(self._handlers.get(type(event), []))
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                _logger.exception(
                    "Event handler %s failed for %s",
                    getattr(handler, "__name__", str(handler)),
                    event_name,
                )
    
    def publish_sync(self, event: Event) -> None:
        """
        Synchronous publish for use in non-async contexts.
        
        Creates an event loop if needed. Prefer async publish() when possible.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish(event))
        except RuntimeError:
            try:
                asyncio.run(self.publish(event))
            except Exception:
                _logger.exception("publish_sync failed")
    
    def get_history(
        self,
        event_type: type[T] | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """
        Get recent events, optionally filtered by type.
        
        Args:
            event_type: Filter to specific event type (None = all)
            limit: Maximum number of events to return
            
        Returns:
            List of events, most recent last
        """
        if event_type is None:
            return self._history[-limit:]
        return [e for e in self._history if isinstance(e, event_type)][-limit:]
    
    def get_stats(self) -> dict[str, int]:
        """Get event statistics."""
        return dict(self._stats)
    
    def handler_count(self, event_type: type | None = None) -> int:
        """Get number of subscribed handlers."""
        if event_type is None:
            return sum(len(h) for h in self._handlers.values())
        return len(self._handlers.get(event_type, []))
    
    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()
    
    def reset(self) -> None:
        """Reset all handlers and history."""
        self._handlers.clear()
        self._history.clear()
        self._stats.clear()


# Global event bus instance
_global_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _global_bus
    if _global_bus is None:
        _global_bus = EventBus()
    return _global_bus


def reset_event_bus() -> None:
    """Reset the global event bus (for testing)."""
    global _global_bus
    _global_bus = None
