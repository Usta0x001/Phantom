"""
Observability Metrics Module (Architecture Improvement)

Provides structured metrics collection for Phantom operations.
Prometheus-compatible interface for monitoring and alerting.

Metric Types:
- Counter: Monotonically increasing values (tool_calls, errors)
- Histogram: Distribution of values (latencies, sizes)
- Gauge: Point-in-time values (active_scans, memory_usage)

Usage:
    from phantom.core.metrics import metrics
    
    metrics.tool_calls.inc()
    metrics.tool_duration.observe(1.5)
    with metrics.timer(metrics.llm_latency):
        await llm.complete(...)
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Sequence

_logger = logging.getLogger(__name__)


@dataclass
class Counter:
    """Monotonically increasing counter metric."""
    
    name: str
    description: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    _value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def inc(self, amount: float = 1.0) -> None:
        """Increment the counter."""
        if amount < 0:
            raise ValueError("Counter can only be incremented")
        with self._lock:
            self._value += amount
    
    @property
    def value(self) -> float:
        """Get current counter value."""
        return self._value
    
    def reset(self) -> None:
        """Reset counter (for testing only)."""
        with self._lock:
            self._value = 0.0


@dataclass
class Gauge:
    """Point-in-time value metric."""
    
    name: str
    description: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    _value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def set(self, value: float) -> None:
        """Set gauge value."""
        with self._lock:
            self._value = value
    
    def inc(self, amount: float = 1.0) -> None:
        """Increment gauge."""
        with self._lock:
            self._value += amount
    
    def dec(self, amount: float = 1.0) -> None:
        """Decrement gauge."""
        with self._lock:
            self._value -= amount
    
    @property
    def value(self) -> float:
        """Get current gauge value."""
        return self._value


@dataclass
class Histogram:
    """
    Distribution metric with configurable buckets.
    
    Tracks count, sum, and distribution across buckets for
    computing percentiles (p50, p95, p99).
    """
    
    name: str
    description: str = ""
    # Default buckets optimized for latencies (seconds)
    buckets: Sequence[float] = (
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float("inf")
    )
    labels: dict[str, str] = field(default_factory=dict)
    _max_samples: int = 10000
    _values: deque = field(default_factory=lambda: deque(maxlen=10000))
    _count: int = 0
    _bucket_counts: dict[float, int] = field(default_factory=dict)
    _sum: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def __post_init__(self) -> None:
        """Initialize bucket counts."""
        for bucket in self.buckets:
            self._bucket_counts[bucket] = 0
    
    def observe(self, value: float) -> None:
        """Record an observation."""
        with self._lock:
            self._values.append(value)
            self._count += 1
            self._sum += value
            # Increment all buckets >= value
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
    
    @property
    def count(self) -> int:
        """Total number of observations."""
        return self._count
    
    @property
    def sum(self) -> float:
        """Sum of all observations."""
        with self._lock:
            return self._sum
    
    @property
    def mean(self) -> float:
        """Mean of observations."""
        with self._lock:
            if self._count == 0:
                return 0.0
            return self._sum / self._count
    
    def percentile(self, p: float) -> float:
        """
        Calculate percentile (0-100).
        
        Args:
            p: Percentile value (e.g., 50, 95, 99)
            
        Returns:
            Value at the given percentile
        """
        if not self._values:
            return 0.0
        with self._lock:
            sorted_vals = sorted(self._values)
            idx = int(len(sorted_vals) * (p / 100.0))
            idx = min(idx, len(sorted_vals) - 1)
            return sorted_vals[idx]
    
    @property
    def p50(self) -> float:
        """Median (50th percentile)."""
        return self.percentile(50)
    
    @property
    def p95(self) -> float:
        """95th percentile."""
        return self.percentile(95)
    
    @property
    def p99(self) -> float:
        """99th percentile."""
        return self.percentile(99)
    
    @property
    def max(self) -> float:
        """Maximum observation."""
        with self._lock:
            return max(self._values) if self._values else 0.0
    
    @property
    def min(self) -> float:
        """Minimum observation."""
        with self._lock:
            return min(self._values) if self._values else 0.0
    
    def reset(self) -> None:
        """Reset histogram (for testing)."""
        with self._lock:
            self._values.clear()
            self._count = 0
            self._sum = 0.0
            for bucket in self.buckets:
                self._bucket_counts[bucket] = 0


class MetricsRegistry:
    """
    Central registry for all Phantom metrics.
    
    Provides pre-defined metrics for common operations and
    methods for creating custom metrics.
    """
    
    def __init__(self) -> None:
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._histograms: dict[str, Histogram] = {}
        self._init_default_metrics()
    
    def _init_default_metrics(self) -> None:
        """Initialize default metrics."""
        
        # ═══════════════════════════════════════════════════════════════════
        # TOOL METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.tool_calls = self._counter(
            "phantom_tool_calls_total",
            "Total number of tool executions"
        )
        self.tool_errors = self._counter(
            "phantom_tool_errors_total",
            "Total number of tool execution errors"
        )
        self.tool_blocked = self._counter(
            "phantom_tool_blocked_total",
            "Total number of tool calls blocked by critic/scope"
        )
        self.tool_duration = self._histogram(
            "phantom_tool_duration_seconds",
            "Tool execution duration in seconds"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # LLM METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.llm_calls = self._counter(
            "phantom_llm_calls_total",
            "Total number of LLM API calls"
        )
        self.llm_errors = self._counter(
            "phantom_llm_errors_total",
            "Total number of LLM API errors"
        )
        self.llm_tokens_input = self._counter(
            "phantom_llm_tokens_input_total",
            "Total input tokens consumed"
        )
        self.llm_tokens_output = self._counter(
            "phantom_llm_tokens_output_total",
            "Total output tokens generated"
        )
        self.llm_cost_usd = self._counter(
            "phantom_llm_cost_usd_total",
            "Total LLM cost in USD"
        )
        self.llm_latency = self._histogram(
            "phantom_llm_latency_seconds",
            "LLM API latency in seconds"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # FINDING METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.findings_total = self._counter(
            "phantom_findings_total",
            "Total findings discovered"
        )
        self.findings_verified = self._counter(
            "phantom_findings_verified_total",
            "Findings successfully verified"
        )
        self.findings_false_positive = self._counter(
            "phantom_findings_false_positive_total",
            "Findings identified as false positives"
        )
        self.findings_by_severity = self._gauge(
            "phantom_findings_by_severity",
            "Current count of findings by severity"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # GRAPH METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.graph_nodes = self._gauge(
            "phantom_graph_nodes_total",
            "Current number of nodes in attack graph"
        )
        self.graph_edges = self._gauge(
            "phantom_graph_edges_total",
            "Current number of edges in attack graph"
        )
        self.attack_chains = self._counter(
            "phantom_attack_chains_total",
            "Total attack chains discovered"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # SCAN METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.scans_started = self._counter(
            "phantom_scans_started_total",
            "Total scans started"
        )
        self.scans_completed = self._counter(
            "phantom_scans_completed_total",
            "Total scans completed successfully"
        )
        self.scans_failed = self._counter(
            "phantom_scans_failed_total",
            "Total scans failed"
        )
        self.active_scans = self._gauge(
            "phantom_active_scans",
            "Currently running scans"
        )
        self.scan_duration = self._histogram(
            "phantom_scan_duration_seconds",
            "Scan duration in seconds",
            buckets=(30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, float("inf")),
        )
        self.iterations_per_scan = self._histogram(
            "phantom_iterations_per_scan",
            "Iterations per scan",
            buckets=(5, 10, 25, 50, 100, 200, 500, 1000, float("inf")),
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # RESOURCE METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.memory_usage_bytes = self._gauge(
            "phantom_memory_usage_bytes",
            "Current memory usage in bytes"
        )
        self.checkpoint_size_bytes = self._histogram(
            "phantom_checkpoint_size_bytes",
            "Checkpoint file size in bytes",
            buckets=(1024, 10240, 102400, 1048576, 10485760, float("inf")),
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # SECURITY METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.scope_violations = self._counter(
            "phantom_scope_violations_total",
            "Total scope violation attempts blocked"
        )
        self.injection_attempts = self._counter(
            "phantom_injection_attempts_total",
            "Prompt injection attempts detected"
        )
        self.circuit_breaker_trips = self._counter(
            "phantom_circuit_breaker_trips_total",
            "Circuit breaker trip events"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # FIREWALL METRICS (H-TF-004)
        # ═══════════════════════════════════════════════════════════════════
        self.firewall_checks = self._counter(
            "phantom_firewall_checks_total",
            "Total tool firewall validation checks"
        )
        self.firewall_blocks = self._counter(
            "phantom_firewall_blocks_total",
            "Total tool invocations blocked by firewall"
        )
        self.firewall_schema_violations = self._counter(
            "phantom_firewall_schema_violations_total",
            "Tool schema validation failures"
        )
        self.firewall_dns_rebinding_blocks = self._counter(
            "phantom_firewall_dns_rebinding_blocks_total",
            "DNS rebinding / SSRF attempts blocked"
        )
        self.firewall_prompt_injection_blocks = self._counter(
            "phantom_firewall_prompt_injection_blocks_total",
            "Prompt injection in tool args detected"
        )
        self.firewall_phase_violations = self._counter(
            "phantom_firewall_phase_violations_total",
            "Phase-ordering violations blocked"
        )
        self.firewall_budget_exhaustions = self._counter(
            "phantom_firewall_budget_exhaustions_total",
            "Tool budget exhaustion events"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # INVARIANT METRICS (H-INV-001)
        # ═══════════════════════════════════════════════════════════════════
        self.invariant_checks = self._counter(
            "phantom_invariant_checks_total",
            "Total invariant validation checks"
        )
        self.invariant_violations = self._counter(
            "phantom_invariant_violations_total",
            "Invariant violations detected"
        )
        self.graph_integrity_checks = self._counter(
            "phantom_graph_integrity_checks_total",
            "Graph integrity validator runs"
        )
        self.graph_integrity_failures = self._counter(
            "phantom_graph_integrity_failures_total",
            "Graph integrity validation failures"
        )
        self.monotonicity_ceiling_enforcements = self._counter(
            "phantom_monotonicity_ceiling_enforcements_total",
            "Confidence monotonicity ceiling enforcement events"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # INTELLIGENCE METRICS (H-IL-001)
        # ═══════════════════════════════════════════════════════════════════
        self.confidence_updates = self._counter(
            "phantom_confidence_updates_total",
            "Confidence engine update events"
        )
        self.negative_evidence_added = self._counter(
            "phantom_negative_evidence_total",
            "Negative (contradicting) evidence entries"
        )
        self.hallucination_detections = self._counter(
            "phantom_hallucination_detections_total",
            "Hallucination patterns detected"
        )
        self.reasoning_steps = self._counter(
            "phantom_reasoning_steps_total",
            "Total reasoning trace steps recorded"
        )
        self.reasoning_loops_detected = self._counter(
            "phantom_reasoning_loops_total",
            "Reasoning loop detections"
        )
        self.confidence_collapses = self._counter(
            "phantom_confidence_collapses_total",
            "Confidence collapse events"
        )
        self.hypothesis_stale_reaped = self._counter(
            "phantom_hypothesis_stale_reaped_total",
            "Stale hypotheses reaped"
        )
        self.avg_confidence = self._gauge(
            "phantom_avg_confidence",
            "Average confidence across tracked vulns"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # PERSISTENCE METRICS (H-PS-001)
        # ═══════════════════════════════════════════════════════════════════
        self.wal_begins = self._counter(
            "phantom_wal_begins_total",
            "WAL transaction begin events"
        )
        self.wal_commits = self._counter(
            "phantom_wal_commits_total",
            "WAL transaction commit events"
        )
        self.wal_rollbacks = self._counter(
            "phantom_wal_rollbacks_total",
            "WAL transaction rollback events"
        )
        self.wal_recovered = self._counter(
            "phantom_wal_recovered_total",
            "WAL crash recovery events"
        )
        self.checkpoint_writes = self._counter(
            "phantom_checkpoint_writes_total",
            "Checkpoint write operations"
        )
        self.checkpoint_failures = self._counter(
            "phantom_checkpoint_failures_total",
            "Checkpoint write failures"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # EVENT BUS METRICS (H-EB-001)
        # ═══════════════════════════════════════════════════════════════════
        self.events_published = self._counter(
            "phantom_events_published_total",
            "Total events published on event bus"
        )
        self.events_storm_dropped = self._counter(
            "phantom_events_storm_dropped_total",
            "Events dropped during storm detection"
        )
        self.event_handler_errors = self._counter(
            "phantom_event_handler_errors_total",
            "Event handler execution errors"
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # DEGRADATION METRICS (H-DG-001)
        # ═══════════════════════════════════════════════════════════════════
        self.degradation_transitions = self._counter(
            "phantom_degradation_transitions_total",
            "Degradation mode transitions"
        )
        self.current_degradation_mode = self._gauge(
            "phantom_degradation_mode",
            "Current degradation mode (0=FULL, 1=REDUCED, 2=MINIMAL)"
        )
    
    def _counter(self, name: str, description: str = "") -> Counter:
        """Create and register a counter."""
        counter = Counter(name=name, description=description)
        self._counters[name] = counter
        return counter
    
    def _gauge(self, name: str, description: str = "") -> Gauge:
        """Create and register a gauge."""
        gauge = Gauge(name=name, description=description)
        self._gauges[name] = gauge
        return gauge
    
    def _histogram(
        self,
        name: str,
        description: str = "",
        buckets: Sequence[float] | None = None,
    ) -> Histogram:
        """Create and register a histogram."""
        histogram = Histogram(
            name=name,
            description=description,
            buckets=buckets or Histogram.buckets,
        )
        self._histograms[name] = histogram
        return histogram
    
    @contextmanager
    def timer(self, histogram: Histogram) -> Generator[None, None, None]:
        """Context manager for timing operations."""
        start = time.monotonic()
        try:
            yield
        finally:
            histogram.observe(time.monotonic() - start)
    
    def snapshot(self) -> dict[str, Any]:
        """
        Get current values of all metrics as a snapshot.
        
        Returns:
            Dictionary with all metric values
        """
        snapshot: dict[str, Any] = {
            "timestamp": time.time(),
            "counters": {},
            "gauges": {},
            "histograms": {},
        }
        
        for name, counter in self._counters.items():
            snapshot["counters"][name] = counter.value
        
        for name, gauge in self._gauges.items():
            snapshot["gauges"][name] = gauge.value
        
        for name, histogram in self._histograms.items():
            snapshot["histograms"][name] = {
                "count": histogram.count,
                "sum": histogram.sum,
                "mean": histogram.mean,
                "p50": histogram.p50,
                "p95": histogram.p95,
                "p99": histogram.p99,
                "max": histogram.max,
            }
        
        return snapshot
    
    def prometheus_format(self) -> str:
        """
        Export metrics in Prometheus text format.
        
        Returns:
            Prometheus-compatible text output
        """
        lines: list[str] = []
        
        # Counters
        for name, counter in self._counters.items():
            if counter.description:
                lines.append(f"# HELP {name} {counter.description}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {counter.value}")
        
        # Gauges
        for name, gauge in self._gauges.items():
            if gauge.description:
                lines.append(f"# HELP {name} {gauge.description}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {gauge.value}")
        
        # Histograms
        for name, histogram in self._histograms.items():
            if histogram.description:
                lines.append(f"# HELP {name} {histogram.description}")
            lines.append(f"# TYPE {name} histogram")
            for bucket, count in sorted(histogram._bucket_counts.items()):
                le = "+Inf" if math.isinf(bucket) else str(bucket)
                lines.append(f'{name}_bucket{{le="{le}"}} {count}')
            lines.append(f"{name}_sum {histogram.sum}")
            lines.append(f"{name}_count {histogram.count}")
        
        return "\n".join(lines)
    
    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        for counter in self._counters.values():
            counter.reset()
        for gauge in self._gauges.values():
            gauge.set(0)
        for histogram in self._histograms.values():
            histogram.reset()


# Global metrics instance
metrics = MetricsRegistry()
