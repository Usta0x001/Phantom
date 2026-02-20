"""
Priority Queue

Priority-based queuing for vulnerabilities and scan tasks.
Ensures critical findings are verified first and high-value targets are scanned first.
"""

import heapq
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, Generic, TypeVar

from phantom.models.vulnerability import Vulnerability, VulnerabilitySeverity
from phantom.models.scan import ScanPhase


logger = logging.getLogger(__name__)


class Priority(IntEnum):
    """Priority levels (lower number = higher priority)."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5
    BACKGROUND = 10


# Mapping from severity to priority
SEVERITY_TO_PRIORITY: dict[VulnerabilitySeverity, Priority] = {
    VulnerabilitySeverity.CRITICAL: Priority.CRITICAL,
    VulnerabilitySeverity.HIGH: Priority.HIGH,
    VulnerabilitySeverity.MEDIUM: Priority.MEDIUM,
    VulnerabilitySeverity.LOW: Priority.LOW,
    VulnerabilitySeverity.INFO: Priority.INFO,
}


T = TypeVar("T")


@dataclass(order=True)
class PriorityItem(Generic[T]):
    """Wrapper for priority queue items."""
    priority: int
    timestamp: float = field(compare=True)  # FIFO within same priority
    item: T = field(compare=False)


class VulnerabilityPriorityQueue:
    """
    Priority queue for vulnerabilities.
    
    Orders vulnerabilities by severity for verification:
    - Critical first (SQLi, RCE)
    - High next (XSS, SSRF)
    - Medium/Low/Info last
    
    Within same priority, FIFO ordering.
    """
    
    def __init__(self):
        self._heap: list[PriorityItem[Vulnerability]] = []
        self._counter = 0
        self._seen_ids: set[str] = set()
    
    def push(self, vuln: Vulnerability) -> bool:
        """
        Add vulnerability to queue.
        
        Returns True if added, False if duplicate.
        """
        if vuln.id in self._seen_ids:
            return False
        
        priority = SEVERITY_TO_PRIORITY.get(vuln.severity, Priority.MEDIUM)
        
        # Boost priority for certain vulnerability classes
        if vuln.vulnerability_class in {"sqli", "rce", "ssti"}:
            priority = min(priority, Priority.HIGH)
        
        item = PriorityItem(
            priority=priority.value,
            timestamp=self._counter,
            item=vuln,
        )
        
        heapq.heappush(self._heap, item)
        self._seen_ids.add(vuln.id)
        self._counter += 1
        
        logger.debug(f"Queued {vuln.id} with priority {priority.name}")
        return True
    
    def pop(self) -> Vulnerability | None:
        """Remove and return highest priority vulnerability."""
        if not self._heap:
            return None
        
        item = heapq.heappop(self._heap)
        return item.item
    
    def peek(self) -> Vulnerability | None:
        """View highest priority without removing."""
        if not self._heap:
            return None
        return self._heap[0].item
    
    def push_batch(self, vulns: list[Vulnerability]) -> int:
        """Add multiple vulnerabilities. Returns count added."""
        return sum(1 for v in vulns if self.push(v))
    
    def pop_batch(self, count: int) -> list[Vulnerability]:
        """Pop up to count vulnerabilities."""
        result = []
        for _ in range(count):
            item = self.pop()
            if item is None:
                break
            result.append(item)
        return result
    
    def __len__(self) -> int:
        return len(self._heap)
    
    def __bool__(self) -> bool:
        return bool(self._heap)
    
    def stats(self) -> dict[str, int]:
        """Get queue statistics."""
        counts = {p.name: 0 for p in Priority}
        for item in self._heap:
            for p in Priority:
                if item.priority == p.value:
                    counts[p.name] += 1
                    break
        return counts


@dataclass
class ScanTask:
    """A single scan task."""
    task_id: str
    target: str
    task_type: str  # "subdomain", "port_scan", "vuln_scan", "fuzz", "verify"
    priority: Priority
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    dependencies: list[str] = field(default_factory=list)  # Task IDs that must complete first


class ScanPriorityQueue:
    """
    Priority queue for scan tasks.
    
    Orders scanning activities:
    1. Active exploitation verification (highest)
    2. Critical vulnerability scanning
    3. High-value target enumeration
    4. Background reconnaissance (lowest)
    
    Supports task dependencies (e.g., port scan before vuln scan).
    """
    
    def __init__(self):
        self._heap: list[PriorityItem[ScanTask]] = []
        self._counter = 0
        self._completed: set[str] = set()
        self._tasks: dict[str, ScanTask] = {}
    
    def push(self, task: ScanTask) -> None:
        """Add task to queue."""
        item = PriorityItem(
            priority=task.priority.value,
            timestamp=self._counter,
            item=task,
        )
        heapq.heappush(self._heap, item)
        self._tasks[task.task_id] = task
        self._counter += 1
    
    def pop(self) -> ScanTask | None:
        """Get highest priority task with satisfied dependencies."""
        if not self._heap:
            return None
        
        # Find first task with satisfied dependencies
        skipped = []
        result = None
        
        while self._heap:
            item = heapq.heappop(self._heap)
            task = item.item
            
            if self._dependencies_satisfied(task):
                result = task
                break
            else:
                skipped.append(item)
        
        # Re-add skipped tasks
        for item in skipped:
            heapq.heappush(self._heap, item)
        
        return result
    
    def _dependencies_satisfied(self, task: ScanTask) -> bool:
        """Check if all dependencies are completed."""
        return all(dep in self._completed for dep in task.dependencies)
    
    def mark_completed(self, task_id: str) -> None:
        """Mark a task as completed."""
        self._completed.add(task_id)
    
    def create_recon_tasks(self, target: str) -> list[ScanTask]:
        """Create standard recon task sequence."""
        tasks = []
        
        # Subdomain enumeration (high priority for web targets)
        tasks.append(ScanTask(
            task_id=f"subdomain_{target}",
            target=target,
            task_type="subdomain",
            priority=Priority.HIGH,
        ))
        
        # Port scan (depends on subdomain)
        tasks.append(ScanTask(
            task_id=f"portscan_{target}",
            target=target,
            task_type="port_scan",
            priority=Priority.HIGH,
            dependencies=[f"subdomain_{target}"],
        ))
        
        # Technology detection (depends on port scan)
        tasks.append(ScanTask(
            task_id=f"techdetect_{target}",
            target=target,
            task_type="tech_detect",
            priority=Priority.MEDIUM,
            dependencies=[f"portscan_{target}"],
        ))
        
        # Vulnerability scan (depends on tech detection)
        tasks.append(ScanTask(
            task_id=f"vulnscan_{target}",
            target=target,
            task_type="vuln_scan",
            priority=Priority.HIGH,
            dependencies=[f"techdetect_{target}"],
        ))
        
        # Directory fuzzing (can run in parallel with vuln scan)
        tasks.append(ScanTask(
            task_id=f"dirfuzz_{target}",
            target=target,
            task_type="fuzz_directory",
            priority=Priority.MEDIUM,
            dependencies=[f"portscan_{target}"],
        ))
        
        for task in tasks:
            self.push(task)
        
        return tasks
    
    def create_verification_task(self, vuln_id: str, target: str) -> ScanTask:
        """Create high-priority verification task."""
        task = ScanTask(
            task_id=f"verify_{vuln_id}",
            target=target,
            task_type="verify",
            priority=Priority.CRITICAL,
            parameters={"vulnerability_id": vuln_id},
        )
        self.push(task)
        return task
    
    def __len__(self) -> int:
        return len(self._heap)
    
    def pending_count(self) -> int:
        """Count pending tasks."""
        return len(self._heap)
    
    def completed_count(self) -> int:
        """Count completed tasks."""
        return len(self._completed)


class ScanOrchestrator:
    """
    High-level orchestrator combining priority queues.
    
    Manages the overall scan flow:
    1. Recon phase -> populate host/subdomain data
    2. Scanning phase -> run vulnerability scanners
    3. Verification phase -> confirm findings
    4. Reporting phase -> generate output
    """
    
    def __init__(self):
        self.vuln_queue = VulnerabilityPriorityQueue()
        self.task_queue = ScanPriorityQueue()
        self._current_phase = ScanPhase.RECON
        self._hosts: dict[str, Any] = {}
        self._vulnerabilities: dict[str, Vulnerability] = {}
    
    def start_scan(self, target: str) -> list[ScanTask]:
        """Initialize scan for target."""
        tasks = self.task_queue.create_recon_tasks(target)
        return tasks
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add discovered vulnerability."""
        self._vulnerabilities[vuln.id] = vuln
        self.vuln_queue.push(vuln)
        
        # Create verification task for critical/high severity
        if vuln.severity in {VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH}:
            self.task_queue.create_verification_task(vuln.id, vuln.target)
    
    def next_task(self) -> ScanTask | None:
        """Get next task to execute."""
        return self.task_queue.pop()
    
    def next_vuln_to_verify(self) -> Vulnerability | None:
        """Get next vulnerability to verify."""
        return self.vuln_queue.pop()
    
    def complete_task(self, task_id: str) -> None:
        """Mark task as completed."""
        self.task_queue.mark_completed(task_id)
    
    def get_status(self) -> dict[str, Any]:
        """Get orchestrator status."""
        return {
            "current_phase": self._current_phase.value,
            "pending_tasks": self.task_queue.pending_count(),
            "completed_tasks": self.task_queue.completed_count(),
            "vulnerabilities_found": len(self._vulnerabilities),
            "vulnerabilities_pending_verification": len(self.vuln_queue),
            "vuln_queue_stats": self.vuln_queue.stats(),
        }
