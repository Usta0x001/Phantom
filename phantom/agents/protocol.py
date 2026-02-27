"""
Agent Communication Protocol

Defines structured message formats for inter-agent communication.
Ensures consistent status reporting and task delegation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class MessageType(str, Enum):
    """Types of inter-agent messages."""

    TASK_ASSIGN = "task_assign"
    STATUS_UPDATE = "status_update"
    FINDING_REPORT = "finding_report"
    QUERY = "query"
    RESPONSE = "response"
    ABORT = "abort"
    HEARTBEAT = "heartbeat"


class AgentStatus(str, Enum):
    """Standard agent lifecycle states."""

    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentMessage:
    """A structured message between agents."""

    msg_type: MessageType
    sender_id: str
    receiver_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    correlation_id: str | None = None  # For request-response pairing

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentMessage:
        return cls(
            msg_type=MessageType(data["msg_type"]),
            sender_id=data["sender_id"],
            receiver_id=data["receiver_id"],
            payload=data.get("payload", {}),
            timestamp=data.get("timestamp", datetime.now(UTC).isoformat()),
            correlation_id=data.get("correlation_id"),
        )


@dataclass
class TaskAssignment:
    """Structured task assignment for subagents."""

    task_type: str  # "recon", "scan", "exploit", "verify", "report"
    target: str
    objective: str
    constraints: list[str] = field(default_factory=list)
    tools_allowed: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    parent_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_task_string(self) -> str:
        """Convert to natural language task description for the agent."""
        parts = [f"[{self.task_type.upper()}] {self.objective}"]
        parts.append(f"Target: {self.target}")

        if self.constraints:
            parts.append("Constraints: " + "; ".join(self.constraints))

        if self.parent_findings:
            parts.append(f"Previous findings to build on: {len(self.parent_findings)}")
            for f in self.parent_findings[:5]:
                parts.append(f"  - {f.get('title', 'Unknown')}: {f.get('description', '')[:100]}")

        return "\n".join(parts)


@dataclass
class ScanPhase:
    """Represents a phase in the scanning methodology."""

    name: str
    description: str
    agent_types: list[str]
    depends_on: list[str] = field(default_factory=list)
    max_agents: int = 3


# ── Standard scan methodology phases ────────────────────────────────

SCAN_PHASES: list[ScanPhase] = [
    ScanPhase(
        name="reconnaissance",
        description="Map attack surface: ports, services, endpoints, technologies",
        agent_types=["recon"],
        max_agents=2,
    ),
    ScanPhase(
        name="scanning",
        description="Run automated scanners against discovered services",
        agent_types=["scan"],
        depends_on=["reconnaissance"],
        max_agents=5,
    ),
    ScanPhase(
        name="exploitation",
        description="Attempt exploitation of discovered vulnerabilities",
        agent_types=["exploit"],
        depends_on=["scanning"],
        max_agents=5,
    ),
    ScanPhase(
        name="verification",
        description="Validate findings with evidence and PoCs",
        agent_types=["verify"],
        depends_on=["exploitation"],
        max_agents=5,
    ),
    ScanPhase(
        name="reporting",
        description="Document confirmed vulnerabilities with full details",
        agent_types=["report"],
        depends_on=["verification"],
        max_agents=3,
    ),
]
