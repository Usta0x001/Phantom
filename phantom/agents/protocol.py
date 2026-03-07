"""
Agent Communication Protocol

Defines structured message formats for inter-agent communication.
Ensures consistent status reporting and task delegation.

ARC-004 FIX: Messages are signed with Ed25519 keypairs per-agent
to prevent message forging between agents.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_logger = logging.getLogger(__name__)


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


# ARC-004 FIX: Per-agent keypair registry for message authentication
# V-LOW-002 FIX: Thread-safe access via lock to prevent concurrent
# agent creation from generating duplicate/conflicting keypairs.
import threading as _threading

_agent_keys: dict[str, tuple[Ed25519PrivateKey, Ed25519PublicKey]] = {}
_agent_keys_lock = _threading.Lock()


def get_or_create_keypair(agent_id: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Get or create an Ed25519 keypair for the given agent (thread-safe)."""
    with _agent_keys_lock:
        if agent_id not in _agent_keys:
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            _agent_keys[agent_id] = (private_key, public_key)
        return _agent_keys[agent_id]


def get_public_key(agent_id: str) -> Ed25519PublicKey | None:
    """Get the public key for a known agent, or None (thread-safe)."""
    with _agent_keys_lock:
        pair = _agent_keys.get(agent_id)
        return pair[1] if pair else None


@dataclass
class AgentMessage:
    """A structured message between agents.

    ARC-004 FIX: Includes signature field for Ed25519 authentication.
    """

    msg_type: MessageType
    sender_id: str
    receiver_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    correlation_id: str | None = None  # For request-response pairing
    signature: bytes = field(default=b"", repr=False)

    def _signable_bytes(self) -> bytes:
        """Canonical bytes for signing: msg_type|sender|receiver|payload|timestamp."""
        canonical = json.dumps({
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
        }, sort_keys=True, separators=(",", ":"))
        return canonical.encode("utf-8")

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        """Sign this message with the sender's private key."""
        self.signature = private_key.sign(self._signable_bytes())

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify the message signature using the sender's public key."""
        if not self.signature:
            return False
        try:
            public_key.verify(self.signature, self._signable_bytes())
            return True
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        import base64
        return {
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "signature": base64.b64encode(self.signature).decode() if self.signature else "",
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentMessage:
        import base64
        sig = data.get("signature", "")
        return cls(
            msg_type=MessageType(data["msg_type"]),
            sender_id=data["sender_id"],
            receiver_id=data["receiver_id"],
            payload=data.get("payload", {}),
            timestamp=data.get("timestamp", datetime.now(UTC).isoformat()),
            correlation_id=data.get("correlation_id"),
            signature=base64.b64decode(sig) if sig else b"",
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
class ScanPhaseConfig:
    """BUG-027 FIX: Renamed from ScanPhase to ScanPhaseConfig to avoid
    collision with models.scan.ScanPhase enum. Represents configuration
    for a phase in the scanning methodology."""

    name: str
    description: str
    agent_types: list[str]
    depends_on: list[str] = field(default_factory=list)
    max_agents: int = 3


# ── Standard scan methodology phases ────────────────────────────────

SCAN_PHASES: list[ScanPhaseConfig] = [
    ScanPhaseConfig(
        name="reconnaissance",
        description="Map attack surface: ports, services, endpoints, technologies",
        agent_types=["recon"],
        max_agents=2,
    ),
    ScanPhaseConfig(
        name="scanning",
        description="Run automated scanners against discovered services",
        agent_types=["scan"],
        depends_on=["reconnaissance"],
        max_agents=5,
    ),
    ScanPhaseConfig(
        name="exploitation",
        description="Attempt exploitation of discovered vulnerabilities",
        agent_types=["exploit"],
        depends_on=["scanning"],
        max_agents=5,
    ),
    ScanPhaseConfig(
        name="verification",
        description="Validate findings with evidence and PoCs",
        agent_types=["verify"],
        depends_on=["exploitation"],
        max_agents=5,
    ),
    ScanPhaseConfig(
        name="reporting",
        description="Document confirmed vulnerabilities with full details",
        agent_types=["report"],
        depends_on=["verification"],
        max_agents=3,
    ),
]
