import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "Phantom Agent"
    parent_id: str | None = None
    sandbox_id: str | None = None
    sandbox_token: str | None = None
    sandbox_info: dict[str, Any] | None = None

    # SECURITY FIX: Hash-based message deduplication to prevent context poisoning
    # Stores SHA-256 hashes of message content to detect duplicates
    _message_hashes: set[str] = PrivateAttr(default_factory=set)

    def clear_sandbox(self) -> None:
        """Zero all sandbox-related fields (called after restoring a checkpoint)."""
        self.sandbox_id = None
        self.sandbox_token = None
        self.sandbox_info = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300
    scan_mode: str = "deep"
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: datetime | None = None
    final_result: dict[str, Any] | None = None
    max_iterations_warning_sent: bool = False

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    # Finding anchors: high-signal items extracted from compressed message history
    # so they survive memory compression and can be re-injected at report time.
    finding_anchors: list[dict[str, Any]] = Field(default_factory=list)

    # Maximum anchors to store (matches injection limit in llm.py)
    MAX_FINDING_ANCHORS: int = 15
    
    # FIX BUG-7: Anchor expiration after 3 compression cycles
    MAX_ANCHOR_AGE_CYCLES: int = 3
    
    # PLAN FIX: Message expiration
    MAX_MESSAGES_BEFORE_CLEANUP: int = 50  # Keep last 50 messages, archive rest
    
    def cleanup_old_messages(self) -> int:
        """PLAN FIX: Remove old messages beyond MAX_MESSAGES_BEFORE_CLEANUP.
        
        Keeps recent messages for context, archives older ones.
        Returns number of messages removed.
        """
        if len(self.messages) <= self.MAX_MESSAGES_BEFORE_CLEANUP:
            return 0
        
        removed_count = len(self.messages) - self.MAX_MESSAGES_BEFORE_CLEANUP
        # Keep recent messages
        self.messages = self.messages[-self.MAX_MESSAGES_BEFORE_CLEANUP:]
        self.last_updated = datetime.now(UTC).isoformat()
        return removed_count
    
    # Track compression cycles for anchor expiration
    _compression_cycle: int = 0
    
    def add_finding_anchor(self, anchor: dict[str, Any]) -> None:
        """Store a high-signal finding so it survives memory compression."""
        # FIX BUG 1: Validate anchor text is not empty, None, or whitespace
        anchor_text = anchor.get("text")
        if not anchor_text or not isinstance(anchor_text, str):
            return  # Reject None or non-string
        anchor_text = anchor_text.strip()
        if not anchor_text:
            return  # Reject empty or whitespace-only anchors
        
        # Deduplicate by key if present
        key = anchor.get("key") or anchor_text[:80]
        for existing in self.finding_anchors:
            if (existing.get("key") or existing.get("text", "")[:80]) == key:
                return  # already anchored
        
        # FIX BUG 2: Enforce maximum anchor limit
        if len(self.finding_anchors) >= self.MAX_FINDING_ANCHORS:
            return  # Reject if at limit
        
        # Store the anchor with cleaned text and compression cycle
        anchor["text"] = anchor_text
        anchor["added_cycle"] = self._compression_cycle
        self.finding_anchors.append(anchor)
        self.last_updated = datetime.now(UTC).isoformat()
    
    def expire_stale_anchors(self) -> int:
        """FIX BUG-7: Remove anchors older than MAX_ANCHOR_AGE_CYCLES compression cycles.
        
        Returns number of anchors removed.
        """
        expired = 0
        retained = []
        for anchor in self.finding_anchors:
            added_cycle = anchor.get("added_cycle", 0)
            age = self._compression_cycle - added_cycle
            if age < self.MAX_ANCHOR_AGE_CYCLES:
                retained.append(anchor)
            else:
                expired += 1
        self.finding_anchors = retained
        return expired
    
    def increment_compression_cycle(self) -> None:
        """FIX BUG-7: Track compression cycles for anchor expiration."""
        self._compression_cycle += 1
        self.expire_stale_anchors()

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None
    ) -> None:
        # SECURITY FIX: Hash-based deduplication to prevent context poisoning
        # Uses SHA-256 hash to efficiently detect duplicate messages
        if isinstance(content, str):
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if content_hash in self._message_hashes:
                return  # Duplicate message - skip to prevent flooding
            self._message_hashes.add(content_hash)
        
        # AUDIT-QW-05: Also keep window-based dedup as secondary defense
        # to prevent error message flooding from circuit breakers / validation.
        if isinstance(content, str) and self.messages:
            _window = self.messages[-5:]
            for m in reversed(_window):
                if m.get("role") == role and m.get("content") == content:
                    return  # already present in recent window
        message = {"role": role, "content": content}
        # Do NOT store thinking_blocks in history — they bloat context invisibly
        # to the memory compressor and get re-sent on every subsequent call.
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action(self, action: dict[str, Any]) -> None:
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
            }
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = datetime.now(UTC).isoformat()

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = datetime.now(UTC).isoformat()

    def set_completed(self, final_result: dict[str, Any] | None = None) -> None:
        if self.completed:
            return  # idempotent — first result wins; ignore duplicate calls
        self.completed = True
        self.final_result = final_result
        self.last_updated = datetime.now(UTC).isoformat()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()

    def should_stop(self) -> bool:
        return self.stop_requested or self.completed or self.has_reached_max_iterations()

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(UTC)
        self.llm_failed = llm_failed
        self.last_updated = datetime.now(UTC).isoformat()

    def resume_from_waiting(self, new_task: str | None = None) -> None:
        self.waiting_for_input = False
        self.waiting_start_time = None
        self.stop_requested = False
        self.completed = False
        self.llm_failed = False
        if new_task:
            self.task = new_task
        self.last_updated = datetime.now(UTC).isoformat()

    def has_reached_max_iterations(self) -> bool:
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        return self.iteration >= int(self.max_iterations * threshold)

    def has_waiting_timeout(self) -> bool:
        if not self.waiting_for_input or not self.waiting_start_time:
            return False

        if (
            self.stop_requested
            or self.llm_failed
            or self.has_reached_max_iterations()
        ):
            return False

        elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
        return elapsed > 600

    def has_empty_last_messages(self, count: int = 3) -> bool:
        if len(self.messages) < count:
            return False

        last_messages = self.messages[-count:]

        for message in last_messages:
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return False

        return True

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return self.messages

    @property
    def conversation_history(self) -> list[dict[str, Any]]:
        """Backward-compatible alias for message history."""
        return self.messages

    @property
    def current_iteration(self) -> int:
        """Backward-compatible alias for iteration counter."""
        return self.iteration

    def get_execution_summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": self.sandbox_info,
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": self.completed,
            "final_result": self.final_result,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_actions": len(self.actions_taken),
            "total_observations": len(self.observations),
            "total_errors": len(self.errors),
            "has_errors": len(self.errors) > 0,
            "max_iterations_reached": self.has_reached_max_iterations() and not self.completed,
        }
