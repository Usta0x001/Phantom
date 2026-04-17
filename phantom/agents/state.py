import hashlib
from copy import deepcopy
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
    # Stores SHA-256 hashes of role+content to detect duplicates
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

    # Bounded archive of trimmed messages so full/deep runs can preserve older
    # context and fold it back into later compression cycles.
    archived_messages: list[dict[str, Any]] = Field(default_factory=list)

    # Compression bookkeeping used by the memory compressor to avoid
    # reprocessing the same history and to carry structured memory forward.
    compression_state: dict[str, Any] = Field(default_factory=dict)

    # Maximum anchors to store (matches injection limit in llm.py)
    MAX_FINDING_ANCHORS: int = 15
    MAX_ARCHIVED_MESSAGES: int = 200
    
    # PLAN FIX: Message expiration
    MAX_MESSAGES_BEFORE_CLEANUP: int = 50  # Keep last 50 messages, archive rest

    def model_post_init(self, __context: Any) -> None:  # noqa: ANN401
        """Rebuild private dedup hashes after model restore.

        PrivateAttrs are not serialized by pydantic; after checkpoint resume we
        rebuild hash memory from loaded messages so duplicate suppression remains
        effective.
        """
        self._message_hashes.clear()
        for msg in self.messages + self.archived_messages:
            content = msg.get("content", "")
            role = msg.get("role", "")
            if isinstance(content, str):
                digest_input = f"{role}\x1f{content}"
                self._message_hashes.add(hashlib.sha256(digest_input.encode("utf-8")).hexdigest())
    
    def cleanup_old_messages(self) -> int:
        """PLAN FIX: Remove old messages beyond MAX_MESSAGES_BEFORE_CLEANUP.
        
        Keeps recent messages for context, archives older ones.
        Returns number of messages removed.
        """
        if len(self.messages) <= self.MAX_MESSAGES_BEFORE_CLEANUP:
            return 0

        removed_count = len(self.messages) - self.MAX_MESSAGES_BEFORE_CLEANUP
        # Keep recent messages and preserve older context in the bounded archive.
        older_messages = deepcopy(self.messages[:-self.MAX_MESSAGES_BEFORE_CLEANUP])
        if older_messages:
            self.archived_messages.extend(older_messages)
            if len(self.archived_messages) > self.MAX_ARCHIVED_MESSAGES:
                self.archived_messages = self.archived_messages[-self.MAX_ARCHIVED_MESSAGES:]

        self.messages = self.messages[-self.MAX_MESSAGES_BEFORE_CLEANUP:]
        self.last_updated = datetime.now(UTC).isoformat()
        return removed_count

    def get_archived_messages(self) -> list[dict[str, Any]]:
        return list(self.archived_messages)

    def clear_archived_messages(self) -> int:
        removed = len(self.archived_messages)
        if removed:
            self.archived_messages = []
            self.last_updated = datetime.now(UTC).isoformat()
        return removed
    
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
        new_score = float(anchor.get("evidence_score", anchor.get("confidence_score", 0.0)) or 0.0)
        for existing in self.finding_anchors:
            if (existing.get("key") or existing.get("text", "")[:80]) == key:
                existing_score = float(existing.get("evidence_score", existing.get("confidence_score", 0.0)) or 0.0)
                if new_score > existing_score:
                    existing.update(anchor)
                    existing["text"] = anchor_text
                    existing["evidence_score"] = new_score
                    if "status" not in existing:
                        existing["status"] = "active"
                    self.finding_anchors.sort(
                        key=lambda item: (
                            float(item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0),
                            item.get("key", ""),
                        ),
                        reverse=True,
                    )
                return  # already anchored

        # FIX BUG 2: Enforce maximum anchor limit by evidential value, not age.
        anchor["evidence_score"] = new_score
        if len(self.finding_anchors) >= self.MAX_FINDING_ANCHORS:
            weakest_index = min(
                range(len(self.finding_anchors)),
                key=lambda i: float(
                    self.finding_anchors[i].get("evidence_score", self.finding_anchors[i].get("confidence_score", 0.0))
                    or 0.0
                ),
            )
            weakest_score = float(
                self.finding_anchors[weakest_index].get("evidence_score", self.finding_anchors[weakest_index].get("confidence_score", 0.0))
                or 0.0
            )
            if new_score <= weakest_score:
                return
            self.finding_anchors.pop(weakest_index)
        
        # Store the anchor with cleaned text and validity status
        anchor["text"] = anchor_text
        if "status" not in anchor:
            anchor["status"] = "active"
        self.finding_anchors.append(anchor)
        self.finding_anchors.sort(
            key=lambda item: (
                float(item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0),
                item.get("key", ""),
            ),
            reverse=True,
        )
        self.last_updated = datetime.now(UTC).isoformat()

    def prune_invalid_anchors(self) -> int:
        removed = 0
        retained = []
        for anchor in self.finding_anchors:
            status = str(anchor.get("status", "active")).lower()
            if status in {"invalidated", "superseded"}:
                removed += 1
                continue
            retained.append(anchor)
        self.finding_anchors = retained
        return removed

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None
    ) -> None:
        # SECURITY FIX: Hash-based deduplication to prevent context poisoning
        # Uses SHA-256 hash to efficiently detect duplicate messages
        if isinstance(content, str):
            content_hash = hashlib.sha256(f"{role}\x1f{content}".encode("utf-8")).hexdigest()
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
        self._trim_bounded_history(self.actions_taken, 200)

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )
        self._trim_bounded_history(self.observations, 200)

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self._trim_bounded_history(self.errors, 100)
        self.last_updated = datetime.now(UTC).isoformat()

    def _trim_bounded_history(self, items: list[Any], limit: int) -> None:
        if len(items) <= limit:
            return
        del items[:-limit]

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
