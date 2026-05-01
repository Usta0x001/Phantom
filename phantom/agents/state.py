import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr


def _generate_agent_id() -> str:
    # FIX: Use full UUID instead of 8 hex chars (32 bits) to avoid collisions
    # at scale. Birthday-boundary collision probability with 32 bits becomes
    # non-negligible at 100+ agents per scan.
    return f"agent_{uuid.uuid4().hex}"


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

    # Session state tracking for pentesting context.
    # The LLM uses this to know its current authentication level and
    # discovered credentials without scrolling through full history.
    session_cookies: dict[str, str] = Field(default_factory=dict)
    session_tokens: dict[str, str] = Field(default_factory=dict)
    current_auth_level: str = "unauthenticated"  # e.g. "unauthenticated", "user", "admin"
    target_base_url: str = ""

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    # Bounded archive of trimmed messages so full/deep runs can preserve older
    # context and fold it back into later compression cycles.
    archived_messages: list[dict[str, Any]] = Field(default_factory=list)

    MAX_ARCHIVED_MESSAGES: int = 200

    # PLAN FIX: Message expiration
    MAX_MESSAGES_BEFORE_CLEANUP: int = 50  # Keep last 50 messages, archive rest

    def model_post_init(self, __context: Any) -> None:  # noqa: ANN401
        """Rebuild private dedup hashes after model restore.

        PrivateAttrs are not serialized by pydantic; after checkpoint resume we
        rebuild hash memory from loaded messages so duplicate suppression remains
        effective. Both string and dict content are hashed so tool-call
        duplicates are also caught after resume.
        """
        import json

        self._message_hashes.clear()
        for msg in self.messages + self.archived_messages:
            content = msg.get("content", "")
            role = msg.get("role", "")
            if isinstance(content, str):
                digest_input = f"{role}\x1f{content}"
            else:
                try:
                    digest_input = f"{role}\x1f{json.dumps(content, sort_keys=True, default=str)}"
                except (TypeError, ValueError):
                    digest_input = f"{role}\x1f{str(content)}"
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
        older_messages = self.messages[: -self.MAX_MESSAGES_BEFORE_CLEANUP]
        if older_messages:
            self.archived_messages.extend(older_messages)
            if len(self.archived_messages) > self.MAX_ARCHIVED_MESSAGES:
                self.archived_messages = self.archived_messages[-self.MAX_ARCHIVED_MESSAGES :]

        self.messages = self.messages[-self.MAX_MESSAGES_BEFORE_CLEANUP :]
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

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(
        self,
        role: str,
        content: Any,
        thinking_blocks: list[dict[str, Any]] | None = None,
        force: bool = False,
    ) -> None:
        # Sliding-window dedup: exact match in last 5 messages.
        if not force and self.messages:
            _window = self.messages[-5:]
            for m in reversed(_window):
                if m.get("role") == role and m.get("content") == content:
                    return

        # Hash-based dedup: SHA-256 of role + canonical content.
        # Covers both string content and dict content (tool calls, images).
        if not force:
            if isinstance(content, str):
                digest_input = f"{role}\x1f{content}"
            else:
                # Canonicalise dict/list content so identical structures are caught.
                import json
                try:
                    digest_input = f"{role}\x1f{json.dumps(content, sort_keys=True, default=str)}"
                except (TypeError, ValueError):
                    digest_input = f"{role}\x1f{str(content)}"
            content_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
            if content_hash in self._message_hashes:
                return
            self._message_hashes.add(content_hash)

        message: dict[str, Any] = {"role": role, "content": content}
        if thinking_blocks:
            message["thinking_blocks"] = thinking_blocks
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

    def update_session(
        self,
        cookies: dict[str, str] | None = None,
        tokens: dict[str, str] | None = None,
        auth_level: str | None = None,
        base_url: str | None = None,
    ) -> None:
        """Update session state so the LLM knows current auth context.

        Called by tools when credentials, cookies, or tokens are discovered.
        """
        if cookies:
            self.session_cookies.update(cookies)
        if tokens:
            self.session_tokens.update(tokens)
        if auth_level is not None:
            self.current_auth_level = auth_level
        if base_url is not None:
            self.target_base_url = base_url
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

        if self.stop_requested or self.llm_failed or self.has_reached_max_iterations():
            return False

        elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
        return elapsed > 600

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return list(self.messages)

    @property
    def conversation_history(self) -> list[dict[str, Any]]:
        """Backward-compatible alias for message history."""
        return list(self.messages)

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
