import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "phantom Agent"
    parent_id: str | None = None
    sandbox_id: str | None = None
    sandbox_token: str | None = Field(default=None, exclude=True)
    sandbox_info: dict[str, Any] | None = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300  # Default iteration budget
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: datetime | None = None
    final_result: dict[str, Any] | None = None
    max_iterations_warning_sent: bool = False

    # Wall-clock time limit (seconds). 0 = disabled.
    # Can be set via scan profile for production use.
    max_scan_duration_seconds: int = 0

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    # Persistent findings ledger — compact, append-only list of key
    # discoveries made during the scan.  Unlike conversation messages, this
    # is NEVER compressed or summarised so critical data survives memory
    # compression without loss.  Each entry is a short human-readable string
    # (e.g. "SQLi confirmed at POST /rest/user/login param=email").
    findings_ledger: list[str] = Field(default_factory=list)

    # ARCH-003 FIX: Queue of HIGH/CRITICAL findings awaiting verification.
    # Populated by _auto_record_findings(), consumed by finish_scan().
    unverified_findings: list[dict[str, Any]] = Field(default_factory=list)

    _MAX_ACTIONS: int = 5000
    _MAX_OBSERVATIONS: int = 5000
    _MAX_ERRORS: int = 1000
    _MAX_FINDINGS: int = 200
    _MAX_MESSAGES: int = 500

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_advisory(self, content: str, ttl: int = 3) -> None:
        """L3-FIX: Add an advisory message that auto-expires after `ttl` iterations.

        Advisory messages (coverage updates, stagnation warnings, etc.) are useful
        for 2-3 iterations but waste tokens if they persist forever in history.
        Tagged with a marker so the memory compressor can strip expired ones.
        """
        tagged_content = f"<advisory ttl='{ttl}' iter='{self.iteration}'>{content}</advisory>"
        self.add_message("user", tagged_content)

    def add_message(self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None) -> None:
        if len(self.messages) >= self._MAX_MESSAGES:
            # Keep the system prompt (first message) and the most recent half
            keep = self._MAX_MESSAGES // 2
            self.messages = self.messages[:1] + self.messages[-keep:]
            logger.warning(
                "Message history exceeded %d — trimmed to %d keeping system prompt",
                self._MAX_MESSAGES,
                len(self.messages),
            )
        message = {"role": role, "content": content}
        if thinking_blocks:
            message["thinking_blocks"] = thinking_blocks
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action(self, action: dict[str, Any]) -> None:
        if len(self.actions_taken) >= self._MAX_ACTIONS:
            self.actions_taken = self.actions_taken[-self._MAX_ACTIONS // 2 :]
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
            }
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        if len(self.observations) >= self._MAX_OBSERVATIONS:
            self.observations = self.observations[-self._MAX_OBSERVATIONS // 2 :]
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        if len(self.errors) >= self._MAX_ERRORS:
            self.errors = self.errors[-self._MAX_ERRORS // 2 :]
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = datetime.now(UTC).isoformat()

    def add_finding(self, finding: str) -> None:
        """Append a discovery to the persistent findings ledger.

        The ledger is compact (one-liners) and NEVER subject to memory
        compression, so it is the safest place to record important data
        such as confirmed vulnerabilities, discovered endpoints, credentials,
        and technology versions.
        """
        # v0.9.39 FIX (ARC-007): Sanitize before persisting
        try:
            from phantom.core.feature_flags import is_enabled
            if is_enabled("PHANTOM_FF_LEDGER_SANITIZE"):
                finding = self._sanitize_finding(finding)
        except Exception:  # noqa: BLE001
            pass

        # M19 FIX: Normalize whitespace for dedup to avoid near-duplicates
        normalized = " ".join(finding.split()).strip().lower()
        for existing in self.findings_ledger:
            if " ".join(existing.split()).strip().lower() == normalized:
                return
        if len(self.findings_ledger) >= self._MAX_FINDINGS:
            # Keep the most recent half
            self.findings_ledger = self.findings_ledger[-self._MAX_FINDINGS // 2 :]
        self.findings_ledger.append(finding)
        self.last_updated = datetime.now(UTC).isoformat()

    @staticmethod
    def _sanitize_finding(text: str) -> str:
        """Strip tool grammar and injection patterns from finding text."""
        import re
        import unicodedata

        # Normalize unicode
        text = unicodedata.normalize("NFKC", text)
        # Strip invisible characters
        text = re.sub(
            r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]", "", text,
        )
        # Strip tool grammar
        text = re.sub(r"<function[=\s][^>]*>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"</function>", "", text, flags=re.IGNORECASE)
        text = re.sub(
            r"<tool_call>.*?</tool_call>", "", text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Strip prompt override patterns
        text = re.sub(
            r"ignore\s+(all\s+)?previous\s+instructions?",
            "[filtered]", text, flags=re.IGNORECASE,
        )
        text = re.sub(
            r"you\s+are\s+now\s+", "[filtered]", text, flags=re.IGNORECASE,
        )
        text = re.sub(r"system:\s*", "[filtered]", text, flags=re.IGNORECASE)
        # Enforce max length per finding (prevent context stuffing)
        if len(text) > 500:
            text = text[:500] + "...[truncated]"
        return text.strip()

    def get_findings_summary(self) -> str:
        """Return the findings ledger as a newline-delimited string."""
        if not self.findings_ledger:
            return ""
        return "\n".join(f"- {f}" for f in self.findings_ledger)

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = datetime.now(UTC).isoformat()

    def set_completed(self, final_result: dict[str, Any] | None = None) -> None:
        self.completed = True
        self.final_result = final_result
        self.last_updated = datetime.now(UTC).isoformat()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()

    def should_stop(self) -> bool:
        return self.stop_requested or self.completed or self.has_reached_max_iterations() or self._has_exceeded_time_limit()

    # Track cumulative elapsed time across resumes (seconds)
    _cumulative_elapsed_seconds: float = 0.0

    def _has_exceeded_time_limit(self) -> bool:
        """LOGIC-005 FIX: Check if wall-clock time limit has been exceeded.

        H14 FIX: accounts for cumulative time across resumes by tracking
        ``_cumulative_elapsed_seconds`` which is updated on each pause/resume.
        """
        if self.max_scan_duration_seconds <= 0:
            return False
        try:
            current_elapsed = (datetime.now(UTC) - datetime.fromisoformat(self.start_time)).total_seconds()
            total = self._cumulative_elapsed_seconds + current_elapsed
            return total >= self.max_scan_duration_seconds
        except (ValueError, TypeError):
            return False

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(UTC)
        self.llm_failed = llm_failed
        self.last_updated = datetime.now(UTC).isoformat()

    def resume_from_waiting(self, new_task: str | None = None) -> None:
        if self.completed:
            logger.warning("Ignoring resume_from_waiting on already-completed agent %s", self.agent_id)
            return
        self.waiting_for_input = False
        self.waiting_start_time = None
        # Only clear stop_requested if not at iteration limit
        if not self.has_reached_max_iterations():
            self.stop_requested = False
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
            or self.completed
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
        # Return direct reference so in-place memory
        # compression in llm.py persists across iterations.
        return self.messages

    def get_execution_summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": {
                k: v for k, v in (self.sandbox_info or {}).items()
                if k != "auth_token"  # L4 FIX: never expose token in summaries
            } if self.sandbox_info else None,
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
