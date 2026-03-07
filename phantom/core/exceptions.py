"""
Phantom Exception Hierarchy

                    BasePhantomError
                    /              \\
    SecurityViolationError    ResourceExhaustedError    OperationalError
      /        |        \\            |                    /      |      \\
  ScopeViolation  AuditTamper  CheckpointTamper  CostLimitExceeded  ToolError  LLMError  StateError
                  SSRFBlockedError                                 /    \\       /     \\
                                                           Timeout NotFound  Rate  Context

Architecture Improvements: Extended hierarchy with recoverable flag,
ToolError subtree, LLMError subtree, SSRFBlockedError, and StateError.

INVARIANT: SecurityViolationError and ResourceExhaustedError MUST NEVER
be caught by generic ``except Exception`` handlers. They propagate to the
top-level agent_loop handler which terminates the scan.
"""

from __future__ import annotations


class BasePhantomError(Exception):
    """Root exception for all Phantom-raised errors.

    Attributes:
        recoverable: Hint to callers whether the error can be retried.
    """

    recoverable: bool = False


class SecurityViolationError(BasePhantomError):
    """Security invariant violated — scan MUST terminate."""

    recoverable = False


class ScopeViolationError(SecurityViolationError):
    """Tool attempted to access resource outside declared scope."""

    def __init__(self, message: str, tool_name: str = "", target: str = ""):
        super().__init__(message)
        self.tool_name = tool_name
        self.target = target


class SSRFBlockedError(SecurityViolationError):
    """Request to internal/private network blocked by egress filter."""

    def __init__(self, message: str, target: str = ""):
        super().__init__(message)
        self.target = target


class AuditTamperError(SecurityViolationError):
    """Audit log integrity check failed."""


class CheckpointTamperError(SecurityViolationError):
    """Checkpoint signature verification failed."""


class ResourceExhaustedError(BasePhantomError):
    """Resource limit exceeded — scan MUST terminate."""

    recoverable = False


class CostLimitExceeded(ResourceExhaustedError):
    """LLM cost budget exhausted."""

    def __init__(self, message: str, current_cost: float = 0.0, limit: float = 0.0):
        super().__init__(message)
        self.current_cost = current_cost
        self.limit = limit


class OperationalError(BasePhantomError):
    """Recoverable operational error (network timeout, Docker failure)."""

    recoverable = True


# ---------------------------------------------------------------------------
# Tool Errors
# ---------------------------------------------------------------------------

class ToolError(OperationalError):
    """A tool execution failed."""

    def __init__(self, message: str, tool_name: str = ""):
        super().__init__(message)
        self.tool_name = tool_name


class ToolTimeoutError(ToolError):
    """Tool execution timed out."""


class ToolNotFoundError(ToolError):
    """Requested tool does not exist in the registry."""

    recoverable = False


# ---------------------------------------------------------------------------
# LLM Errors
# ---------------------------------------------------------------------------

class LLMError(OperationalError):
    """LLM provider call failed."""

    def __init__(self, message: str, provider: str = ""):
        super().__init__(message)
        self.provider = provider


class LLMRateLimitError(LLMError):
    """Rate-limited by the LLM provider."""


class LLMContextOverflowError(LLMError):
    """LLM context window exceeded."""

    recoverable = False


# ---------------------------------------------------------------------------
# Safety Subsystem Errors (ARC-001 FIX)
# ---------------------------------------------------------------------------

class SafetySubsystemFailureError(SecurityViolationError):
    """A safety-critical subsystem (critic, FSM, confidence engine) has failed.

    When this error is raised the agent MUST switch to safe-mode and
    restrict itself to the reconnaissance-only tool whitelist.
    """

    def __init__(self, message: str, subsystem: str = ""):
        super().__init__(message)
        self.subsystem = subsystem


class PhaseViolationError(SecurityViolationError):
    """Tool invoked before the required minimum scan phase (ARC-003 FIX)."""

    def __init__(self, message: str, tool_name: str = "", required_phase: str = "", current_phase: str = ""):
        super().__init__(message)
        self.tool_name = tool_name
        self.required_phase = required_phase
        self.current_phase = current_phase


class MessageAuthenticationError(SecurityViolationError):
    """Inter-agent message signature verification failed (ARC-004 FIX)."""

    def __init__(self, message: str, sender_id: str = ""):
        super().__init__(message)
        self.sender_id = sender_id


class SecurityIntegrityViolationError(SecurityViolationError):
    """Runtime tampering of security configuration detected (ARC-002 FIX)."""


class InvalidCheckpointError(BasePhantomError):
    """Checkpoint data failed semantic validation (BUG-003 FIX)."""

    recoverable = False


class LLMStallError(OperationalError):
    """LLM returned empty/null responses repeatedly (BUG-002 FIX)."""

    recoverable = False


# ---------------------------------------------------------------------------
# State Errors
# ---------------------------------------------------------------------------

class StateError(BasePhantomError):
    """Invalid state machine transition or state corruption."""

    recoverable = True


class InvalidTransitionError(StateError):
    """FSM transition is not allowed from the current state."""

    def __init__(self, message: str, from_state: str = "", to_state: str = ""):
        super().__init__(message)
        self.from_state = from_state
        self.to_state = to_state
