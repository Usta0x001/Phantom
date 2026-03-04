"""
Phantom Exception Hierarchy

                    BasePhantomError
                    /              \\
    SecurityViolationError    ResourceExhaustedError    OperationalError
      /        |        \\            |
  ScopeViolation  AuditTamper  CheckpointTamper  CostLimitExceeded

INVARIANT: SecurityViolationError and ResourceExhaustedError MUST NEVER
be caught by generic ``except Exception`` handlers. They propagate to the
top-level agent_loop handler which terminates the scan.
"""

from __future__ import annotations


class BasePhantomError(Exception):
    """Root exception for all Phantom-raised errors."""


class SecurityViolationError(BasePhantomError):
    """Security invariant violated — scan MUST terminate."""


class ScopeViolationError(SecurityViolationError):
    """Tool attempted to access resource outside declared scope."""

    def __init__(self, message: str, tool_name: str = "", target: str = ""):
        super().__init__(message)
        self.tool_name = tool_name
        self.target = target


class AuditTamperError(SecurityViolationError):
    """Audit log integrity check failed."""


class CheckpointTamperError(SecurityViolationError):
    """Checkpoint signature verification failed."""


class ResourceExhaustedError(BasePhantomError):
    """Resource limit exceeded — scan MUST terminate."""


class CostLimitExceeded(ResourceExhaustedError):
    """LLM cost budget exhausted."""

    def __init__(self, message: str, current_cost: float = 0.0, limit: float = 0.0):
        super().__init__(message)
        self.current_cost = current_cost
        self.limit = limit


class OperationalError(BasePhantomError):
    """Recoverable operational error (network timeout, Docker failure)."""
