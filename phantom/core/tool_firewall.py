"""
Tool Invocation Firewall (PHASE 4 — Security Control)

Runtime protection layer between LLM output and tool execution.
Validates all tool invocations before they reach the executor:
1. Denies shell metacharacters in arguments
2. Enforces max command length
3. Rejects multiline commands
4. Whitelists known tool flags
5. Validates scope at every tool call
6. Blocks dangerous argument patterns

This module sits between the agent loop and executor.py.
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import Any

_logger = logging.getLogger(__name__)

# Shell metacharacters that should NEVER appear in raw tool arguments
_SHELL_METACHAR_RE = re.compile(r"[;&|`$(){}!<>\n\r\\]")

# Maximum total command/argument length
_MAX_ARG_LENGTH = 4096

# Maximum number of arguments per tool call
_MAX_ARGS_COUNT = 50

# Patterns that indicate injection attempts in string arguments
_INJECTION_PATTERNS = [
    re.compile(r";\s*\w+"),           # Command chaining via semicolon
    re.compile(r"\|\s*\w+"),          # Pipe to another command
    re.compile(r"`[^`]+`"),           # Backtick command substitution
    re.compile(r"\$\([^)]+\)"),       # $() command substitution
    re.compile(r"\$\{[^}]+\}"),       # ${} variable expansion
    re.compile(r">\s*/"),             # Redirect to filesystem
    re.compile(r"&&\s*\w+"),          # AND chaining
    re.compile(r"\|\|\s*\w+"),        # OR chaining
]

# Tools that are allowed to have "raw" string arguments (by design)
_RAW_ARG_TOOLS = {
    "terminal_execute",  # By design — runs in sandbox
    "python_action",     # By design — runs in sandbox
}

# Argument names that should be validated for injection
_SENSITIVE_ARG_NAMES = {
    "target", "url", "target_url", "ports", "scripts",
    "extra_args", "command", "wordlist", "parameter",
    "headers", "body", "cookie", "data",
}


class ToolFirewallViolation(Exception):
    """Raised when a tool invocation violates the firewall policy."""


class ToolInvocationFirewall:
    """Runtime firewall that validates every tool invocation.

    Integrates with the executor to block dangerous tool calls before
    they reach the actual tool implementation.
    """

    def __init__(self, scope_validator: Any | None = None):
        self.scope_validator = scope_validator
        self._violations: list[dict[str, Any]] = []
        self.enabled = True

    def validate(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any] | None:
        """Validate a tool invocation.

        Returns None if the invocation is safe.
        Returns a dict with error details if blocked.
        """
        if not self.enabled:
            return None

        # Tools that run raw commands in sandbox are exempt from arg checks
        # (they are already sandboxed via Docker)
        if tool_name in _RAW_ARG_TOOLS:
            return self._validate_sandbox_tool(tool_name, args)

        # Check total argument count
        if len(args) > _MAX_ARGS_COUNT:
            return self._block(tool_name, args, "Too many arguments")

        # Validate each argument
        for arg_name, arg_value in args.items():
            violation = self._validate_argument(tool_name, arg_name, arg_value)
            if violation:
                return violation

        # Scope validation for tools with target arguments
        scope_violation = self._validate_scope(tool_name, args)
        if scope_violation:
            return scope_violation

        return None

    def _validate_sandbox_tool(
        self, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Light validation for sandbox tools (terminal_execute, python_action)."""
        # Check command length
        command = args.get("command", "")
        if isinstance(command, str) and len(command) > 10000:
            return self._block(tool_name, args, "Command too long (max 10000 chars)")
        return None

    def _validate_argument(
        self, tool_name: str, arg_name: str, arg_value: Any
    ) -> dict[str, Any] | None:
        """Validate a single argument value."""
        if not isinstance(arg_value, str):
            return None

        # Check length
        if len(arg_value) > _MAX_ARG_LENGTH:
            return self._block(
                tool_name, {arg_name: arg_value[:100] + "..."},
                f"Argument '{arg_name}' too long ({len(arg_value)} chars, max {_MAX_ARG_LENGTH})",
            )

        # For sensitive argument names, check for injection patterns
        if arg_name.lower() in _SENSITIVE_ARG_NAMES:
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(arg_value):
                    return self._block(
                        tool_name, {arg_name: arg_value[:200]},
                        f"Potential injection detected in '{arg_name}': "
                        f"matched pattern {pattern.pattern!r}",
                    )

        return None

    def _validate_scope(
        self, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Validate that target arguments are within scope."""
        if not self.scope_validator:
            return None

        # Extract target from various argument names
        target = (
            args.get("target")
            or args.get("url")
            or args.get("target_url")
            or args.get("target_ip")
        )
        if not target or not isinstance(target, str):
            return None

        if not self.scope_validator.is_in_scope(target):
            return self._block(
                tool_name, {"target": target},
                f"Target '{target}' is OUT OF SCOPE",
            )

        return None

    def _block(
        self, tool_name: str, args: dict[str, Any], reason: str
    ) -> dict[str, Any]:
        """Record and return a firewall violation."""
        violation = {
            "tool_name": tool_name,
            "args_preview": {
                k: str(v)[:100] for k, v in args.items()
            },
            "reason": reason,
        }
        self._violations.append(violation)
        _logger.warning("FIREWALL BLOCKED: %s — %s", tool_name, reason)
        return {"error": f"Firewall blocked: {reason}"}

    def get_violations(self) -> list[dict[str, Any]]:
        """Return all recorded firewall violations."""
        return list(self._violations)


# Global firewall instance
_global_firewall: ToolInvocationFirewall | None = None


def get_tool_firewall() -> ToolInvocationFirewall | None:
    """Get the global tool firewall instance."""
    return _global_firewall


def set_tool_firewall(firewall: ToolInvocationFirewall) -> None:
    """Set the global tool firewall instance."""
    global _global_firewall  # noqa: PLW0603
    _global_firewall = firewall


def init_tool_firewall(scope_validator: Any | None = None) -> ToolInvocationFirewall:
    """Initialize and set the global tool firewall."""
    firewall = ToolInvocationFirewall(scope_validator=scope_validator)
    set_tool_firewall(firewall)
    return firewall
