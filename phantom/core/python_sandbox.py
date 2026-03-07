"""
Python Code Sandbox Validator — V2-TOOL-001 / FIX-002

AST-based validation for Python code executed via python_action().
Blocks dangerous imports, builtins, and operations before execution.

This module does NOT execute code — it only validates whether code
is safe to execute in the IPython sandbox.
"""

from __future__ import annotations

import ast
import logging
from typing import Final

_logger = logging.getLogger(__name__)

# ── Imports that are BLOCKED (dangerous capabilities) ──
BLOCKED_IMPORTS: Final[frozenset[str]] = frozenset({
    # System access
    "os", "subprocess", "shutil", "pathlib",
    "tempfile", "glob",
    # Low-level
    "ctypes", "cffi", "mmap",
    # Code loading
    "importlib", "pkgutil", "zipimport",
    # Network
    "socket", "http", "urllib", "requests", "httpx",
    "ftplib", "smtplib", "telnetlib", "xmlrpc",
    "aiohttp", "websockets",
    # Process/thread control
    "multiprocessing", "threading", "signal",
    "concurrent",
    # Serialization (code execution vectors)
    "pickle", "shelve", "marshal",
    # System info
    "platform", "resource", "sysconfig",
})

# ── Imports that are ALLOWED (safe for data processing) ──
ALLOWED_IMPORTS: Final[frozenset[str]] = frozenset({
    "re", "json", "base64", "hashlib", "hmac",
    "ipaddress", "struct", "binascii",
    "collections", "itertools", "functools",
    "math", "statistics", "decimal", "fractions",
    "datetime", "time", "calendar",
    "textwrap", "string", "difflib",
    "csv", "xml", "html",
    "copy", "pprint", "enum",
    "dataclasses", "typing",
    "io", "codecs",
    "operator", "bisect", "heapq",
    "contextlib", "abc",
    "unicodedata", "locale",
    # Proxy functions injected into namespace
    "list_requests", "list_sitemap", "repeat_request",
    "scope_rules", "send_request", "view_request",
    "view_sitemap_entry",
})

# ── Builtins that are BLOCKED ──
BLOCKED_BUILTINS: Final[frozenset[str]] = frozenset({
    "exec", "eval", "compile", "__import__",
    "breakpoint", "exit", "quit",
    "open",  # Block direct file access
    "globals", "locals", "vars", "dir",
    "getattr", "setattr", "delattr",  # Attribute manipulation
    "type", "super",  # Metaclass manipulation
})

# ── Dangerous attribute accesses ──
BLOCKED_ATTRIBUTES: Final[frozenset[str]] = frozenset({
    "__class__", "__bases__", "__subclasses__",
    "__globals__", "__builtins__", "__code__",
    "__import__", "__loader__", "__spec__",
    "__dict__", "__init_subclass__",
    "system", "popen", "exec", "spawn",
})


class CodeValidationError(Exception):
    """Raised when Python code fails sandbox validation."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        summary = "; ".join(violations[:5])
        if len(violations) > 5:
            summary += f" ... and {len(violations) - 5} more"
        super().__init__(f"Code validation failed: {summary}")


def validate_python_code(code: str) -> list[str]:
    """Validate Python code against sandbox restrictions.

    Returns a list of violation descriptions.
    Empty list means the code is safe to execute.
    """
    violations: list[str] = []

    # Length check
    if len(code) > 50_000:
        violations.append(f"Code exceeds maximum length (50000 chars, got {len(code)})")
        return violations

    # Parse AST
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        violations.append(f"Syntax error: {e.msg} at line {e.lineno}")
        return violations

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0]
                if root_module in BLOCKED_IMPORTS:
                    violations.append(
                        f"Blocked import: '{alias.name}' (line {node.lineno})"
                    )
                elif root_module not in ALLOWED_IMPORTS:
                    violations.append(
                        f"Unknown import: '{alias.name}' — not in allowlist (line {node.lineno})"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root_module = node.module.split(".")[0]
                if root_module in BLOCKED_IMPORTS:
                    violations.append(
                        f"Blocked import: 'from {node.module}' (line {node.lineno})"
                    )
                elif root_module not in ALLOWED_IMPORTS:
                    violations.append(
                        f"Unknown import: 'from {node.module}' — not in allowlist (line {node.lineno})"
                    )

        # Check dangerous builtin calls
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in BLOCKED_BUILTINS:
                    violations.append(
                        f"Blocked builtin call: '{node.func.id}()' (line {node.lineno})"
                    )
            # Check method calls like os.system()
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in BLOCKED_ATTRIBUTES:
                    violations.append(
                        f"Blocked attribute access: '.{node.func.attr}' (line {node.lineno})"
                    )

        # Check attribute access (not just calls)
        elif isinstance(node, ast.Attribute):
            if node.attr in BLOCKED_ATTRIBUTES:
                violations.append(
                    f"Blocked attribute access: '.{node.attr}' (line {node.lineno})"
                )

    if violations:
        _logger.warning(
            "Python code validation failed with %d violation(s): %s",
            len(violations), "; ".join(violations[:3]),
        )

    return violations
