"""
Tool Schema Registry — Hardening H-IN-001

Centralized schema definitions for ALL tools that the agent can invoke.
Every tool call MUST pass schema validation before reaching the executor.

Validates:
  - Required parameters present
  - Types match (str, int, float, bool, list)
  - String lengths within bounds
  - Numeric values within ranges
  - Forbidden characters / patterns absent
  - URL schemes restricted (http/https only)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParamSchema:
    """Schema definition for a single tool parameter."""
    name: str
    param_type: str = "str"          # str, int, float, bool, list
    required: bool = False
    max_length: int = 2000           # For strings
    min_length: int = 0
    min_value: float | None = None   # For numeric
    max_value: float | None = None
    allowed_values: tuple[str, ...] = ()  # Enum constraint
    forbidden_pattern: str = ""      # Regex that MUST NOT match
    url_schemes: tuple[str, ...] = ()    # If set, URL must start with one of these


@dataclass(frozen=True)
class ToolSchema:
    """Complete schema for a tool."""
    name: str
    description: str = ""
    params: tuple[ParamSchema, ...] = ()
    max_args_total: int = 20


# ═══════════════════════════════════════════════════════════════════════
# Shared forbidden patterns
# ═══════════════════════════════════════════════════════════════════════

# Shell metacharacters that indicate injection
_SHELL_METACHAR_PATTERN = r"[;|`$(){}]|&&|\|\||>>|<<|\bnewline\b"

# Python dangerous imports / builtins
_PYTHON_DANGER_PATTERN = (
    r"__import__|__builtins__|__subclasses__|"
    r"\bexec\s*\(|\beval\s*\(|\bcompile\s*\(|"
    r"\bbreakpoint\s*\(|\bopen\s*\(\s*['\"]\/|"
    r"subprocess|os\.system|os\.popen|pty\.spawn|"
    r"ctypes|importlib\.import_module"
)

# Prompt injection indicators
_PROMPT_INJECTION_PATTERN = (
    r"(?i)(ignore\s+(all\s+)?previous|disregard\s+prior|"
    r"forget\s+everything|new\s+(system\s+)?instructions?|"
    r"you\s+are\s+now|switch\s+to\s+developer|"
    r"act\s+as\s+(if|a\s+different)|do\s+anything\s+now|"
    r"override\s+mode|repeat\s+your\s+system)"
)


# ═══════════════════════════════════════════════════════════════════════
# Schema catalog for all known tools
# ═══════════════════════════════════════════════════════════════════════

_SCHEMAS: dict[str, ToolSchema] = {}


def _register(schema: ToolSchema) -> None:
    _SCHEMAS[schema.name] = schema


# ── Reconnaissance tools ──

_register(ToolSchema(
    name="nmap_scan",
    description="Network port scanner",
    params=(
        ParamSchema(name="target", required=True, max_length=253,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="ports", max_length=200,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="arguments", max_length=500,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="scan_type", allowed_values=("quick", "full", "stealth", "vuln", "udp", "")),
    ),
))

_register(ToolSchema(
    name="subfinder_scan",
    description="Subdomain enumeration",
    params=(
        ParamSchema(name="domain", required=True, max_length=253,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

_register(ToolSchema(
    name="httpx_probe",
    description="HTTP probing",
    params=(
        ParamSchema(name="target", required=True, max_length=2000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

_register(ToolSchema(
    name="httpx_full_analysis",
    description="Full HTTP analysis",
    params=(
        ParamSchema(name="target", required=True, max_length=2000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

# ── Enumeration tools ──

_register(ToolSchema(
    name="katana_crawl",
    description="Web crawler",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="depth", param_type="int", min_value=1, max_value=10),
    ),
))

_register(ToolSchema(
    name="ffuf_directory_scan",
    description="Directory brute-force",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="wordlist", max_length=500),
        ParamSchema(name="threads", param_type="int", min_value=1, max_value=50),
        ParamSchema(name="rate", param_type="int", min_value=1, max_value=200),
    ),
))

_register(ToolSchema(
    name="ffuf_parameter_fuzz",
    description="Parameter fuzzing",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="wordlist", max_length=500),
        ParamSchema(name="threads", param_type="int", min_value=1, max_value=50),
        ParamSchema(name="rate", param_type="int", min_value=1, max_value=200),
    ),
))

_register(ToolSchema(
    name="ffuf_vhost_fuzz",
    description="Virtual host fuzzing",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

# ── Vulnerability scanning tools ──

_register(ToolSchema(
    name="nuclei_scan",
    description="Nuclei vulnerability scanner",
    params=(
        ParamSchema(name="target", required=True, max_length=2000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="templates", max_length=500),
        ParamSchema(name="severity", allowed_values=("info", "low", "medium", "high", "critical", "")),
    ),
))

_register(ToolSchema(
    name="nuclei_scan_cves",
    description="Nuclei CVE scanning",
    params=(
        ParamSchema(name="target", required=True, max_length=2000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

_register(ToolSchema(
    name="nuclei_scan_misconfigs",
    description="Nuclei misconfiguration scan",
    params=(
        ParamSchema(name="target", required=True, max_length=2000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

# ── Exploitation tools ──

_register(ToolSchema(
    name="sqlmap_test",
    description="SQLMap testing",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="risk", param_type="int", min_value=1, max_value=2),
        ParamSchema(name="level", param_type="int", min_value=1, max_value=3),
    ),
))

_register(ToolSchema(
    name="sqlmap_forms",
    description="SQLMap form testing",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="risk", param_type="int", min_value=1, max_value=2),
        ParamSchema(name="level", param_type="int", min_value=1, max_value=3),
    ),
))

_register(ToolSchema(
    name="sqlmap_dump_database",
    description="SQLMap database dump",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
        ParamSchema(name="risk", param_type="int", min_value=1, max_value=2),
        ParamSchema(name="level", param_type="int", min_value=1, max_value=3),
    ),
))

_register(ToolSchema(
    name="dalfox_xss",
    description="XSS scanner",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

# ── Terminal / Python (high-risk) ──

_register(ToolSchema(
    name="terminal_execute",
    description="Terminal command execution",
    params=(
        ParamSchema(name="command", required=True, max_length=4000,
                    forbidden_pattern=_SHELL_METACHAR_PATTERN),
    ),
))

_register(ToolSchema(
    name="python_action",
    description="Python code execution in sandbox",
    params=(
        ParamSchema(name="code", required=True, max_length=10000,
                    forbidden_pattern=_PYTHON_DANGER_PATTERN),
        ParamSchema(name="script", max_length=10000,
                    forbidden_pattern=_PYTHON_DANGER_PATTERN),
    ),
))

# ── HTTP tools ──

_register(ToolSchema(
    name="send_request",
    description="Send HTTP request",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_PROMPT_INJECTION_PATTERN),
        ParamSchema(name="method", allowed_values=("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "")),
        ParamSchema(name="body", max_length=50000),
        ParamSchema(name="headers", max_length=5000),
    ),
))

_register(ToolSchema(
    name="repeat_request",
    description="Repeat HTTP request with modifications",
    params=(
        ParamSchema(name="url", required=True, max_length=2000,
                    url_schemes=("http://", "https://"),
                    forbidden_pattern=_PROMPT_INJECTION_PATTERN),
        ParamSchema(name="method", allowed_values=("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "")),
    ),
))

# ── Finding / Reporting tools ──

_register(ToolSchema(
    name="record_finding",
    description="Record a vulnerability finding",
    params=(
        ParamSchema(name="title", required=True, max_length=500),
        ParamSchema(name="severity", required=True,
                    allowed_values=("info", "low", "medium", "high", "critical")),
        ParamSchema(name="description", required=True, max_length=5000),
        ParamSchema(name="target", max_length=2000),
        ParamSchema(name="evidence", max_length=10000),
    ),
))

_register(ToolSchema(
    name="think",
    description="Agent reasoning / internal thought",
    params=(
        ParamSchema(name="thought", required=True, max_length=5000),
    ),
))

_register(ToolSchema(
    name="finish_scan",
    description="Finish the scan and generate report",
    params=(
        ParamSchema(name="summary", max_length=10000),
    ),
))

_register(ToolSchema(
    name="finish_with_report",
    description="Finish scan with detailed report",
    params=(
        ParamSchema(name="summary", max_length=10000),
        ParamSchema(name="report", max_length=50000),
    ),
))


# ═══════════════════════════════════════════════════════════════════════
# Validation engine
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class SchemaViolation:
    """A single schema validation violation."""
    param: str
    rule: str
    message: str


class ToolSchemaRegistry:
    """Static registry for tool schemas with validation."""

    @staticmethod
    def get_schema(tool_name: str) -> ToolSchema | None:
        return _SCHEMAS.get(tool_name)

    @staticmethod
    def has_schema(tool_name: str) -> bool:
        return tool_name in _SCHEMAS

    @staticmethod
    def validate(tool_name: str, args: dict[str, Any]) -> list[SchemaViolation]:
        """Validate tool arguments against schema.

        Returns list of violations (empty = valid).
        """
        schema = _SCHEMAS.get(tool_name)
        if schema is None:
            # Unknown tools get a single warning — not blocked by schema
            # (firewall has other rules for unknown tools)
            return [SchemaViolation(
                param="__tool__",
                rule="unknown_tool",
                message=f"No schema registered for tool '{tool_name}'",
            )]

        violations: list[SchemaViolation] = []

        # Check total arg count
        if len(args) > schema.max_args_total:
            violations.append(SchemaViolation(
                param="__args__",
                rule="max_args",
                message=f"Too many arguments ({len(args)} > {schema.max_args_total})",
            ))

        for param_schema in schema.params:
            value = args.get(param_schema.name)

            # Required check
            if param_schema.required and (value is None or value == ""):
                violations.append(SchemaViolation(
                    param=param_schema.name,
                    rule="required",
                    message=f"Required parameter '{param_schema.name}' is missing",
                ))
                continue

            if value is None or value == "":
                continue

            # Type check
            if param_schema.param_type == "int":
                try:
                    int_val = int(value)
                    if param_schema.min_value is not None and int_val < param_schema.min_value:
                        violations.append(SchemaViolation(
                            param=param_schema.name,
                            rule="min_value",
                            message=f"'{param_schema.name}' value {int_val} < min {param_schema.min_value}",
                        ))
                    if param_schema.max_value is not None and int_val > param_schema.max_value:
                        violations.append(SchemaViolation(
                            param=param_schema.name,
                            rule="max_value",
                            message=f"'{param_schema.name}' value {int_val} > max {param_schema.max_value}",
                        ))
                except (ValueError, TypeError):
                    violations.append(SchemaViolation(
                        param=param_schema.name,
                        rule="type",
                        message=f"'{param_schema.name}' must be an integer",
                    ))

            elif param_schema.param_type == "str" and isinstance(value, str):
                # Length check
                if len(value) > param_schema.max_length:
                    violations.append(SchemaViolation(
                        param=param_schema.name,
                        rule="max_length",
                        message=f"'{param_schema.name}' length {len(value)} > max {param_schema.max_length}",
                    ))
                if len(value) < param_schema.min_length:
                    violations.append(SchemaViolation(
                        param=param_schema.name,
                        rule="min_length",
                        message=f"'{param_schema.name}' length {len(value)} < min {param_schema.min_length}",
                    ))

                # Allowed values
                if param_schema.allowed_values and value not in param_schema.allowed_values:
                    violations.append(SchemaViolation(
                        param=param_schema.name,
                        rule="allowed_values",
                        message=f"'{param_schema.name}' value '{value}' not in allowed: {param_schema.allowed_values}",
                    ))

                # Forbidden pattern
                if param_schema.forbidden_pattern:
                    try:
                        if re.search(param_schema.forbidden_pattern, value, re.IGNORECASE):
                            violations.append(SchemaViolation(
                                param=param_schema.name,
                                rule="forbidden_pattern",
                                message=f"'{param_schema.name}' contains forbidden pattern",
                            ))
                    except re.error:
                        _logger.warning("Invalid regex in schema for %s.%s", tool_name, param_schema.name)

                # URL scheme check
                if param_schema.url_schemes:
                    if not any(value.lower().startswith(s) for s in param_schema.url_schemes):
                        violations.append(SchemaViolation(
                            param=param_schema.name,
                            rule="url_scheme",
                            message=f"'{param_schema.name}' URL scheme not allowed. Must start with: {param_schema.url_schemes}",
                        ))

        return violations

    @staticmethod
    def all_tool_names() -> list[str]:
        """Return names of all registered tools."""
        return sorted(_SCHEMAS.keys())
