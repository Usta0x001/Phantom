"""
Tool Execution Firewall — STEP 3 Hardening

Deterministic pre-execution validation layer that ALL tool invocations must
pass through before reaching the executor.  This is NOT advisory — blocked
calls raise SecurityViolationError and abort execution.

Responsibilities:
  1. Argument schema validation (required params, type coherence)
  2. Target scope enforcement (delegates to ScopeValidator)
  3. Phase-minimum enforcement (deterministic, not advisory)
  4. Dangerous parameter limiting (risk-level caps, wordlist caps)
  5. Shell injection pattern detection (terminal_execute, python_action)
  6. Invocation rate limiting (per-tool call budget per scan)
  7. Infinite-loop / repetition detection

Architecture:
  executor.py calls ToolFirewall.validate() BEFORE dispatching to sandbox.
  If validate() raises, the tool call is aborted with a hard error.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from phantom.core.exceptions import (
    PhaseViolationError,
    ScopeViolationError,
    SecurityViolationError,
)

if TYPE_CHECKING:
    from phantom.core.scan_state_machine import ScanState

_logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

# Phase ordering — canonical list used for deterministic comparison.
_PHASE_ORDER: list[str] = [
    "init", "reconnaissance", "enumeration", "vulnerability_scanning",
    "exploitation", "verification", "reporting", "completed",
]

# Minimum phase required for each tool.  Tools absent from this map are
# allowed in ANY phase.
TOOL_MINIMUM_PHASE: dict[str, str] = {
    "sqlmap_test": "vulnerability_scanning",
    "sqlmap_forms": "vulnerability_scanning",
    "sqlmap_dump_database": "exploitation",
    "dalfox_xss": "exploitation",
    "nuclei_scan_cves": "vulnerability_scanning",
    "nuclei_scan_misconfigs": "enumeration",
    "ffuf_parameter_fuzz": "enumeration",
    "ffuf_vhost_fuzz": "enumeration",
    "terminal_execute": "exploitation",
    "python_action": "exploitation",
    "finish_scan": "reporting",
    "finish_with_report": "reporting",
}

# Tools that require explicit evidence in the findings ledger before use.
EVIDENCE_REQUIRED_TOOLS: dict[str, list[str]] = {
    "sqlmap_test": ["sql injection", "sqli", "sql syntax", "sql error", "database error"],
    "sqlmap_forms": ["sql injection", "sqli", "form injection", "injectable"],
    "sqlmap_dump_database": ["sqli confirmed", "sql injection confirmed", "injectable", "sqlmap_test"],
    "dalfox_xss": ["xss", "cross-site scripting", "reflected", "dom-based"],
}

# High-risk tools that require justification (non-empty reasoning string).
HIGH_RISK_TOOLS: frozenset[str] = frozenset({
    "sqlmap_dump_database",
    "terminal_execute",
    "python_action",
})

# Shell metacharacters that should NEVER appear in terminal_execute commands
# targeting the host or attempting breakout.
_SHELL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdocker\s+(exec|run|cp|mount)\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget|nc|ncat|socat)\b.*\b(host\.docker\.internal|169\.254\.169\.254|127\.0\.0\.1)\b", re.IGNORECASE),
    re.compile(r"/proc/(1|self)/(root|ns|environ)", re.IGNORECASE),
    re.compile(r"\bmount\s+-", re.IGNORECASE),
    re.compile(r"\bnsenter\b", re.IGNORECASE),
    re.compile(r"\bchroot\b", re.IGNORECASE),
    re.compile(r">(>)?\s*/dev/.*\btcp\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\s+/\s*$", re.IGNORECASE),
    re.compile(r"\bdd\s+.*of=/dev/", re.IGNORECASE),
    re.compile(r"\b(iptables|ip6tables|nftables)\s+.*(-D|--delete|FORWARD)", re.IGNORECASE),
]

# Python code patterns that indicate sandbox escape attempts.
_PYTHON_ESCAPE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"import\s+(ctypes|subprocess)\b.*\b(docker|host\.docker|/proc)", re.IGNORECASE),
    re.compile(r"os\.environ\[.*SANDBOX_TOKEN", re.IGNORECASE),
    re.compile(r"socket\.connect\(.*169\.254", re.IGNORECASE),
    re.compile(r"open\s*\(\s*['\"]?/proc/1", re.IGNORECASE),
]

# Per-tool invocation budget per scan (prevents infinite tool spam).
_DEFAULT_TOOL_BUDGET: int = 50
_TOOL_BUDGETS: dict[str, int] = {
    "nmap_scan": 20,
    "sqlmap_dump_database": 5,
    "terminal_execute": 30,
    "python_action": 20,
    "nuclei_scan": 15,
    "ffuf_directory_scan": 20,
    "ffuf_parameter_fuzz": 20,
    "subfinder_scan": 10,
}

# Repetition detection: same (tool, target) pair called more than N times.
_MAX_DUPLICATE_CALLS = 3

# DNS rebinding / SSRF targets to block (private/link-local/cloud metadata)
_BLOCKED_IP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b169\.254\.169\.254\b"),           # AWS metadata
    re.compile(r"\b169\.254\.[0-9]+\.[0-9]+\b"),     # link-local
    re.compile(r"\b127\.0\.0\.[0-9]+\b"),            # loopback
    re.compile(r"\b10\.[0-9]+\.[0-9]+\.[0-9]+\b"),   # RFC1918
    re.compile(r"\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+\b"),  # RFC1918
    re.compile(r"\b192\.168\.[0-9]+\.[0-9]+\b"),     # RFC1918
    re.compile(r"\b0\.0\.0\.0\b"),                    # any
    re.compile(r"\bhost\.docker\.internal\b", re.IGNORECASE),  # Docker host
    re.compile(r"\bmetadata\.google\.internal\b", re.IGNORECASE),  # GCP metadata
    re.compile(r"\bmetadata\.azure\.internal\b", re.IGNORECASE),  # Azure metadata
]

# Prompt injection patterns in tool arguments (LLM manipulation)
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\b", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"disregard\s+(the\s+)?(above|prior)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"<\|?system\|?>|\[INST\]|\[/INST\]", re.IGNORECASE),
]

# Dangerous parameter caps
_DANGEROUS_PARAM_LIMITS: dict[str, dict[str, Any]] = {
    "sqlmap_test": {"risk": 2, "level": 3},
    "sqlmap_forms": {"risk": 2, "level": 3},
    "sqlmap_dump_database": {"risk": 2, "level": 3},
    "ffuf_directory_scan": {"threads": 50, "rate": 200},
    "ffuf_parameter_fuzz": {"threads": 50, "rate": 200},
    "nmap_scan": {"rate": 5000},
}


# ═══════════════════════════════════════════════════════════════════════
# Firewall Exception
# ═══════════════════════════════════════════════════════════════════════


class ToolFirewallViolation(SecurityViolationError):
    """Raised when the tool firewall blocks an invocation."""

    def __init__(self, message: str, tool_name: str = "", rule: str = ""):
        super().__init__(message)
        self.tool_name = tool_name
        self.rule = rule


# ═══════════════════════════════════════════════════════════════════════
# Firewall Result
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class FirewallVerdict:
    """Result of a firewall check."""
    tool_name: str
    allowed: bool
    violations: list[str] = field(default_factory=list)
    sanitized_args: dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════
# Tool Firewall
# ═══════════════════════════════════════════════════════════════════════


class ToolFirewall:
    """
    Deterministic tool execution firewall.

    All tool invocations MUST pass through validate() before execution.
    Violations raise ToolFirewallViolation (a SecurityViolationError).
    """

    def __init__(self, scope_validator: Any = None) -> None:
        self._scope_validator = scope_validator
        self._lock = threading.Lock()
        self._call_counts: dict[str, int] = defaultdict(int)
        self._call_log: list[tuple[str, str, float]] = []  # (tool, target_key, timestamp)
        self._duplicate_tracker: dict[str, int] = defaultdict(int)

    def validate(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        current_phase: str,
        findings_ledger: list[str] | None = None,
        reasoning: str = "",
    ) -> FirewallVerdict:
        """
        Validate a tool invocation against all firewall rules.

        Args:
            tool_name: Name of the tool being invoked.
            tool_args: Arguments passed to the tool.
            current_phase: Current scan phase (string value).
            findings_ledger: Agent's findings ledger for evidence checks.
            reasoning: LLM reasoning text for justification checks.

        Returns:
            FirewallVerdict with sanitized_args if allowed.

        Raises:
            ToolFirewallViolation if any hard rule is violated.
        """
        violations: list[str] = []
        sanitized = dict(tool_args)

        # ── Rule 0: Schema validation (HARD — H-TF-001) ──
        self._check_schema(tool_name, sanitized, violations)

        # ── Rule 1: Phase enforcement (HARD) ──
        self._check_phase(tool_name, current_phase, violations)

        # ── Rule 2: Scope enforcement (HARD) ──
        self._check_scope(tool_name, sanitized, violations)

        # ── Rule 3: Evidence prerequisite (HARD for exploitation tools) ──
        self._check_evidence(tool_name, sanitized, findings_ledger or [], violations)

        # ── Rule 4: High-risk justification (HARD) ──
        self._check_justification(tool_name, reasoning, violations)

        # ── Rule 5: Shell injection detection (HARD) ──
        self._check_shell_injection(tool_name, sanitized, violations)

        # ── Rule 6: Dangerous parameter capping (SANITIZE) ──
        self._cap_dangerous_params(tool_name, sanitized)

        # ── Rule 7: Invocation budget (HARD) ──
        self._check_budget(tool_name, violations)

        # ── Rule 8: Repetition detection (WARN → HARD after threshold) ──
        self._check_repetition(tool_name, sanitized, violations)

        # ── Rule 9: DNS rebinding / SSRF defense (HARD — H-TF-002) ──
        self._check_dns_rebinding(tool_name, sanitized, violations)

        # ── Rule 10: Prompt injection in args (HARD — H-TF-003) ──
        self._check_prompt_injection_in_args(tool_name, sanitized, violations)

        if violations:
            verdict = FirewallVerdict(
                tool_name=tool_name,
                allowed=False,
                violations=violations,
            )
            _logger.warning(
                "FIREWALL BLOCKED %s: %s", tool_name, "; ".join(violations),
            )
            raise ToolFirewallViolation(
                f"Tool '{tool_name}' blocked by firewall: {'; '.join(violations)}",
                tool_name=tool_name,
                rule=violations[0] if violations else "unknown",
            )

        # Record successful invocation
        with self._lock:
            self._call_counts[tool_name] += 1
            target_key = str(sanitized.get("target") or sanitized.get("url") or sanitized.get("command", "")[:80])
            self._call_log.append((tool_name, target_key, time.monotonic()))
            dup_key = f"{tool_name}:{target_key}"
            self._duplicate_tracker[dup_key] += 1

        return FirewallVerdict(
            tool_name=tool_name,
            allowed=True,
            sanitized_args=sanitized,
        )

    # ── Rule Implementations ──

    def _check_schema(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        """Rule 0: Validate tool arguments against the schema registry (H-TF-001)."""
        try:
            from phantom.core.tool_schema_registry import ToolSchemaRegistry
            schema_violations = ToolSchemaRegistry.validate(tool_name, args)
            for sv in schema_violations:
                violations.append(f"Schema: {sv.message}")
        except ImportError:
            pass  # Schema registry not available — skip

    def _check_phase(self, tool_name: str, current_phase: str, violations: list[str]) -> None:
        min_phase = TOOL_MINIMUM_PHASE.get(tool_name)
        if not min_phase:
            return

        try:
            current_idx = _PHASE_ORDER.index(current_phase)
            min_idx = _PHASE_ORDER.index(min_phase)
        except ValueError:
            return  # Unknown phase — allow (defensive)

        if current_idx < min_idx:
            violations.append(
                f"Phase violation: '{tool_name}' requires phase '{min_phase}' "
                f"but current phase is '{current_phase}'"
            )

    def _check_scope(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        if not self._scope_validator:
            return

        # Extract all potential target parameters
        targets: list[str] = []
        for param in ("target", "url", "host", "domain", "ip"):
            val = args.get(param)
            if val and isinstance(val, str):
                targets.append(val)

        # For terminal_execute, extract URLs from command string
        command = args.get("command", "")
        if command and isinstance(command, str):
            url_matches = re.findall(r"https?://[^\s'\"]+", command)
            targets.extend(url_matches)
            # Also check for raw IPs
            ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", command)
            targets.extend(ip_matches)

        for target in targets:
            try:
                if not self._scope_validator.is_in_scope(target):
                    violations.append(
                        f"Scope violation: target '{target}' is out of scope"
                    )
            except Exception as e:
                _logger.warning("Scope check error for %s: %s", target, e)

    def _check_evidence(
        self,
        tool_name: str,
        args: dict[str, Any],
        findings_ledger: list[str],
        violations: list[str],
    ) -> None:
        required_keywords = EVIDENCE_REQUIRED_TOOLS.get(tool_name)
        if not required_keywords:
            return

        target = str(args.get("url") or args.get("target") or "").lower()
        has_evidence = False

        for finding in findings_ledger:
            lower_finding = finding.lower()
            if any(kw in lower_finding for kw in required_keywords):
                # If target is specified, require the finding to mention it
                if not target or target in lower_finding or len(target) < 5:
                    has_evidence = True
                    break

        if not has_evidence:
            violations.append(
                f"Evidence prerequisite: '{tool_name}' requires prior evidence "
                f"({', '.join(required_keywords[:3])}) in findings ledger"
            )

    def _check_justification(self, tool_name: str, reasoning: str, violations: list[str]) -> None:
        if tool_name not in HIGH_RISK_TOOLS:
            return

        if not reasoning or len(reasoning.strip()) < 20:
            violations.append(
                f"Justification required: high-risk tool '{tool_name}' "
                f"requires >=20 char reasoning explanation"
            )

    def _check_shell_injection(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        if tool_name == "terminal_execute":
            command = args.get("command", "")
            if isinstance(command, str):
                for pattern in _SHELL_INJECTION_PATTERNS:
                    if pattern.search(command):
                        violations.append(
                            f"Shell injection pattern detected in command: "
                            f"'{pattern.pattern[:60]}'"
                        )
                        break

        elif tool_name == "python_action":
            code = args.get("code", "") or args.get("script", "")
            if isinstance(code, str):
                for pattern in _PYTHON_ESCAPE_PATTERNS:
                    if pattern.search(code):
                        violations.append(
                            f"Sandbox escape pattern detected in Python code: "
                            f"'{pattern.pattern[:60]}'"
                        )
                        break

    def _cap_dangerous_params(self, tool_name: str, args: dict[str, Any]) -> None:
        limits = _DANGEROUS_PARAM_LIMITS.get(tool_name)
        if not limits:
            return

        for param, max_val in limits.items():
            val = args.get(param)
            if val is not None:
                try:
                    numeric_val = int(val)
                    if numeric_val > max_val:
                        _logger.info(
                            "Capping %s.%s from %d to %d",
                            tool_name, param, numeric_val, max_val,
                        )
                        args[param] = max_val
                except (ValueError, TypeError):
                    pass

    def _check_budget(self, tool_name: str, violations: list[str]) -> None:
        with self._lock:
            budget = _TOOL_BUDGETS.get(tool_name, _DEFAULT_TOOL_BUDGET)
            current = self._call_counts.get(tool_name, 0)

        if current >= budget:
            violations.append(
                f"Budget exceeded: '{tool_name}' called {current}/{budget} times"
            )

    def _check_repetition(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        target_key = str(args.get("target") or args.get("url") or args.get("command", "")[:80])
        dup_key = f"{tool_name}:{target_key}"

        with self._lock:
            count = self._duplicate_tracker.get(dup_key, 0)

        if count >= _MAX_DUPLICATE_CALLS:
            violations.append(
                f"Repetition limit: '{tool_name}' called {count} times "
                f"with same target '{target_key[:50]}'"
            )

    def _check_dns_rebinding(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        """Rule 9: Block requests targeting private/cloud-metadata IPs (H-TF-002)."""
        # Collect all string values from args
        text_values: list[str] = []
        for val in args.values():
            if isinstance(val, str):
                text_values.append(val)

        for text in text_values:
            for pattern in _BLOCKED_IP_PATTERNS:
                if pattern.search(text):
                    violations.append(
                        f"DNS rebinding/SSRF blocked: argument contains "
                        f"restricted address matching '{pattern.pattern[:50]}'"
                    )
                    return  # One violation is enough

    def _check_prompt_injection_in_args(self, tool_name: str, args: dict[str, Any], violations: list[str]) -> None:
        """Rule 10: Detect prompt injection attempts in tool arguments (H-TF-003)."""
        for key, val in args.items():
            if not isinstance(val, str) or len(val) < 15:
                continue
            for pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(val):
                    violations.append(
                        f"Prompt injection detected in arg '{key}': "
                        f"pattern '{pattern.pattern[:40]}'"
                    )
                    return  # One violation is enough

    # ── State Inspection ──

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_calls": sum(self._call_counts.values()),
                "per_tool": dict(self._call_counts),
                "blocked_duplicates": sum(
                    1 for v in self._duplicate_tracker.values()
                    if v >= _MAX_DUPLICATE_CALLS
                ),
            }

    def reset(self) -> None:
        with self._lock:
            self._call_counts.clear()
            self._call_log.clear()
            self._duplicate_tracker.clear()


# ═══════════════════════════════════════════════════════════════════════
# Module-level singleton
# ═══════════════════════════════════════════════════════════════════════

_global_firewall: ToolFirewall | None = None
_firewall_lock = threading.Lock()


def get_global_firewall() -> ToolFirewall | None:
    return _global_firewall


def set_global_firewall(fw: ToolFirewall) -> None:
    global _global_firewall
    with _firewall_lock:
        _global_firewall = fw


def init_firewall(scope_validator: Any = None) -> ToolFirewall:
    fw = ToolFirewall(scope_validator=scope_validator)
    set_global_firewall(fw)
    return fw
