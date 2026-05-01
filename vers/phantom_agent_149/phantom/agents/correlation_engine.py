"""
Correlation Engine — Identifies potential vulnerability chains.

Follows the same pattern as HypothesisLedger and CoverageTracker:
- Thread-safe with RLock
- Returns SUGGESTIONS not commands (preserves AI autonomy)
- Serializable for checkpoints
- Injectable into LLM context via to_prompt_summary()

The engine identifies patterns where multiple findings could be chained
together (e.g., SSRF + cloud metadata = credential theft). The LLM
decides whether to pursue these chains - the engine never prescribes actions.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


# Vulnerability chain patterns that the engine can recognize.
# These are common attack chains observed in real-world penetration testing.
CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ssrf_to_cloud_metadata",
        "name": "SSRF to Cloud Metadata",
        "description": "SSRF can be chained with cloud metadata endpoints to extract credentials",
        "required_findings": ["ssrf"],
        "suggested_next": ["cloud_metadata_access"],
        "target_hints": ["169.254.169.254", "metadata.google.internal", "100.100.100.200"],
    },
    {
        "id": "sqli_to_rce",
        "name": "SQL Injection to RCE",
        "description": "SQL injection may allow writing files or executing commands depending on DB permissions",
        "required_findings": ["sqli"],
        "suggested_next": ["file_write", "into_outfile", "xp_cmdshell"],
        "db_functions": ["INTO OUTFILE", "LOAD_FILE", "xp_cmdshell", "pg_read_file"],
    },
    {
        "id": "lfi_to_rce",
        "name": "LFI to RCE",
        "description": "Local File Inclusion can potentially lead to RCE via log poisoning, PHP wrappers, or session files",
        "required_findings": ["lfi", "path_traversal"],
        "suggested_next": ["log_poisoning", "php_wrappers", "session_inclusion"],
        "target_hints": ["/var/log/apache2/access.log", "php://filter", "/tmp/sess_"],
    },
    {
        "id": "xxe_to_ssrf",
        "name": "XXE to SSRF",
        "description": "XXE can be leveraged for SSRF to access internal services",
        "required_findings": ["xxe"],
        "suggested_next": ["internal_port_scan", "cloud_metadata"],
    },
    {
        "id": "idor_to_priv_esc",
        "name": "IDOR to Privilege Escalation",
        "description": "IDOR on user resources may allow accessing admin accounts or sensitive data",
        "required_findings": ["idor"],
        "suggested_next": ["admin_account_access", "password_reset_takeover"],
    },
    {
        "id": "xss_to_session_hijack",
        "name": "XSS to Session Hijacking",
        "description": "Stored/Reflected XSS can steal session tokens or perform actions as victim",
        "required_findings": ["xss", "stored_xss", "reflected_xss"],
        "suggested_next": ["cookie_theft", "csrf_via_xss", "keylogging"],
    },
    {
        "id": "auth_bypass_to_admin",
        "name": "Auth Bypass to Admin Access",
        "description": "Authentication bypass may provide access to admin functionality",
        "required_findings": ["auth_bypass", "broken_auth"],
        "suggested_next": ["admin_panel_access", "user_management"],
    },
    {
        "id": "open_redirect_to_phishing",
        "name": "Open Redirect to Credential Phishing",
        "description": "Open redirect can be chained with OAuth flows or used in phishing campaigns",
        "required_findings": ["open_redirect"],
        "suggested_next": ["oauth_token_theft", "credential_phishing"],
    },
    {
        "id": "ssti_to_rce",
        "name": "SSTI to RCE",
        "description": "Server-Side Template Injection typically leads directly to RCE",
        "required_findings": ["ssti"],
        "suggested_next": ["command_execution", "file_access"],
    },
    {
        "id": "info_disclosure_to_exploit",
        "name": "Information Disclosure to Targeted Exploit",
        "description": "Leaked version info, stack traces, or config can enable targeted exploits",
        "required_findings": ["info_disclosure", "version_leak", "stack_trace"],
        "suggested_next": ["cve_exploit", "default_credentials"],
    },
]


@dataclass
class Finding:
    """A recorded security finding."""

    id: str
    vuln_class: str  # e.g., "ssrf", "sqli", "xss"
    surface: str  # Where it was found (URL, parameter, etc.)
    severity: str = "medium"  # low, medium, high, critical
    details: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_class": self.vuln_class,
            "surface": self.surface,
            "severity": self.severity,
            "details": self.details,
            "discovered_at": self.discovered_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ChainSuggestion:
    """A suggested vulnerability chain to explore."""

    id: str
    chain_name: str
    description: str
    trigger_finding_id: str  # The finding that triggered this suggestion
    trigger_vuln_class: str
    suggested_next_steps: list[str]
    target_hints: list[str] = field(default_factory=list)
    status: str = "suggested"  # suggested, exploring, exploited, dismissed
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "chain_name": self.chain_name,
            "description": self.description,
            "trigger_finding_id": self.trigger_finding_id,
            "trigger_vuln_class": self.trigger_vuln_class,
            "suggested_next_steps": self.suggested_next_steps,
            "target_hints": self.target_hints,
            "status": self.status,
            "created_at": self.created_at,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ChainSuggestion":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class CorrelationEngine:
    """
    Thread-safe engine for identifying potential vulnerability chains.

    Key principles:
    - Returns SUGGESTIONS not commands (preserves AI autonomy)
    - LLM decides whether to pursue chains
    - Analyzes findings to identify chaining opportunities
    - Serializable for checkpointing
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._findings: dict[str, Finding] = {}
        self._suggestions: dict[str, ChainSuggestion] = {}
        self._counter: int = 0

    # ── Finding Management ────────────────────────────────────────────────────

    def add_finding(
        self,
        vuln_class: str,
        surface: str,
        severity: str = "medium",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Record a finding and check for potential chain opportunities.

        Returns:
            dict with:
            - finding_id: The ID of the recorded finding
            - new_suggestions: List of newly identified chain opportunities
        """
        with self._lock:
            # Generate finding ID
            self._counter += 1
            finding_id = f"F-{self._counter:04d}"

            # Store the finding
            self._findings[finding_id] = Finding(
                id=finding_id,
                vuln_class=vuln_class.lower(),
                surface=surface,
                severity=severity,
                details=details or {},
            )

            # Check for chain opportunities
            new_suggestions = self._identify_chains(finding_id, vuln_class.lower())

            return {
                "finding_id": finding_id,
                "new_suggestions": [s.to_dict() for s in new_suggestions],
                "total_findings": len(self._findings),
                "total_suggestions": len(self._suggestions),
            }

    def _identify_chains(self, finding_id: str, vuln_class: str) -> list[ChainSuggestion]:
        """Identify potential chains based on a new finding."""
        new_suggestions: list[ChainSuggestion] = []

        for pattern in CHAIN_PATTERNS:
            # Check if this vuln_class matches any required finding in the pattern
            required = pattern.get("required_findings", [])
            if vuln_class not in required:
                continue

            # Create a unique suggestion ID based on finding + pattern
            suggestion_key = f"{finding_id}:{pattern['id']}"
            suggestion_id = f"C-{hashlib.md5(suggestion_key.encode()).hexdigest()[:8].upper()}"

            # Skip if we already have this suggestion
            if suggestion_id in self._suggestions:
                continue

            # Create the suggestion
            suggestion = ChainSuggestion(
                id=suggestion_id,
                chain_name=pattern["name"],
                description=pattern["description"],
                trigger_finding_id=finding_id,
                trigger_vuln_class=vuln_class,
                suggested_next_steps=pattern.get("suggested_next", []),
                target_hints=pattern.get("target_hints", []),
            )

            self._suggestions[suggestion_id] = suggestion
            new_suggestions.append(suggestion)

        return new_suggestions

    # ── Chain Management ──────────────────────────────────────────────────────

    def update_chain_status(
        self,
        suggestion_id: str,
        status: str,
        note: str | None = None,
    ) -> bool:
        """
        Update the status of a chain suggestion.

        Args:
            suggestion_id: The suggestion to update
            status: New status (suggested, exploring, exploited, dismissed)
            note: Optional note about the update
        """
        with self._lock:
            if suggestion_id not in self._suggestions:
                return False

            suggestion = self._suggestions[suggestion_id]
            suggestion.status = status
            if note:
                suggestion.notes.append(f"[{status}] {note}")

            return True

    def get_active_suggestions(self) -> list[ChainSuggestion]:
        """Return suggestions that haven't been dismissed or fully exploited."""
        with self._lock:
            return [
                s for s in self._suggestions.values()
                if s.status in {"suggested", "exploring"}
            ]

    def get_all_suggestions(self) -> list[ChainSuggestion]:
        """Return all chain suggestions."""
        with self._lock:
            return list(self._suggestions.values())

    def get_findings(self) -> list[Finding]:
        """Return all recorded findings."""
        with self._lock:
            return list(self._findings.values())

    # ── Cross-Finding Analysis ────────────────────────────────────────────────

    def analyze_combinations(self) -> dict[str, Any]:
        """
        Analyze all findings for multi-vulnerability chains.

        Returns FACTS about potential combinations - LLM decides what to pursue.
        """
        with self._lock:
            findings_list = list(self._findings.values())

        if len(findings_list) < 2:
            return {"combinations": [], "message": "Need at least 2 findings for combination analysis"}

        # Group findings by type
        by_class: dict[str, list[Finding]] = {}
        for f in findings_list:
            if f.vuln_class not in by_class:
                by_class[f.vuln_class] = []
            by_class[f.vuln_class].append(f)

        combinations: list[dict[str, Any]] = []

        # Look for interesting combinations
        vuln_classes = set(by_class.keys())

        # SSRF + XXE = powerful internal access
        if "ssrf" in vuln_classes and "xxe" in vuln_classes:
            combinations.append({
                "type": "ssrf_xxe_combo",
                "description": "Both SSRF and XXE found - consider combining for enhanced internal access",
                "involved_classes": ["ssrf", "xxe"],
            })

        # Multiple injection types = likely weak input validation
        injection_types = vuln_classes & {"sqli", "xss", "ssti", "xxe", "command_injection"}
        if len(injection_types) >= 2:
            combinations.append({
                "type": "weak_input_validation",
                "description": f"Multiple injection types found ({', '.join(injection_types)}) - suggests weak input validation across application",
                "involved_classes": list(injection_types),
            })

        # Auth issues + IDOR = account takeover potential
        if vuln_classes & {"auth_bypass", "broken_auth"} and "idor" in vuln_classes:
            combinations.append({
                "type": "account_takeover_potential",
                "description": "Auth issues combined with IDOR may enable full account takeover",
                "involved_classes": ["auth_bypass", "idor"],
            })

        return {
            "combinations": combinations,
            "total_findings": len(findings_list),
            "unique_vuln_classes": list(vuln_classes),
        }

    # ── Prompt Summary (for LLM context injection) ────────────────────────────

    def to_prompt_summary(self, max_items: int = 10) -> str:
        """
        Return a compact text summary safe to inject into LLM context.

        Reports SUGGESTIONS not commands - LLM decides what to pursue.
        """
        with self._lock:
            findings_list = list(self._findings.values())
            active_suggestions = [
                s for s in self._suggestions.values()
                if s.status in {"suggested", "exploring"}
            ]

        if not findings_list and not active_suggestions:
            return ""

        lines = ["[CORRELATION ENGINE — vulnerability chain analysis]"]

        # Summary stats
        lines.append(f"  Findings: {len(findings_list)} | Active chain suggestions: {len(active_suggestions)}")

        # List findings briefly
        if findings_list:
            vuln_classes = set(f.vuln_class for f in findings_list)
            lines.append(f"  Finding types: {', '.join(sorted(vuln_classes))}")

        # Active chain suggestions (SUGGESTIONS, not commands)
        if active_suggestions:
            lines.append("  Chain opportunities to consider:")
            for suggestion in active_suggestions[:max_items]:
                status_marker = "*" if suggestion.status == "exploring" else " "
                hints = f" (hints: {', '.join(suggestion.target_hints[:2])})" if suggestion.target_hints else ""
                lines.append(
                    f"   {status_marker} [{suggestion.id}] {suggestion.chain_name}: "
                    f"{suggestion.description[:60]}...{hints}"
                )
                if suggestion.suggested_next_steps:
                    next_steps = ", ".join(suggestion.suggested_next_steps[:3])
                    lines.append(f"       Suggested exploration: {next_steps}")

        # Run combination analysis
        combo_result = self.analyze_combinations()
        if combo_result.get("combinations"):
            lines.append("  Multi-finding patterns:")
            for combo in combo_result["combinations"][:3]:
                lines.append(f"    - {combo['description'][:70]}...")

        lines.append("[END CORRELATION]")
        return "\n".join(lines)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize for checkpointing/persistence."""
        with self._lock:
            return {
                "counter": self._counter,
                "findings": {k: v.to_dict() for k, v in self._findings.items()},
                "suggestions": {k: v.to_dict() for k, v in self._suggestions.items()},
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CorrelationEngine":
        """Restore from serialized state."""
        engine = cls()
        engine._counter = d.get("counter", 0)
        for k, v in d.get("findings", {}).items():
            engine._findings[k] = Finding.from_dict(v)
        for k, v in d.get("suggestions", {}).items():
            engine._suggestions[k] = ChainSuggestion.from_dict(v)
        return engine

    def __len__(self) -> int:
        with self._lock:
            return len(self._findings) + len(self._suggestions)
