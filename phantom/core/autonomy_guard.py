"""
Autonomy Guard — STEP 7 Hardening

Safety layer that validates LLM decisions BEFORE they become tool invocations.
Operates between the LLM response parser and the tool executor.

Responsibilities:
  1. Validate LLM decisions against current scan state (coherence check)
  2. Limit exploit escalation (no jump from recon to dump_database)
  3. Detect irrational tool sequences (contradictory or nonsensical)
  4. Prevent unsafe execution chains (e.g. 3 exploits without verification)
  5. Drift detection — compare current actions to original task objective
  6. Watchdog — detect stuck agents and force termination

Architecture:
  BaseAgent._execute_actions() calls AutonomyGuard.check() for each action
  batch.  If check() returns a blocking verdict, the action is removed from
  the allowed list.  Drift detection runs every N iterations via evaluate_drift().
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

# Escalation chain: tools ordered by destructiveness.
_ESCALATION_LEVELS: dict[str, int] = {
    "nmap_scan": 0,
    "subfinder_scan": 0,
    "httpx_probe": 0,
    "httpx_full_analysis": 0,
    "katana_crawl": 1,
    "ffuf_directory_scan": 1,
    "ffuf_parameter_fuzz": 2,
    "nuclei_scan": 2,
    "nuclei_scan_cves": 2,
    "nuclei_scan_misconfigs": 2,
    "sqlmap_test": 3,
    "sqlmap_forms": 3,
    "dalfox_xss": 3,
    "sqlmap_dump_database": 4,
    "terminal_execute": 4,
    "python_action": 4,
}

# Maximum escalation jump allowed in a single step (e.g. 0→4 is blocked).
_MAX_ESCALATION_JUMP = 2

# Maximum consecutive exploit-class tools without a verification or
# evidence-collection tool in between.
_MAX_CONSECUTIVE_EXPLOITS = 3

# Exploit-class tools (level >= 3)
_EXPLOIT_TOOLS: frozenset[str] = frozenset(
    name for name, level in _ESCALATION_LEVELS.items() if level >= 3
)

# Verification/evidence tools that reset the exploit counter
_VERIFICATION_TOOLS: frozenset[str] = frozenset({
    "send_request", "repeat_request", "record_finding",
    "think", "verify_vulnerability", "nmap_scan", "httpx_probe",
    "nuclei_scan", "get_findings_ledger",
})

# Drift detection: keywords that MUST appear in agent reasoning/actions
# to be considered on-task.  Populated from the original task at init time.
_TASK_RELEVANCE_WINDOW = 15  # iterations

# Agent watchdog timeout (seconds without producing an action)
_AGENT_WATCHDOG_TIMEOUT = 300.0  # 5 minutes

# Drift check interval (every N iterations)
DRIFT_CHECK_INTERVAL = 15


# ═══════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class AutonomyVerdict:
    """Result of an autonomy guard check."""
    allowed: bool
    reason: str = ""
    action: str = ""  # "allow", "block", "warn"


@dataclass
class DriftReport:
    """Result of a drift evaluation."""
    is_drifting: bool
    drift_score: float = 0.0  # 0.0 = on task, 1.0 = completely off task
    original_task_keywords: list[str] = field(default_factory=list)
    recent_action_keywords: list[str] = field(default_factory=list)
    recommendation: str = ""


# ═══════════════════════════════════════════════════════════════════════
# Autonomy Guard
# ═══════════════════════════════════════════════════════════════════════


class AutonomyGuard:
    """
    Validates LLM decisions for safety, coherence, and task relevance.

    Thread-safe.  One instance per scan.
    """

    def __init__(self, original_task: str = "", max_iterations: int = 300) -> None:
        self._original_task = original_task
        self._max_iterations = max_iterations
        self._lock = threading.Lock()

        # Tool invocation history (bounded deque)
        self._tool_history: deque[tuple[str, float]] = deque(maxlen=500)
        self._consecutive_exploits: int = 0
        self._last_escalation_level: int = 0
        self._last_action_time: float = time.monotonic()

        # Extract task keywords for drift detection
        self._task_keywords = self._extract_keywords(original_task)

        # Drift tracking
        self._recent_tool_targets: deque[str] = deque(maxlen=50)
        self._drift_warnings: int = 0

    def check_action(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        current_phase: str,
        iteration: int,
    ) -> AutonomyVerdict:
        """
        Validate a single tool invocation for autonomy safety.

        Returns AutonomyVerdict.  If allowed=False, the action MUST be blocked.
        """
        with self._lock:
            self._last_action_time = time.monotonic()

            # ── Check 1: Escalation jump ──
            current_level = _ESCALATION_LEVELS.get(tool_name, 1)
            jump = current_level - self._last_escalation_level

            if jump > _MAX_ESCALATION_JUMP and self._last_escalation_level >= 0:
                return AutonomyVerdict(
                    allowed=False,
                    reason=(
                        f"Escalation violation: jump from level {self._last_escalation_level} "
                        f"to {current_level} (max jump={_MAX_ESCALATION_JUMP}). "
                        f"Use intermediate tools before '{tool_name}'."
                    ),
                    action="block",
                )

            # ── Check 2: Consecutive exploit limit ──
            if tool_name in _EXPLOIT_TOOLS:
                self._consecutive_exploits += 1
                if self._consecutive_exploits > _MAX_CONSECUTIVE_EXPLOITS:
                    return AutonomyVerdict(
                        allowed=False,
                        reason=(
                            f"Exploit chain limit: {self._consecutive_exploits} consecutive "
                            f"exploit-class tools without verification. "
                            f"Verify or record findings before continuing exploitation."
                        ),
                        action="block",
                    )
            elif tool_name in _VERIFICATION_TOOLS:
                self._consecutive_exploits = 0

            # ── Check 3: Irrational sequence detection ──
            irrationality = self._detect_irrational_sequence(tool_name, tool_args)
            if irrationality:
                return AutonomyVerdict(
                    allowed=False,
                    reason=irrationality,
                    action="block",
                )

            # Update tracking state
            self._last_escalation_level = max(self._last_escalation_level, current_level)
            self._tool_history.append((tool_name, time.monotonic()))

            target = str(tool_args.get("target") or tool_args.get("url") or "")
            if target:
                self._recent_tool_targets.append(target)

        return AutonomyVerdict(allowed=True, action="allow")

    def evaluate_drift(
        self,
        iteration: int,
        recent_messages: list[dict[str, Any]] | None = None,
    ) -> DriftReport:
        """
        Evaluate whether the agent has drifted from the original task.

        Called every DRIFT_CHECK_INTERVAL iterations.  If drift_score > 0.7,
        the agent should receive a corrective message.
        """
        with self._lock:
            if not self._task_keywords:
                return DriftReport(is_drifting=False, drift_score=0.0)

            # Build set of recently-used keywords from tool targets and messages
            recent_keywords: set[str] = set()

            for target in self._recent_tool_targets:
                recent_keywords.update(self._extract_keywords(target))

            if recent_messages:
                for msg in recent_messages[-_TASK_RELEVANCE_WINDOW:]:
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        recent_keywords.update(self._extract_keywords(content))

            if not recent_keywords:
                return DriftReport(
                    is_drifting=True,
                    drift_score=0.8,
                    original_task_keywords=list(self._task_keywords),
                    recommendation="No recent activity keywords found — agent may be stalled.",
                )

            # Calculate overlap between task keywords and recent activity
            overlap = self._task_keywords & recent_keywords
            if len(self._task_keywords) == 0:
                drift_score = 0.0
            else:
                drift_score = 1.0 - (len(overlap) / len(self._task_keywords))

            is_drifting = drift_score > 0.7

            if is_drifting:
                self._drift_warnings += 1

            recommendation = ""
            if is_drifting:
                recommendation = (
                    f"DRIFT DETECTED (score={drift_score:.2f}): Agent actions do not "
                    f"correlate with original task. Missing keywords: "
                    f"{', '.join(sorted(self._task_keywords - recent_keywords)[:10])}. "
                    f"Re-focus on the original objective."
                )

            return DriftReport(
                is_drifting=is_drifting,
                drift_score=drift_score,
                original_task_keywords=list(self._task_keywords),
                recent_action_keywords=list(recent_keywords)[:20],
                recommendation=recommendation,
            )

    def check_watchdog(self) -> bool:
        """
        Check if the agent has been inactive for too long.

        Returns True if the agent appears stuck (no actions for WATCHDOG_TIMEOUT).
        """
        with self._lock:
            elapsed = time.monotonic() - self._last_action_time
            return elapsed > _AGENT_WATCHDOG_TIMEOUT

    def get_corrective_message(self, original_task: str) -> str:
        """
        Generate a corrective message to re-anchor the agent to its task.
        """
        return (
            f"[AUTONOMY GUARD — DRIFT CORRECTION]\n"
            f"Your original task is: {original_task}\n"
            f"Recent actions show deviation from this objective.\n"
            f"You MUST re-evaluate your approach and return to the primary task.\n"
            f"If the current line of investigation is unproductive, abandon it.\n"
            f"Focus on: {', '.join(sorted(self._task_keywords)[:10])}"
        )

    # ── Internal Helpers ──

    def _detect_irrational_sequence(self, tool_name: str, tool_args: dict[str, Any]) -> str:
        """Detect tool sequences that make no logical sense."""
        if len(self._tool_history) < 2:
            return ""

        recent = [t[0] for t in list(self._tool_history)[-5:]]

        # Pattern 1: finish_scan immediately after recon tools (scan not complete)
        if tool_name == "finish_scan" and all(
            t in ("nmap_scan", "subfinder_scan", "httpx_probe") for t in recent
        ):
            return (
                "Irrational sequence: attempting finish_scan immediately after "
                "reconnaissance tools without any vulnerability scanning."
            )

        # Pattern 2: Same tool called 5+ times in a row
        if len(recent) >= 4 and all(t == tool_name for t in recent[-4:]):
            return (
                f"Repetitive pattern: '{tool_name}' called {len(recent)} times "
                f"consecutively. Try a different approach."
            )

        # Pattern 3: sqlmap_dump without sqlmap_test first
        if tool_name == "sqlmap_dump_database":
            if "sqlmap_test" not in recent and "sqlmap_forms" not in recent:
                return (
                    "Irrational escalation: sqlmap_dump_database called without "
                    "prior sqlmap_test or sqlmap_forms confirmation."
                )

        return ""

    @staticmethod
    def _extract_keywords(text: str) -> set[str]:
        """Extract meaningful keywords from text for drift detection."""
        if not text:
            return set()

        # Extract domain names, IPs, paths, and significant words
        keywords: set[str] = set()

        # Domains
        for match in re.findall(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", text):
            keywords.add(match.lower())

        # IPs
        for match in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            keywords.add(match)

        # URL paths
        for match in re.findall(r"/[a-zA-Z0-9_/-]{3,50}", text):
            keywords.add(match.lower())

        # Significant security terms
        security_terms = re.findall(
            r"\b(sql injection|xss|ssrf|csrf|idor|rce|lfi|rfi|xxe|"
            r"authentication|authorization|cookie|jwt|api|admin|login|"
            r"upload|download|backup|config|database|user|password)\b",
            text,
            re.IGNORECASE,
        )
        for term in security_terms:
            keywords.add(term.lower())

        return keywords

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_actions": len(self._tool_history),
                "consecutive_exploits": self._consecutive_exploits,
                "max_escalation_level": self._last_escalation_level,
                "drift_warnings": self._drift_warnings,
                "task_keywords": list(self._task_keywords)[:10],
            }
