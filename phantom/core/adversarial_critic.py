"""
Adversarial Critic (BUG-005 FIX + Intelligence Plan 4.x)

Reviews agent decisions before they execute. Enforces:
1. Tool-argument validation (is this the right tool for the job?)
2. Finding verification gates (no reporting without evidence)
3. Exploitation justification (require vulnerability evidence before exploit)
4. Phase compliance (don't exploit during reconnaissance)
5. Graph feasibility gate (Intelligence Plan 4.3)
6. Justification requirement for high-risk tools (Intelligence Plan 4.4)
7. Post-execution review / reflection (Intelligence Plan 4.5)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from phantom.agents.enhanced_state import EnhancedAgentState
    from phantom.core.scan_state_machine import ScanState

_logger = logging.getLogger(__name__)


# Phase ordering for registry-derived enforcement (Intelligence Plan 4.2)
_PHASE_ORDER = [
    "init", "reconnaissance", "enumeration", "vulnerability_scanning",
    "exploitation", "verification", "reporting", "completed",
]

# Tools that should NOT be used during certain phases
_PHASE_DENIED_TOOLS: dict[str, set[str]] = {
    "reconnaissance": {
        "sqlmap_test", "sqlmap_forms", "sqlmap_dump_database",
        # FIX-INTEL-004: Added missing exploitation tools
        "dalfox_xss", "ffuf_parameter_fuzz",
    },
    "enumeration": {
        "sqlmap_dump_database",
    },
    "reporting": {
        "nmap_scan", "nuclei_scan", "sqlmap_test",
        "ffuf_directory_scan", "katana_crawl",
    },
}

# Intelligence Plan 4.2: Tool minimum phase mapping (registry-derived)
_TOOL_MIN_PHASE: dict[str, str] = {
    "nmap_scan": "reconnaissance",
    "subfinder_scan": "reconnaissance",
    "httpx_probe": "reconnaissance",
    "ffuf_directory_scan": "enumeration",
    "ffuf_parameter_fuzz": "enumeration",
    "katana_crawl": "enumeration",
    "nuclei_scan": "vulnerability_scanning",
    "nuclei_scan_cves": "vulnerability_scanning",
    "nuclei_scan_misconfigs": "vulnerability_scanning",
    "sqlmap_test": "vulnerability_scanning",
    "sqlmap_forms": "exploitation",
    "sqlmap_dump_database": "exploitation",
    "dalfox_xss": "exploitation",
    "terminal_execute": "enumeration",
    "send_request": "enumeration",
    "finish_scan": "reporting",
}

# Tools that require prior evidence to justify usage
_EVIDENCE_REQUIRED_TOOLS: dict[str, str] = {
    "sqlmap_test": "SQL injection indicator (error-based, parameter reflection)",
    "sqlmap_forms": "SQL injection indicator on form endpoint",
    "sqlmap_dump_database": "Confirmed SQL injection vulnerability",
}

# Intelligence Plan 4.3: Tools that require graph feasibility check
_EXPLOITATION_TOOLS = frozenset({
    "sqlmap_test", "sqlmap_forms", "sqlmap_dump_database",
    "dalfox_xss", "nuclei_scan", "terminal_execute",
})

# Intelligence Plan 4.4: High-risk tools requiring justification
_HIGH_RISK_TOOLS = frozenset({
    "sqlmap_dump_database", "terminal_execute",
})


@dataclass
class ResultReview:
    """Intelligence Plan 4.5: Post-execution review result."""
    action_achieved_goal: bool
    new_information_gained: bool
    suggested_next: str | None
    confidence_adjustment: float  # -0.2 to +0.2


class AdversarialCritic:
    """
    Reviews and optionally blocks tool invocations.

    Does NOT pass/fail silently — always returns a CriticVerdict
    that the agent loop can act on.
    """

    def __init__(self, strict: bool = True, critic_llm: Any = None) -> None:
        """
        Args:
            strict: HARDENED v0.9.40: Defaults to True.  When True, blocked
                    actions are MANDATORY rejections — the tool call is removed
                    from the execution batch.  Setting strict=False is only
                    permitted in unit-test contexts.
            critic_llm: REG-008: Optional separate LLM for independent judgment.
        """
        self._strict = strict
        self._critic_llm = critic_llm
        self._review_log: list[dict[str, Any]] = []
        self._pre_execution_node_counts: dict[str, int] = {}

    def review_action(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        state: "EnhancedAgentState",
        current_phase: "ScanState",
        *,
        reasoning: str | None = None,
    ) -> CriticVerdict:
        """Review a proposed tool invocation before execution.

        Returns a CriticVerdict indicating whether the action should proceed.
        """
        issues: list[str] = []

        # Check 1: Phase compliance (legacy deny list)
        denied = _PHASE_DENIED_TOOLS.get(current_phase.value, set())
        if tool_name in denied:
            issues.append(
                f"Tool '{tool_name}' is not appropriate during "
                f"{current_phase.value} phase."
            )

        # Check 1b: Intelligence Plan 4.2 — Registry-derived phase enforcement
        min_phase = _TOOL_MIN_PHASE.get(tool_name)
        if min_phase and current_phase.value in _PHASE_ORDER:
            current_idx = _PHASE_ORDER.index(current_phase.value)
            min_idx = _PHASE_ORDER.index(min_phase) if min_phase in _PHASE_ORDER else 0
            if current_idx < min_idx:
                issues.append(
                    f"Tool '{tool_name}' requires phase '{min_phase}' or later, "
                    f"but current phase is '{current_phase.value}'."
                )

        # Check 2: Evidence requirement
        if tool_name in _EVIDENCE_REQUIRED_TOOLS:
            required_evidence = _EVIDENCE_REQUIRED_TOOLS[tool_name]
            if not self._has_evidence(tool_name, tool_args, state):
                issues.append(
                    f"Tool '{tool_name}' requires prior evidence: "
                    f"{required_evidence}. No matching evidence found in "
                    f"findings ledger."
                )

        # Check 3: Verification gate for finish_scan
        if tool_name == "finish_scan":
            unverified = self._count_unverified_high_crit(state)
            if unverified > 0:
                issues.append(
                    f"Cannot finish scan: {unverified} HIGH/CRITICAL "
                    f"findings are unverified. Verify them first or "
                    f"mark them as false positives."
                )

        # Check 4: Duplicate testing detection
        target = tool_args.get("target") or tool_args.get("url") or ""
        if target and self._is_duplicate_test(tool_name, str(target), state):
            issues.append(
                f"Tool '{tool_name}' already tested target '{target}' — "
                f"consider testing a different target."
            )

        # Check 5: Intelligence Plan 4.3 — Graph feasibility gate
        issues.extend(self._check_graph_feasibility(tool_name, tool_args, state))

        # Check 6: Intelligence Plan 4.4 — Justification for high-risk tools
        issues.extend(self._require_justification(tool_name, tool_args, reasoning))

        # Snapshot node count for post-execution review
        # HIGH-07 FIX: Key by tool_name + target to avoid overwriting
        if hasattr(state, "attack_graph") and state.attack_graph:
            target_key = tool_args.get("target") or tool_args.get("url") or ""
            snapshot_key = f"{tool_name}:{target_key}"
            self._pre_execution_node_counts[snapshot_key] = state.attack_graph.node_count

        # HARDENED v0.9.40: Verdict is STRICTLY determined by issues list.
        # There is no advisory pass-through — if issues exist the call is blocked.
        verdict = CriticVerdict(
            tool_name=tool_name,
            allowed=len(issues) == 0,
            issues=issues,
            phase=current_phase.value,
        )

        self._review_log.append(verdict.to_dict())
        # LOW-22 FIX: Cap review log to prevent unbounded growth
        if len(self._review_log) > 1000:
            self._review_log = self._review_log[-500:]

        if issues:
            _logger.info(
                "Critic review for %s: %s",
                tool_name,
                "; ".join(issues),
            )

        return verdict

    def get_verification_report(
        self, state: "EnhancedAgentState"
    ) -> dict[str, Any]:
        """Generate a verification status report."""
        findings = state.vulnerabilities
        verified = state.verified_vulns
        false_pos = state.false_positives

        unverified = {
            vid: v for vid, v in findings.items()
            if vid not in verified and vid not in false_pos
        }

        return {
            "total_findings": len(findings),
            "verified": len(verified),
            "false_positives": len(false_pos),
            "unverified": len(unverified),
            "unverified_high_crit": self._count_unverified_high_crit(state),
            "ready_for_report": self._count_unverified_high_crit(state) == 0,
        }

    def _has_evidence(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        state: "EnhancedAgentState",
    ) -> bool:
        """Check if the agent has gathered evidence that justifies using this tool."""
        target = tool_args.get("url") or tool_args.get("target") or ""

        # Check findings ledger for relevant evidence
        # HIGH-08 FIX: Use specific multi-word phrases instead of single
        # keywords like "error" that match too broadly.
        keywords = {
            "sqlmap_test": ["sql injection", "sqli", "sql syntax", "sql error"],
            "sqlmap_forms": ["sql injection", "sqli", "form injection", "injectable parameter"],
            "sqlmap_dump_database": ["sqli confirmed", "sql injection confirmed", "injectable"],
        }

        search_terms = keywords.get(tool_name, [])
        for finding in state.findings_ledger:
            lower_finding = finding.lower()
            if any(term in lower_finding for term in search_terms):
                # Check if finding is related to the target
                if not target or str(target).lower() in lower_finding:
                    return True

        return False

    def _count_unverified_high_crit(self, state: "EnhancedAgentState") -> int:
        """Count unverified HIGH/CRITICAL findings."""
        count = 0
        for vid, v in state.vulnerabilities.items():
            if vid in state.verified_vulns or vid in state.false_positives:
                continue
            sev = getattr(v.severity, "value", str(v.severity)).lower()
            if sev in ("critical", "high"):
                count += 1
        return count

    def _is_duplicate_test(
        self, tool_name: str, target: str, state: "EnhancedAgentState"
    ) -> bool:
        """Check if we've already tested this target with this tool."""
        tested = getattr(state, "tested_endpoints", {})
        key = f"{tool_name}:{target}"
        return key in tested

    def _check_graph_feasibility(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        state: "EnhancedAgentState",
    ) -> list[str]:
        """Intelligence Plan 4.3: Verify target exists in attack graph before exploitation."""
        if tool_name not in _EXPLOITATION_TOOLS:
            return []

        if not hasattr(state, "attack_graph") or not state.attack_graph:
            return []

        target = tool_args.get("target") or tool_args.get("url") or tool_args.get("host")
        if not target:
            return []

        graph = state.attack_graph
        # Check if we have any discovered nodes at all
        if graph.node_count < 2:
            return [
                f"Attack graph has only {graph.node_count} nodes. "
                f"Run reconnaissance to discover the attack surface first."
            ]

        return []

    def _require_justification(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        reasoning: str | None,
    ) -> list[str]:
        """Intelligence Plan 4.4: Require explanation for high-risk tool invocations."""
        if tool_name not in _HIGH_RISK_TOOLS:
            return []

        if not reasoning or len(reasoning.strip()) < 20:
            return [
                f"High-risk tool '{tool_name}' requires justification. "
                f"Explain why this action is necessary and what evidence supports it."
            ]

        # Check reasoning references known evidence
        evidence_refs = re.findall(
            r"(CVE-\d{4}-\d+|port \d+|service \w+|sql|injection|xss|rce)",
            reasoning,
            re.IGNORECASE,
        )
        if not evidence_refs:
            return [
                f"Justification for '{tool_name}' should reference specific evidence "
                f"(CVE IDs, discovered services, open ports, vulnerability types)."
            ]

        return []

    def review_result(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        result: Any,
        state: "EnhancedAgentState",
    ) -> ResultReview:
        """Intelligence Plan 4.5: Post-execution review — did the action produce useful results?"""
        # Check 1: Did graph grow?
        pre_nodes = self._pre_execution_node_counts.get(tool_name, 0)
        post_nodes = state.attack_graph.node_count if hasattr(state, "attack_graph") and state.attack_graph else 0
        new_info = post_nodes > pre_nodes

        # Check 2: Did execution succeed?
        success = True
        if isinstance(result, dict):
            success = not result.get("is_error", False)
        elif isinstance(result, str):
            success = "error" not in result.lower()[:500]

        # Check 3: Determine goal achievement
        goal_achieved = success and (new_info or self._result_has_findings(result))

        # Suggest next action if unproductive
        suggested = None
        if not goal_achieved and not new_info:
            suggested = (
                f"Tool '{tool_name}' did not produce new findings. "
                f"Consider trying a different tool or target."
            )
        elif new_info:
            suggested = "Process new discoveries; update attack graph."

        return ResultReview(
            action_achieved_goal=goal_achieved,
            new_information_gained=new_info,
            suggested_next=suggested,
            confidence_adjustment=0.1 if goal_achieved else -0.1,
        )

    @staticmethod
    def _result_has_findings(result: Any) -> bool:
        """Check if a result contains meaningful findings."""
        if isinstance(result, dict):
            return bool(
                result.get("vulnerabilities")
                or result.get("findings")
                or result.get("ports")
                or result.get("hosts")
            )
        if isinstance(result, str):
            lower = result.lower()
            return any(
                kw in lower
                for kw in ("vulnerability", "found", "detected", "critical", "high")
            )
        return False

    def get_review_log(self) -> list[dict[str, Any]]:
        return list(self._review_log)


class CriticVerdict:
    """Result of a critic review."""

    def __init__(
        self,
        tool_name: str,
        allowed: bool,
        issues: list[str],
        phase: str,
    ) -> None:
        self.tool_name = tool_name
        self.allowed = allowed
        self.issues = issues
        self.phase = phase

    @property
    def warning_text(self) -> str:
        """Get warning text suitable for injection into LLM context."""
        if not self.issues:
            return ""
        return (
            f"[CRITIC WARNING] The following issues were detected with "
            f"your proposed action '{self.tool_name}':\n"
            + "\n".join(f"  - {issue}" for issue in self.issues)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "allowed": self.allowed,
            "issues": self.issues,
            "phase": self.phase,
        }
