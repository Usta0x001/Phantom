"""
Strategic Planner (BUG-001 FIX + Intelligence Plan 2.x)

Sits between the LLM output and tool execution to provide:
1. Phase-aware tool recommendations based on current scan state
2. Attack surface prioritization using the attack graph
3. Stagnation detection and corrective actions
4. Coverage tracking across the target surface
5. Dynamic priority scoring (Intelligence Plan 2.2)
6. Tool effectiveness tracking (Intelligence Plan 2.4)

The planner does NOT replace the LLM — it constrains and guides it.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from phantom.agents.enhanced_state import EnhancedAgentState
    from phantom.core.attack_graph import AttackGraph
    from phantom.core.scan_state_machine import ScanState

_logger = logging.getLogger(__name__)


# Tool recommendations per scan phase
_PHASE_TOOL_RECOMMENDATIONS: dict[str, list[str]] = {
    "reconnaissance": [
        "nmap_scan", "subfinder_scan", "dns_lookup",
        "httpx_probe", "httpx_full_analysis",
    ],
    "enumeration": [
        "ffuf_directory_scan", "katana_crawl",
        "httpx_full_analysis", "ffuf_vhost_fuzz",
    ],
    "vulnerability_scanning": [
        "nuclei_scan", "nuclei_scan_cves", "nuclei_scan_misconfigs",
        "sqlmap_test", "nmap_vuln_scan",
    ],
    "exploitation": [
        "sqlmap_test", "sqlmap_forms", "sqlmap_dump_database",
        "send_request", "terminal_execute",
    ],
    "verification": [
        "send_request", "repeat_request", "terminal_execute",
    ],
    "reporting": [
        "finish_scan",
    ],
}


class StrategicPlanner:
    """
    Phase-aware planner that guides agent behavior.

    Responsibilities:
    - Generate phase guidance for the LLM system prompt
    - Detect stagnation and recommend corrective actions
    - Track coverage across the attack surface
    - Recommend tool usage based on current phase and findings
    """

    # Stagnation detection: if the agent repeats the same tool N times
    # in a row with no new findings, it's stagnating.
    _STAGNATION_THRESHOLD = 5
    _STAGNATION_WINDOW = 10  # Look at last N tool calls

    def __init__(self, attack_graph: "AttackGraph | None" = None) -> None:
        self._attack_graph = attack_graph
        self._tool_history: list[dict[str, Any]] = []
        self._stagnation_warnings = 0
        self._coverage: dict[str, set[str]] = {
            "hosts_scanned": set(),
            "endpoints_tested": set(),
            "vulns_tested": set(),
            "tools_used": set(),
        }

    def generate_phase_guidance(
        self,
        state: "EnhancedAgentState",
        current_phase: "ScanState",
    ) -> str:
        """Generate contextual guidance for the current phase.

        This is injected into the LLM system prompt to keep the agent
        focused on phase-appropriate activities.
        """
        parts: list[str] = []

        # Phase name and description
        phase_name = current_phase.value.upper()
        parts.append(f"=== CURRENT PHASE: {phase_name} ===")

        # Recommended tools
        recommended = _PHASE_TOOL_RECOMMENDATIONS.get(
            current_phase.value, []
        )
        if recommended:
            parts.append(f"Recommended tools: {', '.join(recommended)}")

        # Coverage summary
        coverage_summary = self._get_coverage_summary(state)
        if coverage_summary:
            parts.append(f"Coverage: {coverage_summary}")

        # Stagnation warning
        stagnation = self._detect_stagnation()
        if stagnation:
            parts.append(f"WARNING: {stagnation}")

        # Attack graph summary (if available)
        if self._attack_graph and self._attack_graph.node_count > 0:
            risk_summary = self._attack_graph.get_risk_summary()
            parts.append(
                f"Attack surface: {risk_summary['total_nodes']} nodes, "
                f"{risk_summary['total_vulnerabilities']} vulns, "
                f"max risk={risk_summary['max_risk']:.1f}"
            )

        return "\n".join(parts)

    def record_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        state: "EnhancedAgentState",
    ) -> None:
        """Record a tool call for planning and stagnation detection."""
        self._tool_history.append({
            "tool": tool_name,
            "args": args,
            "timestamp": datetime.now(UTC).isoformat(),
            "had_findings": self._result_has_findings(result),
        })
        # MED-18 FIX: Cap tool history to prevent unbounded growth
        if len(self._tool_history) > 500:
            self._tool_history = self._tool_history[-250:]

        self._coverage["tools_used"].add(tool_name)

        # Track target coverage
        target = (
            args.get("target")
            or args.get("host")
            or args.get("url", "")
        )
        if target:
            if tool_name in ("nmap_scan", "subfinder_scan"):
                self._coverage["hosts_scanned"].add(str(target))
            elif tool_name in ("ffuf_directory_scan", "katana_crawl"):
                self._coverage["endpoints_tested"].add(str(target))

    def get_next_recommendation(
        self,
        state: "EnhancedAgentState",
        current_phase: "ScanState",
    ) -> str | None:
        """Get a specific recommendation if the agent seems stuck."""
        stagnation = self._detect_stagnation()
        if not stagnation:
            return None

        recommended = _PHASE_TOOL_RECOMMENDATIONS.get(
            current_phase.value, []
        )
        used = self._coverage["tools_used"]
        unused = [t for t in recommended if t not in used]

        if unused:
            return (
                f"You appear to be stagnating. Try using: {unused[0]}. "
                f"Other unused tools for this phase: {', '.join(unused[1:3])}"
            )

        return (
            "You appear to be stagnating with no new findings. "
            "Consider advancing to the next scan phase."
        )

    def _detect_stagnation(self) -> str | None:
        """Detect if the agent is repeating actions without progress."""
        if len(self._tool_history) < self._STAGNATION_WINDOW:
            return None

        recent = self._tool_history[-self._STAGNATION_WINDOW:]
        tool_counts = Counter(entry["tool"] for entry in recent)

        # Check if any single tool dominates
        most_common_tool, most_common_count = tool_counts.most_common(1)[0]
        if most_common_count >= self._STAGNATION_THRESHOLD:
            # Check if any of those calls produced findings
            recent_calls = [
                e for e in recent if e["tool"] == most_common_tool
            ]
            finding_count = sum(1 for e in recent_calls if e["had_findings"])
            if finding_count == 0:
                self._stagnation_warnings += 1
                return (
                    f"Tool '{most_common_tool}' called {most_common_count} times "
                    f"in last {self._STAGNATION_WINDOW} iterations with no new "
                    f"findings. Try a different approach."
                )

        return None

    def _get_coverage_summary(self, state: "EnhancedAgentState") -> str:
        """Get a summary of scan coverage."""
        parts = []
        if self._coverage["hosts_scanned"]:
            parts.append(f"{len(self._coverage['hosts_scanned'])} hosts scanned")
        if self._coverage["endpoints_tested"]:
            parts.append(f"{len(self._coverage['endpoints_tested'])} endpoints tested")
        total_vulns = state.vuln_stats.get("total", 0)
        if total_vulns > 0:
            parts.append(f"{total_vulns} vulns found")
        verified = len(state.verified_vulns)
        if verified > 0:
            parts.append(f"{verified} verified")
        return ", ".join(parts) if parts else "No data yet"

    @staticmethod
    def _result_has_findings(result: Any) -> bool:
        """Check if a tool result contains meaningful findings."""
        if isinstance(result, dict):
            # Check for vulnerability/finding indicators
            if result.get("vulnerabilities") or result.get("findings"):
                return True
            if result.get("ports") or result.get("hosts"):
                return True
            if result.get("results") and len(result.get("results", [])) > 0:
                return True
        elif isinstance(result, str):
            # MED-20 FIX: Check for positive finding keywords while excluding
            # negations like "not found" or "no vulnerability".
            lower = result.lower()
            negative_phrases = ("not found", "no vulnerability", "no findings", "0 found")
            if any(neg in lower for neg in negative_phrases):
                return False
            if any(kw in lower for kw in ("vulnerability", "found", "detected", "critical", "high")):
                return True
        return False

    @property
    def tool_history_names(self) -> list[str]:
        """REG-006: Expose tool history for external queries."""
        return [entry["tool"] for entry in self._tool_history]

    def serialize(self) -> dict[str, Any]:
        """Serialize planner state for checkpoint persistence."""
        return {
            "tool_history": self._tool_history[-100:],  # Keep last 100
            "coverage": {k: list(v) for k, v in self._coverage.items()},
            "stagnation_warnings": self._stagnation_warnings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], attack_graph: "AttackGraph | None" = None) -> "StrategicPlanner":
        """Restore planner from checkpoint."""
        planner = cls(attack_graph=attack_graph)
        planner._tool_history = data.get("tool_history", [])
        for key, vals in data.get("coverage", {}).items():
            if key in planner._coverage:
                planner._coverage[key] = set(vals)
        planner._stagnation_warnings = data.get("stagnation_warnings", 0)
        return planner

    def get_status(self) -> dict[str, Any]:
        """Get planner status for debugging."""
        return {
            "total_tool_calls": len(self._tool_history),
            "stagnation_warnings": self._stagnation_warnings,
            "coverage": {
                k: len(v) if isinstance(v, set) else v
                for k, v in self._coverage.items()
            },
        }


# ---------------------------------------------------------------------------
# Intelligence Plan 2.2: Dynamic Priority Scoring
# ---------------------------------------------------------------------------

@dataclass
class ScoredAction:
    """A candidate tool action with its priority score."""
    tool: str
    priority: float
    signals: dict[str, float] = field(default_factory=dict)


class PriorityScorer:
    """Scores candidate tool actions by expected information gain.

    Intelligence Plan 2.2: Multi-signal scoring to select the most
    valuable tool action at each iteration.
    """

    def __init__(
        self,
        attack_graph: "AttackGraph | None" = None,
        planner: StrategicPlanner | None = None,
    ) -> None:
        self._graph = attack_graph
        self._planner = planner

    def score_candidates(
        self,
        candidates: list[str],
        state: "EnhancedAgentState",
        current_phase: "ScanState",
    ) -> list[ScoredAction]:
        """Score and rank candidate tools by expected value."""
        scored = []
        for tool_name in candidates:
            signals = {
                "phase_alignment": self._phase_alignment_score(tool_name, current_phase),
                "novelty": self._novelty_score(tool_name),
                "coverage_gap": self._coverage_gap_score(tool_name, state),
            }
            weights = {
                "phase_alignment": 0.4,
                "novelty": 0.3,
                "coverage_gap": 0.3,
            }
            priority = sum(signals[k] * weights[k] for k in weights)
            scored.append(ScoredAction(tool=tool_name, priority=priority, signals=signals))

        scored.sort(key=lambda s: s.priority, reverse=True)
        return scored

    def _phase_alignment_score(self, tool: str, current_phase: "ScanState") -> float:
        """Higher score if tool is recommended for current phase."""
        recommended = _PHASE_TOOL_RECOMMENDATIONS.get(current_phase.value, [])
        return 1.0 if tool in recommended else 0.3

    def _novelty_score(self, tool: str) -> float:
        """Higher score if tool hasn't been used recently."""
        if not self._planner:
            return 0.5
        recent = self._planner._tool_history[-10:]
        uses = sum(1 for r in recent if r["tool"] == tool)
        return max(0.0, 1.0 - uses * 0.25)

    def _coverage_gap_score(self, tool: str, state: "EnhancedAgentState") -> float:
        """Higher score if tool addresses uncovered areas."""
        if not self._planner:
            return 0.5
        coverage = self._planner._coverage
        if tool in ("nmap_scan", "subfinder_scan") and len(coverage.get("hosts_scanned", set())) < 3:
            return 0.9
        if tool in ("ffuf_directory_scan", "katana_crawl") and len(coverage.get("endpoints_tested", set())) < 5:
            return 0.8
        if tool in ("nuclei_scan",) and state.vuln_stats.get("total", 0) < 3:
            return 0.7
        return 0.4


# ---------------------------------------------------------------------------
# Intelligence Plan 2.4: Adaptive Tool Selection with Learning
# ---------------------------------------------------------------------------

@dataclass
class ToolOutcome:
    """Records tool execution outcome for effectiveness learning."""
    tool: str
    context: str  # e.g., "nginx/1.18", "apache/2.4", "ssh"
    success: bool
    information_gain: float  # New nodes/edges added to graph
    duration: float = 0.0


class ToolEffectivenessTracker:
    """Tracks tool success rates per context to learn optimal tool selection.

    Intelligence Plan 2.4: Purely advisory — feeds into PriorityScorer.
    """

    def __init__(self) -> None:
        self._outcomes: list[ToolOutcome] = []
        self._effectiveness: dict[tuple[str, str], float] = {}

    def record(self, outcome: ToolOutcome) -> None:
        """Record a tool execution outcome."""
        self._outcomes.append(outcome)
        # MED-19 FIX: Cap outcomes to prevent unbounded growth
        if len(self._outcomes) > 1000:
            self._outcomes = self._outcomes[-500:]
        key = (outcome.tool, outcome.context)
        history = [o for o in self._outcomes if (o.tool, o.context) == key]
        success_rate = sum(1 for o in history if o.success) / len(history)
        avg_gain = sum(o.information_gain for o in history) / len(history)
        self._effectiveness[key] = success_rate * 0.6 + min(1.0, avg_gain) * 0.4

    def get_best_tools(self, context: str, candidates: list[str]) -> list[str]:
        """Rank candidate tools by historical effectiveness in this context."""
        scored = []
        for tool in candidates:
            eff = self._effectiveness.get((tool, context), 0.5)
            scored.append((tool, eff))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [t for t, _ in scored]

    def get_effectiveness(self, tool: str, context: str) -> float:
        """Get effectiveness score for a tool in a context."""
        return self._effectiveness.get((tool, context), 0.5)

    def serialize(self) -> dict[str, Any]:
        """Serialize for persistence."""
        return {
            "outcomes": [
                {"tool": o.tool, "context": o.context, "success": o.success,
                 "information_gain": o.information_gain, "duration": o.duration}
                for o in self._outcomes[-500:]
            ],
            "effectiveness": {
                f"{k[0]}:{k[1]}": v for k, v in self._effectiveness.items()
            },
        }
