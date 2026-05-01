"""
Unified scan status tool - gives LLM a single compressed picture of scan state.
This is THE MOST IMPORTANT tool for LLM reasoning quality.

FIX 5: Now includes attack graph analysis for vulnerability chain visualization.
"""

from __future__ import annotations

import threading
from typing import Any, TYPE_CHECKING

from phantom.tools.context import get_current_agent_id
from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.agents.coverage_tracker import CoverageTracker


_CONTEXT_BY_AGENT: dict[str, dict[str, Any]] = {}
_CONTEXT_LOCK = threading.RLock()


def clear_scan_status_context(agent_id: str | None = None) -> None:
    with _CONTEXT_LOCK:
        if agent_id is None:
            _CONTEXT_BY_AGENT.clear()
            return

        _CONTEXT_BY_AGENT.pop(agent_id, None)


def set_scan_status_context(
    hypothesis_ledger: HypothesisLedger | None = None,
    coverage_tracker: CoverageTracker | None = None,
    agent_state: Any | None = None,
) -> None:
    """Set the global context for scan status queries."""
    if agent_state is None:
        raise ValueError("agent_id required")

    with _CONTEXT_LOCK:
        agent_id = str(getattr(agent_state, "agent_id", None) or "default")
        _CONTEXT_BY_AGENT[agent_id] = {
            "hypothesis_ledger": hypothesis_ledger,
            "coverage_tracker": coverage_tracker,
            "agent_state": agent_state,
        }


def _resolve_context(agent_id: str | None = None) -> tuple[Any, Any, Any]:
    if not agent_id:
        agent_id = "default"
    with _CONTEXT_LOCK:
        if agent_id and agent_id in _CONTEXT_BY_AGENT:
            ctx = _CONTEXT_BY_AGENT[agent_id]
            return (
                ctx.get("hypothesis_ledger"),
                ctx.get("coverage_tracker"),
                ctx.get("agent_state"),
            )

    raise ValueError(f"scan status context missing for agent_id={agent_id}")


def _resolve_effective_agent_id(agent_id: str | None = None) -> str:
    if agent_id:
        return str(agent_id)

    current_agent = (get_current_agent_id() or "").strip()
    if current_agent and current_agent != "default":
        return current_agent

    with _CONTEXT_LOCK:
        if len(_CONTEXT_BY_AGENT) == 1:
            return next(iter(_CONTEXT_BY_AGENT.keys()))

    return "default"


def _empty_scan_status(include_recommendations: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scan_progress": {
            "iteration": 0,
            "max_iterations": 300,
            "phase": "RECON",
            "percent_complete": 0.0,
        },
        "findings": {
            "confirmed_vulnerabilities": 0,
            "actively_testing": 0,
            "pending_hypotheses": 0,
        },
        "coverage": {
            "surfaces_tested": 0,
            "surfaces_remaining": 0,
            "coverage_percent": 0.0,
        },
        "blocked_surfaces": [],
        "top_hypotheses": [],
        "archived_messages": {"count": 0, "recent": []},
        "chain_opportunities": [],
        "recommended_next_action": (
            "Continue systematic testing" if include_recommendations else None
        ),
        "warnings": [],
    }
    if not include_recommendations:
        result["recommended_next_action"] = None
    return result


@register_tool(sandbox_execution=False)
def get_scan_status(include_recommendations: bool = True, agent_id: str | None = None) -> dict[str, Any]:
    """
    Get a compressed summary of the entire scan state.
    
    Call this when you need to understand where the scan stands, what to do next,
    or when context feels stale.
    
    Args:
        include_recommendations: Include AI-computed recommendations for next action
    
    Returns:
        Dictionary with:
        - scan_progress: Current iteration, phase, percent complete
        - findings: Confirmed vulnerabilities, actively testing, pending hypotheses
        - coverage: Surfaces tested vs remaining
        - chain_opportunities: Active vulnerability chains to explore
        - recommended_next_action: Suggested next step
        - warnings: Critical alerts (running out of iterations, etc.)
    
    Example:
        get_scan_status(include_recommendations=True)
    """
    explicit_agent_requested = bool(agent_id and str(agent_id).strip())
    agent_id = _resolve_effective_agent_id(agent_id)

    # Get references (agent-scoped only)
    try:
        hypothesis_ledger, coverage_tracker, state = _resolve_context(agent_id)
    except (ValueError, AttributeError):
        if explicit_agent_requested:
            return _empty_scan_status(include_recommendations=include_recommendations)
        hypothesis_ledger = None
        coverage_tracker = None
        state = None
    
    # Compute phase
    iteration = getattr(state, "iteration", 0) if state else 0
    max_iter = getattr(state, "max_iterations", 300) if state else 300
    phase = _compute_phase(iteration, max_iter)
    
    # Get hypothesis stats
    hyp_stats = {"confirmed_count": 0, "testing_count": 0, "open_count": 0}
    if hypothesis_ledger:
        all_hyps = hypothesis_ledger.get_all()
        hyp_stats["confirmed_count"] = sum(1 for h in all_hyps.values() if h.status == "confirmed")
        hyp_stats["testing_count"] = sum(
            1
            for h in all_hyps.values()
            if h.status in {"testing", "partial", "inconclusive", "underdetermined"}
        )
        hyp_stats["open_count"] = sum(1 for h in all_hyps.values() if h.status == "open")
    
    confirmed = hyp_stats.get("confirmed_count", 0)
    testing = hyp_stats.get("testing_count", 0)
    pending = hyp_stats.get("open_count", 0)
    
    # Get coverage stats
    cov_stats = {}
    blocked_surfaces = []
    archived_messages = {"count": 0, "recent": []}
    if coverage_tracker:
        tested = len(coverage_tracker.get_tested_surfaces())
        untested = len(coverage_tracker.get_untested_surfaces())
        cov_stats = {"tested": tested, "untested": untested}
        try:
            blocked_surfaces = coverage_tracker.get_blocked_surfaces()[:5]
        except (AttributeError, TypeError, ValueError):  # noqa: BLE001
            blocked_surfaces = []

    top_hypotheses = []
    if hypothesis_ledger:
        try:
            top_hypotheses = hypothesis_ledger.get_scored_hypotheses()[:5]
        except (AttributeError, TypeError, ValueError):  # noqa: BLE001
            top_hypotheses = []

    if state and hasattr(state, "get_archived_messages"):
        try:
            archived = state.get_archived_messages()
            archived_messages = {
                "count": len(archived),
                "recent": [str(msg.get("content", ""))[:120] for msg in archived[-2:]],
            }
        except (AttributeError, TypeError, ValueError, KeyError):  # noqa: BLE001
            archived_messages = {"count": 0, "recent": []}
    
    # FIX 5: Get attack graph metrics
    chains: list[dict[str, Any]] = []
    # Compute recommendation
    recommendation = None
    if include_recommendations:
        recommendation = _compute_recommendation(
            hypothesis_ledger, coverage_tracker, phase
        )
    
    result = {
        "scan_progress": {
            "iteration": iteration,
            "max_iterations": max_iter,
            "phase": phase,
            "percent_complete": round(iteration / max_iter * 100, 1) if max_iter > 0 else 0
        },
        "findings": {
            "confirmed_vulnerabilities": confirmed,
            "actively_testing": testing,
            "pending_hypotheses": pending
        },
        "coverage": {
            "surfaces_tested": cov_stats.get("tested", 0),
            "surfaces_remaining": cov_stats.get("untested", 0),
            "coverage_percent": _calc_coverage_percent(cov_stats)
        },
        "blocked_surfaces": blocked_surfaces,
        "top_hypotheses": top_hypotheses,
        "archived_messages": archived_messages,
        "chain_opportunities": chains,
        "recommended_next_action": recommendation,
        "warnings": _get_warnings(iteration, max_iter, pending, chains)
    }

    return result


def _compute_phase(iteration: int, max_iter: int) -> str:
    """Compute current scan phase."""
    if max_iter == 0:
        return "UNKNOWN"
    pct = iteration / max_iter
    if pct < 0.15:
        return "RECON"
    elif pct < 0.85:
        return "TESTING"
    else:
        return "WRAP_UP"


def _compute_recommendation(
    hyp_ledger: HypothesisLedger | None,
    cov_tracker: CoverageTracker | None,
    phase: str
) -> str:
    """Compute a recommendation string without taking execution decisions."""
    # Hypothesis ledger facts only
    if hyp_ledger:
        summary = hyp_ledger.get_summary()
        open_count = len(summary.get("open_hypotheses", []))
        if open_count:
            top = hyp_ledger.get_scored_hypotheses()
            if top:
                top_item = top[0]
                return (
                    f"Open hypotheses available: {open_count} "
                    f"(score: {top_item.get('priority_score', 0):.3f}, belief: {top_item.get('belief', 0.5):.3f})"
                )
            return f"Open hypotheses available: {open_count}"
    
    # Untested surfaces facts only
    if cov_tracker:
        untested = cov_tracker.get_untested_surfaces()
        if untested:
            top = untested[0]
            surface = getattr(top, "surface", None)
            if not isinstance(surface, str):
                surface = str(top)
            return f"Untested surfaces remain: {surface[:50]}"
    
    # Default
    if phase == "WRAP_UP":
        return "Report findings and call finish_scan"
    return "Continue systematic testing"


def _calc_coverage_percent(cov_stats: dict[str, int]) -> float:
    """Calculate coverage percentage."""
    tested = cov_stats.get("tested", 0)
    untested = cov_stats.get("untested", 0)
    total = tested + untested
    if total == 0:
        return 0.0
    return round(tested / total * 100, 1)


def _get_warnings(iteration: int, max_iter: int, pending: int, chains: list) -> list[str]:
    """Generate warnings based on scan state."""
    warnings = []
    
    if max_iter == 0:
        return warnings
    
    pct = iteration / max_iter
    if pct > 0.8:
        remaining_pct = int((1 - pct) * 100)
        warnings.append(f"URGENT: {remaining_pct}% iterations remaining - prioritize reporting")
    if pct > 0.9:
        warnings.append("CRITICAL: Must finish soon - report all confirmed findings NOW")
    if pending > 10:
        warnings.append(f"HIGH: {pending} hypotheses pending - focus on high-priority ones")
    if chains and pct < 0.7:
        warnings.append(f"OPPORTUNITY: {len(chains)} unexplored chains could yield high-severity findings")
    
    return warnings
