"""
Unified scan status tool - gives LLM a single compressed picture of scan state.
This is THE MOST IMPORTANT tool for LLM reasoning quality.

FIX 5: Now includes attack graph analysis for vulnerability chain visualization.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.agents.coverage_tracker import CoverageTracker
    from phantom.agents.correlation_engine import CorrelationEngine
    from phantom.core.attack_graph import AttackGraph


# Global references (set by base_agent.py during initialization)
_GLOBAL_HYPOTHESIS_LEDGER: HypothesisLedger | None = None
_GLOBAL_COVERAGE_TRACKER: CoverageTracker | None = None
_GLOBAL_CORRELATION_ENGINE: CorrelationEngine | None = None
_GLOBAL_ATTACK_GRAPH: AttackGraph | None = None  # FIX 5
_GLOBAL_AGENT_STATE: Any | None = None


def set_scan_status_context(
    hypothesis_ledger: HypothesisLedger | None = None,
    coverage_tracker: CoverageTracker | None = None,
    correlation_engine: CorrelationEngine | None = None,
    attack_graph: Any | None = None,  # FIX 5: AttackGraph
    agent_state: Any | None = None,
) -> None:
    """Set the global context for scan status queries."""
    global _GLOBAL_HYPOTHESIS_LEDGER, _GLOBAL_COVERAGE_TRACKER, _GLOBAL_CORRELATION_ENGINE, _GLOBAL_ATTACK_GRAPH, _GLOBAL_AGENT_STATE
    if hypothesis_ledger is not None:
        _GLOBAL_HYPOTHESIS_LEDGER = hypothesis_ledger
    if coverage_tracker is not None:
        _GLOBAL_COVERAGE_TRACKER = coverage_tracker
    if correlation_engine is not None:
        _GLOBAL_CORRELATION_ENGINE = correlation_engine
    if attack_graph is not None:
        _GLOBAL_ATTACK_GRAPH = attack_graph
    if agent_state is not None:
        _GLOBAL_AGENT_STATE = agent_state


@register_tool
def get_scan_status(include_recommendations: bool = True) -> dict[str, Any]:
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
        - attack_graph: FIX 5 - Attack graph metrics and critical vulnerabilities
        - recommended_next_action: Suggested next step
        - warnings: Critical alerts (running out of iterations, etc.)
    
    Example:
        get_scan_status(include_recommendations=True)
    """
    # Get references
    hypothesis_ledger = _GLOBAL_HYPOTHESIS_LEDGER
    coverage_tracker = _GLOBAL_COVERAGE_TRACKER
    correlation_engine = _GLOBAL_CORRELATION_ENGINE
    attack_graph = _GLOBAL_ATTACK_GRAPH
    state = _GLOBAL_AGENT_STATE
    
    # Compute phase
    iteration = getattr(state, "iteration", 0) if state else 0
    max_iter = getattr(state, "max_iterations", 300) if state else 300
    phase = _compute_phase(iteration, max_iter)
    
    # Get hypothesis stats
    hyp_stats = {"confirmed_count": 0, "testing_count": 0, "open_count": 0}
    if hypothesis_ledger:
        all_hyps = hypothesis_ledger.get_all()
        hyp_stats["confirmed_count"] = sum(1 for h in all_hyps.values() if h.status == "confirmed")
        hyp_stats["testing_count"] = sum(1 for h in all_hyps.values() if h.status == "testing")
        hyp_stats["open_count"] = sum(1 for h in all_hyps.values() if h.status == "open")
    
    confirmed = hyp_stats.get("confirmed_count", 0)
    testing = hyp_stats.get("testing_count", 0)
    pending = hyp_stats.get("open_count", 0)
    
    # Get coverage stats
    cov_stats = {}
    if coverage_tracker:
        tested = len(coverage_tracker.get_tested_surfaces())
        untested = len(coverage_tracker.get_untested_surfaces())
        cov_stats = {"tested": tested, "untested": untested}
    
    # Get chain opportunities
    chains = []
    if correlation_engine:
        active = correlation_engine.get_active_suggestions()
        chains = [
            {
                "chain": s.chain_name,
                "surface": s.trigger_vuln_class,
                "description": s.description[:60]
            }
            for s in active[:3]
        ]
    
    # FIX 5: Get attack graph metrics
    attack_graph_summary = None
    if attack_graph:
        try:
            surface = attack_graph.get_attack_surface()
            critical = attack_graph.get_critical_vulnerabilities(top_n=3)
            attack_graph_summary = {
                "total_nodes": surface.get("total_nodes", 0),
                "total_vulnerabilities": surface.get("total_vulnerabilities", 0),
                "total_edges": surface.get("total_edges", 0),
                "density": round(surface.get("density", 0), 3),
                "critical_vulns": [
                    {"id": v[0], "centrality": round(v[1], 4)} 
                    for v in critical
                ],
            }
        except Exception:  # noqa: BLE001
            pass  # Attack graph analysis failed - continue without it
    
    # Compute recommendation
    recommendation = None
    if include_recommendations:
        recommendation = _compute_recommendation(
            hypothesis_ledger, coverage_tracker, correlation_engine, phase
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
        "chain_opportunities": chains,
        "recommended_next_action": recommendation,
        "warnings": _get_warnings(iteration, max_iter, pending, chains)
    }
    
    # FIX 5: Include attack graph if available
    if attack_graph_summary:
        result["attack_graph"] = attack_graph_summary
    
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
    corr_engine: CorrelationEngine | None,
    phase: str
) -> str:
    """Compute recommended next action based on scan state."""
    # Priority 1: Confirmed vulns with chains
    if corr_engine:
        active_chains = corr_engine.get_active_suggestions()
        if active_chains:
            top = active_chains[0]
            return f"Explore chain: {top.chain_name} from {top.trigger_vuln_class}"
    
    # Priority 2: High-scoring hypotheses
    if hyp_ledger:
        scored = hyp_ledger.get_scored_hypotheses()
        if scored:
            top = scored[0]
            return f"Test hypothesis: {top['vuln_class']} on {top['surface'][:40]} (score: {top['priority_score']})"
    
    # Priority 3: Untested surfaces
    if cov_tracker:
        untested = cov_tracker.get_untested_surfaces()
        if untested:
            top = untested[0]
            return f"Test untested surface: {top[:50]}"
    
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
