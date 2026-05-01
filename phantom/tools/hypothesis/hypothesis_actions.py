"""
Hypothesis Ledger Tools — LLM-Accessible Interface
==================================================

Exposes the hypothesis ledger to the LLM via tool calls, allowing
the agent to query, add, and update hypotheses during a scan.
"""

from __future__ import annotations

import threading
from typing import Any, TYPE_CHECKING

from phantom.tools.context import get_current_agent_id
from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    from phantom.agents.hypothesis_ledger import HypothesisLedger

# FIX Bug #3: Use dict keyed by agent_id instead of single global.
# This prevents sub-agents from overwriting each other's ledgers.
_LEDGERS_BY_AGENT: dict[str, "HypothesisLedger"] = {}
_HYPOTHESIS_CONTEXT_LOCK = threading.RLock()


def _resolve_agent_id(agent_id: str | None = None) -> str:
    if agent_id and str(agent_id).strip():
        return str(agent_id).strip()

    current = (get_current_agent_id() or "").strip()
    if current and current != "default":
        return current

    return "default"


def _require_active_ledger() -> HypothesisLedger:
    ledger = _get_active_ledger()
    if ledger is None:
        raise ValueError("agent_id required")
    return ledger


def set_ledger(ledger: "HypothesisLedger", agent_id: str | None = None) -> None:
    """Set the hypothesis ledger instance for a specific agent.
    
    Args:
        ledger: The HypothesisLedger instance
        agent_id: The agent ID to associate with this ledger (default: "default")
    """
    resolved = _resolve_agent_id(agent_id)
    with _HYPOTHESIS_CONTEXT_LOCK:
        _LEDGERS_BY_AGENT[resolved] = ledger


def set_global_ledger(ledger: HypothesisLedger) -> None:
    """Backward-compatible alias for tests and older call sites."""
    set_ledger(ledger, "default")


def get_ledger(agent_id: str | None = None) -> HypothesisLedger | None:
    """Get the hypothesis ledger instance for a specific agent.
    
    Args:
        agent_id: The agent ID to get ledger for (default: "default")
    
    Returns:
        The HypothesisLedger instance or None
    """
    resolved = _resolve_agent_id(agent_id)
    with _HYPOTHESIS_CONTEXT_LOCK:
        return _LEDGERS_BY_AGENT.get(resolved)


def clear_hypothesis_context(agent_id: str | None = None) -> None:
    """Clear hypothesis context (all or one agent)."""
    if agent_id is None:
        with _HYPOTHESIS_CONTEXT_LOCK:
            _LEDGERS_BY_AGENT.clear()
        return

    resolved = _resolve_agent_id(agent_id)
    with _HYPOTHESIS_CONTEXT_LOCK:
        _LEDGERS_BY_AGENT.pop(resolved, None)


def _get_active_ledger() -> HypothesisLedger | None:
    """Get the active ledger - tries new dict-based approach first, falls back to global."""
    try:
        from phantom.tools.context import get_current_agent_id

        current_agent_id = get_current_agent_id()
    except Exception:
        current_agent_id = None
    return get_ledger(current_agent_id or "default")


@register_tool(sandbox_execution=False)
def add_hypothesis(surface: str, vuln_class: str) -> dict[str, Any]:
    """
    Add a new hypothesis to the ledger.
    
    A hypothesis represents a potential vulnerability at a specific
    attack surface (URL + parameter) for a specific vulnerability class.
    
    Args:
        surface: Attack surface identifier (e.g., "/api/login::username")
        vuln_class: Vulnerability class (e.g., "sqli", "xss", "idor")
    
    Returns:
        Dictionary with:
        - success: Whether the hypothesis was added
        - hypothesis_id: The ID of the hypothesis
        - is_new: Whether this is a new hypothesis or existing
        - message: Status message
    
    Example:
        add_hypothesis(
            surface="/api/users::id",
            vuln_class="idor"
        )
    """
    # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
    _ledger = _require_active_ledger()
    
    # Check if already exists
    existing = _ledger.find_by_surface_and_class(surface, vuln_class)
    is_new = existing is None
    
    # Add (will dedupe internally)
    hyp_id = _ledger.add(surface, vuln_class)
    
    return {
        "success": True,
        "hypothesis_id": hyp_id,
        "is_new": is_new,
        "surface": surface,
        "vuln_class": vuln_class,
        "message": f"{'Created new' if is_new else 'Found existing'} hypothesis {hyp_id}",
    }


@register_tool(sandbox_execution=False)
async def record_payload_test(
    hypothesis_id: str,
    payload: str,
    outcome: str,
    evidence: str = "",
) -> dict[str, Any]:
    """
    Record that a payload was tested for a hypothesis.
    
    This prevents redundant testing and tracks evidence for/against
    the vulnerability hypothesis.
    
    Args:
        hypothesis_id: The hypothesis ID (e.g., "H-0001")
        payload: The payload that was tested
        outcome: Test outcome: "success" or "failure"
        evidence: Evidence from the test (response differences, errors, etc.)
    
    Returns:
        Dictionary with:
        - success: Whether the record was added
        - hypothesis_status: Current status of the hypothesis
        - message: Status message
    
    Example:
        record_payload_test(
            hypothesis_id="H-0001",
            payload="' OR '1'='1",
            outcome="success",
            evidence="SQL error: syntax error near OR"
        )
    """
    # FIX Bug #4: Use _get_active_ledger() with proper validation
    _ledger = _require_active_ledger()
    
    # FIX Bug #4: Validate hypothesis_id exists before recording
    hyp = _ledger.get(hypothesis_id)
    if not hyp:
        return {
            "success": False,
            "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
        }
    
    # Record the payload
    _ledger.record_payload(hypothesis_id, payload)
    
    # Add evidence
    if outcome == "success" and evidence:
        _ledger.add_evidence_for(hypothesis_id, evidence)
    elif outcome == "failure" and evidence:
        _ledger.add_evidence_against(hypothesis_id, evidence)

    # Get current status
    hyp = _ledger.get(hypothesis_id)
    status = hyp.status if hyp else "unknown"
    
    return {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "hypothesis_status": status,
        "payload": payload,
        "outcome": outcome,
        "message": f"Recorded {outcome} for {hypothesis_id} (now {status})",
    }


@register_tool(sandbox_execution=False)
async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any]:
    """
    Confirm a hypothesis as a valid vulnerability.
    
    Args:
        hypothesis_id: The hypothesis ID (e.g., "H-0001")
        evidence: Evidence confirming the vulnerability
    
    Returns:
        Dictionary with success status, hypothesis ID, and any detected chains.
    
    Example:
        confirm_hypothesis(
            hypothesis_id="H-0042",
            evidence="SQL error: 'You have an error in your SQL syntax near...' confirmed SQLi"
        )
    """
    # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
    _ledger = _require_active_ledger()
    
    # FIX Bug #4: Validate hypothesis_id exists
    hyp = _ledger.get(hypothesis_id)
    if not hyp:
        return {
            "success": False,
            "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
        }
    
    _ledger.confirm(hypothesis_id, evidence)
    
    hyp = _ledger.get(hypothesis_id)
    status = hyp.status if hyp else "unknown"

    response = {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "status": "confirmed",
        "message": f"Confirmed {hypothesis_id} as valid vulnerability",
    }
    
    return response


@register_tool(sandbox_execution=False)
async def reject_hypothesis(hypothesis_id: str, reason: str) -> dict[str, Any]:
    """
    Mark a hypothesis as rejected (not vulnerable).
    
    Args:
        hypothesis_id: The hypothesis ID
        reason: Reason for rejection
    
    Returns:
        Dictionary with success status and message.
    
    Example:
        reject_hypothesis(
            hypothesis_id="H-0001",
            reason="WAF blocks all SQL injection attempts"
        )
    """
    # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
    _ledger = _require_active_ledger()
    
    # FIX Bug #4: Validate hypothesis_id exists
    hyp = _ledger.get(hypothesis_id)
    if not hyp:
        return {
            "success": False,
            "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
        }
    
    _ledger.reject(hypothesis_id, reason)
    
    return {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "status": "rejected",
        "message": f"Rejected {hypothesis_id}: {reason}",
    }


@register_tool(sandbox_execution=False)
def query_hypotheses(
    status: str | None = None,
    vuln_class: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """
    Query hypotheses from the ledger.
    
    Retrieve hypotheses by status and/or vulnerability class.
    Useful for finding open hypotheses to test or reviewing confirmed findings.
    
    Args:
        status: Filter by status: "open", "testing", "confirmed", "rejected"
        vuln_class: Filter by vulnerability class: "sqli", "xss", "idor", etc.
        limit: Maximum number of hypotheses to return
    
    Returns:
        Dictionary with:
        - hypotheses: List of matching hypotheses
        - count: Number of hypotheses returned
        - total: Total hypotheses in ledger
    
    Example:
        # Get open SQLi hypotheses
        query_hypotheses(status="open", vuln_class="sqli")
        
        # Get all confirmed vulnerabilities
        query_hypotheses(status="confirmed")
    """
    # Get all hypotheses
    _ledger = _require_active_ledger()
    
    all_hyps = list(_ledger.get_all().values())
    
    # Filter by status
    if status:
        all_hyps = [h for h in all_hyps if h.status == status]
    
    # Filter by vuln_class
    if vuln_class:
        all_hyps = [h for h in all_hyps if h.vuln_class == vuln_class]
    
    # Limit
    result_hyps = all_hyps[:limit]
    
    return {
        "success": True,
        "hypotheses": [h.to_dict() for h in result_hyps],
        "count": len(result_hyps),
        "total": len(_ledger.get_all()),
        "message": f"Found {len(result_hyps)} hypotheses",
    }


@register_tool(sandbox_execution=False)
def get_hypothesis_summary() -> dict[str, Any]:
    """
    Get a summary of all hypotheses in the ledger.
    
    Returns statistics and top hypotheses for quick overview.
    
    Returns:
        Dictionary with:
        - total: Total hypotheses
        - by_status: Count by status
        - by_vuln_class: Count by vulnerability class
        - top_confirmed: Top confirmed vulnerabilities
        - top_open: Top open hypotheses to test
    
    Example:
        get_hypothesis_summary()
    """
    _ledger = _require_active_ledger()
    
    summary = _ledger.get_summary()
    
    all_hyps = _ledger.get_all()
    confirmed = [h.to_dict() for h in all_hyps.values() if h.status == "confirmed"]
    open_hyps = [h.to_dict() for h in all_hyps.values() if h.status == "open"]
    
    return {
        "success": True,
        "total": summary.get("total", 0),
        "by_status": summary.get("by_status", {}),
        "by_vuln_class": summary.get("by_class", {}),
        "top_confirmed": confirmed[:5],
        "top_open": open_hyps[:10],
        "prioritized_summary": _ledger.get_scored_hypotheses()[:10],
        "message": f"Ledger contains {summary.get('total', 0)} hypotheses",
    }


@register_tool(sandbox_execution=False)
def has_tested_payload(surface: str, vuln_class: str, payload: str) -> dict[str, Any]:
    """
    Check if a payload has already been tested for a surface/vuln_class.
    
    Prevents redundant testing by checking the hypothesis ledger.
    
    Args:
        surface: Attack surface (e.g., "/api/login::username")
        vuln_class: Vulnerability class (e.g., "sqli")
        payload: The payload to check
    
    Returns:
        Dictionary with:
        - tested: Whether the payload was already tested
        - hypothesis_id: ID of the hypothesis (if exists)
        - message: Status message
    
    Example:
        has_tested_payload(
            surface="/api/users::id",
            vuln_class="sqli",
            payload="' OR 1=1--"
        )
    """
    _ledger = _require_active_ledger()
    
    tested = _ledger.has_tested(surface, vuln_class, payload)
    
    # Find hypothesis if it exists
    hyp = _ledger.find_by_surface_and_class(surface, vuln_class)
    hyp_id = hyp.id if hyp else None
    
    return {
        "success": True,
        "tested": tested,
        "hypothesis_id": hyp_id,
        "surface": surface,
        "vuln_class": vuln_class,
        "message": f"Payload {'already tested' if tested else 'not yet tested'}",
    }
