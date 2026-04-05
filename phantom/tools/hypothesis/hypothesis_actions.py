"""
Hypothesis Ledger Tools — LLM-Accessible Interface
===================================================

Exposes the hypothesis ledger to the LLM via tool calls, allowing
the agent to query, add, and update hypotheses during a scan.

This solves the import error in base_agent.py and provides a clean
interface for hypothesis management.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    from phantom.agents.hypothesis_ledger import HypothesisLedger

# Global ledger instance (set by base_agent.py during initialization)
_GLOBAL_LEDGER: HypothesisLedger | None = None


def set_ledger(ledger: HypothesisLedger) -> None:
    """Set the global hypothesis ledger instance."""
    global _GLOBAL_LEDGER
    _GLOBAL_LEDGER = ledger


def get_ledger() -> HypothesisLedger | None:
    """Get the global hypothesis ledger instance."""
    return _GLOBAL_LEDGER


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "hypothesis_id": None,
        }
    
    # Check if already exists
    existing = _GLOBAL_LEDGER.find_by_surface_and_class(surface, vuln_class)
    is_new = existing is None
    
    # Add (will dedupe internally)
    hyp_id = _GLOBAL_LEDGER.add(surface, vuln_class)
    
    return {
        "success": True,
        "hypothesis_id": hyp_id,
        "is_new": is_new,
        "surface": surface,
        "vuln_class": vuln_class,
        "message": f"{'Created new' if is_new else 'Found existing'} hypothesis {hyp_id}",
    }


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    # Record the payload
    _GLOBAL_LEDGER.record_payload(hypothesis_id, payload)
    
    # Add evidence
    if outcome == "success" and evidence:
        await _GLOBAL_LEDGER.add_evidence_for(hypothesis_id, evidence, outcome)
    elif outcome == "failure" and evidence:
        await _GLOBAL_LEDGER.add_evidence_against(hypothesis_id, evidence, outcome)
    
    # Get current status
    hyp = _GLOBAL_LEDGER.get(hypothesis_id)
    status = hyp.status if hyp else "unknown"
    
    return {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "hypothesis_status": status,
        "payload": payload,
        "outcome": outcome,
        "message": f"Recorded {outcome} for {hypothesis_id} (now {status})",
    }


@register_tool
async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any]:
    """
    Mark a hypothesis as confirmed (vulnerability found).
    
    Args:
        hypothesis_id: The hypothesis ID
        evidence: Strong evidence of the vulnerability
    
    Returns:
        Dictionary with success status and message.
    
    Example:
        confirm_hypothesis(
            hypothesis_id="H-0001",
            evidence="Extracted database schema with UNION injection"
        )
    """
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    await _GLOBAL_LEDGER.confirm(hypothesis_id, evidence)
    
    return {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "status": "confirmed",
        "message": f"Confirmed {hypothesis_id} as valid vulnerability",
    }


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    await _GLOBAL_LEDGER.reject(hypothesis_id, reason)
    
    return {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "status": "rejected",
        "message": f"Rejected {hypothesis_id}: {reason}",
    }


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "hypotheses": [],
        }
    
    # Get all hypotheses
    all_hyps = list(_GLOBAL_LEDGER.get_all().values())
    
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
        "total": len(_GLOBAL_LEDGER.get_all()),
        "message": f"Found {len(result_hyps)} hypotheses",
    }


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    summary = _GLOBAL_LEDGER.get_summary()
    
    # Get top confirmed and open
    all_hyps = _GLOBAL_LEDGER.get_all()
    confirmed = [h.to_dict() for h in all_hyps.values() if h.status == "confirmed"]
    open_hyps = [h.to_dict() for h in all_hyps.values() if h.status == "open"]
    
    return {
        "success": True,
        "total": summary.get("total", 0),
        "by_status": summary.get("by_status", {}),
        "by_vuln_class": summary.get("by_class", {}),
        "top_confirmed": confirmed[:5],
        "top_open": open_hyps[:10],
        "message": f"Ledger contains {summary.get('total', 0)} hypotheses",
    }


@register_tool
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
    if not _GLOBAL_LEDGER:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "tested": False,
        }
    
    tested = _GLOBAL_LEDGER.has_tested(surface, vuln_class, payload)
    
    # Find hypothesis if it exists
    hyp = _GLOBAL_LEDGER.find_by_surface_and_class(surface, vuln_class)
    hyp_id = hyp.id if hyp else None
    
    return {
        "success": True,
        "tested": tested,
        "hypothesis_id": hyp_id,
        "surface": surface,
        "vuln_class": vuln_class,
        "message": f"Payload {'already tested' if tested else 'not yet tested'}",
    }
