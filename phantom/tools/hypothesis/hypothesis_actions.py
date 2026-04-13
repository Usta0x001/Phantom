"""
Hypothesis Ledger Tools — LLM-Accessible Interface
===================================================

Exposes the hypothesis ledger to the LLM via tool calls, allowing
the agent to query, add, and update hypotheses during a scan.

FIX 4: Integrated with correlation engine to enable automatic
vulnerability chain detection when hypotheses are confirmed.

This solves the import error in base_agent.py and provides a clean
interface for hypothesis management.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    from phantom.agents.correlation_engine import CorrelationEngine

# FIX Bug #3: Use dict keyed by agent_id instead of single global
# This prevents sub-agents from overwriting each other's ledgers
_LEDGERS_BY_AGENT: dict[str, HypothesisLedger] = {}

# FIX 4: Global correlation engine instance for chain detection
_GLOBAL_CORRELATION_ENGINE: CorrelationEngine | None = None


def set_correlation_engine(engine: CorrelationEngine) -> None:
    """Set the global correlation engine instance."""
    global _GLOBAL_CORRELATION_ENGINE
    _GLOBAL_CORRELATION_ENGINE = engine


def set_ledger(ledger: HypothesisLedger, agent_id: str = "default") -> None:
    """Set the hypothesis ledger instance for a specific agent.
    
    Args:
        ledger: The HypothesisLedger instance
        agent_id: The agent ID to associate with this ledger (default: "default")
    """
    global _LEDGERS_BY_AGENT
    _LEDGERS_BY_AGENT[agent_id] = ledger


def get_ledger(agent_id: str = "default") -> HypothesisLedger | None:
    """Get the hypothesis ledger instance for a specific agent.
    
    Args:
        agent_id: The agent ID to get ledger for (default: "default")
    
    Returns:
        The HypothesisLedger instance or None
    """
    return _LEDGERS_BY_AGENT.get(agent_id)


def _get_active_ledger() -> HypothesisLedger | None:
    """Get the active ledger - tries new dict-based approach first, falls back to global."""
    # Try dict-based approach first (new fix for Bug #3)
    ledger = get_ledger("default")
    if ledger is not None:
        return ledger
    
    # Try global for backward compatibility
    if _GLOBAL_LEDGER is not None:
        return _GLOBAL_LEDGER
    
    return None


# Backward compatibility alias - for setting global when not using agent_id
def set_global_ledger(ledger: HypothesisLedger) -> None:
    """Set the global hypothesis ledger instance (backward compatibility)."""
    global _GLOBAL_LEDGER
    _GLOBAL_LEDGER = ledger


# Global ledger instance (for backward compatibility)
_GLOBAL_LEDGER: HypothesisLedger | None = None


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
    # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "hypothesis_id": None,
        }
    
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
    # FIX Bug #4: Use _get_active_ledger() with proper validation
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
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
        await _ledger.add_evidence_for(hypothesis_id, evidence, outcome)
    elif outcome == "failure" and evidence:
        await _ledger.add_evidence_against(hypothesis_id, evidence, outcome)

    if _GLOBAL_CORRELATION_ENGINE is not None and hyp:
        payload_family = _ledger._make_payload_family(hyp.vuln_class, payload)
        learned_outcome = "testing"
        if str(outcome).strip().lower() == "failure":
            learned_outcome = "rejected"
        _GLOBAL_CORRELATION_ENGINE.record_outcome(
            vuln_class=hyp.vuln_class,
            surface=hyp.surface,
            outcome=learned_outcome,
            payload_family=payload_family,
            evidence_strength=1.0,
        )
    
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


@register_tool
async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any]:
    """
    Confirm a hypothesis as a valid vulnerability.
    
    FIX 4: Now automatically adds the finding to the correlation engine
    to enable vulnerability chain detection (e.g., SSRF → cloud metadata).
    
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
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    # FIX Bug #4: Validate hypothesis_id exists
    hyp = _ledger.get(hypothesis_id)
    if not hyp:
        return {
            "success": False,
            "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
        }
    
    await _ledger.confirm(hypothesis_id, evidence)
    
    # FIX 4: Add finding to correlation engine for chain detection
    new_chains = []
    if _GLOBAL_CORRELATION_ENGINE is not None:
        hyp = _ledger.get(hypothesis_id)
        if hyp:
            # Determine severity from vulnerability class
            severity_map = {
                "sqli": "high",
                "rce": "critical",
                "cmd_injection": "critical",
                "ssti": "critical",
                "ssrf": "high",
                "xxe": "high",
                "lfi": "high",
                "xss": "medium",
                "idor": "medium",
                "auth_bypass": "critical",
            }
            severity = severity_map.get(hyp.vuln_class.lower(), "medium")
            
            result = _GLOBAL_CORRELATION_ENGINE.add_finding(
                vuln_class=hyp.vuln_class.lower(),
                surface=hyp.surface,
                severity=severity,
                details={
                    "hypothesis_id": hypothesis_id,
                    "evidence": evidence,
                    "outcome": "confirmed",
                    "payload_family": (
                        _ledger._make_payload_family(
                            hyp.vuln_class,
                            hyp.successful_payloads[-1],
                        )
                        if hyp.successful_payloads
                        else None
                    ),
                    "tested_at": hyp.last_updated,  # FIX Bug #2: Use last_updated instead of non-existent tested_at
                }
            )
            new_chains = result.get("new_suggestions", [])
    
    response = {
        "success": True,
        "hypothesis_id": hypothesis_id,
        "status": "confirmed",
        "message": f"Confirmed {hypothesis_id} as valid vulnerability",
    }
    
    # FIX 4: Include chain suggestions in response
    if new_chains:
        response["chain_opportunities"] = new_chains
        response["message"] += f" | {len(new_chains)} vulnerability chain(s) detected!"
    
    return response
    # FIX Bug #1: DELETE unreachable dead code below (lines 282-289)
    # This code was unreachable because return statement above exits function


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
    # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    # FIX Bug #4: Validate hypothesis_id exists
    hyp = _ledger.get(hypothesis_id)
    if not hyp:
        return {
            "success": False,
            "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
        }
    
    await _ledger.reject(hypothesis_id, reason)

    if _GLOBAL_CORRELATION_ENGINE is not None and hyp:
        _GLOBAL_CORRELATION_ENGINE.record_outcome(
            vuln_class=hyp.vuln_class,
            surface=hyp.surface,
            outcome="rejected",
            payload_family=None,
            evidence_strength=1.0,
        )
    
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
    # Get all hypotheses
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "hypotheses": [],
        }
    
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
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
        }
    
    summary = _ledger.get_summary()
    
    # Get top confirmed and open
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
        "prioritized_summary": _ledger.get_prioritized_summary(top_n=10),
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
    _ledger = _get_active_ledger()
    if _ledger is None:
        return {
            "success": False,
            "error": "Hypothesis ledger not initialized",
            "tested": False,
        }
    
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
