"""Findings ledger tools.

Provides a lightweight tool for the agent to record key discoveries
(endpoints, technologies, vulnerabilities, credentials) into a
persistent ledger that survives memory compression.
"""

from typing import Any

from phantom.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def record_finding(
    agent_state: Any,
    finding: str,
    category: str = "general",
) -> dict[str, Any]:
    """Record an important discovery into the persistent findings ledger.

    The findings ledger is NEVER compressed or summarised — it survives
    across memory compression cycles, so anything recorded here is
    guaranteed to remain available for the rest of the scan.

    Use this tool to save:
    - Confirmed vulnerability details (type, location, evidence)
    - Discovered endpoints and API routes
    - Technology versions and stack info
    - Credentials, tokens, secrets found
    - Important observations about target behaviour
    - Dead-end notes (to avoid re-testing)

    Args:
        finding: A concise one-line description of the discovery.
                 Example: "SQLi confirmed at POST /rest/user/login param=email"
        category: Optional category tag (e.g., "vuln", "endpoint", "tech",
                  "credential", "dead-end"). Default: "general"

    Returns:
        Confirmation with current ledger size.
    """
    tagged_finding = f"[{category}] {finding}" if category != "general" else finding

    if hasattr(agent_state, "add_finding"):
        agent_state.add_finding(tagged_finding)
    else:
        # Fallback: append directly if method not available
        if not hasattr(agent_state, "findings_ledger"):
            agent_state.findings_ledger = []
        agent_state.findings_ledger.append(tagged_finding)

    ledger_size = len(getattr(agent_state, "findings_ledger", []))

    return {
        "success": True,
        "message": f"Finding recorded: {tagged_finding}",
        "ledger_size": ledger_size,
    }


@register_tool(sandbox_execution=False)
def get_findings_ledger(
    agent_state: Any,
) -> dict[str, Any]:
    """Retrieve all recorded findings from the persistent ledger.

    Use this to review what has been discovered so far and avoid
    duplicate testing.

    Returns:
        Complete list of recorded findings with count.
    """
    ledger = getattr(agent_state, "findings_ledger", [])

    return {
        "success": True,
        "total_findings": len(ledger),
        "findings": list(ledger),
    }
