"""
OAST Tool Actions — Registered tools for out-of-band testing.

These are pure executor functions - LLM decides when to use them.
They return DATA not commands.
"""

from typing import Any, Literal

from phantom.tools.registry import register_tool


OASTType = Literal["http", "dns", "smtp", "ldap"]


# NOTE: oast module not available in sandbox container.
# Re-add @register_tool decorator if container is rebuilt with oast support.
def generate_oast_payload(
    payload_type: OASTType,
    context: str,
    target_surface: str,
) -> dict[str, Any]:
    """
    Generate an OAST callback payload for blind vulnerability testing.

    Use this when testing for vulnerabilities that don't produce visible output
    but might cause the server to make external requests (blind SSRF, XXE, RCE, etc.).

    Args:
        payload_type: Type of callback - "http", "dns", "smtp", or "ldap"
        context: What vulnerability you're testing - "ssrf", "xxe", "rce", "sqli_oob", "log4j"
        target_surface: Where you'll inject the payload (URL, parameter name, etc.)

    Returns:
        Payload details including callback_url and raw_payload to inject
    """
    from .oast_manager import get_oast_manager

    manager = get_oast_manager()
    return manager.generate_payload(payload_type, context, target_surface)


# NOTE: oast module not available in sandbox container.
# Re-add @register_tool decorator if container is rebuilt with oast support.
def check_oast_interactions(
    payload_id: str | None = None,
) -> dict[str, Any]:
    """
    Check for out-of-band interactions on OAST payloads.

    Call this after injecting OAST payloads to see if any callbacks were received.
    Interactions indicate the server made a request to the callback URL, confirming
    a blind vulnerability.

    Args:
        payload_id: Specific payload to check, or None to check all payloads

    Returns:
        Interaction data including source IPs and timestamps
    """
    from .oast_manager import get_oast_manager

    manager = get_oast_manager()
    return manager.check_interactions(payload_id)




