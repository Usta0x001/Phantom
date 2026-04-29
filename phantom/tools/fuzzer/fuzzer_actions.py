"""
Fuzzer Tool Actions — Registered tools for AI-guided parallel fuzzing.

CRITICAL: LLM generates ALL payloads. No static lists.
"""

from typing import Any, Literal

from phantom.tools.registry import register_tool


InjectionPoint = Literal["param", "header", "body", "path"]


# NOTE: fuzzer module not available in sandbox container.
# Re-add @register_tool decorator if container is rebuilt with fuzzer support.
def execute_fuzz_batch(
    base_url: str,
    method: str,
    payloads: list[str],
    injection_point: InjectionPoint,
    param_name: str | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """
    Execute a batch of AI-generated payloads in parallel.

    Use this when you want to test multiple payloads against the same endpoint.
    You MUST generate the payloads yourself based on the context - do NOT use
    static payload lists.

    Args:
        base_url: Target URL (use {FUZZ} marker for path injection)
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        payloads: List of payloads YOU generated for this specific test
        injection_point: Where to inject - "param", "header", "body", or "path"
        param_name: Parameter/header name (required for param/header injection)
        headers: Additional HTTP headers to include
        timeout_seconds: Request timeout in seconds

    Returns:
        Batch execution results with response codes, times, lengths, and anomalies

    Example:
        # Testing for SQL injection - YOU generate payloads based on context
        execute_fuzz_batch(
            base_url="https://target.com/api/users",
            method="GET",
            payloads=["' OR '1'='1", "1 UNION SELECT NULL--", "admin'--"],
            injection_point="param",
            param_name="id"
        )
    """
    from .fuzzer_manager import get_fuzzer_manager

    manager = get_fuzzer_manager()
    return manager.execute_batch(
        base_url=base_url,
        method=method,
        payloads=payloads,
        injection_point=injection_point,
        param_name=param_name,
        headers=headers,
        timeout_seconds=timeout_seconds,
    )




