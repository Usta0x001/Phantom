"""
Fuzzer Tool Actions — Registered tools for AI-guided parallel fuzzing.

CRITICAL: LLM generates ALL payloads. No static lists.
"""

from typing import Any, Literal

from phantom.tools.registry import register_tool


InjectionPoint = Literal["param", "header", "body", "path"]


@register_tool
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


@register_tool
def get_fuzz_results(
    batch_id: str | None = None,
) -> dict[str, Any]:
    """
    Get results from previous fuzz batches.

    Use this to retrieve detailed results for analysis.

    Args:
        batch_id: Specific batch to retrieve, or None for all batches

    Returns:
        Fuzz results with status codes, response times, lengths, and markers
    """
    from .fuzzer_manager import get_fuzzer_manager

    manager = get_fuzzer_manager()
    return manager.get_results(batch_id=batch_id)


@register_tool
def clear_fuzz_results(
    batch_id: str | None = None,
) -> dict[str, Any]:
    """
    Clear fuzzing results to free memory.

    Use this to clean up old batch results that are no longer needed.

    Args:
        batch_id: Specific batch to clear, or None to clear all

    Returns:
        Summary of cleared results
    """
    from .fuzzer_manager import get_fuzzer_manager

    manager = get_fuzzer_manager()
    return manager.clear_results(batch_id=batch_id)
