"""
Fuzzer Tool — AI-guided parallel fuzzing for web applications.

This tool allows the LLM to generate payloads and execute them in parallel.
NO STATIC PAYLOAD LISTS - LLM creates all payloads.
"""

from .fuzzer_actions import (
    execute_fuzz_batch,
    get_fuzz_results,
    clear_fuzz_results,
)

__all__ = [
    "execute_fuzz_batch",
    "get_fuzz_results",
    "clear_fuzz_results",
]
