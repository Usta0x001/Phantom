"""
OAST (Out-of-band Application Security Testing) Tool

Provides out-of-band interaction detection for blind vulnerability testing.
This is a pure executor tool - the LLM decides when and how to use it.

Key features:
- Generate unique callback URLs/payloads
- Track interactions asynchronously
- Detect blind SSRF, XXE, command injection, etc.
- Returns DATA (interactions detected) not commands
"""

from .oast_actions import (
    generate_oast_payload,
    check_oast_interactions,
    list_oast_payloads,
    clear_oast_payloads,
)

__all__ = [
    "generate_oast_payload",
    "check_oast_interactions",
    "list_oast_payloads",
    "clear_oast_payloads",
]
