"""
Payload Generation Tools - Phase 2 Enhancement
===============================================

Context-aware payload generation for web application penetration testing.
Generates XSS, SQLi, XXE, and other injection payloads based on detected
technology stack and context.

SECURITY NOTES:
- Payloads are generated locally - no external API calls
- All tools follow RBAC and audit logging
- Payloads are context-aware to maximize effectiveness
"""

from phantom.tools.payload_gen.payload_gen_actions import (
    generate_smart_payloads,
)

__all__ = [
    "generate_smart_payloads",
]
