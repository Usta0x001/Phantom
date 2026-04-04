"""
Session Management Tools - Phase 2 Enhancement
===============================================

Authentication and session handling for web application testing.
Manages cookies, tokens, and session state across requests.
"""

from phantom.tools.session_mgmt.session_mgmt_actions import (
    create_session,
    update_session,
    get_session_info,
    extract_csrf_token,
    manage_cookies,
)

__all__ = [
    "create_session",
    "update_session",
    "get_session_info",
    "extract_csrf_token",
    "manage_cookies",
]
