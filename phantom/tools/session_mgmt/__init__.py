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

from phantom.tools.session_mgmt.auth_automation import (
    automate_login,
    refresh_jwt_token,
    extract_jwt_from_response,
    check_jwt_expiration,
    multi_step_login,
)

__all__ = [
    "create_session",
    "update_session",
    "get_session_info",
    "extract_csrf_token",
    "manage_cookies",
    "automate_login",
    "refresh_jwt_token",
    "extract_jwt_from_response",
    "check_jwt_expiration",
    "multi_step_login",
]
