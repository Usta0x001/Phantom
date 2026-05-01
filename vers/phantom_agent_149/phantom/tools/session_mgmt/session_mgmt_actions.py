"""
Session Management Tools - Phase 2 Enhancement
===============================================

Authentication and session handling for web application testing.
Manages cookies, tokens, CSRF protection, and session state.

SECURITY NOTES:
- Session data is stored locally in memory
- Tokens and cookies are handled securely
- No credentials are logged or exposed
"""

import base64
import hashlib
import json
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# In-memory session storage
_SESSIONS: dict[str, dict[str, Any]] = {}


# CSRF token patterns for extraction
_CSRF_PATTERNS: list[dict[str, Any]] = [
    # Hidden input fields
    {"pattern": r'<input[^>]+name=["\']?(csrf[_-]?token|_?csrf|csrfmiddlewaretoken|_token|authenticity_token|__RequestVerificationToken)["\']?[^>]*value=["\']([^"\']+)["\']', "group": 2},
    {"pattern": r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?(csrf[_-]?token|_?csrf|csrfmiddlewaretoken|_token|authenticity_token|__RequestVerificationToken)["\']?', "group": 1},
    # Meta tags
    {"pattern": r'<meta[^>]+name=["\']?csrf-token["\']?[^>]*content=["\']([^"\']+)["\']', "group": 1},
    {"pattern": r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']?csrf-token["\']?', "group": 1},
    # JavaScript variables
    {"pattern": r'(?:csrf[_-]?token|csrfToken)\s*[=:]\s*["\']([^"\']+)["\']', "group": 1},
    {"pattern": r'window\.__csrf\s*=\s*["\']([^"\']+)["\']', "group": 1},
    # Data attributes
    {"pattern": r'data-csrf[^=]*=["\']([^"\']+)["\']', "group": 1},
]


# Cookie security analysis patterns
_COOKIE_SECURITY_FLAGS = {
    "httponly": {"pattern": r"\bhttponly\b", "severity": "high", "missing_msg": "Cookie missing HttpOnly flag - vulnerable to XSS theft"},
    "secure": {"pattern": r"\bsecure\b", "severity": "high", "missing_msg": "Cookie missing Secure flag - sent over HTTP"},
    "samesite": {"pattern": r"\bsamesite\s*=\s*(strict|lax|none)", "severity": "medium", "missing_msg": "Cookie missing SameSite - CSRF risk"},
}


@register_tool(sandbox_execution=False)
async def create_session(
    session_name: str,
    base_url: str | None = None,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    auth_token: str | None = None,
    auth_type: str = "bearer",
) -> dict[str, Any]:
    """
    Create a new session for authenticated testing.
    
    Creates and stores a session with cookies, headers, and authentication
    tokens for use across multiple requests.
    
    Args:
        session_name: Unique name for this session
        base_url: Base URL for the session (optional)
        cookies: Initial cookies as dict (optional)
        headers: Custom headers as dict (optional)
        auth_token: Authentication token (optional)
        auth_type: Token type - "bearer", "basic", "api_key", "custom" (default: bearer)
    
    Returns:
        Dict with session_id and session details
    """
    session_id = str(uuid.uuid4())[:8]
    
    session_data: dict[str, Any] = {
        "id": session_id,
        "name": session_name,
        "created_at": time.time(),
        "updated_at": time.time(),
        "base_url": base_url,
        "cookies": cookies or {},
        "headers": headers or {},
        "csrf_token": None,
        "auth": None,
    }
    
    # Set up authentication
    if auth_token:
        if auth_type == "bearer":
            session_data["headers"]["Authorization"] = f"Bearer {auth_token}"
            session_data["auth"] = {"type": "bearer", "token_preview": _redact_token(auth_token)}
        elif auth_type == "basic":
            # Assume token is already base64 encoded or "user:pass"
            if ":" in auth_token:
                encoded = base64.b64encode(auth_token.encode()).decode()
                session_data["headers"]["Authorization"] = f"Basic {encoded}"
            else:
                session_data["headers"]["Authorization"] = f"Basic {auth_token}"
            session_data["auth"] = {"type": "basic"}
        elif auth_type == "api_key":
            session_data["headers"]["X-API-Key"] = auth_token
            session_data["auth"] = {"type": "api_key", "header": "X-API-Key"}
        elif auth_type == "custom":
            session_data["auth"] = {"type": "custom", "token_preview": _redact_token(auth_token)}
    
    # Store session
    _SESSIONS[session_id] = session_data
    
    return {
        "success": True,
        "session_id": session_id,
        "session_name": session_name,
        "base_url": base_url,
        "cookie_count": len(session_data["cookies"]),
        "header_count": len(session_data["headers"]),
        "auth_type": auth_type if auth_token else None,
        "message": f"Session '{session_name}' created with ID {session_id}",
    }


@register_tool(sandbox_execution=False)
async def update_session(
    session_id: str,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    csrf_token: str | None = None,
    merge: bool = True,
) -> dict[str, Any]:
    """
    Update an existing session with new data.
    
    Add or update cookies, headers, and CSRF tokens for a session.
    
    Args:
        session_id: Session ID to update
        cookies: Cookies to add/update (optional)
        headers: Headers to add/update (optional)
        csrf_token: CSRF token to store (optional)
        merge: If True, merge with existing data; if False, replace (default: True)
    
    Returns:
        Dict with updated session details
    """
    if session_id not in _SESSIONS:
        return {
            "success": False,
            "error": f"Session '{session_id}' not found",
            "available_sessions": list(_SESSIONS.keys()),
        }
    
    session = _SESSIONS[session_id]
    session["updated_at"] = time.time()
    
    # Update cookies
    if cookies:
        if merge:
            session["cookies"].update(cookies)
        else:
            session["cookies"] = cookies
    
    # Update headers
    if headers:
        if merge:
            session["headers"].update(headers)
        else:
            session["headers"] = headers
    
    # Update CSRF token
    if csrf_token:
        session["csrf_token"] = csrf_token
    
    return {
        "success": True,
        "session_id": session_id,
        "session_name": session["name"],
        "cookie_count": len(session["cookies"]),
        "header_count": len(session["headers"]),
        "has_csrf": session["csrf_token"] is not None,
        "message": f"Session '{session['name']}' updated",
    }


@register_tool(sandbox_execution=False)
async def get_session_info(
    session_id: str | None = None,
    list_all: bool = False,
) -> dict[str, Any]:
    """
    Get information about a session or list all sessions.
    
    Args:
        session_id: Specific session to query (optional)
        list_all: If True, list all active sessions (default: False)
    
    Returns:
        Dict with session details or list of sessions
    """
    if list_all:
        sessions = []
        for sid, session in _SESSIONS.items():
            sessions.append({
                "id": sid,
                "name": session["name"],
                "base_url": session["base_url"],
                "cookie_count": len(session["cookies"]),
                "has_auth": session["auth"] is not None,
                "has_csrf": session["csrf_token"] is not None,
                "age_seconds": int(time.time() - session["created_at"]),
            })
        return {
            "success": True,
            "sessions": sessions,
            "total_count": len(sessions),
        }
    
    if not session_id:
        return {
            "success": False,
            "error": "Either session_id or list_all=True must be provided",
        }
    
    if session_id not in _SESSIONS:
        return {
            "success": False,
            "error": f"Session '{session_id}' not found",
        }
    
    session = _SESSIONS[session_id]
    
    # Prepare safe output (redact sensitive values)
    safe_cookies = {k: _redact_cookie(v) for k, v in session["cookies"].items()}
    safe_headers = {}
    for k, v in session["headers"].items():
        if k.lower() in ["authorization", "x-api-key", "cookie"]:
            safe_headers[k] = _redact_token(v)
        else:
            safe_headers[k] = v
    
    return {
        "success": True,
        "session_id": session_id,
        "name": session["name"],
        "base_url": session["base_url"],
        "cookies": safe_cookies,
        "headers": safe_headers,
        "csrf_token": _redact_token(session["csrf_token"]) if session["csrf_token"] else None,
        "auth": session["auth"],
        "created_at": session["created_at"],
        "updated_at": session["updated_at"],
    }


@register_tool(sandbox_execution=False)
async def extract_csrf_token(
    content: str,
    token_name: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Extract CSRF token from HTML content.
    
    Searches for common CSRF token patterns in HTML and JavaScript.
    Optionally stores the token in a session.
    
    Args:
        content: HTML/JavaScript content to search
        token_name: Specific token name to look for (optional)
        session_id: Session ID to store token in (optional)
    
    Returns:
        Dict with extracted token(s) and metadata
    """
    tokens: list[dict[str, Any]] = []
    
    # Search using predefined patterns
    for pattern_info in _CSRF_PATTERNS:
        try:
            matches = re.findall(pattern_info["pattern"], content, re.IGNORECASE)
            for match in matches:
                # Handle tuple results from groups
                if isinstance(match, tuple):
                    token_value = match[pattern_info["group"] - 1] if len(match) >= pattern_info["group"] else match[0]
                else:
                    token_value = match
                
                if token_value and len(token_value) > 8:  # Filter out likely false positives
                    tokens.append({
                        "token": token_value,
                        "pattern": pattern_info["pattern"][:50] + "...",
                        "length": len(token_value),
                    })
        except re.error:
            continue
    
    # Search for custom token name
    if token_name:
        custom_patterns = [
            f'name=["\']?{re.escape(token_name)}["\']?[^>]*value=["\']([^"\']+)["\']',
            f'value=["\']([^"\']+)["\'][^>]*name=["\']?{re.escape(token_name)}["\']?',
            f'{re.escape(token_name)}\\s*[=:]\\s*["\']([^"\']+)["\']',
        ]
        for pattern in custom_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match and len(match) > 8:
                        tokens.append({
                            "token": match,
                            "name": token_name,
                            "custom": True,
                        })
            except re.error:
                continue
    
    # Deduplicate tokens
    seen: set[str] = set()
    unique_tokens: list[dict[str, Any]] = []
    for t in tokens:
        if t["token"] not in seen:
            seen.add(t["token"])
            unique_tokens.append(t)
    
    # Store in session if specified
    if session_id and unique_tokens:
        if session_id in _SESSIONS:
            _SESSIONS[session_id]["csrf_token"] = unique_tokens[0]["token"]
            _SESSIONS[session_id]["updated_at"] = time.time()
    
    return {
        "success": len(unique_tokens) > 0,
        "tokens": unique_tokens,
        "token_count": len(unique_tokens),
        "primary_token": unique_tokens[0]["token"] if unique_tokens else None,
        "stored_in_session": session_id if (session_id and unique_tokens) else None,
        "message": f"Found {len(unique_tokens)} CSRF token(s)" if unique_tokens else "No CSRF tokens found",
    }


@register_tool(sandbox_execution=False)
async def manage_cookies(
    action: str,
    cookies: str | dict[str, str] | None = None,
    session_id: str | None = None,
    cookie_header: str | None = None,
) -> dict[str, Any]:
    """
    Parse, analyze, and manage cookies.
    
    Actions:
    - parse: Parse Set-Cookie header or cookie string
    - analyze: Analyze cookie security (HttpOnly, Secure, SameSite)
    - export: Export session cookies as Cookie header
    
    Args:
        action: Action to perform - "parse", "analyze", "export"
        cookies: Cookies as string or dict (for parse/analyze)
        session_id: Session ID for export action
        cookie_header: Raw Set-Cookie or Cookie header string
    
    Returns:
        Dict with parsed cookies, security analysis, or export string
    """
    if action == "parse":
        if cookie_header:
            parsed = _parse_cookie_header(cookie_header)
        elif cookies:
            if isinstance(cookies, str):
                parsed = _parse_cookie_string(cookies)
            else:
                parsed = cookies
        else:
            return {"success": False, "error": "No cookies provided to parse"}
        
        return {
            "success": True,
            "cookies": parsed,
            "cookie_count": len(parsed),
        }
    
    elif action == "analyze":
        if not cookie_header:
            return {"success": False, "error": "cookie_header required for analyze action"}
        
        analysis = _analyze_cookie_security(cookie_header)
        return {
            "success": True,
            "analysis": analysis,
        }
    
    elif action == "export":
        if not session_id:
            return {"success": False, "error": "session_id required for export action"}
        
        if session_id not in _SESSIONS:
            return {"success": False, "error": f"Session '{session_id}' not found"}
        
        session_cookies = _SESSIONS[session_id]["cookies"]
        cookie_string = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
        
        return {
            "success": True,
            "cookie_header": cookie_string,
            "cookie_count": len(session_cookies),
        }
    
    return {"success": False, "error": f"Unknown action: {action}"}


# ============================================================================
# Helper Functions
# ============================================================================


def _redact_token(value: str | None) -> str:
    """Redact a token, showing only partial info."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _redact_cookie(value: str) -> str:
    """Redact cookie value."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "..." + value[-3:]


def _parse_cookie_header(header: str) -> dict[str, str]:
    """Parse Set-Cookie or Cookie header."""
    cookies: dict[str, str] = {}
    
    # Handle Set-Cookie (single cookie with attributes)
    if ";" in header and "=" in header:
        parts = header.split(";")
        if parts:
            main_cookie = parts[0].strip()
            if "=" in main_cookie:
                name, value = main_cookie.split("=", 1)
                cookies[name.strip()] = value.strip()
    else:
        # Simple name=value
        if "=" in header:
            name, value = header.split("=", 1)
            cookies[name.strip()] = value.strip()
    
    return cookies


def _parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """Parse Cookie header string (multiple cookies)."""
    cookies: dict[str, str] = {}
    
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    
    return cookies


def _analyze_cookie_security(cookie_header: str) -> dict[str, Any]:
    """Analyze security flags in Set-Cookie header."""
    header_lower = cookie_header.lower()
    
    findings: list[dict[str, Any]] = []
    secure_flags: dict[str, bool] = {}
    
    for flag_name, flag_info in _COOKIE_SECURITY_FLAGS.items():
        match = re.search(flag_info["pattern"], header_lower, re.IGNORECASE)
        if match:
            secure_flags[flag_name] = True
        else:
            secure_flags[flag_name] = False
            findings.append({
                "flag": flag_name,
                "severity": flag_info["severity"],
                "message": flag_info["missing_msg"],
            })
    
    # Check for session cookie indicators
    is_session = any(x in header_lower for x in ["session", "sess", "auth", "token", "jwt"])
    
    # Calculate security score
    score = sum(1 for v in secure_flags.values() if v) / len(secure_flags) * 100
    
    return {
        "secure_flags": secure_flags,
        "findings": findings,
        "finding_count": len(findings),
        "is_session_cookie": is_session,
        "security_score": int(score),
        "recommendation": "Add missing security flags" if findings else "Cookie security looks good",
    }
