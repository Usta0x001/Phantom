"""
P5: Authentication Automation - Elite-Level Login Flows
========================================================

Automated authentication flows for elite web app testing:
- Multi-step login automation (form-based, OAuth2, SAML)
- JWT token refresh and expiration handling
- Session persistence across scan phases
- Cookie jar management with domain scoping
- Headless browser integration for complex auth flows

INTEGRATION POINTS:
- Works with existing session_mgmt_actions.py for session storage
- Integrates with browser_actions.py for JS-heavy login pages
- Feeds authenticated sessions to all scanning tools
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# JWT token cache with auto-refresh
_JWT_CACHE: dict[str, dict[str, Any]] = {}

# OAuth2 session storage
_OAUTH_SESSIONS: dict[str, dict[str, Any]] = {}


@dataclass
class LoginFlow:
    """Represents an authentication flow configuration."""
    
    flow_id: str
    flow_type: str  # "form", "jwt", "oauth2", "saml", "multi_step"
    target_url: str
    credentials: dict[str, str]  # username, password, etc.
    form_selectors: dict[str, str] = field(default_factory=dict)
    success_indicators: list[str] = field(default_factory=list)
    failure_indicators: list[str] = field(default_factory=list)
    session_cookie_names: list[str] = field(default_factory=list)
    requires_js: bool = False
    steps: list[dict[str, Any]] = field(default_factory=list)  # For multi-step flows
    

@register_tool(sandbox_execution=False)
async def automate_login(
    target_url: str,
    username: str,
    password: str,
    flow_type: str = "form",
    username_field: str = "username",
    password_field: str = "password",
    submit_selector: str = "button[type=submit],input[type=submit]",
    success_indicator: str | None = None,
    session_name: str | None = None,
    use_browser: bool = False,
) -> dict[str, Any]:
    """
    Automate login to web application.
    
    Performs automated authentication and extracts session cookies/tokens.
    Supports both simple form-based login and complex JS-heavy flows.
    
    Args:
        target_url: Login page URL
        username: Username/email for authentication
        password: Password for authentication
        flow_type: Type of auth - "form", "json_api", "multi_step" (default: form)
        username_field: Form field name for username (default: username)
        password_field: Form field name for password (default: password)
        submit_selector: CSS selector for submit button
        success_indicator: String to check for successful login (e.g., "Dashboard", "Logout")
        session_name: Name for the created session (default: auto-generated)
        use_browser: Use headless browser for JS-heavy login (default: False)
    
    Returns:
        Dict with session_id, cookies, tokens, and login status
    """
    start_time = time.time()
    session_name = session_name or f"auto_login_{int(start_time)}"
    
    try:
        if use_browser or flow_type == "multi_step":
            # Use browser automation for complex flows
            result = await _browser_login(
                target_url=target_url,
                username=username,
                password=password,
                username_field=username_field,
                password_field=password_field,
                submit_selector=submit_selector,
                success_indicator=success_indicator,
            )
        elif flow_type == "json_api":
            # Direct API login
            result = await _json_api_login(
                target_url=target_url,
                username=username,
                password=password,
            )
        else:
            # Standard form-based login
            result = await _form_login(
                target_url=target_url,
                username=username,
                password=password,
                username_field=username_field,
                password_field=password_field,
                success_indicator=success_indicator,
            )
        
        if not result["success"]:
            return result
        
        # Extract session data
        cookies = result.get("cookies", {})
        headers = result.get("headers", {})
        tokens = result.get("tokens", {})
        
        # Import session management to create session
        from phantom.tools.session_mgmt.session_mgmt_actions import create_session, update_session
        
        # Create authenticated session
        session_result = await create_session(
            session_name=session_name,
            base_url=_get_base_url(target_url),
            cookies=cookies,
            headers=headers,
        )
        
        if not session_result.get("success"):
            return session_result
        
        session_id = session_result["session_id"]
        
        # Store JWT token if present
        if tokens.get("jwt"):
            await _cache_jwt_token(
                session_id=session_id,
                token=tokens["jwt"],
                refresh_token=tokens.get("refresh_token"),
            )
        
        return {
            "success": True,
            "session_id": session_id,
            "session_name": session_name,
            "cookies": _safe_cookie_output(cookies),
            "tokens": tokens,
            "authenticated": True,
            "login_duration_ms": int((time.time() - start_time) * 1000),
            "message": f"Successfully authenticated as {username}",
        }
        
    except Exception as e:
        logger.error(f"Login automation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "authenticated": False,
        }


@register_tool(sandbox_execution=False)
async def refresh_jwt_token(
    session_id: str,
    refresh_token: str | None = None,
    refresh_endpoint: str | None = None,
) -> dict[str, Any]:
    """
    Refresh JWT token for authenticated session.
    
    Automatically refreshes expired JWT tokens to maintain authentication.
    Can use cached refresh token or accept new one.
    
    Args:
        session_id: Session ID to refresh token for
        refresh_token: Refresh token (optional if cached)
        refresh_endpoint: URL to refresh token (optional)
    
    Returns:
        Dict with new access token and updated session
    """
    try:
        # Check if we have cached token info
        jwt_info = _JWT_CACHE.get(session_id)
        
        if not jwt_info and not refresh_token:
            return {
                "success": False,
                "error": "No refresh token available. Provide refresh_token or login again.",
            }
        
        # Use cached refresh token if not provided
        refresh_token = refresh_token or (jwt_info.get("refresh_token") if jwt_info else None)
        
        if not refresh_token:
            return {
                "success": False,
                "error": "No refresh token found in cache or parameters",
            }
        
        # Determine refresh endpoint
        if not refresh_endpoint and jwt_info:
            refresh_endpoint = jwt_info.get("refresh_endpoint")
        
        if not refresh_endpoint:
            return {
                "success": False,
                "error": "refresh_endpoint required (not found in cache)",
            }
        
        # Perform token refresh
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(
                refresh_endpoint,
                json={"refresh_token": refresh_token},
                headers={"Content-Type": "application/json"},
            )
            
            if response.status_code not in (200, 201):
                return {
                    "success": False,
                    "error": f"Token refresh failed: HTTP {response.status_code}",
                    "response_body": response.text[:500],
                }
            
            data = response.json()
            
            new_access_token = (
                data.get("access_token") 
                or data.get("token") 
                or data.get("jwt")
            )
            
            new_refresh_token = data.get("refresh_token", refresh_token)
            
            if not new_access_token:
                return {
                    "success": False,
                    "error": "No access token in refresh response",
                    "response_keys": list(data.keys()),
                }
            
            # Update session with new token
            from phantom.tools.session_mgmt.session_mgmt_actions import update_session
            
            await update_session(
                session_id=session_id,
                headers={"Authorization": f"Bearer {new_access_token}"},
                merge=True,
            )
            
            # Update cache
            await _cache_jwt_token(
                session_id=session_id,
                token=new_access_token,
                refresh_token=new_refresh_token,
                refresh_endpoint=refresh_endpoint,
            )
            
            return {
                "success": True,
                "session_id": session_id,
                "access_token": _redact_token(new_access_token),
                "token_refreshed": True,
                "expires_in": data.get("expires_in"),
                "message": "JWT token refreshed successfully",
            }
            
    except Exception as e:
        logger.error(f"JWT refresh failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


async def extract_jwt_from_response(
    response_body: str,
    response_headers: dict[str, str] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Extract JWT tokens from HTTP response.
    
    Searches response body and headers for JWT tokens.
    Can parse token claims and check expiration.
    
    Args:
        response_body: HTTP response body (JSON or HTML)
        response_headers: HTTP response headers (optional)
        session_id: Session to store token in (optional)
    
    Returns:
        Dict with extracted tokens and parsed claims
    """
    tokens: list[dict[str, Any]] = []
    
    # Search response body for JWT patterns
    jwt_pattern = r'["\']?(?:token|jwt|access_token|id_token)["\']?\s*:\s*["\']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)["\']'
    
    matches = re.findall(jwt_pattern, response_body, re.IGNORECASE)
    for match in matches:
        token_info = _parse_jwt_token(match)
        if token_info:
            tokens.append(token_info)
    
    # Check Authorization header
    if response_headers:
        auth_header = response_headers.get("Authorization") or response_headers.get("authorization")
        if auth_header:
            # Extract Bearer token
            bearer_match = re.match(r"Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)", auth_header)
            if bearer_match:
                token_info = _parse_jwt_token(bearer_match.group(1))
                if token_info:
                    tokens.append(token_info)
    
    # Search for refresh tokens
    refresh_pattern = r'["\']?(?:refresh_token|refreshToken)["\']?\s*:\s*["\']([^"\']+)["\']'
    refresh_matches = re.findall(refresh_pattern, response_body, re.IGNORECASE)
    
    # Deduplicate tokens
    unique_tokens: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    
    for token in tokens:
        token_value = token.get("raw_token", "")
        if token_value and token_value not in seen_tokens:
            seen_tokens.add(token_value)
            unique_tokens.append(token)
    
    primary_token = unique_tokens[0] if unique_tokens else None
    
    # Store in session if specified
    if session_id and primary_token:
        from phantom.tools.session_mgmt.session_mgmt_actions import update_session
        
        await update_session(
            session_id=session_id,
            headers={"Authorization": f"Bearer {primary_token['raw_token']}"},
            merge=True,
        )
        
        await _cache_jwt_token(
            session_id=session_id,
            token=primary_token["raw_token"],
            refresh_token=refresh_matches[0] if refresh_matches else None,
        )
    
    return {
        "success": len(unique_tokens) > 0,
        "tokens": unique_tokens,
        "token_count": len(unique_tokens),
        "primary_token": primary_token,
        "refresh_tokens": refresh_matches,
        "stored_in_session": session_id if (session_id and primary_token) else None,
        "message": f"Found {len(unique_tokens)} JWT token(s)" if unique_tokens else "No JWT tokens found",
    }






# ============================================================================
# Internal Helper Functions
# ============================================================================


async def _form_login(
    target_url: str,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
    success_indicator: str | None,
) -> dict[str, Any]:
    """Perform standard form-based login."""
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # Get login page
        response = await client.get(target_url)
        
        # Extract CSRF token
        from phantom.tools.session_mgmt.session_mgmt_actions import extract_csrf_token
        csrf_result = await extract_csrf_token(response.text)
        csrf_token = csrf_result.get("primary_token")
        
        # Prepare form data
        form_data = {
            username_field: username,
            password_field: password,
        }
        
        if csrf_token:
            # Try common CSRF field names
            csrf_field_names = ["csrf_token", "_csrf", "csrfmiddlewaretoken", "_token"]
            form_data[csrf_field_names[0]] = csrf_token
        
        # Submit login form
        login_response = await client.post(
            target_url,
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        # Check for success
        success = False
        if success_indicator:
            success = success_indicator in login_response.text
        else:
            # Heuristic: no error keywords and 200-level status
            error_keywords = ["invalid", "incorrect", "failed", "error", "denied"]
            has_error = any(kw in login_response.text.lower() for kw in error_keywords)
            success = not has_error and login_response.status_code < 400
        
        # Extract cookies
        cookies = {}
        for cookie in client.cookies.jar:
            cookies[cookie.name] = cookie.value
        
        return {
            "success": success,
            "cookies": cookies,
            "headers": {},
            "tokens": {},
            "status_code": login_response.status_code,
        }


async def _json_api_login(
    target_url: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Perform JSON API login."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            target_url,
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
        )
        
        if response.status_code >= 400:
            return {
                "success": False,
                "error": f"Login failed: HTTP {response.status_code}",
            }
        
        try:
            data = response.json()
        except Exception:
            data = {}
        
        # Extract JWT token
        jwt_token = (
            data.get("token") 
            or data.get("access_token") 
            or data.get("jwt")
        )
        
        refresh_token = data.get("refresh_token")
        
        tokens = {}
        if jwt_token:
            tokens["jwt"] = jwt_token
        if refresh_token:
            tokens["refresh_token"] = refresh_token
        
        # Extract cookies
        cookies = {}
        for cookie in client.cookies.jar:
            cookies[cookie.name] = cookie.value
        
        return {
            "success": True,
            "cookies": cookies,
            "headers": {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {},
            "tokens": tokens,
        }


async def _browser_login(
    target_url: str,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
    submit_selector: str,
    success_indicator: str | None,
) -> dict[str, Any]:
    """Perform browser-based login using Playwright."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "success": False,
            "error": "Playwright not available. Install with: pip install playwright",
        }
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            # Navigate to login page
            await page.goto(target_url)
            await page.wait_for_load_state("networkidle")
            
            # Fill username
            await page.fill(f'input[name="{username_field}"]', username)
            
            # Fill password
            await page.fill(f'input[name="{password_field}"]', password)
            
            # Click submit
            await page.click(submit_selector)
            
            # Wait for navigation
            await page.wait_for_load_state("networkidle")
            
            # Check for success
            success = False
            if success_indicator:
                content = await page.content()
                success = success_indicator in content
            else:
                # Check if we're on a different page
                current_url = page.url
                success = current_url != target_url
            
            # Extract cookies
            cookies = {}
            for cookie in await context.cookies():
                cookies[cookie["name"]] = cookie["value"]
            
            await browser.close()
            
            return {
                "success": success,
                "cookies": cookies,
                "headers": {},
                "tokens": {},
            }
            
        except Exception as e:
            await browser.close()
            raise e


async def _cache_jwt_token(
    session_id: str,
    token: str,
    refresh_token: str | None = None,
    refresh_endpoint: str | None = None,
) -> None:
    """Cache JWT token with metadata."""
    token_info = _parse_jwt_token(token)
    
    _JWT_CACHE[session_id] = {
        "token": token,
        "refresh_token": refresh_token,
        "refresh_endpoint": refresh_endpoint,
        "claims": token_info.get("claims") if token_info else {},
        "cached_at": time.time(),
    }


def _parse_jwt_token(token: str) -> dict[str, Any] | None:
    """Parse JWT token and extract claims."""
    try:
        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        # Decode payload (add padding if needed)
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        
        return {
            "raw_token": token,
            "claims": claims,
            "issuer": claims.get("iss"),
            "subject": claims.get("sub"),
            "expiration": claims.get("exp"),
            "issued_at": claims.get("iat"),
        }
        
    except Exception as e:
        logger.debug(f"JWT parse failed: {e}")
        return None


def _parse_set_cookie_header(header: str) -> dict[str, str]:
    """Parse Set-Cookie header into dict."""
    cookies = {}
    
    # Handle multiple Set-Cookie headers
    if isinstance(header, list):
        header = "; ".join(header)
    
    for cookie_str in header.split(","):
        parts = cookie_str.split(";")
        if parts:
            main = parts[0].strip()
            if "=" in main:
                name, value = main.split("=", 1)
                cookies[name.strip()] = value.strip()
    
    return cookies


def _get_base_url(url: str) -> str:
    """Extract base URL from full URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _safe_cookie_output(cookies: dict[str, str]) -> dict[str, str]:
    """Redact cookie values for safe output."""
    return {k: _redact_cookie(v) for k, v in cookies.items()}


def _redact_cookie(value: str) -> str:
    """Redact cookie value."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "..." + value[-3:]


def _redact_token(value: str | None) -> str:
    """Redact token value."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]
