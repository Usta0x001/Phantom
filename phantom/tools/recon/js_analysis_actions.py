"""
JavaScript Endpoint Extraction — Priority 2 Enhancement
========================================================

Extracts API endpoints, parameters, authentication patterns, and potential secrets
from JavaScript files. Supports both static fetching and dynamic browser-based extraction.

SECURITY NOTES:
- Passive analysis of JS files (no modification)
- Detects hardcoded secrets, API keys, tokens
- Identifies authentication patterns and headers
- Extracts REST/GraphQL endpoints for fuzzing
- Feeds discovered surfaces into coverage tracker

Tools:
- fetch_js_files: Fetch all JavaScript files from a URL
- extract_endpoints: Extract API endpoints from JS content
- extract_secrets: Detect potential secrets/credentials
- analyze_js_frameworks: Detect frontend frameworks and their routing
- comprehensive_js_analysis: Full JS reconnaissance pipeline
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx

from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Cache for JS analysis results
_JS_ANALYSIS_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 3600  # 1 hour


# ============================================================================
# Pattern Definitions
# ============================================================================

# API endpoint patterns - comprehensive regex collection
_ENDPOINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # REST API patterns
    ("fetch_url", re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("fetch_template", re.compile(r'fetch\s*\(\s*`([^`]+)`', re.IGNORECASE)),
    ("axios_url", re.compile(r'axios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("axios_config", re.compile(r'axios\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("xhr_open", re.compile(r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("jquery_ajax", re.compile(r'\$\s*\.\s*(?:ajax|get|post|put|delete)\s*\(\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("jquery_ajax_obj", re.compile(r'\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    
    # URL string patterns (general)
    ("url_pattern", re.compile(r'[\'"`](/api/[^\'"`,\s]{2,100})[\'"`]', re.IGNORECASE)),
    ("url_v_pattern", re.compile(r'[\'"`](/v[0-9]+/[^\'"`,\s]{2,100})[\'"`]', re.IGNORECASE)),
    ("graphql_endpoint", re.compile(r'[\'"`](/graphql[^\'"`,\s]*)[\'"`]', re.IGNORECASE)),
    ("rest_endpoint", re.compile(r'[\'"`](/rest/[^\'"`,\s]{2,100})[\'"`]', re.IGNORECASE)),
    
    # Full URLs
    ("full_api_url", re.compile(r'[\'"`](https?://[^\'"`,\s]+/api/[^\'"`,\s]*)[\'"`]', re.IGNORECASE)),
    ("full_url", re.compile(r'[\'"`](https?://[^\'"`,\s]+/v[0-9]+/[^\'"`,\s]*)[\'"`]', re.IGNORECASE)),
    
    # Route definitions (frameworks)
    ("express_route", re.compile(r'(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("path_constant", re.compile(r'(?:PATH|URL|ENDPOINT|API_URL|BASE_URL)\s*[=:]\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    
    # WebSocket endpoints
    ("websocket_url", re.compile(r'new\s+WebSocket\s*\(\s*[\'"`](wss?://[^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("socket_io", re.compile(r'io\s*\(\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
]

# Parameter patterns
_PARAM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Query parameters in URLs
    ("url_params", re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,50})=', re.IGNORECASE)),
    
    # Object properties that look like params
    ("object_params", re.compile(r'(?:params|query|data|body)\s*[=:]\s*\{([^}]+)\}', re.IGNORECASE)),
    
    # FormData appends
    ("formdata_append", re.compile(r'\.append\s*\(\s*[\'"`]([a-zA-Z_][a-zA-Z0-9_]{0,50})[\'"`]', re.IGNORECASE)),
    
    # URLSearchParams
    ("search_params", re.compile(r'URLSearchParams\s*\([^)]*[\'"`]([a-zA-Z_][a-zA-Z0-9_]{0,50})[\'"`]', re.IGNORECASE)),
    
    # JSON keys in requests
    ("json_keys", re.compile(r'JSON\.stringify\s*\(\s*\{([^}]+)\}', re.IGNORECASE)),
]

# Authentication header patterns
_AUTH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bearer_token", re.compile(r'[\'"`](Bearer\s+[^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("auth_header", re.compile(r'[\'"`]Authorization[\'"`]\s*[=:]\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("api_key_header", re.compile(r'[\'"`](?:X-API-Key|X-Api-Key|Api-Key|apikey)[\'"`]\s*[=:]\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("token_header", re.compile(r'[\'"`](?:X-Token|X-Auth-Token|Token)[\'"`]\s*[=:]\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("cookie_auth", re.compile(r'[\'"`]Cookie[\'"`]\s*[=:]\s*[\'"`]([^\'"`,\s]+)[\'"`]', re.IGNORECASE)),
    ("basic_auth", re.compile(r'[\'"`](Basic\s+[A-Za-z0-9+/=]+)[\'"`]', re.IGNORECASE)),
]

# Secret patterns - high-entropy strings and known formats
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # API Keys - various formats
    ("aws_access_key", "AWS Access Key ID", re.compile(r'(?:AKIA|A3T|AGPA|AIPA|AROA|ASCA|AIDA)[A-Z0-9]{16}')),
    ("aws_secret_key", "AWS Secret Access Key", re.compile(r'[\'"`]([A-Za-z0-9/+=]{40})[\'"`]')),
    ("google_api_key", "Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("google_oauth", "Google OAuth Token", re.compile(r'ya29\.[0-9A-Za-z\-_]+')),
    ("github_token", "GitHub Token", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}')),
    ("github_oauth", "GitHub OAuth", re.compile(r'gho_[A-Za-z0-9_]{36}')),
    ("slack_token", "Slack Token", re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}')),
    ("slack_webhook", "Slack Webhook", re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+')),
    ("stripe_key", "Stripe API Key", re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}')),
    ("stripe_pk", "Stripe Publishable Key", re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}')),
    ("twilio_sid", "Twilio Account SID", re.compile(r'AC[a-f0-9]{32}')),
    ("twilio_token", "Twilio Auth Token", re.compile(r'SK[a-f0-9]{32}')),
    ("firebase_key", "Firebase API Key", re.compile(r'[\'"`]([A-Za-z0-9_-]{39})[\'"`]')),
    ("mailgun_key", "Mailgun API Key", re.compile(r'key-[a-f0-9]{32}')),
    ("sendgrid_key", "SendGrid API Key", re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}')),
    ("square_token", "Square Access Token", re.compile(r'sq0atp-[A-Za-z0-9_-]{22}')),
    ("square_oauth", "Square OAuth Secret", re.compile(r'sq0csp-[A-Za-z0-9_-]{43}')),
    ("paypal_token", "PayPal/Braintree Token", re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}')),
    ("heroku_key", "Heroku API Key", re.compile(r'[\'"`]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\'"`]')),
    ("npm_token", "NPM Token", re.compile(r'npm_[A-Za-z0-9]{36}')),
    
    # Generic patterns
    ("jwt_token", "JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*')),
    ("private_key", "Private Key Block", re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("generic_secret", "Generic Secret", re.compile(r'(?:secret|password|passwd|pwd|api_key|apikey|api-key|auth_token|access_token|private_key|client_secret)\s*[=:]\s*[\'"`]([^\'"`,\s]{8,100})[\'"`]', re.IGNORECASE)),
    ("bearer_literal", "Bearer Token Literal", re.compile(r'Bearer\s+[A-Za-z0-9._-]{20,}')),
    ("base64_secret", "Base64 Encoded Secret", re.compile(r'(?:secret|key|token|password)[\'"`]?\s*[=:]\s*[\'"`]([A-Za-z0-9+/]{40,}={0,2})[\'"`]', re.IGNORECASE)),
]

# Framework detection patterns
_FRAMEWORK_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "react": [
        ("react_import", re.compile(r'(?:import|require)\s*\(?[\'"`]react[\'"`]', re.IGNORECASE)),
        ("react_dom", re.compile(r'ReactDOM\.render|createRoot', re.IGNORECASE)),
        ("jsx_pragma", re.compile(r'@jsx|React\.createElement')),
        ("use_state", re.compile(r'useState|useEffect|useContext')),
    ],
    "react_router": [
        ("router_import", re.compile(r'react-router|@reach/router')),
        ("route_component", re.compile(r'<Route\s+[^>]*path\s*=\s*[\'"`]([^\'"`,]+)[\'"`]', re.IGNORECASE)),
        ("link_component", re.compile(r'<Link\s+[^>]*to\s*=\s*[\'"`]([^\'"`,]+)[\'"`]', re.IGNORECASE)),
        ("use_navigate", re.compile(r'useNavigate|useHistory|useLocation')),
    ],
    "angular": [
        ("angular_core", re.compile(r'@angular/core|angular\.module')),
        ("ng_component", re.compile(r'@Component|@NgModule')),
        ("router_module", re.compile(r'RouterModule|@angular/router')),
        ("http_client", re.compile(r'HttpClient|HttpClientModule')),
    ],
    "vue": [
        ("vue_import", re.compile(r'(?:import|require)\s*\(?[\'"`]vue[\'"`]')),
        ("vue_component", re.compile(r'Vue\.component|createApp|defineComponent')),
        ("vue_router", re.compile(r'vue-router|VueRouter|createRouter')),
        ("vue_template", re.compile(r'<template>|\.vue[\'"`]')),
    ],
    "next_js": [
        ("next_import", re.compile(r'(?:import|require)\s*\(?[\'"`]next')),
        ("next_link", re.compile(r'import\s+Link\s+from\s+[\'"`]next/link')),
        ("next_router", re.compile(r'import\s+\{\s*useRouter|next/router')),
        ("next_api", re.compile(r'pages/api/|/api/.*\.ts')),
    ],
    "nuxt": [
        ("nuxt_config", re.compile(r'nuxt\.config|@nuxt/')),
        ("async_data", re.compile(r'asyncData|useFetch|useAsyncData')),
        ("nuxt_link", re.compile(r'<NuxtLink|<nuxt-link')),
    ],
    "jquery": [
        ("jquery_ready", re.compile(r'\$\s*\(\s*(?:document|function|\(\s*\))')),
        ("jquery_ajax", re.compile(r'\$\.ajax|\$\.get|\$\.post')),
        ("jquery_selector", re.compile(r'\$\s*\(\s*[\'"`][#.][^\'"`,]+')),
    ],
    "axios": [
        ("axios_import", re.compile(r'(?:import|require)\s*\(?[\'"`]axios[\'"`]')),
        ("axios_create", re.compile(r'axios\.create|axios\.defaults')),
        ("axios_interceptor", re.compile(r'axios\.interceptors')),
    ],
    "graphql": [
        ("graphql_import", re.compile(r'(?:import|require)\s*\(?[\'"`](?:graphql|@apollo)')),
        ("gql_tag", re.compile(r'gql`|graphql`')),
        ("graphql_query", re.compile(r'query\s+\w+\s*(?:\([^)]*\))?\s*\{')),
        ("graphql_mutation", re.compile(r'mutation\s+\w+\s*(?:\([^)]*\))?\s*\{')),
    ],
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ExtractedEndpoint:
    """Represents an extracted API endpoint."""
    url: str
    method: str = "GET"
    source_pattern: str = ""
    context: str = ""
    parameters: list[str] = field(default_factory=list)
    is_authenticated: bool = False
    auth_type: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "source_pattern": self.source_pattern,
            "context": self.context,
            "parameters": self.parameters,
            "is_authenticated": self.is_authenticated,
            "auth_type": self.auth_type,
        }


@dataclass
class ExtractedSecret:
    """Represents a potential secret found in JS."""
    type: str
    description: str
    value: str
    context: str = ""
    severity: str = "high"
    
    def to_dict(self) -> dict[str, Any]:
        # Redact most of the secret value for safety
        redacted = self.value[:4] + "..." + self.value[-4:] if len(self.value) > 10 else "***"
        return {
            "type": self.type,
            "description": self.description,
            "value_preview": redacted,
            "full_value": self.value,  # Include full for hypothesis generation
            "context": self.context,
            "severity": self.severity,
        }


@dataclass
class FrameworkInfo:
    """Detected frontend framework information."""
    name: str
    confidence: float
    routes: list[str] = field(default_factory=list)
    api_patterns: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "confidence": self.confidence,
            "routes": self.routes,
            "api_patterns": self.api_patterns,
        }


# ============================================================================
# Helper Functions
# ============================================================================

def _normalize_endpoint(url: str, base_url: str | None = None) -> str:
    """Normalize an endpoint URL."""
    url = url.strip()
    
    # Skip data URIs, javascript:, etc.
    if url.startswith(('data:', 'javascript:', 'mailto:', '#', 'blob:')):
        return ""
    
    # Handle template literals with variables
    url = re.sub(r'\$\{[^}]+\}', '{param}', url)
    url = re.sub(r'\{\{[^}]+\}\}', '{param}', url)
    
    # If it's a relative URL and we have a base, resolve it
    if base_url and not url.startswith(('http://', 'https://', '//')):
        url = urljoin(base_url, url)
    
    # Clean up the URL
    url = url.split('?')[0]  # Remove query string for deduplication
    url = url.rstrip('/')
    
    return url


def _extract_context(content: str, match: re.Match[str], context_chars: int = 100) -> str:
    """Extract surrounding context for a regex match."""
    start = max(0, match.start() - context_chars)
    end = min(len(content), match.end() + context_chars)
    
    context = content[start:end]
    # Clean up for readability
    context = re.sub(r'\s+', ' ', context).strip()
    
    return context


def _detect_http_method(context: str) -> str:
    """Detect HTTP method from context."""
    context_lower = context.lower()
    
    if any(kw in context_lower for kw in ['post', '.post(', 'method: "post', "method: 'post"]):
        return "POST"
    if any(kw in context_lower for kw in ['put', '.put(', 'method: "put', "method: 'put"]):
        return "PUT"
    if any(kw in context_lower for kw in ['delete', '.delete(', 'method: "delete', "method: 'delete"]):
        return "DELETE"
    if any(kw in context_lower for kw in ['patch', '.patch(', 'method: "patch', "method: 'patch"]):
        return "PATCH"
    if any(kw in context_lower for kw in ['head', '.head(']):
        return "HEAD"
    if any(kw in context_lower for kw in ['options', '.options(']):
        return "OPTIONS"
    
    return "GET"


def _is_valid_endpoint(url: str) -> bool:
    """Check if the extracted URL looks like a valid API endpoint."""
    if not url or len(url) < 2:
        return False
    
    # Skip obvious non-endpoints
    skip_patterns = [
        r'^\./', r'^\.\.',  # Relative paths like ./
        r'\.(?:css|scss|less|sass|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm|mp3|pdf)$',  # Static files
        r'^(?:true|false|null|undefined|NaN)$',  # JS literals
        r'^\d+$',  # Pure numbers
        r'^[a-zA-Z]$',  # Single letters
        r'localhost:\d+$',  # Just localhost
    ]
    
    for pattern in skip_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return False
    
    return True


async def _fetch_url(url: str, timeout: float = 30.0) -> tuple[str, dict[str, Any]]:
    """Fetch content from a URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/javascript, text/javascript, */*",
    }
    
    metadata: dict[str, Any] = {
        "url": url,
        "status": None,
        "content_type": None,
        "size": 0,
        "error": None,
    }
    
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            metadata["status"] = response.status_code
            metadata["content_type"] = response.headers.get("content-type", "")
            
            if response.status_code == 200:
                content = response.text
                metadata["size"] = len(content)
                return content, metadata
            else:
                metadata["error"] = f"HTTP {response.status_code}"
                return "", metadata
                
    except Exception as e:
        metadata["error"] = str(e)[:200]
        return "", metadata


# ============================================================================
# Core Analysis Functions
# ============================================================================

def _extract_endpoints_from_content(
    content: str,
    base_url: str | None = None,
) -> list[ExtractedEndpoint]:
    """Extract all API endpoints from JavaScript content."""
    endpoints: list[ExtractedEndpoint] = []
    seen_urls: set[str] = set()
    
    for pattern_name, pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            url = match.group(1)
            normalized = _normalize_endpoint(url, base_url)
            
            if not normalized or not _is_valid_endpoint(normalized):
                continue
            
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)
            
            context = _extract_context(content, match)
            method = _detect_http_method(context)
            
            # Check for authentication patterns in context
            is_auth = bool(re.search(r'(?:auth|token|bearer|api[_-]?key|credential)', context, re.IGNORECASE))
            auth_type = None
            if is_auth:
                if 'bearer' in context.lower():
                    auth_type = "Bearer"
                elif 'basic' in context.lower():
                    auth_type = "Basic"
                elif re.search(r'api[_-]?key', context, re.IGNORECASE):
                    auth_type = "API Key"
            
            endpoints.append(ExtractedEndpoint(
                url=normalized,
                method=method,
                source_pattern=pattern_name,
                context=context[:200],
                is_authenticated=is_auth,
                auth_type=auth_type,
            ))
    
    return endpoints


def _extract_parameters_from_content(content: str) -> list[str]:
    """Extract potential parameter names from JavaScript content."""
    params: set[str] = set()
    
    for pattern_name, pattern in _PARAM_PATTERNS:
        for match in pattern.finditer(content):
            captured = match.group(1)
            
            if pattern_name in ("object_params", "json_keys"):
                # Extract individual keys from object notation
                keys = re.findall(r'[\'"`]?([a-zA-Z_][a-zA-Z0-9_]{0,50})[\'"`]?\s*:', captured)
                params.update(keys)
            else:
                params.add(captured)
    
    # Filter out common non-parameter names
    skip_params = {
        'function', 'return', 'const', 'let', 'var', 'class', 'import', 'export',
        'true', 'false', 'null', 'undefined', 'this', 'async', 'await',
        'if', 'else', 'for', 'while', 'switch', 'case', 'break', 'continue',
    }
    
    return sorted([p for p in params if p.lower() not in skip_params])


def _extract_secrets_from_content(content: str) -> list[ExtractedSecret]:
    """Extract potential secrets and credentials from JavaScript content."""
    secrets: list[ExtractedSecret] = []
    seen_values: set[str] = set()
    
    for secret_type, description, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            # Get the full match or first group
            value = match.group(1) if match.lastindex else match.group(0)
            
            # Skip if we've seen this value
            value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
            if value_hash in seen_values:
                continue
            seen_values.add(value_hash)
            
            # Validate the finding
            # Skip short values for generic patterns
            if secret_type in ("generic_secret", "base64_secret") and len(value) < 16:
                continue
            
            # Skip obvious false positives
            if value.lower() in ('undefined', 'null', 'example', 'test', 'demo', 'sample'):
                continue
            
            context = _extract_context(content, match, 50)
            
            # Determine severity
            severity = "high"
            if secret_type in ("generic_secret", "base64_secret"):
                severity = "medium"
            if "test" in context.lower() or "example" in context.lower():
                severity = "low"
            
            secrets.append(ExtractedSecret(
                type=secret_type,
                description=description,
                value=value,
                context=context,
                severity=severity,
            ))
    
    return secrets


def _detect_frameworks(content: str) -> list[FrameworkInfo]:
    """Detect frontend frameworks and extract routing information."""
    frameworks: list[FrameworkInfo] = []
    
    for framework_name, patterns in _FRAMEWORK_PATTERNS.items():
        matches = 0
        routes: list[str] = []
        api_patterns: list[str] = []
        
        for pattern_name, pattern in patterns:
            found = pattern.findall(content)
            if found:
                matches += 1
                
                # Extract routes from specific patterns
                if 'route' in pattern_name.lower() or 'link' in pattern_name.lower():
                    for route in found:
                        if isinstance(route, str) and route.startswith('/'):
                            routes.append(route)
                
                # Extract API patterns
                if 'api' in pattern_name.lower() or 'query' in pattern_name.lower():
                    for api in found:
                        if isinstance(api, str):
                            api_patterns.append(api)
        
        if matches > 0:
            confidence = min(matches / len(patterns), 1.0)
            if confidence >= 0.3:  # At least 30% of patterns matched
                frameworks.append(FrameworkInfo(
                    name=framework_name,
                    confidence=round(confidence, 2),
                    routes=list(set(routes))[:20],
                    api_patterns=list(set(api_patterns))[:20],
                ))
    
    # Sort by confidence
    frameworks.sort(key=lambda x: x.confidence, reverse=True)
    
    return frameworks


# ============================================================================
# Tool Implementations
# ============================================================================

@register_tool(sandbox_execution=False)
async def fetch_js_files(
    url: str,
    use_browser: bool = False,
    include_inline: bool = True,
    max_files: int = 50,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Fetch all JavaScript files from a webpage.
    
    Extracts both external JS file references and inline script content.
    Can optionally use browser automation to capture dynamically loaded JS.
    
    Args:
        url: Target webpage URL
        use_browser: Use Playwright for dynamic JS extraction (slower but more complete)
        include_inline: Include inline <script> content
        max_files: Maximum number of JS files to fetch (default: 50)
        timeout: Timeout per request in seconds
    
    Returns:
        Dictionary containing:
        - success: Whether fetch succeeded
        - url: The target URL
        - js_files: List of JS file objects with url, content, size
        - inline_scripts: List of inline script contents (if include_inline)
        - total_size: Total size of all JS content
        - message: Status message
    
    Example:
        result = await fetch_js_files("https://example.com")
    """
    if not url:
        return {"success": False, "error": "URL is required", "js_files": []}
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    start_time = time.time()
    js_files: list[dict[str, Any]] = []
    inline_scripts: list[str] = []
    errors: list[str] = []
    
    try:
        # Fetch the main page
        page_content, page_meta = await _fetch_url(url, timeout)
        
        if not page_content:
            return {
                "success": False,
                "error": page_meta.get("error", "Failed to fetch page"),
                "url": url,
                "js_files": [],
            }
        
        # Parse base URL for relative paths
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Extract external JS file URLs
        external_patterns = [
            re.compile(r'<script[^>]+src\s*=\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]', re.IGNORECASE),
            re.compile(r'<script[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
        ]
        
        js_urls: set[str] = set()
        for pattern in external_patterns:
            for match in pattern.finditer(page_content):
                js_url = match.group(1)
                # Skip data URIs
                if js_url.startswith('data:'):
                    continue
                    
                # Resolve relative URLs
                if js_url.startswith('//'):
                    js_url = f"{parsed.scheme}:{js_url}"
                elif js_url.startswith('/'):
                    js_url = f"{base_url}{js_url}"
                elif not js_url.startswith('http'):
                    js_url = urljoin(url, js_url)
                
                js_urls.add(js_url)
        
        # Fetch external JS files concurrently
        async def fetch_js_file(js_url: str) -> dict[str, Any] | None:
            try:
                content, meta = await _fetch_url(js_url, timeout)
                if content:
                    return {
                        "url": js_url,
                        "content": content,
                        "size": len(content),
                        "status": meta.get("status"),
                    }
                else:
                    errors.append(f"Failed to fetch {js_url}: {meta.get('error')}")
                    return None
            except Exception as e:
                errors.append(f"Error fetching {js_url}: {str(e)[:100]}")
                return None
        
        # Limit concurrent fetches
        js_url_list = list(js_urls)[:max_files]
        tasks = [fetch_js_file(u) for u in js_url_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result:
                js_files.append(result)
        
        # Extract inline scripts
        if include_inline:
            inline_pattern = re.compile(
                r'<script[^>]*>([^<]+)</script>',
                re.IGNORECASE | re.DOTALL
            )
            for match in inline_pattern.finditer(page_content):
                script_content = match.group(1).strip()
                # Skip empty or very short scripts
                if script_content and len(script_content) > 20:
                    inline_scripts.append(script_content)
        
        elapsed = time.time() - start_time
        total_size = sum(f.get("size", 0) for f in js_files)
        total_size += sum(len(s) for s in inline_scripts)
        
        return {
            "success": True,
            "url": url,
            "js_files": js_files,
            "js_file_count": len(js_files),
            "inline_scripts": inline_scripts if include_inline else [],
            "inline_count": len(inline_scripts),
            "total_size": total_size,
            "total_size_kb": round(total_size / 1024, 2),
            "errors": errors if errors else None,
            "elapsed_seconds": round(elapsed, 2),
            "message": f"Fetched {len(js_files)} JS files and {len(inline_scripts)} inline scripts ({total_size // 1024}KB total)",
        }
        
    except Exception as e:
        logger.error(f"Error fetching JS files from {url}: {e}")
        return {
            "success": False,
            "error": str(e)[:200],
            "url": url,
            "js_files": [],
        }


@register_tool(sandbox_execution=False)
async def extract_endpoints(
    content: str | None = None,
    url: str | None = None,
    include_parameters: bool = True,
    include_auth_patterns: bool = True,
) -> dict[str, Any]:
    """
    Extract API endpoints from JavaScript content or a URL.
    
    Parses JavaScript for REST API calls, GraphQL endpoints, WebSocket URLs,
    and other backend communication patterns.
    
    Args:
        content: JavaScript content to analyze (provide this OR url)
        url: URL to fetch and analyze (if content not provided)
        include_parameters: Also extract parameter names
        include_auth_patterns: Detect authentication headers/patterns
    
    Returns:
        Dictionary containing:
        - success: Whether extraction succeeded
        - endpoints: List of extracted endpoints with metadata
        - parameters: List of discovered parameter names
        - auth_patterns: Detected authentication patterns
        - message: Status message
    
    Example:
        # From URL
        result = await extract_endpoints(url="https://example.com/app.js")
        
        # From content
        result = await extract_endpoints(content=js_code)
    """
    if not content and not url:
        return {
            "success": False,
            "error": "Either content or url must be provided",
            "endpoints": [],
        }
    
    # Fetch content if URL provided
    if url and not content:
        content, meta = await _fetch_url(url)
        if not content:
            return {
                "success": False,
                "error": meta.get("error", "Failed to fetch URL"),
                "url": url,
                "endpoints": [],
            }
        base_url = url
    
    if not content:
        return {
            "success": False,
            "error": "No content available to analyze",
            "endpoints": [],
        }
    
    # Extract endpoints
    endpoints = _extract_endpoints_from_content(content, base_url)
    
    # Extract parameters if requested
    parameters: list[str] = []
    if include_parameters:
        parameters = _extract_parameters_from_content(content)
    
    # Extract auth patterns if requested
    auth_patterns: list[dict[str, str]] = []
    if include_auth_patterns:
        for pattern_name, pattern in _AUTH_PATTERNS:
            for match in pattern.finditer(content):
                auth_patterns.append({
                    "type": pattern_name,
                    "value_preview": match.group(1)[:20] + "..." if len(match.group(1)) > 20 else match.group(1),
                    "context": _extract_context(content, match, 50),
                })
    
    return {
        "success": True,
        "url": url,
        "endpoints": [e.to_dict() for e in endpoints],
        "endpoint_count": len(endpoints),
        "parameters": parameters,
        "parameter_count": len(parameters),
        "auth_patterns": auth_patterns if auth_patterns else None,
        "message": f"Extracted {len(endpoints)} endpoints and {len(parameters)} parameters",
    }


@register_tool(sandbox_execution=False)
async def extract_secrets(
    content: str | None = None,
    url: str | None = None,
    severity_filter: str | None = None,
) -> dict[str, Any]:
    """
    Detect potential secrets, API keys, and credentials in JavaScript.
    
    Scans for known secret patterns (AWS keys, Stripe keys, JWT tokens, etc.)
    and high-entropy strings that may be credentials.
    
    WARNING: This tool may expose sensitive information. Handle results carefully.
    
    Args:
        content: JavaScript content to analyze (provide this OR url)
        url: URL to fetch and analyze
        severity_filter: Filter by severity: "high", "medium", "low"
    
    Returns:
        Dictionary containing:
        - success: Whether scan completed
        - secrets: List of potential secrets found
        - high_count: Number of high-severity findings
        - message: Status message
    
    Example:
        result = await extract_secrets(url="https://example.com/app.js")
    """
    if not content and not url:
        return {
            "success": False,
            "error": "Either content or url must be provided",
            "secrets": [],
        }
    
    # Fetch content if URL provided
    if url and not content:
        content, meta = await _fetch_url(url)
        if not content:
            return {
                "success": False,
                "error": meta.get("error", "Failed to fetch URL"),
                "url": url,
                "secrets": [],
            }
    
    if not content:
        return {
            "success": False,
            "error": "No content available to analyze",
            "secrets": [],
        }
    
    # Extract secrets
    secrets = _extract_secrets_from_content(content)
    
    # Apply severity filter
    if severity_filter:
        secrets = [s for s in secrets if s.severity == severity_filter.lower()]
    
    # Count by severity
    high_count = sum(1 for s in secrets if s.severity == "high")
    medium_count = sum(1 for s in secrets if s.severity == "medium")
    low_count = sum(1 for s in secrets if s.severity == "low")
    
    return {
        "success": True,
        "url": url,
        "secrets": [s.to_dict() for s in secrets],
        "secret_count": len(secrets),
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "severity_breakdown": {
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
        "message": f"Found {len(secrets)} potential secrets ({high_count} high severity)",
    }


@register_tool(sandbox_execution=False)
async def analyze_js_frameworks(
    content: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    """
    Detect frontend frameworks and extract routing patterns.
    
    Identifies React, Angular, Vue, Next.js, and other frameworks,
    and extracts their routing configuration for potential attack surfaces.
    
    Args:
        content: JavaScript content to analyze
        url: URL to fetch and analyze
    
    Returns:
        Dictionary containing:
        - success: Whether analysis completed
        - frameworks: List of detected frameworks with confidence scores
        - routes: All extracted frontend routes
        - api_patterns: Framework-specific API patterns
        - message: Status message
    
    Example:
        result = await analyze_js_frameworks(url="https://spa.example.com/bundle.js")
    """
    if not content and not url:
        return {
            "success": False,
            "error": "Either content or url must be provided",
            "frameworks": [],
        }
    
    # Fetch content if URL provided
    if url and not content:
        content, meta = await _fetch_url(url)
        if not content:
            return {
                "success": False,
                "error": meta.get("error", "Failed to fetch URL"),
                "url": url,
                "frameworks": [],
            }
    
    if not content:
        return {
            "success": False,
            "error": "No content available to analyze",
            "frameworks": [],
        }
    
    # Detect frameworks
    frameworks = _detect_frameworks(content)
    
    # Aggregate all routes and API patterns
    all_routes: set[str] = set()
    all_api_patterns: set[str] = set()
    
    for fw in frameworks:
        all_routes.update(fw.routes)
        all_api_patterns.update(fw.api_patterns)
    
    return {
        "success": True,
        "url": url,
        "frameworks": [f.to_dict() for f in frameworks],
        "framework_count": len(frameworks),
        "primary_framework": frameworks[0].name if frameworks else None,
        "routes": sorted(all_routes),
        "route_count": len(all_routes),
        "api_patterns": sorted(all_api_patterns),
        "message": f"Detected {len(frameworks)} frameworks, {len(all_routes)} routes",
    }


@register_tool(sandbox_execution=False)
async def comprehensive_js_analysis(
    url: str,
    include_inline: bool = True,
    max_files: int = 30,
    include_secrets: bool = True,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Perform comprehensive JavaScript analysis on a target URL.
    
    This orchestrates the full JS reconnaissance pipeline:
    1. Fetch all JS files (external and inline)
    2. Extract API endpoints
    3. Detect secrets and credentials
    4. Identify frameworks and routing
    5. Extract parameters for fuzzing
    
    This is the recommended entry point for JS analysis.
    
    Args:
        url: Target webpage URL
        include_inline: Include inline scripts
        max_files: Maximum JS files to fetch
        include_secrets: Scan for secrets (may expose sensitive data)
        timeout: Timeout per request
    
    Returns:
        Comprehensive analysis results including all findings.
    
    Example:
        result = await comprehensive_js_analysis("https://spa.example.com")
    """
    start_time = time.time()
    
    # Step 1: Fetch all JS files
    fetch_result = await fetch_js_files(
        url=url,
        include_inline=include_inline,
        max_files=max_files,
        timeout=timeout,
    )
    
    if not fetch_result.get("success"):
        return {
            "success": False,
            "error": fetch_result.get("error", "Failed to fetch JS files"),
            "url": url,
        }
    
    # Combine all JS content
    all_content: list[str] = []
    
    for js_file in fetch_result.get("js_files", []):
        if js_file.get("content"):
            all_content.append(js_file["content"])
    
    for inline in fetch_result.get("inline_scripts", []):
        if inline:
            all_content.append(inline)
    
    combined_content = "\n\n".join(all_content)
    
    if not combined_content:
        return {
            "success": True,
            "url": url,
            "message": "No JavaScript content found to analyze",
            "js_files_found": 0,
            "endpoints": [],
            "secrets": [],
            "frameworks": [],
        }
    
    # Step 2: Extract endpoints
    endpoints_result = await extract_endpoints(
        content=combined_content,
        include_parameters=True,
        include_auth_patterns=True,
    )
    
    # Step 3: Detect frameworks
    frameworks_result = await analyze_js_frameworks(content=combined_content)
    
    # Step 4: Extract secrets (if requested)
    secrets_result: dict[str, Any] = {"secrets": [], "secret_count": 0}
    if include_secrets:
        secrets_result = await extract_secrets(content=combined_content)
    
    elapsed = time.time() - start_time
    
    # Compile comprehensive results
    return {
        "success": True,
        "url": url,
        
        # JS file info
        "js_files_found": fetch_result.get("js_file_count", 0),
        "inline_scripts_found": fetch_result.get("inline_count", 0),
        "total_js_size_kb": fetch_result.get("total_size_kb", 0),
        
        # Endpoints
        "endpoints": endpoints_result.get("endpoints", []),
        "endpoint_count": endpoints_result.get("endpoint_count", 0),
        "parameters": endpoints_result.get("parameters", []),
        "parameter_count": endpoints_result.get("parameter_count", 0),
        "auth_patterns": endpoints_result.get("auth_patterns"),
        
        # Frameworks
        "frameworks": frameworks_result.get("frameworks", []),
        "primary_framework": frameworks_result.get("primary_framework"),
        "routes": frameworks_result.get("routes", []),
        
        # Secrets
        "secrets": secrets_result.get("secrets", []) if include_secrets else [],
        "secret_count": secrets_result.get("secret_count", 0),
        "high_severity_secrets": secrets_result.get("high_count", 0),
        
        # Metadata
        "elapsed_seconds": round(elapsed, 2),
        "message": (
            f"Analyzed {fetch_result.get('js_file_count', 0)} JS files: "
            f"{endpoints_result.get('endpoint_count', 0)} endpoints, "
            f"{secrets_result.get('secret_count', 0)} secrets, "
            f"{frameworks_result.get('framework_count', 0)} frameworks"
        ),
    }
