"""
Response Analysis Tools - Phase 2 Enhancement
==============================================

HTTP response analysis for vulnerability detection, error parsing,
information disclosure, and technology stack identification.

SECURITY NOTES:
- All tools analyze response data locally
- No external API calls required
- Pattern matching is used for detection

ENHANCEMENT (P0.1): Added semantic HTML context analysis for XSS detection.
- Uses html.parser for lenient HTML parsing
- Detects reflection context (attribute, script, tag content)
- Identifies executable vs benign reflections
"""

import html as html_module
import logging
import re
from html.parser import HTMLParser
from typing import Any, NamedTuple
from urllib.parse import unquote as url_unquote

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# ============================================================================
# P0.1: HTML Context Analysis for XSS Detection
# ============================================================================

class ReflectionContext(NamedTuple):
    """Context information about where a payload was reflected in HTML."""
    location: str  # 'attribute_value', 'tag_content', 'script', 'comment', 'style', 'tag_name'
    tag: str       # 'div', 'script', 'img', etc.
    attribute: str | None  # 'onclick', 'src', 'href', etc.
    is_escaped: bool  # True if HTML-encoded
    is_executable: bool  # True if in dangerous context
    details: str  # Additional context info


# Dangerous attributes that can execute JavaScript
_DANGEROUS_ATTRS = frozenset({
    # Event handlers
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmousemove',
    'onmouseout', 'onmouseenter', 'onmouseleave', 'onkeydown', 'onkeypress', 'onkeyup',
    'onload', 'onerror', 'onabort', 'onbeforeunload', 'onunload', 'onresize', 'onscroll',
    'onfocus', 'onblur', 'onchange', 'oninput', 'onsubmit', 'onreset', 'onselect',
    'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
    'oncontextmenu', 'oncopy', 'oncut', 'onpaste', 'onwheel', 'ontouchstart', 'ontouchmove',
    'ontouchend', 'ontouchcancel', 'onpointerdown', 'onpointerup', 'onpointermove',
    'onanimationstart', 'onanimationend', 'onanimationiteration', 'ontransitionend',
    'onloadeddata', 'onloadedmetadata', 'oncanplay', 'oncanplaythrough', 'onplay', 'onpause',
    'onplaying', 'onseeking', 'onseeked', 'ontimeupdate', 'onended', 'onvolumechange',
    'onwaiting', 'onstalled', 'onsuspend', 'onemptied', 'onratechange', 'ondurationchange',
    'onprogress', 'oninvalid', 'onsearch', 'ontoggle', 'onshow', 'onmessage', 'ononline',
    'onoffline', 'onstorage', 'onpopstate', 'onhashchange', 'onbeforeprint', 'onafterprint',
})

# Attributes that can have javascript: URLs
_JS_URL_ATTRS = frozenset({
    'href', 'src', 'action', 'formaction', 'data', 'poster', 'codebase',
    'cite', 'background', 'profile', 'usemap', 'longdesc', 'dynsrc', 'lowsrc',
})


class HTMLContextAnalyzer(HTMLParser):
    """
    Lenient HTML parser that tracks where a payload appears in the DOM.
    
    This handles malformed HTML gracefully and identifies:
    - Reflections in attribute values (especially event handlers)
    - Reflections in script/style tags (executable context)
    - Reflections in regular tag content (potentially executable)
    - Reflections in comments (usually safe)
    """
    
    def __init__(self, payload: str):
        super().__init__(convert_charrefs=False)  # Don't auto-convert entities
        self.payload = payload
        self.payload_lower = payload.lower()
        self.contexts: list[ReflectionContext] = []
        self._current_tag = ""
        self._in_script = False
        self._in_style = False
        self._tag_stack: list[str] = []
    
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        self._current_tag = tag_lower
        self._tag_stack.append(tag_lower)
        self._in_script = tag_lower == "script"
        self._in_style = tag_lower == "style"
        
        # Check if payload appears in tag name (rare but possible)
        if self.payload_lower in tag_lower:
            self.contexts.append(ReflectionContext(
                location="tag_name",
                tag=tag,
                attribute=None,
                is_escaped=False,
                is_executable=True,  # Custom tags can be dangerous
                details=f"Payload found in tag name: <{tag}>"
            ))
        
        # Check attribute values
        for attr_name, attr_value in attrs:
            if attr_value is None:
                continue
            
            attr_name_lower = attr_name.lower()
            
            if self.payload in attr_value or self.payload_lower in attr_value.lower():
                # Determine if this is a dangerous context
                is_event_handler = attr_name_lower in _DANGEROUS_ATTRS
                has_js_url = (
                    attr_name_lower in _JS_URL_ATTRS and
                    ("javascript:" in attr_value.lower() or 
                     "data:" in attr_value.lower() or
                     "vbscript:" in attr_value.lower())
                )
                
                is_dangerous = is_event_handler or has_js_url
                
                self.contexts.append(ReflectionContext(
                    location="attribute_value",
                    tag=tag_lower,
                    attribute=attr_name_lower,
                    is_escaped=False,  # If we found it in parsed attr, it's not escaped
                    is_executable=is_dangerous,
                    details=f"Payload in {attr_name}=\"{attr_value[:50]}...\"" if len(attr_value) > 50 else f"Payload in {attr_name}=\"{attr_value}\""
                ))
    
    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if self._tag_stack and self._tag_stack[-1] == tag_lower:
            self._tag_stack.pop()
        if tag_lower == "script":
            self._in_script = False
        elif tag_lower == "style":
            self._in_style = False
        self._current_tag = self._tag_stack[-1] if self._tag_stack else ""
    
    def handle_data(self, data: str) -> None:
        if self.payload in data or self.payload_lower in data.lower():
            if self._in_script:
                self.contexts.append(ReflectionContext(
                    location="script",
                    tag="script",
                    attribute=None,
                    is_escaped=False,
                    is_executable=True,  # Inside <script> is always dangerous
                    details=f"Payload in <script> content: {data[:100]}..."
                ))
            elif self._in_style:
                # CSS injection can be dangerous (expression(), url(), etc.)
                self.contexts.append(ReflectionContext(
                    location="style",
                    tag="style",
                    attribute=None,
                    is_escaped=False,
                    is_executable="expression" in data.lower() or "javascript:" in data.lower(),
                    details=f"Payload in <style> content"
                ))
            else:
                self.contexts.append(ReflectionContext(
                    location="tag_content",
                    tag=self._current_tag or "body",
                    attribute=None,
                    is_escaped=False,
                    is_executable=False,  # Plain text content - not directly executable
                    details=f"Payload in <{self._current_tag}> content"
                ))
    
    def handle_comment(self, data: str) -> None:
        if self.payload in data or self.payload_lower in data.lower():
            # Check for conditional comments (IE) which CAN execute
            is_conditional = data.strip().startswith("[if") or data.strip().startswith("![if")
            self.contexts.append(ReflectionContext(
                location="comment",
                tag="comment",
                attribute=None,
                is_escaped=False,
                is_executable=is_conditional,
                details=f"Payload in HTML comment{' (IE conditional)' if is_conditional else ''}"
            ))
    
    def error(self, message: str) -> None:
        """Override to prevent exceptions on malformed HTML."""
        pass  # Silently ignore parse errors


def _normalize_for_xss_check(text: str) -> str:
    """Normalize text before XSS checking to catch encoded payloads."""
    # URL decode
    try:
        text = url_unquote(text)
    except (TypeError, ValueError):
        pass
    
    # Decode common HTML entities
    try:
        text = html_module.unescape(text)
    except (TypeError, ValueError):
        pass
    
    return text


def _check_reflection_with_context(content: str, payload: str) -> dict[str, Any] | None:
    """
    Enhanced reflection check with HTML context awareness (P0.1 FIX).
    
    Analyzes WHERE the payload appears in the HTML structure to determine
    if it's actually exploitable for XSS, not just reflected.
    
    Returns:
        dict with reflection info and exploitability assessment, or None if no reflection
    """
    if not payload or len(payload) < 3:
        return None
    
    # Normalize content for checking
    normalized_content = _normalize_for_xss_check(content)
    normalized_payload = _normalize_for_xss_check(payload)
    
    # First check: is payload present at all (in any form)?
    payload_found = (
        payload in content or 
        normalized_payload in normalized_content or
        payload.lower() in content.lower()
    )
    
    if not payload_found:
        return None
    
    # Check if payload is HTML-encoded (false positive indicator)
    encoded_payload = html_module.escape(payload)
    if encoded_payload in content and payload not in content:
        return {
            "type": "reflection_escaped",
            "severity": "info",
            "name": "HTML-Escaped Reflection",
            "description": "Payload reflected but HTML-encoded - NOT directly exploitable",
            "vuln_type": "xss_unlikely",
            "is_exploitable": False,
            "requires_investigation": False,
            "contexts": [],
        }
    
    # Parse HTML to find context
    contexts: list[dict[str, Any]] = []
    try:
        analyzer = HTMLContextAnalyzer(payload)
        analyzer.feed(content)
        
        for ctx in analyzer.contexts:
            contexts.append({
                "location": ctx.location,
                "tag": ctx.tag,
                "attribute": ctx.attribute,
                "is_escaped": ctx.is_escaped,
                "is_executable": ctx.is_executable,
                "details": ctx.details,
            })
    except (TypeError, ValueError, RecursionError) as e:
        logger.debug(f"HTML parsing failed: {e}")
    
    if not contexts:
        # Payload found but context unclear (maybe in JSON, plain text, etc.)
        return {
            "type": "reflection",
            "severity": "low",
            "name": "Input Reflection (Context Unknown)",
            "description": "Payload found in response but HTML context could not be determined",
            "vuln_type": "xss_potential",
            "is_exploitable": False,
            "requires_investigation": True,
            "contexts": [],
        }
    
    # Categorize by exploitability
    executable_contexts = [c for c in contexts if c["is_executable"]]
    
    if executable_contexts:
        # HIGH severity - payload in executable context
        primary_ctx = executable_contexts[0]
        return {
            "type": "reflection_executable",
            "severity": "high" if primary_ctx["location"] in ("script", "attribute_value") else "medium",
            "name": f"XSS - Reflection in {primary_ctx['location'].replace('_', ' ').title()}",
            "description": f"Payload reflected in executable context: {primary_ctx['details']}",
            "vuln_type": "xss",
            "is_exploitable": True,
            "requires_investigation": False,  # High confidence
            "contexts": contexts,
            "primary_context": primary_ctx,
        }
    else:
        # Reflected but not in dangerous context
        return {
            "type": "reflection_benign",
            "severity": "low",
            "name": "Input Reflection (Benign Context)",
            "description": "Payload reflected in non-executable context (tag content, comment)",
            "vuln_type": "xss_unlikely",
            "is_exploitable": False,
            "requires_investigation": True,  # Might still be exploitable with different payload
            "contexts": contexts,
        }


# ============================================================================
# Error Pattern Database
# ============================================================================

_ERROR_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "sql_error": [
        {"pattern": r"SQL syntax.*MySQL", "db": "mysql", "severity": "high"},
        {"pattern": r"Warning.*mysql_", "db": "mysql", "severity": "high"},
        {"pattern": r"MySqlException", "db": "mysql", "severity": "high"},
        {"pattern": r"valid MySQL result", "db": "mysql", "severity": "medium"},
        {"pattern": r"check the manual that corresponds to your MySQL", "db": "mysql", "severity": "high"},
        {"pattern": r"MySqlClient\.", "db": "mysql", "severity": "high"},
        {"pattern": r"PostgreSQL.*ERROR", "db": "postgresql", "severity": "high"},
        {"pattern": r"Warning.*pg_", "db": "postgresql", "severity": "high"},
        {"pattern": r"valid PostgreSQL result", "db": "postgresql", "severity": "medium"},
        {"pattern": r"Npgsql\.", "db": "postgresql", "severity": "high"},
        {"pattern": r"PG::SyntaxError", "db": "postgresql", "severity": "high"},
        {"pattern": r"Driver.*SQL.*Server", "db": "mssql", "severity": "high"},
        {"pattern": r"OLE DB.*SQL Server", "db": "mssql", "severity": "high"},
        {"pattern": r"SQLServer JDBC Driver", "db": "mssql", "severity": "high"},
        {"pattern": r"SqlClient\.", "db": "mssql", "severity": "high"},
        {"pattern": r"Unclosed quotation mark", "db": "mssql", "severity": "high"},
        {"pattern": r"mssql_query\(\)", "db": "mssql", "severity": "high"},
        {"pattern": r"ORA-\d{5}", "db": "oracle", "severity": "high"},
        {"pattern": r"Oracle error", "db": "oracle", "severity": "high"},
        {"pattern": r"Oracle.*Driver", "db": "oracle", "severity": "high"},
        {"pattern": r"Warning.*oci_", "db": "oracle", "severity": "high"},
        {"pattern": r"quoted string not properly terminated", "db": "oracle", "severity": "high"},
        {"pattern": r"SQLite/JDBCDriver", "db": "sqlite", "severity": "high"},
        {"pattern": r"SQLite\.Exception", "db": "sqlite", "severity": "high"},
        {"pattern": r"System\.Data\.SQLite\.SQLiteException", "db": "sqlite", "severity": "high"},
        {"pattern": r"Warning.*sqlite_", "db": "sqlite", "severity": "high"},
        {"pattern": r"SQLITE_ERROR", "db": "sqlite", "severity": "high"},
    ],
    "path_disclosure": [
        {"pattern": r"(?:[A-Z]:\\|/)(?:home|var|www|usr|opt|etc|tmp|inetpub|xampp)[^\s<>\"']*", "severity": "medium"},
        {"pattern": r"/var/www/[^\s<>\"']+", "severity": "medium"},
        {"pattern": r"C:\\\\[Ii]netpub\\\\[^\s<>\"']+", "severity": "medium"},
        {"pattern": r"/home/\w+/[^\s<>\"']+", "severity": "medium"},
        {"pattern": r"DocumentRoot.*?[\"']([^\"']+)[\"']", "severity": "medium"},
    ],
    "stack_trace": [
        {"pattern": r"at [\w\.$]+\([\w]+\.(java|cs|vb):\d+\)", "language": "java/c#", "severity": "high"},
        {"pattern": r"File \"[^\"]+\", line \d+, in", "language": "python", "severity": "high"},
        {"pattern": r"Traceback \(most recent call last\)", "language": "python", "severity": "high"},
        {"pattern": r"#\d+ (?:0x[\da-f]+|/)[^\n]+", "language": "php/c", "severity": "high"},
        {"pattern": r"Error in .+ line \d+", "language": "ruby", "severity": "high"},
        {"pattern": r"at\s+.+\s+\(.+:\d+:\d+\)", "language": "javascript", "severity": "high"},
    ],
    "debug_info": [
        {"pattern": r"DEBUG\s*[=:]\s*[Tt]rue", "severity": "medium"},
        {"pattern": r"debug\s*mode\s*(is\s*)?(enabled|on|true)", "severity": "medium", "flags": re.IGNORECASE},
        {"pattern": r"DJANGO_DEBUG", "severity": "medium"},
        {"pattern": r"display_errors\s*=\s*On", "severity": "medium"},
        {"pattern": r"error_reporting\s*\(\s*E_ALL\s*\)", "severity": "low"},
    ],
    "version_disclosure": [
        {"pattern": r"(Apache|nginx|IIS|lighttpd|LiteSpeed)/[\d\.]+", "severity": "low"},
        {"pattern": r"PHP/[\d\.]+", "severity": "low"},
        {"pattern": r"Python/[\d\.]+", "severity": "low"},
        {"pattern": r"ASP\.NET Version:[\d\.]+", "severity": "low"},
        {"pattern": r"X-Powered-By:\s*([^\r\n]+)", "severity": "low"},
        {"pattern": r"Server:\s*([^\r\n]+)", "severity": "low"},
    ],
    "auth_bypass_indicators": [
        {"pattern": r"(?:admin|administrator|root|superuser)\s*(?:panel|dashboard|area)", "severity": "high", "flags": re.IGNORECASE},
        {"pattern": r"logged\s+in\s+as", "severity": "high", "flags": re.IGNORECASE},
        {"pattern": r"welcome\s+back", "severity": "medium", "flags": re.IGNORECASE},
        {"pattern": r"session[_-]?id\s*[=:]\s*['\"]?[\w-]+", "severity": "medium", "flags": re.IGNORECASE},
    ],
}


# ============================================================================
# Secret Pattern Database
# ============================================================================

_SECRET_PATTERNS: list[dict[str, Any]] = [
    # API Keys
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "pattern": r"(?:aws)?_?secret_?(?:access)?_?key['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "critical"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
    {"name": "Google OAuth ID", "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "high"},
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}", "severity": "critical"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9_]{36,}", "severity": "critical"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}", "severity": "critical"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "severity": "high"},
    {"name": "Stripe API Key", "pattern": r"sk_live_[0-9a-zA-Z]{24}", "severity": "critical"},
    {"name": "Stripe Publishable", "pattern": r"pk_live_[0-9a-zA-Z]{24}", "severity": "medium"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "high"},
    {"name": "SendGrid API Key", "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "severity": "high"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "high"},
    {"name": "Heroku API Key", "pattern": r"[h|H]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "severity": "high"},
    {"name": "Firebase Key", "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "severity": "high"},
    
    # Tokens & Secrets
    {"name": "Generic API Key", "pattern": r"(?:api[_-]?key|apikey|api_secret)['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})", "severity": "high"},
    {"name": "Generic Secret", "pattern": r"(?:secret|password|passwd|pwd)['\"]?\s*[=:]\s*['\"]?([^'\"\s]{8,})", "severity": "high"},
    {"name": "Bearer Token", "pattern": r"[Bb]earer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "severity": "high"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "severity": "high"},
    {"name": "Private Key", "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "SSH Private Key", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----", "severity": "critical"},
    
    # Database Credentials
    {"name": "MongoDB Connection", "pattern": r"mongodb(?:\+srv)?://[^\s\"'<>]+", "severity": "critical"},
    {"name": "MySQL Connection", "pattern": r"mysql://[^\s\"'<>]+", "severity": "critical"},
    {"name": "PostgreSQL Connection", "pattern": r"postgres(?:ql)?://[^\s\"'<>]+", "severity": "critical"},
    {"name": "Redis URL", "pattern": r"redis://[^\s\"'<>]+", "severity": "high"},
    
    # Cloud Provider
    {"name": "Azure Storage Key", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", "severity": "critical"},
    {"name": "GCP Service Account", "pattern": r'"type"\s*:\s*"service_account"', "severity": "high"},
]


# ============================================================================
# Technology Stack Detection
# ============================================================================

_TECH_SIGNATURES: dict[str, list[dict[str, Any]]] = {
    "web_server": [
        {"name": "Apache", "patterns": [r"Apache/[\d\.]+", r"mod_\w+"], "header": "Server"},
        {"name": "nginx", "patterns": [r"nginx/[\d\.]+", r"nginx"], "header": "Server"},
        {"name": "IIS", "patterns": [r"Microsoft-IIS/[\d\.]+"], "header": "Server"},
        {"name": "LiteSpeed", "patterns": [r"LiteSpeed"], "header": "Server"},
        {"name": "Cloudflare", "patterns": [r"cloudflare"], "header": "Server"},
    ],
    "language": [
        {"name": "PHP", "patterns": [r"PHP/[\d\.]+", r"PHPSESSID", r"\.php"], "header": "X-Powered-By"},
        {"name": "ASP.NET", "patterns": [r"ASP\.NET", r"\.aspx?", r"__VIEWSTATE"], "header": "X-Powered-By"},
        {"name": "Python", "patterns": [r"Python/[\d\.]+", r"gunicorn", r"uvicorn", r"wsgi"], "header": "X-Powered-By"},
        {"name": "Java", "patterns": [r"Servlet", r"JSP", r"\.jsp", r"JSESSIONID"], "header": "X-Powered-By"},
        {"name": "Ruby", "patterns": [r"Phusion Passenger", r"\.erb", r"_session_id"], "header": "X-Powered-By"},
        {"name": "Node.js", "patterns": [r"Express", r"next\.js", r"connect\.sid"], "header": "X-Powered-By"},
    ],
    "framework": [
        {"name": "Django", "patterns": [r"csrfmiddlewaretoken", r"django", r"__admin__"]},
        {"name": "Flask", "patterns": [r"flask", r"Werkzeug"]},
        {"name": "Laravel", "patterns": [r"laravel_session", r"XSRF-TOKEN"]},
        {"name": "Rails", "patterns": [r"_rails", r"X-Request-Id", r"authenticity_token"]},
        {"name": "Spring", "patterns": [r"spring", r"JSESSIONID", r"X-Application-Context"]},
        {"name": "Express", "patterns": [r"express", r"connect\.sid"]},
        {"name": "WordPress", "patterns": [r"wp-content", r"wp-includes", r"wp-json"]},
        {"name": "Drupal", "patterns": [r"Drupal", r"sites/default", r"drupal\.js"]},
        {"name": "Joomla", "patterns": [r"Joomla", r"/components/", r"/modules/"]},
    ],
    "cdn_waf": [
        {"name": "Cloudflare", "patterns": [r"__cfduid", r"cf-ray", r"cloudflare"]},
        {"name": "Akamai", "patterns": [r"akamai", r"ak_bmsc", r"AkamaiGHost"]},
        {"name": "AWS CloudFront", "patterns": [r"x-amz-cf-", r"CloudFront"]},
        {"name": "Fastly", "patterns": [r"fastly", r"x-served-by"]},
        {"name": "Sucuri", "patterns": [r"sucuri", r"x-sucuri-"]},
    ],
    "security": [
        {"name": "CSP", "patterns": [r"Content-Security-Policy"], "header": "Content-Security-Policy"},
        {"name": "HSTS", "patterns": [r"Strict-Transport-Security"], "header": "Strict-Transport-Security"},
        {"name": "X-Frame-Options", "patterns": [r"X-Frame-Options"], "header": "X-Frame-Options"},
        {"name": "X-XSS-Protection", "patterns": [r"X-XSS-Protection"], "header": "X-XSS-Protection"},
    ],
}


# ============================================================================
# Vulnerability Indicators
# ============================================================================

_VULN_INDICATORS: list[dict[str, Any]] = [
    # XSS Indicators
    {"name": "Reflected Input", "pattern": r"<[^>]*(?:on\w+|javascript:|data:)[^>]*>", "vuln": "xss", "severity": "high"},
    {"name": "Unescaped Output", "pattern": r"<script>[^<]*\$_(?:GET|POST|REQUEST)", "vuln": "xss", "severity": "high"},
    
    # SSTI Indicators
    {"name": "Template Evaluation", "pattern": r"\{\{.*?\}\}", "vuln": "ssti_potential", "severity": "medium"},
    {"name": "Template Error", "pattern": r"(?:Jinja|Twig|Freemarker|Velocity).*(?:Error|Exception)", "vuln": "ssti", "severity": "high"},
    
    # LFI/RFI Indicators
    {"name": "File Inclusion Error", "pattern": r"(?:include|require)(?:_once)?\s*\([^)]+\)", "vuln": "lfi_potential", "severity": "medium"},
    {"name": "Failed Open", "pattern": r"failed to open stream", "vuln": "lfi", "severity": "high"},
    {"name": "Permission Denied", "pattern": r"Permission denied", "vuln": "lfi_potential", "severity": "medium"},
    
    # SSRF Indicators
    {"name": "URL Fetch Error", "pattern": r"(?:Could not|Unable to) (?:connect|fetch|open|read)", "vuln": "ssrf_potential", "severity": "medium"},
    {"name": "Connection Refused", "pattern": r"Connection refused", "vuln": "ssrf_potential", "severity": "medium"},
    
    # XXE Indicators
    {"name": "XML Parser Error", "pattern": r"(?:XML|SAX|DOM).*(?:Error|Exception|Parser)", "vuln": "xxe_potential", "severity": "medium"},
    {"name": "Entity Error", "pattern": r"entity.*not (?:found|allowed|defined)", "vuln": "xxe", "severity": "high"},
    
    # Deserialization
    {"name": "Unserialize Error", "pattern": r"unserialize\(\).*(?:error|failed)", "vuln": "deserialization", "severity": "critical"},
    {"name": "Java Deserialize", "pattern": r"java\.io\.(?:Object|Invalid).*(?:Stream|Class)", "vuln": "deserialization", "severity": "critical"},
    
    # Information Disclosure
    {"name": "phpinfo", "pattern": r"<title>phpinfo\(\)</title>", "vuln": "info_disclosure", "severity": "high"},
    {"name": "Server Status", "pattern": r"Apache Server Status", "vuln": "info_disclosure", "severity": "medium"},
    {"name": "Git Exposed", "pattern": r"\.git/config", "vuln": "info_disclosure", "severity": "critical"},
]


# ============================================================================
# Analysis Functions
# ============================================================================


@register_tool(sandbox_execution=False)
async def analyze_response(
    response_body: str,
    response_headers: dict[str, str] | None = None,
    status_code: int = 200,
    request_payload: str | None = None,
) -> dict[str, Any]:
    """
    Comprehensive HTTP response analysis for vulnerability detection.
    
    Analyzes response body and headers for errors, information disclosure,
    security issues, and vulnerability indicators.
    
    Args:
        response_body: HTTP response body content
        response_headers: Response headers as dict (optional)
        status_code: HTTP status code (default: 200)
        request_payload: Original request payload for reflection check (optional)
    
    Returns:
        Dict with detected issues, tech stack, and recommendations
    """
    headers = response_headers or {}
    findings: list[dict[str, Any]] = []
    
    # Check for errors
    errors = await detect_errors(response_body)
    if errors.get("errors"):
        findings.extend([{"type": "error", **e} for e in errors["errors"]])
    
    # Check for secrets
    secrets = await extract_secrets(response_body)
    if secrets.get("secrets"):
        findings.extend([{"type": "secret", **s} for s in secrets["secrets"]])
    
    # Identify tech stack
    tech = await identify_tech_stack(response_body, headers)
    
    # Check for vulnerability indicators
    vuln_findings = _check_vuln_indicators(response_body)
    findings.extend(vuln_findings)
    
    # Check for input reflection (potential XSS)
    if request_payload:
        reflection = _check_reflection(response_body, request_payload)
        if reflection:
            findings.append(reflection)
    
    # Analyze response headers for security issues
    header_issues = _analyze_security_headers(headers)
    findings.extend(header_issues)
    
    # Status code analysis
    status_findings = _analyze_status_code(status_code, response_body)
    if status_findings:
        findings.append(status_findings)
    
    # Calculate overall risk
    risk_level = _calculate_risk_level(findings)
    
    return {
        "success": True,
        "findings": findings,
        "finding_count": len(findings),
        "tech_stack": tech.get("technologies", {}),
        "risk_level": risk_level,
        "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
        "high_count": sum(1 for f in findings if f.get("severity") == "high"),
        "recommendations": _generate_recommendations(findings),
    }


async def detect_errors(
    content: str,
    error_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Detect error messages and stack traces in response content.
    
    Identifies SQL errors, path disclosure, stack traces, debug info,
    and version disclosure.
    
    Args:
        content: Response content to analyze
        error_types: Specific error types to check (optional)
                    Options: "sql_error", "path_disclosure", "stack_trace",
                            "debug_info", "version_disclosure"
    
    Returns:
        Dict with detected errors and their severity
    """
    check_types = error_types or list(_ERROR_PATTERNS.keys())
    errors: list[dict[str, Any]] = []
    
    for error_type in check_types:
        if error_type not in _ERROR_PATTERNS:
            continue
        
        for pattern_info in _ERROR_PATTERNS[error_type]:
            flags = pattern_info.get("flags", 0)
            pattern = pattern_info["pattern"]
            try:
                full_matches = []
                for match in re.finditer(pattern, content, flags):
                    full_matches.append(match.group(0))
                matches = full_matches
                if matches:
                    error_data = {
                        "error_type": error_type,
                        "pattern": pattern_info["pattern"],
                        "severity": pattern_info.get("severity", "medium"),
                        "matches": matches[:5],  # Limit matches
                        "match_count": len(matches),
                    }
                    
                    # Add additional context
                    if "db" in pattern_info:
                        error_data["database"] = pattern_info["db"]
                    if "language" in pattern_info:
                        error_data["language"] = pattern_info["language"]
                    
                    errors.append(error_data)
            except re.error:
                continue
    
    # Deduplicate by error type
    seen_types: set[str] = set()
    unique_errors: list[dict[str, Any]] = []
    for e in errors:
        key = f"{e['error_type']}:{e.get('database', '')}:{e.get('language', '')}"
        if key not in seen_types:
            seen_types.add(key)
            unique_errors.append(e)
    
    return {
        "success": True,
        "errors": unique_errors,
        "error_count": len(unique_errors),
        "has_sql_errors": any(e["error_type"] == "sql_error" for e in unique_errors),
        "has_stack_traces": any(e["error_type"] == "stack_trace" for e in unique_errors),
        "has_path_disclosure": any(e["error_type"] == "path_disclosure" for e in unique_errors),
    }


async def extract_secrets(
    content: str,
    secret_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Extract potential secrets, API keys, and credentials from content.
    
    Detects AWS keys, API tokens, database connection strings,
    private keys, and other sensitive data.
    
    Args:
        content: Content to search for secrets
        secret_types: Specific secret types to check (optional)
    
    Returns:
        Dict with detected secrets (redacted for safety)
    """
    secrets: list[dict[str, Any]] = []
    
    for pattern_info in _SECRET_PATTERNS:
        # Filter by type if specified
        if secret_types and pattern_info["name"] not in secret_types:
            continue
        
        try:
            matches = re.findall(pattern_info["pattern"], content, re.IGNORECASE)
            if matches:
                # Redact the actual secret value
                for match in matches[:3]:  # Limit to 3 matches per type
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    
                    redacted = _redact_secret(match)
                    
                    secrets.append({
                        "type": pattern_info["name"],
                        "severity": pattern_info["severity"],
                        "redacted_value": redacted,
                        "length": len(match),
                    })
        except re.error:
            continue
    
    return {
        "success": True,
        "secrets": secrets,
        "secret_count": len(secrets),
        "critical_secrets": sum(1 for s in secrets if s["severity"] == "critical"),
        "warning": "CRITICAL: Secrets detected in response. Immediate remediation required." if secrets else None,
    }


async def identify_tech_stack(
    content: str,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Identify technology stack from response content and headers.
    
    Detects web servers, programming languages, frameworks,
    CDN/WAF providers, and security headers.
    
    Args:
        content: Response body content
        headers: Response headers as dict (optional)
    
    Returns:
        Dict with detected technologies and confidence levels
    """
    headers = headers or {}
    technologies: dict[str, list[dict[str, Any]]] = {}
    
    # Combine content and headers for analysis
    full_text = content
    for header_name, header_value in headers.items():
        full_text += f"\n{header_name}: {header_value}"
    
    for category, signatures in _TECH_SIGNATURES.items():
        technologies[category] = []
        
        for sig in signatures:
            matched = False
            confidence = 0
            version = None
            
            # Check header if specified
            if "header" in sig and sig["header"] in headers:
                header_val = headers[sig["header"]]
                for pattern in sig["patterns"]:
                    match = re.search(pattern, header_val, re.IGNORECASE)
                    if match:
                        matched = True
                        confidence = 90
                        # Try to extract version
                        version_match = re.search(r"[\d\.]+", match.group(0))
                        if version_match:
                            version = version_match.group(0)
                        break
            
            # Check content
            if not matched:
                for pattern in sig["patterns"]:
                    if re.search(pattern, full_text, re.IGNORECASE):
                        matched = True
                        confidence = 70  # Lower confidence for content match
                        break
            
            if matched:
                tech_info: dict[str, Any] = {
                    "name": sig["name"],
                    "confidence": confidence,
                }
                if version:
                    tech_info["version"] = version
                technologies[category].append(tech_info)
    
    # Remove empty categories
    technologies = {k: v for k, v in technologies.items() if v}
    
    # Check for missing security headers
    missing_security = []
    security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", 
                       "Strict-Transport-Security", "X-XSS-Protection"]
    for header in security_headers:
        if header not in headers and header.lower() not in [h.lower() for h in headers]:
            missing_security.append(header)
    
    return {
        "success": True,
        "technologies": technologies,
        "tech_count": sum(len(v) for v in technologies.values()),
        "missing_security_headers": missing_security,
        "security_score": _calculate_security_score(headers, missing_security),
    }


# ============================================================================
# Helper Functions
# ============================================================================


def _check_vuln_indicators(content: str) -> list[dict[str, Any]]:
    """Check for vulnerability indicators in content."""
    findings: list[dict[str, Any]] = []
    
    for indicator in _VULN_INDICATORS:
        try:
            if re.search(indicator["pattern"], content, re.IGNORECASE):
                findings.append({
                    "type": "vulnerability_indicator",
                    "name": indicator["name"],
                    "vuln_type": indicator["vuln"],
                    "severity": indicator["severity"],
                    "description": f"Potential {indicator['vuln'].replace('_', ' ').title()} detected",
                })
        except re.error:
            continue
    
    return findings


def _check_reflection(content: str, payload: str) -> dict[str, Any] | None:
    """
    Check if payload is reflected in response with HTML context awareness.
    
    ENHANCED (P0.1): Now uses semantic HTML parsing to determine if reflection
    is in an executable context (XSS) vs benign context (safe reflection).
    """
    # Use the new context-aware reflection checker
    return _check_reflection_with_context(content, payload)


def _analyze_security_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Analyze security headers for issues."""
    findings: list[dict[str, Any]] = []
    
    # Check for weak CSP
    csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
    if csp:
        if "unsafe-inline" in csp:
            findings.append({
                "type": "security_header",
                "severity": "medium",
                "name": "Weak CSP",
                "description": "Content-Security-Policy allows unsafe-inline",
            })
        if "unsafe-eval" in csp:
            findings.append({
                "type": "security_header",
                "severity": "high",
                "name": "Weak CSP",
                "description": "Content-Security-Policy allows unsafe-eval",
            })
    
    # Check X-Frame-Options
    xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
    if not xfo:
        findings.append({
            "type": "security_header",
            "severity": "low",
            "name": "Missing X-Frame-Options",
            "description": "Application may be vulnerable to clickjacking",
        })
    
    # Check HSTS
    hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))
    if not hsts:
        findings.append({
            "type": "security_header",
            "severity": "medium",
            "name": "Missing HSTS",
            "description": "Strict-Transport-Security header not present",
        })
    
    return findings


def _analyze_status_code(status_code: int, content: str) -> dict[str, Any] | None:
    """Analyze status code for security implications."""
    if status_code == 500:
        return {
            "type": "status_code",
            "severity": "medium",
            "name": "Internal Server Error",
            "description": "Server returned 500 error, may indicate vulnerability",
        }
    elif status_code == 403 and "forbidden" in content.lower():
        return {
            "type": "status_code",
            "severity": "low",
            "name": "Forbidden Response",
            "description": "Access denied, but resource exists",
        }
    elif status_code == 401:
        return {
            "type": "status_code",
            "severity": "low",
            "name": "Authentication Required",
            "description": "Resource requires authentication",
        }
    
    return None


def _redact_secret(value: str) -> str:
    """Redact a secret value, showing only partial info."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _calculate_risk_level(findings: list[dict[str, Any]]) -> str:
    """Calculate overall risk level from findings."""
    if any(f.get("severity") == "critical" for f in findings):
        return "CRITICAL"
    if sum(1 for f in findings if f.get("severity") == "high") >= 2:
        return "HIGH"
    if any(f.get("severity") == "high" for f in findings):
        return "HIGH"
    if any(f.get("severity") == "medium" for f in findings):
        return "MEDIUM"
    if findings:
        return "LOW"
    return "NONE"


def _calculate_security_score(headers: dict[str, str], missing: list[str]) -> int:
    """Calculate security header score (0-100)."""
    total = 5  # Total expected security headers
    present = total - len(missing)
    return int((present / total) * 100)


def _generate_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    """Generate recommendations based on findings."""
    recommendations: list[str] = []
    
    finding_types = set(f.get("type") for f in findings)
    vuln_types = set(f.get("vuln_type") for f in findings if f.get("vuln_type"))
    
    if "error" in finding_types:
        recommendations.append("Disable detailed error messages in production")
    
    if any("sql" in str(f.get("error_type", "")) for f in findings):
        recommendations.append("Review and parameterize all SQL queries")
    
    if "secret" in finding_types:
        recommendations.append("URGENT: Remove exposed secrets and rotate credentials")
    
    if "xss" in str(vuln_types) or "xss_potential" in str(vuln_types):
        recommendations.append("Implement proper output encoding for all user input")
    
    if "security_header" in finding_types:
        recommendations.append("Configure security headers (CSP, HSTS, X-Frame-Options)")
    
    if any("path_disclosure" in str(f.get("error_type", "")) for f in findings):
        recommendations.append("Disable path disclosure in error messages")
    
    return recommendations
