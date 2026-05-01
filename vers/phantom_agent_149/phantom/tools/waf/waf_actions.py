"""
WAF Detection and Evasion Tools - Phase 1 Enhancement
======================================================

Passive WAF detection and evasion strategy tools.
These tools fingerprint WAFs from HTTP responses and provide bypass strategies.

SECURITY NOTES:
- WAF detection uses response fingerprinting (headers, cookies, body patterns)
- No active exploitation or attack payloads sent
- Evasion strategies are informational/educational
- All HTTP requests use benign payloads

Tools:
- detect_waf: Detect WAF presence from HTTP responses
- get_waf_evasion_strategies: Get evasion strategies for detected WAF
"""

import hashlib
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Rate limiting state
_RATE_LIMIT_STATE: dict[str, float] = {}
_RATE_LIMIT_INTERVAL = 1.0  # 1 second between requests

# Simple cache for WAF detection results
_WAF_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 1800  # 30 minutes


def _rate_limit(api_name: str = "waf") -> None:
    """Enforce rate limiting for requests."""
    now = time.monotonic()
    last_call = _RATE_LIMIT_STATE.get(api_name, 0.0)
    wait_time = _RATE_LIMIT_INTERVAL - (now - last_call)
    if wait_time > 0:
        time.sleep(wait_time)
    _RATE_LIMIT_STATE[api_name] = time.monotonic()


def _get_cache_key(prefix: str, *args: Any) -> str:
    """Generate a cache key from prefix and arguments."""
    data = f"{prefix}:{':'.join(str(a) for a in args)}"
    return hashlib.md5(data.encode()).hexdigest()


def _get_cached(key: str) -> Any | None:
    """Get cached result if not expired."""
    if key not in _WAF_CACHE:
        return None
    result, timestamp = _WAF_CACHE[key]
    if time.time() - timestamp > _CACHE_TTL:
        del _WAF_CACHE[key]
        return None
    return result


def _set_cached(key: str, result: Any) -> None:
    """Store result in cache."""
    _WAF_CACHE[key] = (result, time.time())


# ==============================================================================
# WAF Signature Database
# ==============================================================================

WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "name": "Cloudflare",
        "vendor": "Cloudflare, Inc.",
        "headers": {
            "cf-ray": r".*",
            "cf-cache-status": r".*",
            "server": r"cloudflare",
            "cf-request-id": r".*",
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance", "_cfuvid"],
        "body_patterns": [
            r"cloudflare",
            r"attention required.*cloudflare",
            r"cf-error-details",
            r"ray id:",
        ],
        "status_codes": [403, 503, 1020],
    },
    "akamai": {
        "name": "Akamai Kona Site Defender",
        "vendor": "Akamai Technologies",
        "headers": {
            "server": r"akamaigh|akamai",
            "x-akamai-transformed": r".*",
            "akamai-grn": r".*",
            "x-akamai-session-info": r".*",
        },
        "cookies": ["ak_bmsc", "bm_sz", "bm_sv", "_abck", "akamai_generated"],
        "body_patterns": [
            r"access denied.*akamai",
            r"reference.*#\d+\.\w+",
            r"akamaigh",
        ],
        "status_codes": [403],
    },
    "aws_waf": {
        "name": "AWS WAF",
        "vendor": "Amazon Web Services",
        "headers": {
            "x-amzn-requestid": r".*",
            "x-amz-cf-id": r".*",
            "x-amz-cf-pop": r".*",
            "x-amz-id-2": r".*",
        },
        "cookies": ["awsalb", "awsalbcors", "awselb"],
        "body_patterns": [
            r"request blocked",
            r"access denied",
            r"x-amzn-errortype",
        ],
        "status_codes": [403],
    },
    "imperva_incapsula": {
        "name": "Imperva Incapsula",
        "vendor": "Imperva, Inc.",
        "headers": {
            "x-cdn": r"incapsula",
            "x-iinfo": r".*",
        },
        "cookies": ["visid_incap", "incap_ses", "nlbi_", "__inc"],
        "body_patterns": [
            r"incapsula incident",
            r"powered by incapsula",
            r"_incapsula_resource",
            r"incap_ses",
        ],
        "status_codes": [403],
    },
    "sucuri": {
        "name": "Sucuri CloudProxy",
        "vendor": "Sucuri",
        "headers": {
            "server": r"sucuri",
            "x-sucuri-id": r".*",
            "x-sucuri-cache": r".*",
        },
        "cookies": ["sucuri_cloudproxy_uuid"],
        "body_patterns": [
            r"sucuri website firewall",
            r"access denied.*sucuri",
            r"sucuri cloudproxy",
            r"cloudproxy.*block",
        ],
        "status_codes": [403],
    },
    "f5_big_ip": {
        "name": "F5 BIG-IP ASM",
        "vendor": "F5 Networks",
        "headers": {
            "server": r"big-?ip",
            "x-wa-info": r".*",
        },
        "cookies": ["TS", "BIGipServer", "F5_ST", "F5_HT"],
        "body_patterns": [
            r"request rejected",
            r"the requested url was rejected",
            r"support id:",
            r"f5 networks",
        ],
        "status_codes": [403],
    },
    "modsecurity": {
        "name": "ModSecurity",
        "vendor": "Trustwave (Open Source)",
        "headers": {
            "server": r"mod_security|modsecurity",
        },
        "cookies": [],
        "body_patterns": [
            r"mod_security",
            r"modsecurity",
            r"not acceptable",
            r"this error was generated by mod_security",
            r"owasp crs",
        ],
        "status_codes": [403, 406],
    },
    "fortiweb": {
        "name": "FortiWeb",
        "vendor": "Fortinet",
        "headers": {
            "server": r"fortiweb",
        },
        "cookies": ["FORTIWAFSID"],
        "body_patterns": [
            r"fortigate",
            r"fortiweb",
            r"fgd_icon",
            r".fgtauth",
        ],
        "status_codes": [403],
    },
    "barracuda": {
        "name": "Barracuda WAF",
        "vendor": "Barracuda Networks",
        "headers": {
            "server": r"barracuda",
        },
        "cookies": ["barra_counter_session"],
        "body_patterns": [
            r"barracuda",
            r"barracuda\.css",
        ],
        "status_codes": [403],
    },
    "wordfence": {
        "name": "Wordfence",
        "vendor": "Defiant Inc.",
        "headers": {},
        "cookies": ["wfwaf-authcookie"],
        "body_patterns": [
            r"wordfence",
            r"this response was generated by wordfence",
            r"your access to this site has been limited",
            r"generated by wordfence",
        ],
        "status_codes": [403, 503],
    },
    "azure_waf": {
        "name": "Azure Application Gateway WAF",
        "vendor": "Microsoft Azure",
        "headers": {
            "x-azure-ref": r".*",
            "x-ms-request-id": r".*",
        },
        "cookies": [],
        "body_patterns": [
            r"azure",
            r"microsoft",
            r"waf blocked",
        ],
        "status_codes": [403],
    },
    "radware": {
        "name": "Radware AppWall",
        "vendor": "Radware",
        "headers": {
            "x-sl-compstate": r".*",
        },
        "cookies": [],
        "body_patterns": [
            r"radware",
            r"unauthorized activity",
        ],
        "status_codes": [403],
    },
    "wallarm": {
        "name": "Wallarm",
        "vendor": "Wallarm Inc.",
        "headers": {
            "server": r"nginx-wallarm",
        },
        "cookies": [],
        "body_patterns": [
            r"wallarm",
        ],
        "status_codes": [403],
    },
    "citrix_netscaler": {
        "name": "Citrix NetScaler AppFirewall",
        "vendor": "Citrix",
        "headers": {
            "via": r"ns-cache",
            "cneonction": r".*",
            "nncoection": r".*",
        },
        "cookies": ["citrix_ns_id", "NSC_"],
        "body_patterns": [
            r"citrix",
            r"netscaler",
            r"ns_af",
        ],
        "status_codes": [403],
    },
    "comodo": {
        "name": "Comodo WAF",
        "vendor": "Comodo",
        "headers": {
            "server": r"protected by anti-ddos",
        },
        "cookies": [],
        "body_patterns": [
            r"comodo waf",
            r"protected by comodo",
        ],
        "status_codes": [403],
    },
    "edgecast": {
        "name": "Edgecast (Verizon Digital Media)",
        "vendor": "Verizon Digital Media Services",
        "headers": {
            "server": r"ecs",
            "x-ec-custom-error": r".*",
        },
        "cookies": [],
        "body_patterns": [],
        "status_codes": [403],
    },
    "fastly": {
        "name": "Fastly",
        "vendor": "Fastly, Inc.",
        "headers": {
            "x-fastly-request-id": r".*",
            "fastly-io-info": r".*",
            "x-served-by": r"cache-",
        },
        "cookies": [],
        "body_patterns": [
            r"fastly error",
        ],
        "status_codes": [403, 503],
    },
    "stackpath": {
        "name": "StackPath",
        "vendor": "StackPath",
        "headers": {
            "x-sp-url": r".*",
            "x-sp-waf-handler": r".*",
        },
        "cookies": [],
        "body_patterns": [
            r"stackpath",
        ],
        "status_codes": [403],
    },
    "reblaze": {
        "name": "Reblaze",
        "vendor": "Reblaze Technologies",
        "headers": {
            "server": r"reblaze",
        },
        "cookies": ["rbzid"],
        "body_patterns": [
            r"reblaze",
            r"access denied.*rbz",
        ],
        "status_codes": [403],
    },
    "wangsu": {
        "name": "Wangsu (ChinaNetCenter)",
        "vendor": "ChinaNetCenter",
        "headers": {
            "x-via": r".*ws.*",
            "server": r"wangsu",
        },
        "cookies": [],
        "body_patterns": [],
        "status_codes": [403],
    },
}

# ==============================================================================
# WAF Evasion Strategies Database
# ==============================================================================

WAF_EVASION_STRATEGIES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "general_info": (
            "Cloudflare is one of the most common WAFs. It uses JavaScript challenges, "
            "CAPTCHAs, and signature-based detection. Finding the origin IP is often the "
            "most effective bypass."
        ),
        "strategies": [
            {
                "name": "Origin IP Discovery",
                "description": "Find the real origin IP behind Cloudflare",
                "techniques": [
                    "Check DNS history via SecurityTrails, ViewDNS",
                    "Search Shodan/Censys for SSL certificate matching",
                    "Check MX records - mail servers often reveal origin",
                    "Look for subdomains not behind Cloudflare",
                    "Check Crunchbase/builtwith for IP leaks",
                ],
                "effectiveness": "HIGH",
            },
            {
                "name": "Rate Limit Bypass",
                "description": "Avoid triggering rate limits",
                "techniques": [
                    "Distribute requests across time",
                    "Use different User-Agents",
                    "Rotate source IPs (residential proxies)",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Encoding Techniques",
                "description": "Bypass signature-based rules",
                "techniques": [
                    "URL encoding (single/double)",
                    "Unicode normalization",
                    "Case variation",
                    "Null bytes insertion",
                    "Chunked transfer encoding",
                ],
                "effectiveness": "LOW-MEDIUM",
            },
        ],
        "limitations": [
            "JavaScript challenge requires browser automation",
            "Bot management is increasingly sophisticated",
            "Origin IP may have IP restrictions configured",
        ],
    },
    "akamai": {
        "general_info": (
            "Akamai Kona Site Defender is enterprise-grade with advanced bot detection. "
            "It uses behavioral analysis and sensor data collection."
        ),
        "strategies": [
            {
                "name": "Browser Emulation",
                "description": "Mimic legitimate browser behavior",
                "techniques": [
                    "Use headless browsers with stealth plugins",
                    "Execute Akamai's sensor JavaScript properly",
                    "Maintain consistent TLS fingerprint",
                    "Handle _abck cookie flow correctly",
                ],
                "effectiveness": "MEDIUM-HIGH",
            },
            {
                "name": "Request Timing",
                "description": "Avoid triggering behavioral detection",
                "techniques": [
                    "Add random delays between requests",
                    "Simulate human browsing patterns",
                    "Avoid sequential parameter enumeration",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Parameter Manipulation",
                "description": "Bypass signature rules",
                "techniques": [
                    "Use HPP (HTTP Parameter Pollution)",
                    "Try different content-types",
                    "Use multipart form data",
                ],
                "effectiveness": "LOW-MEDIUM",
            },
        ],
        "limitations": [
            "Sensor data validation is complex to replicate",
            "Bot detection improves with each request",
            "Enterprise configs are highly customized",
        ],
    },
    "aws_waf": {
        "general_info": (
            "AWS WAF uses managed rule groups and custom rules. Rules are often based "
            "on OWASP recommendations. Less sophisticated than dedicated WAF vendors."
        ),
        "strategies": [
            {
                "name": "Rule Fingerprinting",
                "description": "Identify which rule sets are active",
                "techniques": [
                    "Test common OWASP CRS patterns",
                    "Identify SQL injection rule strictness",
                    "Test XSS filter patterns",
                    "Check for rate-based rules",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Encoding Bypass",
                "description": "Evade pattern matching",
                "techniques": [
                    "Double URL encoding",
                    "HTML entity encoding",
                    "UTF-8 overlong encoding",
                    "Mixed case in SQL keywords",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Payload Splitting",
                "description": "Split malicious payloads across parameters",
                "techniques": [
                    "Use multiple parameters",
                    "Leverage JSON/XML parsing differences",
                    "Chunked payload delivery",
                ],
                "effectiveness": "MEDIUM",
            },
        ],
        "limitations": [
            "Managed rules are regularly updated",
            "Custom rules vary per deployment",
            "CloudFront integration adds extra layers",
        ],
    },
    "imperva_incapsula": {
        "general_info": (
            "Imperva Incapsula uses advanced bot protection and DDoS mitigation. "
            "Has strong JavaScript challenge mechanism."
        ),
        "strategies": [
            {
                "name": "Cookie Chain Resolution",
                "description": "Properly handle Incapsula's cookie flow",
                "techniques": [
                    "Execute initial JavaScript challenge",
                    "Maintain visid_incap cookie",
                    "Handle incap_ses session cookies",
                    "Preserve cookie order in requests",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Origin Discovery",
                "description": "Find the real server IP",
                "techniques": [
                    "DNS history lookup",
                    "SSL certificate scanning",
                    "Mail server enumeration",
                    "IPv6 might not be protected",
                ],
                "effectiveness": "HIGH",
            },
        ],
        "limitations": [
            "Bot detection is behavioral",
            "JavaScript execution required",
            "Fingerprinting is advanced",
        ],
    },
    "modsecurity": {
        "general_info": (
            "ModSecurity is open-source and highly configurable. OWASP Core Rule Set "
            "(CRS) is commonly used. Rules are signature-based and well-documented."
        ),
        "strategies": [
            {
                "name": "CRS Rule Bypass",
                "description": "Bypass OWASP Core Rule Set patterns",
                "techniques": [
                    "Use SQL comments: /*!50000SELECT*/",
                    "Variable case: SeLeCt, UnIoN",
                    "Whitespace alternatives: %09, %0a, %0d",
                    "String concatenation: 'sel'||'ect'",
                ],
                "effectiveness": "MEDIUM-HIGH",
            },
            {
                "name": "Paranoia Level Detection",
                "description": "Identify CRS paranoia level",
                "techniques": [
                    "Test progressively suspicious payloads",
                    "Check if common XSS vectors are blocked",
                    "Identify if SQL comments are filtered",
                ],
                "effectiveness": "HIGH",
            },
            {
                "name": "Content-Type Manipulation",
                "description": "Exploit parser differences",
                "techniques": [
                    "Use application/x-www-form-urlencoded vs multipart",
                    "Send JSON payloads as form data",
                    "Malformed Content-Type headers",
                ],
                "effectiveness": "MEDIUM",
            },
        ],
        "limitations": [
            "Paranoia level 3+ is very strict",
            "Custom rules may exist",
            "SecRule exceptions vary",
        ],
    },
    "f5_big_ip": {
        "general_info": (
            "F5 BIG-IP ASM is enterprise-grade with learning mode capabilities. "
            "Can be very strict when properly configured."
        ),
        "strategies": [
            {
                "name": "Support ID Analysis",
                "description": "Analyze error responses for intelligence",
                "techniques": [
                    "Collect support IDs to understand rule triggers",
                    "Map which payloads trigger which rules",
                    "Look for patterns in blocking behavior",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Cookie Manipulation",
                "description": "Exploit BIG-IP cookie handling",
                "techniques": [
                    "Decode BIGipServer cookies for backend info",
                    "Check if TS cookies leak information",
                ],
                "effectiveness": "LOW-MEDIUM",
            },
        ],
        "limitations": [
            "Learning mode creates custom signatures",
            "Enterprise deployments are complex",
            "Cookie decoding reveals limited info",
        ],
    },
    "sucuri": {
        "general_info": (
            "Sucuri CloudProxy is popular for WordPress sites. Has website firewall "
            "and malware scanning. Often used with default configurations."
        ),
        "strategies": [
            {
                "name": "Origin Discovery",
                "description": "Find real server IP",
                "techniques": [
                    "Check DNS history",
                    "Look for cPanel/Plesk on common ports",
                    "Check for mail server IP leaks",
                    "Search for IP in JS/CSS files",
                ],
                "effectiveness": "HIGH",
            },
            {
                "name": "Default Rule Bypass",
                "description": "Bypass common default configurations",
                "techniques": [
                    "Test for whitelist gaps (admin panels)",
                    "Check if /wp-admin is accessible",
                    "Test XML-RPC if WordPress",
                ],
                "effectiveness": "MEDIUM",
            },
        ],
        "limitations": [
            "Origin IP may have Sucuri firewall rules",
            "Custom rules vary per deployment",
        ],
    },
    "generic": {
        "general_info": (
            "Generic WAF bypass strategies that work across multiple WAF vendors. "
            "These techniques exploit common implementation weaknesses."
        ),
        "strategies": [
            {
                "name": "HTTP Method Override",
                "description": "Use alternative methods to bypass method restrictions",
                "techniques": [
                    "X-HTTP-Method-Override header",
                    "X-HTTP-Method header",
                    "X-Method-Override header",
                    "_method parameter in body",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Protocol-Level Bypass",
                "description": "Exploit HTTP parsing differences",
                "techniques": [
                    "HTTP/0.9 downgrade (rare)",
                    "HTTP/2 specific bypasses",
                    "Malformed HTTP requests",
                    "Request smuggling (if applicable)",
                ],
                "effectiveness": "LOW-HIGH",
            },
            {
                "name": "Encoding Chains",
                "description": "Use multiple encoding layers",
                "techniques": [
                    "URL encode + Base64",
                    "HTML entities + URL encoding",
                    "Unicode + URL encoding",
                    "Punycode for domain-based filters",
                ],
                "effectiveness": "MEDIUM",
            },
            {
                "name": "Header Injection",
                "description": "Inject via HTTP headers",
                "techniques": [
                    "X-Forwarded-For spoofing (if trusted)",
                    "X-Originating-IP manipulation",
                    "Custom headers that may be logged/processed",
                ],
                "effectiveness": "LOW-MEDIUM",
            },
        ],
        "limitations": [
            "Effectiveness varies greatly",
            "Many techniques are patched",
            "May require specific backend vulnerabilities",
        ],
    },
}


def _match_waf_signature(
    headers: dict[str, str],
    cookies: dict[str, str],
    body: str,
    status_code: int,
    waf_id: str,
    signature: dict[str, Any],
) -> dict[str, Any]:
    """Match a WAF signature against response data."""
    matches: list[str] = []
    confidence = 0.0
    
    # Check headers
    for header_name, pattern in signature.get("headers", {}).items():
        header_value = headers.get(header_name.lower(), "")
        if header_value and re.search(pattern, header_value, re.IGNORECASE):
            matches.append(f"header:{header_name}")
            confidence += 0.25
    
    # Check cookies
    for cookie_name in signature.get("cookies", []):
        # Check if cookie name or prefix matches
        for c_name in cookies:
            if c_name.lower().startswith(cookie_name.lower()):
                matches.append(f"cookie:{c_name}")
                confidence += 0.2
                break
    
    # Check body patterns
    for pattern in signature.get("body_patterns", []):
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(f"body_pattern:{pattern[:30]}")
            confidence += 0.3
    
    # Check status codes (only if blocked)
    if status_code in signature.get("status_codes", []) and status_code >= 400:
        matches.append(f"status_code:{status_code}")
        confidence += 0.1
    
    return {
        "waf_id": waf_id,
        "name": signature.get("name", waf_id),
        "vendor": signature.get("vendor", "Unknown"),
        "matches": matches,
        "confidence": min(confidence, 1.0),
    }


@register_tool(sandbox_execution=False)
async def detect_waf(
    url: str,
    test_payload: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """
    Detect Web Application Firewall (WAF) presence by fingerprinting HTTP responses.
    
    This tool analyzes HTTP response headers, cookies, and body content to identify
    WAF vendors. It uses passive fingerprinting and optionally sends benign test
    requests.
    
    Args:
        url: Target URL to analyze (e.g., "https://example.com")
        test_payload: If True, send additional requests with benign test strings
                     that might trigger WAF responses (e.g., "' OR 1=1" in User-Agent)
        verbose: Include detailed match information in response
    
    Returns:
        Dictionary containing:
        - success: Whether detection succeeded
        - url: The analyzed URL
        - waf_detected: Whether a WAF was detected
        - wafs: List of detected WAFs with confidence scores
        - primary_waf: The most likely WAF (highest confidence)
        - headers_analyzed: Key headers that were checked
        - recommendations: Suggested next steps
        - message: Status message
    
    Supported WAFs:
        Cloudflare, Akamai, AWS WAF, Imperva/Incapsula, Sucuri,
        F5 BIG-IP, ModSecurity, FortiWeb, Barracuda, Wordfence,
        Azure WAF, Radware, Wallarm, Citrix NetScaler, and more.
    """
    # Validate URL
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https scheme")
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid URL: {str(e)}",
            "waf_detected": False,
            "wafs": [],
        }
    
    # Check cache
    cache_key = _get_cache_key("waf_detect", url, test_payload)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    # Rate limit
    _rate_limit()
    
    detected_wafs: list[dict[str, Any]] = []
    all_headers: dict[str, str] = {}
    all_cookies: dict[str, str] = {}
    
    try:
        async with httpx.AsyncClient(
            trust_env=False,
            timeout=30.0,
            follow_redirects=True,
            verify=False,  # Some WAFs have cert issues
        ) as client:
            # Request 1: Normal request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            
            response = await client.get(url, headers=headers)
            
            # Collect headers (lowercase for consistency)
            all_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Parse cookies
            for cookie in response.cookies:
                all_cookies[cookie.name] = cookie.value
            
            # Get body for pattern matching
            body = response.text[:50000]  # Limit body size
            status_code = response.status_code
            
            # Match against all WAF signatures
            for waf_id, signature in WAF_SIGNATURES.items():
                match_result = _match_waf_signature(
                    all_headers, all_cookies, body, status_code, waf_id, signature
                )
                if match_result["matches"]:
                    detected_wafs.append(match_result)
            
            # Request 2: Test with benign "suspicious" payload (if enabled)
            if test_payload:
                _rate_limit()
                
                # Send request with benign SQLi-like pattern in User-Agent
                test_headers = {
                    **headers,
                    "User-Agent": "Mozilla/5.0 (test' OR '1'='1) AppleWebKit/537.36",
                }
                
                try:
                    test_response = await client.get(url, headers=test_headers)
                    test_body = test_response.text[:50000]
                    test_status = test_response.status_code
                    
                    # If we got blocked, re-check signatures
                    if test_status >= 400 and test_status != 404:
                        test_headers_dict = {k.lower(): v for k, v in test_response.headers.items()}
                        test_cookies = {c.name: c.value for c in test_response.cookies}
                        
                        for waf_id, signature in WAF_SIGNATURES.items():
                            match_result = _match_waf_signature(
                                test_headers_dict, test_cookies, test_body, test_status, waf_id, signature
                            )
                            if match_result["matches"]:
                                # Check if we already have this WAF
                                existing = next((w for w in detected_wafs if w["waf_id"] == waf_id), None)
                                if existing:
                                    # Increase confidence
                                    existing["confidence"] = min(existing["confidence"] + 0.2, 1.0)
                                    existing["matches"].extend(match_result["matches"])
                                    existing["triggered_by_test"] = True
                                else:
                                    match_result["triggered_by_test"] = True
                                    detected_wafs.append(match_result)
                                    
                except httpx.HTTPError:
                    # Test request failed - might itself indicate WAF
                    pass
        
        # Sort by confidence
        detected_wafs.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Determine primary WAF
        primary_waf = None
        if detected_wafs:
            primary = detected_wafs[0]
            if primary["confidence"] >= 0.3:
                primary_waf = {
                    "name": primary["name"],
                    "vendor": primary["vendor"],
                    "confidence": round(primary["confidence"] * 100, 1),
                    "waf_id": primary["waf_id"],
                }
        
        # Build recommendations
        recommendations = []
        if primary_waf:
            recommendations.append(f"Use get_waf_evasion_strategies('{primary_waf['waf_id']}') for bypass techniques")
            recommendations.append("Consider searching for origin IP (DNS history, certificate search)")
            recommendations.append("Check if all subdomains use the same WAF")
        else:
            recommendations.append("No WAF detected - but absence of evidence is not evidence of absence")
            recommendations.append("The site might use a custom or unknown WAF")
            recommendations.append("Try with test_payload=True for more aggressive detection")
        
        # Clean up match details if not verbose
        if not verbose:
            for waf in detected_wafs:
                waf["matches"] = len(waf.get("matches", []))
        
        result = {
            "success": True,
            "url": url,
            "waf_detected": bool(primary_waf),
            "wafs": detected_wafs[:5],  # Top 5
            "primary_waf": primary_waf,
            "headers_analyzed": {
                "server": all_headers.get("server", ""),
                "x-powered-by": all_headers.get("x-powered-by", ""),
                "via": all_headers.get("via", ""),
            },
            "cookies_found": list(all_cookies.keys())[:10],
            "recommendations": recommendations,
            "message": (
                f"Detected {primary_waf['name']} (confidence: {primary_waf['confidence']}%)"
                if primary_waf
                else "No WAF definitively detected"
            ),
        }
        
        _set_cached(cache_key, result)
        return result
        
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out - target may be blocking or slow",
            "waf_detected": False,
            "wafs": [],
        }
    except httpx.HTTPError as e:
        return {
            "success": False,
            "error": f"HTTP error: {str(e)[:200]}",
            "waf_detected": False,
            "wafs": [],
        }
    except Exception as e:
        logger.exception("WAF detection failed")
        return {
            "success": False,
            "error": f"Detection failed: {str(e)[:200]}",
            "waf_detected": False,
            "wafs": [],
        }


@register_tool(sandbox_execution=False)
async def get_waf_evasion_strategies(
    waf_id: str | None = None,
    waf_name: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """
    Get WAF evasion strategies and bypass techniques for a specific WAF.
    
    This tool provides educational information about WAF bypass techniques.
    Use this after detect_waf() identifies the target's WAF.
    
    Args:
        waf_id: WAF identifier from detect_waf() (e.g., "cloudflare", "akamai")
        waf_name: Alternative: search by WAF name (e.g., "Cloudflare")
        category: Optional: filter strategies by category
                 Options: "encoding", "origin", "browser", "protocol"
    
    Returns:
        Dictionary containing:
        - success: Whether lookup succeeded
        - waf: WAF name and vendor information
        - general_info: Overview of the WAF and its defenses
        - strategies: List of evasion strategies with techniques
        - limitations: Known limitations and caveats
        - available_wafs: List of WAFs with available strategies
        - message: Status message
    
    Supported WAFs:
        cloudflare, akamai, aws_waf, imperva_incapsula, sucuri,
        f5_big_ip, modsecurity, generic (universal techniques)
    """
    # Normalize inputs
    if waf_name and not waf_id:
        # Try to find waf_id from name
        waf_name_lower = waf_name.lower()
        for wid, strategies in WAF_EVASION_STRATEGIES.items():
            if waf_name_lower in wid or waf_name_lower in strategies.get("general_info", "").lower():
                waf_id = wid
                break
    
    if not waf_id:
        # List available WAFs
        available = []
        for wid in WAF_EVASION_STRATEGIES.keys():
            if wid in WAF_SIGNATURES:
                available.append({
                    "id": wid,
                    "name": WAF_SIGNATURES[wid].get("name", wid),
                    "vendor": WAF_SIGNATURES[wid].get("vendor", "Unknown"),
                })
            else:
                available.append({"id": wid, "name": wid.title(), "vendor": "N/A"})
        
        return {
            "success": True,
            "waf_id": None,
            "message": "No WAF specified. Use waf_id parameter or run detect_waf() first.",
            "available_wafs": available,
            "suggestion": "Try get_waf_evasion_strategies(waf_id='cloudflare') or waf_id='generic' for universal techniques",
        }
    
    waf_id = waf_id.lower().replace(" ", "_").replace("-", "_")
    
    # Check if we have strategies for this WAF
    if waf_id not in WAF_EVASION_STRATEGIES:
        # Try partial match
        for wid in WAF_EVASION_STRATEGIES.keys():
            if waf_id in wid or wid in waf_id:
                waf_id = wid
                break
    
    if waf_id not in WAF_EVASION_STRATEGIES:
        return {
            "success": False,
            "error": f"No evasion strategies found for WAF: {waf_id}",
            "suggestion": "Try waf_id='generic' for universal bypass techniques",
            "available_wafs": list(WAF_EVASION_STRATEGIES.keys()),
        }
    
    strategies_data = WAF_EVASION_STRATEGIES[waf_id]
    
    # Get WAF info from signatures if available
    waf_info = {
        "id": waf_id,
        "name": WAF_SIGNATURES.get(waf_id, {}).get("name", waf_id.title()),
        "vendor": WAF_SIGNATURES.get(waf_id, {}).get("vendor", "Unknown"),
    }
    
    # Filter strategies by category if specified
    strategies = strategies_data.get("strategies", [])
    if category:
        category_lower = category.lower()
        strategies = [
            s for s in strategies
            if category_lower in s.get("name", "").lower()
            or category_lower in s.get("description", "").lower()
            or any(category_lower in t.lower() for t in s.get("techniques", []))
        ]
    
    return {
        "success": True,
        "waf": waf_info,
        "general_info": strategies_data.get("general_info", ""),
        "strategies": strategies,
        "limitations": strategies_data.get("limitations", []),
        "note": "These techniques are for authorized security testing only",
        "message": f"Found {len(strategies)} evasion strategies for {waf_info['name']}",
    }
