"""
Vulnerability Intelligence Tools - Phase 1 Enhancement
=======================================================

Tools for correlating version information with known CVEs and exploits.
Critical for turning version fingerprints into actionable exploits.

SECURITY NOTES:
- All tools are READ-ONLY (query public databases)
- No interaction with target systems
- Results are cached to reduce API calls
- Rate limiting prevents abuse

Tools:
- cve_search: Search NVD for CVEs by product/version
- exploit_search: Search ExploitDB for available exploits
- version_to_cves: Map technology version to known CVEs
"""

import asyncio
import hashlib
import logging
import os
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote_plus

import httpx

from phantom.config.config import Config
from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Rate limiting
_RATE_LIMIT_STATE: dict[str, float] = {}
_RATE_LIMIT_INTERVALS: dict[str, float] = {
    "nvd": 6.0,       # NVD: 6 seconds between requests (public API limit)
    "exploitdb": 2.0,  # ExploitDB: 2 seconds
    "vulners": 1.0,    # Vulners: 1 second
}

# Cache for CVE results
_CVE_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 7200  # 2 hour cache TTL for CVE data


def _rate_limit(api_name: str) -> None:
    """Enforce rate limiting for API calls."""
    now = time.monotonic()
    last_call = _RATE_LIMIT_STATE.get(api_name, 0.0)
    interval = _RATE_LIMIT_INTERVALS.get(api_name, 1.0)
    wait_time = interval - (now - last_call)
    if wait_time > 0:
        time.sleep(wait_time)
    _RATE_LIMIT_STATE[api_name] = time.monotonic()


def _get_cache_key(prefix: str, *args: Any) -> str:
    """Generate a cache key."""
    data = f"{prefix}:{':'.join(str(a) for a in args)}"
    return hashlib.md5(data.encode()).hexdigest()


def _get_cached(key: str) -> Any | None:
    """Get cached result if not expired."""
    if key not in _CVE_CACHE:
        return None
    result, timestamp = _CVE_CACHE[key]
    if time.time() - timestamp > _CACHE_TTL:
        del _CVE_CACHE[key]
        return None
    return result


def _set_cached(key: str, result: Any) -> None:
    """Store result in cache."""
    _CVE_CACHE[key] = (result, time.time())
    # Cleanup
    if len(_CVE_CACHE) > 500:
        cutoff = time.time() - _CACHE_TTL
        keys_to_delete = [k for k, (_, ts) in _CVE_CACHE.items() if ts < cutoff]
        for k in keys_to_delete:
            del _CVE_CACHE[k]


def _parse_version(version_string: str) -> tuple[str, str]:
    """Parse a product/version string into (product, version)."""
    # Common formats:
    # nginx/1.19.0
    # Apache/2.4.49
    # PHP/7.4.3
    # OpenSSH_8.2p1
    # Microsoft-IIS/10.0
    
    patterns = [
        r"^([a-zA-Z][a-zA-Z0-9_-]*)[/_ ]([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9._-]*)?)$",
        r"^([a-zA-Z][a-zA-Z0-9_-]*)-([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9._-]*)?)$",
    ]
    
    for pattern in patterns:
        match = re.match(pattern, version_string.strip())
        if match:
            return match.group(1).lower(), match.group(2)
    
    # Fallback: try splitting on common delimiters
    for delim in ["/", "_", "-", " "]:
        if delim in version_string:
            parts = version_string.split(delim, 1)
            if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                return parts[0].lower().strip(), parts[1].strip()
    
    return version_string.lower().strip(), ""


def _calculate_cvss_severity(score: float) -> str:
    """Convert CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


@register_tool(sandbox_execution=False)
async def cve_search(
    product: str,
    version: str | None = None,
    vendor: str | None = None,
    severity: str | None = None,
    max_results: int = 25,
) -> dict[str, Any]:
    """
    Search the NVD (National Vulnerability Database) for CVEs.
    
    This is a PASSIVE reconnaissance tool - it queries public CVE databases,
    NOT the target. Use this to find known vulnerabilities for detected software.
    
    Args:
        product: Product name (e.g., "nginx", "apache", "openssh")
        version: Optional version number (e.g., "1.19.0", "2.4.49")
        vendor: Optional vendor name (e.g., "apache", "microsoft")
        severity: Filter by severity: "CRITICAL", "HIGH", "MEDIUM", "LOW"
        max_results: Maximum CVEs to return (default: 25)
    
    Returns:
        Dictionary containing:
        - success: Whether the search succeeded
        - cves: List of CVE details with scores, descriptions, and references
        - total_results: Total CVEs matching criteria
        - critical_count: Number of CRITICAL severity CVEs
        - high_count: Number of HIGH severity CVEs
        - message: Status message
    
    Common products to search:
        - Web servers: nginx, apache, iis, tomcat
        - Languages: php, python, nodejs, java
        - Frameworks: spring, django, rails, express
        - Databases: mysql, postgresql, mongodb, redis
        - CMS: wordpress, drupal, joomla
    """
    if not product:
        return {"success": False, "error": "Product name is required", "cves": []}
    
    product = product.lower().strip()
    
    # Check cache
    cache_key = _get_cache_key("nvd", product, version, vendor, severity)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    # Rate limit
    _rate_limit("nvd")
    
    try:
        # Build NVD API query
        # Using the new NVD API 2.0
        params = {
            "keywordSearch": product,
            "resultsPerPage": min(max_results, 100),
        }
        
        if version:
            params["keywordSearch"] = f"{product} {version}"
        
        if vendor:
            params["keywordSearch"] = f"{vendor} {params['keywordSearch']}"
        
        # NVD API key (optional but recommended for higher rate limits)
        api_key = Config.get("phantom_nvd_api_key")
        headers = {
            "User-Agent": "Phantom-Scanner/1.0",
        }
        if api_key:
            headers["apiKey"] = api_key
        
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            response = await client.get(url, params=params, headers=headers)
            
            if response.status_code == 403:
                return {
                    "success": False,
                    "error": "NVD API rate limited. Set NVD_API_KEY for higher limits.",
                    "cves": [],
                }
            
            response.raise_for_status()
            data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        cves: list[dict[str, Any]] = []
        critical_count = 0
        high_count = 0
        
        for vuln in vulnerabilities[:max_results]:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Get CVSS scores (try v3.1, then v3.0, then v2)
            cvss_score = 0.0
            cvss_vector = ""
            
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            
            severity_label = _calculate_cvss_severity(cvss_score)
            
            # Filter by severity if specified
            if severity and severity_label != severity.upper():
                continue
            
            if severity_label == "CRITICAL":
                critical_count += 1
            elif severity_label == "HIGH":
                high_count += 1
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:500]
                    break
            
            # Get references
            references = []
            for ref in cve_data.get("references", [])[:5]:
                references.append({
                    "url": ref.get("url", ""),
                    "tags": ref.get("tags", []),
                })
            
            # Get affected configurations
            affected = []
            for config in cve_data.get("configurations", [])[:3]:
                for node in config.get("nodes", [])[:3]:
                    for cpe_match in node.get("cpeMatch", [])[:5]:
                        criteria = cpe_match.get("criteria", "")
                        if criteria:
                            affected.append(criteria)
            
            cve_entry = {
                "cve_id": cve_id,
                "severity": severity_label,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "description": description,
                "references": references,
                "affected_versions": affected[:5],
                "published": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
            }
            
            cves.append(cve_entry)
        
        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x["cvss_score"], reverse=True)
        
        result = {
            "success": True,
            "product": product,
            "version": version,
            "cves": cves,
            "total_results": total_results,
            "returned_count": len(cves),
            "critical_count": critical_count,
            "high_count": high_count,
            "message": f"Found {len(cves)} CVEs ({critical_count} critical, {high_count} high)",
        }
        
        _set_cached(cache_key, result)
        return result
        
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "NVD API request timed out",
            "cves": [],
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"NVD API error: HTTP {e.response.status_code}",
            "cves": [],
        }
    except Exception as e:
        logger.exception("CVE search failed")
        return {
            "success": False,
            "error": f"CVE search failed: {str(e)[:200]}",
            "cves": [],
        }


@register_tool(sandbox_execution=False)
async def exploit_search(
    cve_id: str | None = None,
    product: str | None = None,
    exploit_type: str | None = None,
    max_results: int = 20,
) -> dict[str, Any]:
    """
    Search for available exploits in public databases (ExploitDB, Vulners).
    
    This is a PASSIVE reconnaissance tool - it searches exploit databases,
    NOT the target. Use this to find working exploits for identified CVEs.
    
    Args:
        cve_id: CVE ID to search for (e.g., "CVE-2021-44228")
        product: Product name to search (e.g., "apache", "wordpress")
        exploit_type: Filter by type: "remote", "local", "webapps", "dos"
        max_results: Maximum exploits to return (default: 20)
    
    Returns:
        Dictionary containing:
        - success: Whether the search succeeded
        - exploits: List of exploit details with URLs and descriptions
        - total_count: Total exploits found
        - has_metasploit: Whether Metasploit modules exist
        - has_poc: Whether proof-of-concept code exists
        - message: Status message
    
    Note: At least one of cve_id or product must be provided.
    """
    if not cve_id and not product:
        return {
            "success": False,
            "error": "Either 'cve_id' or 'product' must be provided",
            "exploits": [],
        }
    
    # Check cache
    cache_key = _get_cache_key("exploits", cve_id, product, exploit_type)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    exploits: list[dict[str, Any]] = []
    has_metasploit = False
    has_poc = False
    
    try:
        # Try Vulners API first (if API key available)
        vulners_api_key = Config.get("phantom_vulners_api_key")
        
        if vulners_api_key:
            _rate_limit("vulners")
            
            async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
                # Build search query
                query_parts = []
                if cve_id:
                    query_parts.append(cve_id)
                if product:
                    query_parts.append(product)
                
                query = " ".join(query_parts)
                
                url = "https://vulners.com/api/v3/search/lucene/"
                payload = {
                    "query": query,
                    "apiKey": vulners_api_key,
                    "size": max_results,
                }
                
                response = await client.post(url, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("result") == "OK":
                        for doc in data.get("data", {}).get("search", [])[:max_results]:
                            doc_type = doc.get("_type", "").lower()
                            source = doc.get("_source", {})
                            
                            exploit_entry = {
                                "id": doc.get("_id", ""),
                                "title": source.get("title", "")[:200],
                                "description": source.get("description", "")[:300],
                                "type": doc_type,
                                "source": source.get("type", ""),
                                "published": source.get("published", ""),
                                "cvss_score": source.get("cvss", {}).get("score", 0),
                                "url": source.get("href", ""),
                                "references": source.get("references", [])[:5],
                            }
                            
                            # Check for Metasploit
                            if "metasploit" in doc_type or "msf" in source.get("title", "").lower():
                                has_metasploit = True
                                exploit_entry["metasploit"] = True
                            
                            # Check for PoC
                            if "exploit" in doc_type or "poc" in source.get("title", "").lower():
                                has_poc = True
                                exploit_entry["has_code"] = True
                            
                            exploits.append(exploit_entry)
        
        # Also search ExploitDB via searchsploit-style query
        # (This uses the ExploitDB GitLab mirror which is public)
        if cve_id or product:
            _rate_limit("exploitdb")
            
            search_term = cve_id if cve_id else product
            
            async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
                # Query the ExploitDB API
                url = f"https://www.exploit-db.com/search?cve={quote_plus(search_term)}" if cve_id else f"https://www.exploit-db.com/search?q={quote_plus(search_term)}"
                
                # ExploitDB doesn't have a public API, but we can check GitLab
                gitlab_url = f"https://gitlab.com/api/v4/projects/8218206/repository/tree?path=exploits&search={quote_plus(search_term)}&per_page=20"
                
                try:
                    response = await client.get(gitlab_url, timeout=15.0)
                    if response.status_code == 200:
                        files = response.json()
                        for f in files[:max_results]:
                            if f.get("type") == "blob":
                                name = f.get("name", "")
                                path = f.get("path", "")
                                
                                exploit_entry = {
                                    "id": f"EDB-{name.split('.')[0] if '.' in name else name}",
                                    "title": name,
                                    "type": "exploitdb",
                                    "source": "ExploitDB",
                                    "path": path,
                                    "url": f"https://www.exploit-db.com/exploits/{name.split('.')[0] if '.' in name else name}",
                                    "has_code": True,
                                }
                                
                                has_poc = True
                                
                                # Check for duplicates
                                if not any(e.get("title") == name for e in exploits):
                                    exploits.append(exploit_entry)
                except Exception:
                    pass  # ExploitDB search is optional
        
        # Sort by CVSS score if available
        exploits.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        result = {
            "success": True,
            "cve_id": cve_id,
            "product": product,
            "exploits": exploits[:max_results],
            "total_count": len(exploits),
            "has_metasploit": has_metasploit,
            "has_poc": has_poc,
            "message": f"Found {len(exploits)} exploits (Metasploit: {has_metasploit}, PoC: {has_poc})",
        }
        
        _set_cached(cache_key, result)
        return result
        
    except Exception as e:
        logger.exception("Exploit search failed")
        return {
            "success": False,
            "error": f"Exploit search failed: {str(e)[:200]}",
            "exploits": [],
        }


@register_tool(sandbox_execution=False)
async def version_to_cves(
    version_string: str,
    include_exploits: bool = True,
) -> dict[str, Any]:
    """
    Map a technology version string to known CVEs and exploits.
    
    This is a PASSIVE reconnaissance tool - it parses version info and
    queries CVE databases. Use after fingerprinting to find vulnerabilities.
    
    Args:
        version_string: Version string from fingerprinting (e.g., "nginx/1.19.0",
                       "Apache/2.4.49", "PHP/7.4.3", "OpenSSH_8.2p1")
        include_exploits: Also search for available exploits (default: True)
    
    Returns:
        Dictionary containing:
        - success: Whether the correlation succeeded
        - product: Detected product name
        - version: Detected version number
        - cves: List of matching CVEs
        - exploits: List of available exploits (if include_exploits=True)
        - risk_level: Overall risk assessment
        - recommendations: Suggested actions
        - message: Status message
    
    Common version formats:
        - "nginx/1.19.0"
        - "Apache/2.4.49" (CVE-2021-41773 - path traversal)
        - "PHP/7.4.3"
        - "OpenSSH_8.2p1"
        - "Microsoft-IIS/10.0"
        - "Express" (JS framework)
    """
    if not version_string:
        return {
            "success": False,
            "error": "Version string is required",
            "cves": [],
        }
    
    # Parse the version string
    product, version = _parse_version(version_string)
    
    if not product:
        return {
            "success": False,
            "error": f"Could not parse version string: {version_string}",
            "cves": [],
        }
    
    # Search for CVEs
    cve_result = await cve_search(
        product=product,
        version=version if version else None,
        max_results=20,
    )
    
    cves = cve_result.get("cves", [])
    
    # Calculate risk level
    critical_count = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    high_count = sum(1 for c in cves if c.get("severity") == "HIGH")
    
    if critical_count > 0:
        risk_level = "CRITICAL"
    elif high_count > 0:
        risk_level = "HIGH"
    elif len(cves) > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Search for exploits if requested
    exploits: list[dict[str, Any]] = []
    if include_exploits and cves:
        # Search for exploits of top CVEs
        for cve in cves[:5]:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                exploit_result = await exploit_search(cve_id=cve_id, max_results=5)
                exploits.extend(exploit_result.get("exploits", []))
        
        # Also search by product
        product_exploits = await exploit_search(product=product, max_results=10)
        for exp in product_exploits.get("exploits", []):
            if not any(e.get("id") == exp.get("id") for e in exploits):
                exploits.append(exp)
    
    # Generate recommendations
    recommendations = []
    if risk_level == "CRITICAL":
        recommendations.append("IMMEDIATE: Prioritize exploitation of critical CVEs")
        recommendations.append("Check for public exploits and Metasploit modules")
    elif risk_level == "HIGH":
        recommendations.append("High-value target: Focus testing on identified CVEs")
        recommendations.append("Manual verification of exploitability recommended")
    elif risk_level == "MEDIUM":
        recommendations.append("Moderate risk: Include in comprehensive testing")
    else:
        recommendations.append("Low risk from known CVEs")
        recommendations.append("Focus on zero-day discovery and logic flaws")
    
    if version:
        recommendations.append(f"Confirm version {version} matches target exactly")
    
    if exploits:
        has_msf = any(e.get("metasploit") for e in exploits)
        if has_msf:
            recommendations.append("Metasploit modules available - consider automated exploitation")
    
    return {
        "success": True,
        "version_string": version_string,
        "product": product,
        "version": version,
        "cves": cves,
        "exploits": exploits[:20] if exploits else [],
        "risk_level": risk_level,
        "critical_count": critical_count,
        "high_count": high_count,
        "total_cves": len(cves),
        "total_exploits": len(exploits),
        "recommendations": recommendations,
        "message": f"Mapped {product}/{version} to {len(cves)} CVEs, {len(exploits)} exploits (Risk: {risk_level})",
    }


@register_tool(sandbox_execution=False)
async def get_cve_details(cve_id: str) -> dict[str, Any]:
    """
    Get detailed information about a specific CVE.
    
    This is a PASSIVE reconnaissance tool - it queries the NVD for CVE details.
    Use this to get full information about a specific vulnerability.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228", "CVE-2021-41773")
    
    Returns:
        Dictionary containing:
        - success: Whether the lookup succeeded
        - cve_id: The CVE identifier
        - description: Full vulnerability description
        - cvss_score: CVSS score
        - cvss_vector: Full CVSS vector string
        - severity: Severity level
        - affected_products: List of affected CPE configurations
        - references: List of reference URLs
        - exploitability: Exploitability metrics
        - impact: Impact metrics
        - weaknesses: CWE identifiers
        - message: Status message
    """
    if not cve_id:
        return {"success": False, "error": "CVE ID is required"}
    
    # Normalize CVE ID
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    
    # Validate format
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {"success": False, "error": f"Invalid CVE ID format: {cve_id}"}
    
    # Check cache
    cache_key = _get_cache_key("cve_details", cve_id)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    _rate_limit("nvd")
    
    try:
        api_key = Config.get("phantom_nvd_api_key")
        headers = {"User-Agent": "Phantom-Scanner/1.0"}
        if api_key:
            headers["apiKey"] = api_key
        
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {
                "success": False,
                "error": f"CVE {cve_id} not found in NVD",
            }
        
        cve_data = vulnerabilities[0].get("cve", {})
        
        # Get CVSS metrics
        cvss_score = 0.0
        cvss_vector = ""
        severity = "UNKNOWN"
        exploitability_score = 0.0
        impact_score = 0.0
        
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            exploitability_score = metrics["cvssMetricV31"][0].get("exploitabilityScore", 0.0)
            impact_score = metrics["cvssMetricV31"][0].get("impactScore", 0.0)
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
        
        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Get affected products
        affected_products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    affected_products.append({
                        "cpe": cpe_match.get("criteria", ""),
                        "vulnerable": cpe_match.get("vulnerable", True),
                        "version_start": cpe_match.get("versionStartIncluding", ""),
                        "version_end": cpe_match.get("versionEndExcluding", ""),
                    })
        
        # Get references
        references = []
        for ref in cve_data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", []),
            })
        
        # Get weaknesses (CWE)
        weaknesses = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
        
        result = {
            "success": True,
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "exploitability_score": exploitability_score,
            "impact_score": impact_score,
            "affected_products": affected_products[:20],
            "references": references[:15],
            "weaknesses": weaknesses,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "message": f"Retrieved details for {cve_id} (CVSS: {cvss_score}, {severity})",
        }
        
        _set_cached(cache_key, result)
        return result
        
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"NVD API error: HTTP {e.response.status_code}",
        }
    except Exception as e:
        logger.exception("CVE details lookup failed")
        return {
            "success": False,
            "error": f"CVE details lookup failed: {str(e)[:200]}",
        }
