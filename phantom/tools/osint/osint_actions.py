"""
OSINT Tools - Phase 1 Enhancement
=================================

Passive reconnaissance tools for attack surface discovery.
These tools query external APIs and databases - they NEVER touch the target directly.

SECURITY NOTES:
- All tools are READ-ONLY (passive reconnaissance)
- API keys are optional - tools degrade gracefully without them
- Rate limiting is built-in to prevent API abuse
- Results are cached to reduce redundant queries
- No data is sent to the target

Tools:
- crtsh_search: Certificate Transparency log search (crt.sh)
- shodan_search: Shodan API search for exposed services
- whois_lookup: WHOIS history lookup
- dns_history: DNS history lookup via SecurityTrails
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

# Rate limiting state (simple in-memory)
_RATE_LIMIT_STATE: dict[str, float] = {}
_RATE_LIMIT_INTERVALS: dict[str, float] = {
    "crtsh": 2.0,      # crt.sh: 2 seconds between requests
    "shodan": 1.0,     # Shodan: 1 second between requests
    "whois": 3.0,      # WHOIS: 3 seconds between requests
    "securitytrails": 2.0,  # SecurityTrails: 2 seconds between requests
}

# Simple in-memory cache for OSINT results
_OSINT_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 3600  # 1 hour cache TTL


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
    """Generate a cache key from prefix and arguments."""
    data = f"{prefix}:{':'.join(str(a) for a in args)}"
    return hashlib.md5(data.encode()).hexdigest()


def _get_cached(key: str) -> Any | None:
    """Get cached result if not expired."""
    if key not in _OSINT_CACHE:
        return None
    result, timestamp = _OSINT_CACHE[key]
    if time.time() - timestamp > _CACHE_TTL:
        del _OSINT_CACHE[key]
        return None
    return result


def _set_cached(key: str, result: Any) -> None:
    """Store result in cache."""
    _OSINT_CACHE[key] = (result, time.time())
    # Cleanup old entries if cache grows too large
    if len(_OSINT_CACHE) > 1000:
        cutoff = time.time() - _CACHE_TTL
        keys_to_delete = [k for k, (_, ts) in _OSINT_CACHE.items() if ts < cutoff]
        for k in keys_to_delete:
            del _OSINT_CACHE[k]


def _extract_domain(target: str) -> str:
    """Extract the root domain from a URL or hostname."""
    # Remove protocol
    if "://" in target:
        target = target.split("://", 1)[1]
    # Remove path
    target = target.split("/")[0]
    # Remove port
    target = target.split(":")[0]
    # Lowercase first, then remove www prefix
    target = target.lower().strip()
    if target.startswith("www."):
        target = target[4:]
    return target


def _validate_domain(domain: str) -> tuple[bool, str]:
    """Validate domain format for OSINT queries."""
    if not domain:
        return False, "Domain cannot be empty"
    if len(domain) > 253:
        return False, "Domain too long"
    # Basic domain validation
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if not pattern.match(domain):
        # Allow wildcard prefix for crt.sh
        if domain.startswith("%."):
            return _validate_domain(domain[2:])
        return False, f"Invalid domain format: {domain}"
    return True, ""


@register_tool(sandbox_execution=False)
async def crtsh_search(domain: str, include_expired: bool = False) -> dict[str, Any]:
    """
    Search Certificate Transparency logs via crt.sh for subdomain discovery.
    
    This is a PASSIVE reconnaissance tool - it queries crt.sh, NOT the target.
    Discovers subdomains by finding certificates issued for the domain.
    
    Args:
        domain: Target domain to search (e.g., "example.com")
        include_expired: Include expired certificates (default: False)
    
    Returns:
        Dictionary containing:
        - success: Whether the search succeeded
        - domain: The searched domain
        - subdomains: List of unique subdomains found
        - certificates: List of certificate details
        - total_certs: Total certificates found
        - message: Status message
    """
    domain = _extract_domain(domain)
    valid, error = _validate_domain(domain)
    if not valid:
        return {"success": False, "error": error, "subdomains": []}
    
    # Check cache
    cache_key = _get_cache_key("crtsh", domain, include_expired)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    # Rate limit
    _rate_limit("crtsh")
    
    try:
        # Query crt.sh JSON API
        url = f"https://crt.sh/?q=%.{quote_plus(domain)}&output=json"
        if not include_expired:
            url += "&exclude=expired"
        
        async with httpx.AsyncClient(
            trust_env=False, 
            timeout=60.0,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            
            if response.status_code == 404:
                return {
                    "success": True,
                    "domain": domain,
                    "subdomains": [],
                    "subdomain_count": 0,
                    "certificates": [],
                    "total_certs": 0,
                    "message": "No certificates found for this domain",
                }
            
            response.raise_for_status()
            
            try:
                certs = response.json()
            except Exception as e:
                # crt.sh sometimes returns HTML on overload
                logger.warning("crt.sh returned invalid JSON: %s", str(e)[:200])
                return {
                    "success": False,
                    "error": "crt.sh returned invalid JSON (service may be overloaded)",
                    "subdomains": [],
                    "subdomain_count": 0,
                }
        
        # Extract unique subdomains
        subdomains: set[str] = set()
        cert_details: list[dict[str, Any]] = []
        
        for cert in certs[:500]:  # Limit to 500 certs to prevent memory issues
            name_value = cert.get("name_value", "")
            issuer = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")
            
            # Parse all names from certificate
            names = [n.strip().lower() for n in name_value.split("\n") if n.strip()]
            for name in names:
                # Skip wildcard entries but keep the base
                if name.startswith("*."):
                    name = name[2:]
                if domain in name:
                    subdomains.add(name)
            
            cert_details.append({
                "names": names[:5],  # Limit names per cert
                "issuer": issuer[:100],
                "valid_from": not_before,
                "valid_to": not_after,
            })
        
        # Sort subdomains
        sorted_subdomains = sorted(subdomains)
        
        result = {
            "success": True,
            "domain": domain,
            "subdomains": sorted_subdomains,
            "subdomain_count": len(sorted_subdomains),
            "certificates": cert_details[:50],  # Limit cert details
            "total_certs": len(certs),
            "message": f"Found {len(sorted_subdomains)} unique subdomains from {len(certs)} certificates",
        }
        
        _set_cached(cache_key, result)
        return result
        
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "crt.sh request timed out (service may be slow)",
            "subdomains": [],
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"crt.sh HTTP error: {e.response.status_code}",
            "subdomains": [],
        }
    except Exception as e:
        logger.exception("crt.sh search failed")
        return {
            "success": False,
            "error": f"crt.sh search failed: {str(e)[:200]}",
            "subdomains": [],
        }


@register_tool(sandbox_execution=False)
async def shodan_search(
    query: str,
    search_type: str = "host",
    max_results: int = 50,
) -> dict[str, Any]:
    """
    Search Shodan for exposed services, open ports, and vulnerabilities.
    
    This is a PASSIVE reconnaissance tool - it queries Shodan's database,
    NOT the target directly. Requires SHODAN_API_KEY environment variable.
    
    Args:
        query: Search query - can be:
            - IP address (e.g., "8.8.8.8")
            - Domain (e.g., "example.com")
            - Shodan dork (e.g., "hostname:example.com port:443")
        search_type: Type of search:
            - "host": Look up a specific IP/domain
            - "search": General Shodan search with dorks
        max_results: Maximum results to return (default: 50)
    
    Returns:
        Dictionary containing:
        - success: Whether the search succeeded
        - results: List of found hosts/services
        - total: Total results in Shodan
        - vulns: List of CVEs found (if any)
        - message: Status message
    
    Common Shodan dorks:
        - hostname:example.com - Find all IPs for a domain
        - org:"Company Name" - Find IPs belonging to an organization
        - port:22 - Find SSH servers
        - product:nginx - Find nginx servers
        - vuln:CVE-2021-44228 - Find vulnerable systems
        - ssl.cert.subject.cn:example.com - Find by SSL certificate CN
    """
    api_key = Config.get("phantom_shodan_api_key")
    if not api_key:
        return {
            "success": False,
            "error": "PHANTOM_SHODAN_API_KEY not set. "
                     "Get a free API key at https://shodan.io",
            "results": [],
        }
    
    # Check cache
    cache_key = _get_cache_key("shodan", query, search_type, max_results)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    # Rate limit
    _rate_limit("shodan")
    
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            headers = {"User-Agent": "Phantom-Scanner/1.0"}
            
            if search_type == "host":
                # Host lookup - for specific IP or domain
                target = query.strip()
                if "://" in target:
                    target = target.split("://")[1].split("/")[0]
                
                # Check if it's an IP or domain
                ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
                if ip_pattern.match(target):
                    # Direct IP lookup
                    url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
                else:
                    # DNS resolve first
                    url = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={api_key}"
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    dns_result = response.json()
                    
                    if target not in dns_result or not dns_result[target]:
                        return {
                            "success": True,
                            "query": query,
                            "results": [],
                            "message": f"Could not resolve {target} to an IP address",
                        }
                    
                    target_ip = dns_result[target]
                    url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"
                
                response = await client.get(url, headers=headers)
                
                if response.status_code == 404:
                    return {
                        "success": True,
                        "query": query,
                        "results": [],
                        "total": 0,
                        "message": "No results found in Shodan database",
                    }
                
                response.raise_for_status()
                data = response.json()
                
                # Extract relevant information
                results = []
                all_vulns: set[str] = set()
                
                for service in data.get("data", [])[:max_results]:
                    result = {
                        "ip": data.get("ip_str", ""),
                        "port": service.get("port"),
                        "protocol": service.get("transport", "tcp"),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "os": data.get("os", ""),
                        "banner": (service.get("data", "")[:500] if service.get("data") else ""),
                        "vulns": service.get("vulns", []),
                    }
                    results.append(result)
                    all_vulns.update(service.get("vulns", []))
                
                return {
                    "success": True,
                    "query": query,
                    "results": results,
                    "total": len(data.get("data", [])),
                    "vulns": sorted(all_vulns),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org", ""),
                    "country": data.get("country_name", ""),
                    "last_update": data.get("last_update", ""),
                    "message": f"Found {len(results)} services, {len(all_vulns)} CVEs",
                }
            
            else:
                # General search
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={quote_plus(query)}"
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                
                results = []
                all_vulns: set[str] = set()
                
                for match in data.get("matches", [])[:max_results]:
                    result = {
                        "ip": match.get("ip_str", ""),
                        "port": match.get("port"),
                        "protocol": match.get("transport", "tcp"),
                        "product": match.get("product", ""),
                        "version": match.get("version", ""),
                        "hostnames": match.get("hostnames", []),
                        "org": match.get("org", ""),
                        "os": match.get("os", ""),
                        "banner": (match.get("data", "")[:300] if match.get("data") else ""),
                        "vulns": match.get("vulns", []),
                    }
                    results.append(result)
                    all_vulns.update(match.get("vulns", []))
                
                result = {
                    "success": True,
                    "query": query,
                    "results": results,
                    "total": data.get("total", 0),
                    "vulns": sorted(all_vulns),
                    "message": f"Found {len(results)} of {data.get('total', 0)} total results",
                }
                
                _set_cached(cache_key, result)
                return result
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {
                "success": False,
                "error": "Invalid Shodan API key",
                "results": [],
            }
        elif e.response.status_code == 429:
            return {
                "success": False,
                "error": "Shodan rate limit exceeded. Wait and retry.",
                "results": [],
            }
        return {
            "success": False,
            "error": f"Shodan HTTP error: {e.response.status_code}",
            "results": [],
        }
    except Exception as e:
        logger.exception("Shodan search failed")
        return {
            "success": False,
            "error": f"Shodan search failed: {str(e)[:200]}",
            "results": [],
        }


@register_tool(sandbox_execution=False)
async def whois_lookup(domain: str, include_history: bool = False) -> dict[str, Any]:
    """
    Perform WHOIS lookup for domain registration information.
    
    This is a PASSIVE reconnaissance tool - it queries WHOIS servers,
    NOT the target directly.
    
    Args:
        domain: Domain to look up (e.g., "example.com")
        include_history: Try to get historical WHOIS data (requires API key)
    
    Returns:
        Dictionary containing:
        - success: Whether the lookup succeeded
        - domain: The queried domain
        - registrar: Domain registrar
        - creation_date: Domain creation date
        - expiration_date: Domain expiration date
        - name_servers: List of name servers
        - registrant: Registrant information (if available)
        - message: Status message
    """
    domain = _extract_domain(domain)
    valid, error = _validate_domain(domain)
    if not valid:
        return {"success": False, "error": error}
    
    # Check cache
    cache_key = _get_cache_key("whois", domain)
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    # Rate limit
    _rate_limit("whois")
    
    try:
        # Use a free WHOIS API (fallback to python-whois if available)
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            # Try WhoisXML API if key is available
            api_key = Config.get("phantom_whoisxml_api_key")
            if api_key:
                url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                whois_record = data.get("WhoisRecord", {})
                result = {
                    "success": True,
                    "domain": domain,
                    "registrar": whois_record.get("registrarName", ""),
                    "creation_date": whois_record.get("createdDate", ""),
                    "expiration_date": whois_record.get("expiresDate", ""),
                    "updated_date": whois_record.get("updatedDate", ""),
                    "name_servers": whois_record.get("nameServers", {}).get("hostNames", []),
                    "status": whois_record.get("status", ""),
                    "registrant": {
                        "organization": whois_record.get("registrant", {}).get("organization", ""),
                        "country": whois_record.get("registrant", {}).get("country", ""),
                        "state": whois_record.get("registrant", {}).get("state", ""),
                    },
                    "message": "WHOIS lookup successful",
                }
            else:
                # Fallback to free public API
                url = f"https://api.api-ninjas.com/v1/whois?domain={domain}"
                api_key_ninja = Config.get("phantom_api_ninjas_key") or ""
                headers = {"X-Api-Key": api_key_ninja} if api_key_ninja else {}
                
                response = await client.get(url, headers=headers)
                
                if response.status_code == 404:
                    return {
                        "success": True,
                        "domain": domain,
                        "message": "Domain not found in WHOIS database",
                    }
                
                if response.status_code == 401:
                    # No API key or invalid - return limited info
                    return {
                        "success": False,
                        "domain": domain,
                        "error": "WHOIS lookup requires API key. Set WHOISXML_API_KEY or API_NINJAS_KEY",
                        "suggestion": "Use terminal_execute with 'whois' command as fallback",
                    }
                
                response.raise_for_status()
                data = response.json()
                
                result = {
                    "success": True,
                    "domain": domain,
                    "registrar": data.get("registrar", ""),
                    "creation_date": data.get("creation_date", ""),
                    "expiration_date": data.get("expiration_date", ""),
                    "name_servers": data.get("name_servers", []),
                    "dnssec": data.get("dnssec", ""),
                    "message": "WHOIS lookup successful (limited data without premium API)",
                }
            
            _set_cached(cache_key, result)
            return result
            
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"WHOIS HTTP error: {e.response.status_code}",
        }
    except Exception as e:
        logger.exception("WHOIS lookup failed")
        return {
            "success": False,
            "error": f"WHOIS lookup failed: {str(e)[:200]}",
        }


@register_tool(sandbox_execution=False)
async def dns_enum(domain: str, record_types: list[str] | None = None) -> dict[str, Any]:
    """
    Enumerate DNS records for a domain using multiple sources.
    
    This is a PASSIVE reconnaissance tool - it queries DNS servers and
    public APIs, NOT the target directly.
    
    Args:
        domain: Domain to enumerate (e.g., "example.com")
        record_types: List of record types to query 
                     (default: ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
    
    Returns:
        Dictionary containing:
        - success: Whether enumeration succeeded
        - domain: The queried domain
        - records: Dictionary of record type -> list of values
        - subdomains: Discovered subdomains from DNS
        - message: Status message
    """
    domain = _extract_domain(domain)
    valid, error = _validate_domain(domain)
    if not valid:
        return {"success": False, "error": error}
    
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    # Check cache
    cache_key = _get_cache_key("dns", domain, tuple(record_types))
    cached = _get_cached(cache_key)
    if cached:
        return {**cached, "cached": True}
    
    try:
        records: dict[str, list[str]] = {}
        discovered_subdomains: set[str] = set()
        
        async with httpx.AsyncClient(trust_env=False, timeout=20.0) as client:
            # Use Google's DNS-over-HTTPS for reliability
            for rtype in record_types:
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                    data = response.json()
                    
                    answers = data.get("Answer", [])
                    if answers:
                        records[rtype] = []
                        for answer in answers:
                            value = answer.get("data", "")
                            if value:
                                records[rtype].append(value)
                                # Look for subdomains in CNAME, MX, NS records
                                if domain in value and value != domain:
                                    discovered_subdomains.add(value.rstrip("."))
                
                except Exception as e:
                    logger.debug(f"DNS query for {rtype} failed: {e}")
                    continue
        
        # Also try common subdomain prefixes
        common_prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "app", "portal", "vpn", "remote", "owa", "webmail",
        ]
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
                    response = await client.get(f"https://dns.google/resolve?name={subdomain}&type=A")
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("Answer"):
                            discovered_subdomains.add(subdomain)
            except Exception:
                continue
        
        result = {
            "success": True,
            "domain": domain,
            "records": records,
            "subdomains": sorted(discovered_subdomains),
            "record_count": sum(len(v) for v in records.values()),
            "message": f"Found {sum(len(v) for v in records.values())} DNS records",
        }
        
        _set_cached(cache_key, result)
        return result
        
    except Exception as e:
        logger.exception("DNS enumeration failed")
        return {
            "success": False,
            "error": f"DNS enumeration failed: {str(e)[:200]}",
        }


@register_tool(sandbox_execution=False)
async def github_dork(
    organization: str | None = None,
    domain: str | None = None,
    keywords: list[str] | None = None,
) -> dict[str, Any]:
    """
    Search GitHub for leaked secrets, exposed configs, and sensitive data.
    
    This is a PASSIVE reconnaissance tool - it queries GitHub's API,
    NOT the target directly. Requires GITHUB_TOKEN for better rate limits.
    
    Args:
        organization: GitHub organization name to search (e.g., "google")
        domain: Domain to search for in code (e.g., "example.com")
        keywords: Additional keywords to search for (e.g., ["password", "api_key"])
    
    Returns:
        Dictionary containing:
        - success: Whether the search succeeded
        - results: List of potential exposures
        - total_count: Total matching results
        - message: Status message
    
    Common findings:
        - Hardcoded credentials
        - API keys and tokens
        - Internal URLs and endpoints
        - Configuration files
        - Database connection strings
    """
    if not organization and not domain:
        return {
            "success": False,
            "error": "Either 'organization' or 'domain' must be provided",
            "results": [],
        }
    
    github_token = Config.get("phantom_github_token")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Phantom-Scanner/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    # Build search queries for sensitive data
    base_queries = []
    if domain:
        domain = _extract_domain(domain)
        base_queries.extend([
            f'"{domain}" password',
            f'"{domain}" api_key OR apikey',
            f'"{domain}" secret',
            f'"{domain}" AWS_ACCESS',
            f'"{domain}" PRIVATE_KEY',
        ])
    
    if organization:
        base_queries.extend([
            f'org:{organization} password filename:.env',
            f'org:{organization} api_key OR apikey OR api-key',
            f'org:{organization} filename:credentials',
            f'org:{organization} filename:config extension:json password',
            f'org:{organization} AWS_SECRET_ACCESS_KEY',
        ])
    
    if keywords:
        for kw in keywords[:5]:  # Limit to 5 keywords
            if domain:
                base_queries.append(f'"{domain}" {kw}')
            if organization:
                base_queries.append(f'org:{organization} {kw}')
    
    results: list[dict[str, Any]] = []
    total_count = 0
    
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            for query in base_queries[:10]:  # Limit queries
                url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=5"
                
                try:
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code == 403:
                        # Rate limited
                        return {
                            "success": False,
                            "error": "GitHub API rate limited. Set GITHUB_TOKEN for higher limits.",
                            "results": results,
                        }
                    
                    if response.status_code == 422:
                        # Invalid query
                        continue
                    
                    response.raise_for_status()
                    data = response.json()
                    
                    total_count += data.get("total_count", 0)
                    
                    for item in data.get("items", []):
                        result = {
                            "query": query,
                            "repository": item.get("repository", {}).get("full_name", ""),
                            "file_path": item.get("path", ""),
                            "html_url": item.get("html_url", ""),
                            "score": item.get("score", 0),
                        }
                        # Avoid duplicates
                        if result["html_url"] not in [r["html_url"] for r in results]:
                            results.append(result)
                    
                    # Small delay to avoid rate limiting
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"GitHub query failed: {e}")
                    continue
        
        return {
            "success": True,
            "organization": organization,
            "domain": domain,
            "results": results[:50],  # Limit results
            "total_count": total_count,
            "queries_run": len(base_queries),
            "message": f"Found {len(results)} potential exposures across {total_count} total matches",
        }
        
    except Exception as e:
        logger.exception("GitHub dork search failed")
        return {
            "success": False,
            "error": f"GitHub search failed: {str(e)[:200]}",
            "results": [],
        }
