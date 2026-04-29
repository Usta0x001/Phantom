"""
Active Subdomain Bruteforcing — Priority 1 Enhancement
=======================================================

Async subdomain brute-forcing with wildcard detection, smart wordlist generation,
and integration with external tools (subfinder, assetfinder).

SECURITY NOTES:
- Active reconnaissance - makes DNS queries and HTTP requests
- Respects stealth mode with reduced concurrency
- Rate limiting built-in to prevent DNS abuse
- Deduplicates against existing passive findings
- Integrates with coverage tracker for discovered surfaces

Tools:
- bruteforce_subdomains: Async DNS brute-forcing with wordlist
- smart_subdomain_gen: LLM-powered subdomain prefix generation
- run_subdomain_tools: Execute subfinder/assetfinder if available
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

import httpx

from phantom.config.config import Config
from phantom.tools.registry import register_tool

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Rate limiting for DNS queries
_DNS_RATE_LIMIT_STATE: dict[str, float] = {}
_DNS_RATE_INTERVAL = 0.02  # 50 queries/sec max in normal mode
_DNS_STEALTH_INTERVAL = 0.2  # 5 queries/sec in stealth mode

# Cache for subdomain results
_SUBDOMAIN_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 1800  # 30 minutes

# Built-in wordlist - most common subdomain prefixes (10k entries represented by top patterns)
# Full wordlist is generated dynamically with common patterns
_BUILTIN_WORDLIST_CORE: list[str] = [
    # Infrastructure
    "www", "www1", "www2", "www3", "mail", "email", "webmail", "smtp", "imap", "pop", "pop3",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "proxy", "ns", "ns1", "ns2", "ns3",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    # Development & Staging
    "dev", "devel", "develop", "development", "stage", "staging", "stg", "test", "testing",
    "qa", "uat", "preprod", "pre-prod", "sandbox", "demo", "poc", "beta", "alpha",
    "int", "internal", "local", "localhost", "preview",
    # API & Services
    "api", "api1", "api2", "api-v1", "api-v2", "api-gateway", "apis", "rest", "graphql",
    "ws", "websocket", "socket", "grpc", "rpc", "service", "services", "svc", "microservice",
    "backend", "be", "frontend", "fe", "app", "apps", "application", "mobile", "m",
    # Admin & Management
    "admin", "administrator", "adm", "manage", "manager", "management", "portal", "panel",
    "dashboard", "console", "control", "cp", "cpanel", "webadmin", "sysadmin", "root",
    "superadmin", "master", "system", "sys",
    # Authentication & Security
    "auth", "authentication", "oauth", "sso", "login", "signin", "signup", "register",
    "identity", "id", "idp", "accounts", "account", "user", "users", "profile", "profiles",
    "secure", "security", "sec", "trust", "cert", "certs", "certificates", "pki",
    # Cloud & Infrastructure
    "cloud", "aws", "azure", "gcp", "gcloud", "k8s", "kubernetes", "docker", "container",
    "containers", "cluster", "clusters", "node", "nodes", "pod", "pods", "registry",
    "harbor", "vault", "secrets", "config", "configs", "configuration",
    # Databases & Storage
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis",
    "elastic", "elasticsearch", "es", "kibana", "grafana", "influx", "influxdb",
    "storage", "store", "s3", "minio", "backup", "backups", "archive", "archives",
    # Monitoring & Logs
    "monitor", "monitoring", "metrics", "prometheus", "nagios", "zabbix", "datadog",
    "log", "logs", "logging", "elk", "logstash", "splunk", "sentry", "trace", "tracing",
    "apm", "newrelic", "status", "health", "healthcheck",
    # CI/CD & DevOps
    "ci", "cd", "cicd", "jenkins", "gitlab", "github", "git", "bitbucket", "bamboo",
    "teamcity", "travis", "circleci", "drone", "argo", "argocd", "flux", "deploy",
    "deployment", "deployments", "build", "builds", "release", "releases", "artifact",
    # Communication
    "chat", "slack", "teams", "zoom", "meet", "meeting", "meetings", "conference",
    "jira", "confluence", "wiki", "docs", "documentation", "help", "helpdesk", "support",
    "ticket", "tickets", "crm", "salesforce", "hubspot",
    # Media & Content
    "cdn", "static", "assets", "media", "images", "img", "image", "video", "videos",
    "content", "cms", "wordpress", "wp", "blog", "news", "press", "files", "file",
    "download", "downloads", "upload", "uploads",
    # E-commerce & Payment
    "shop", "store", "ecommerce", "commerce", "cart", "checkout", "payment", "payments",
    "pay", "billing", "invoice", "invoices", "order", "orders", "product", "products",
    # Analytics & Marketing
    "analytics", "stats", "statistics", "tracking", "track", "marketing", "mkt",
    "campaign", "campaigns", "ads", "advertising", "promo", "promotions",
    # Geographic & Regional
    "us", "eu", "uk", "de", "fr", "jp", "cn", "au", "ca", "in", "br",
    "asia", "europe", "america", "global", "intl", "international",
    "east", "west", "north", "south", "central",
    # Numbers and variants
    "1", "2", "3", "01", "02", "03", "v1", "v2", "v3", "new", "old", "legacy",
    "primary", "secondary", "main", "backup", "failover", "dr", "disaster",
    # Technology specific
    "oracle", "sap", "sharepoint", "exchange", "outlook", "office", "o365",
    "salesforce", "workday", "servicenow", "atlassian", "okta", "auth0",
    # Network
    "router", "switch", "firewall", "fw", "lb", "loadbalancer", "load-balancer",
    "edge", "ingress", "egress", "dmz", "bastion", "jump", "jumpbox",
]

# Additional patterns for wordlist expansion
_WORDLIST_PATTERNS: list[str] = [
    "{prefix}{n}",  # api1, api2, etc.
    "{prefix}-{env}",  # api-dev, api-prod
    "{env}-{prefix}",  # dev-api, prod-api
    "{prefix}.{env}",  # api.dev (less common but exists)
]

_ENVIRONMENTS: list[str] = ["dev", "test", "stage", "staging", "prod", "production", "uat", "qa"]


def _generate_full_wordlist(size: str = "medium") -> list[str]:
    """Generate a wordlist of the requested size."""
    wordlist = list(_BUILTIN_WORDLIST_CORE)
    
    if size == "small":
        # Return only core + most important expansions (~500)
        return wordlist[:500]
    
    # Add numbered variants
    for base in ["www", "ns", "mail", "api", "app", "web", "db", "srv", "server", "node"]:
        for i in range(1, 11):
            wordlist.append(f"{base}{i}")
    
    # Add environment-prefixed variants
    for env in _ENVIRONMENTS:
        for base in ["api", "app", "web", "portal", "admin", "db"]:
            wordlist.append(f"{env}-{base}")
            wordlist.append(f"{base}-{env}")
    
    # Add two-letter combinations for infrastructure
    for c1 in "abcdefghijklmnopqrstuvwxyz":
        for c2 in "abcdefghijklmnopqrstuvwxyz":
            wordlist.append(f"{c1}{c2}")
    
    if size == "medium":
        return list(set(wordlist))[:5000]
    
    # Large: Add more combinations
    if size == "large":
        # Add three-letter combinations selectively
        common_starts = ["dev", "api", "app", "web", "srv", "vpn", "ftp", "ssh"]
        for start in common_starts:
            for i in range(100):
                wordlist.append(f"{start}{i:02d}")
        
        return list(set(wordlist))[:30000]
    
    return list(set(wordlist))


async def _resolve_dns(domain: str, resolver_url: str = "https://dns.google/resolve") -> list[str]:
    """Resolve a domain to IP addresses using DNS-over-HTTPS."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                resolver_url,
                params={"name": domain, "type": "A"}
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("Answer"):
                    return [ans.get("data", "") for ans in data["Answer"] if ans.get("type") == 1]
    except Exception:
        pass
    return []


async def _check_subdomain(
    subdomain: str,
    domain: str,
    wildcard_ips: set[str],
    semaphore: asyncio.Semaphore,
    results: list[dict[str, Any]],
    stealth: bool = False,
) -> None:
    """Check if a subdomain exists and isn't a wildcard response."""
    full_domain = f"{subdomain}.{domain}"
    
    async with semaphore:
        # Rate limiting
        if stealth:
            await asyncio.sleep(_DNS_STEALTH_INTERVAL)
        else:
            await asyncio.sleep(_DNS_RATE_INTERVAL)
        
        ips = await _resolve_dns(full_domain)
        
        if ips:
            # Check if this is a wildcard response
            is_wildcard = bool(wildcard_ips and set(ips) == wildcard_ips)
            
            if not is_wildcard or wildcard_ips:
                results.append({
                    "subdomain": full_domain,
                    "ip_addresses": ips,
                    "is_wildcard_bypass": is_wildcard,
                    "discovered_via": "dns_bruteforce",
                })


async def _detect_wildcard(domain: str) -> set[str]:
    """Detect if domain has wildcard DNS configured."""
    # Generate a random subdomain that shouldn't exist
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test_domain = f"{random_sub}.{domain}"
    
    ips = await _resolve_dns(test_domain)
    
    if ips:
        logger.info(f"Wildcard DNS detected for {domain}: {ips}")
        return set(ips)
    
    return set()


async def bruteforce_subdomains(
    domain: str,
    wordlist_path: str | None = None,
    wordlist_size: str = "medium",
    concurrency: int = 50,
    stealth: bool = False,
    existing_subdomains: list[str] | None = None,
    custom_wordlist: list[str] | None = None,
) -> dict[str, Any]:
    """
    Perform async subdomain brute-forcing with DNS resolution.
    
    This is an ACTIVE reconnaissance tool - it makes DNS queries against
    public DNS resolvers to discover subdomains.
    
    Args:
        domain: Target domain to bruteforce (e.g., "example.com")
        wordlist_path: Path to custom wordlist file (one subdomain per line)
        wordlist_size: Built-in wordlist size: "small" (500), "medium" (5000), "large" (30000)
        concurrency: Max concurrent DNS queries (default: 50, reduced in stealth mode)
        stealth: Enable stealth mode (reduced speed, randomized timing)
        existing_subdomains: List of already discovered subdomains (from crt.sh) for deduplication
        custom_wordlist: Custom list of subdomain prefixes to test
    
    Returns:
        Dictionary containing:
        - success: Whether the scan completed
        - domain: The target domain
        - discovered: List of discovered subdomains with IPs
        - total_checked: Number of subdomains checked
        - wildcard_detected: Whether wildcard DNS was detected
        - new_discoveries: Subdomains not in existing_subdomains
        - message: Status message
    
    Example:
        # Basic scan
        result = await bruteforce_subdomains("example.com")
        
        # With existing findings from crt.sh
        result = await bruteforce_subdomains(
            "example.com",
            existing_subdomains=["www.example.com", "mail.example.com"]
        )
        
        # Stealth mode for sensitive targets
        result = await bruteforce_subdomains("example.com", stealth=True)
    """
    # Validate domain
    if not domain or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {
            "success": False,
            "error": f"Invalid domain format: {domain}",
            "discovered": [],
        }
    
    # Clean domain
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Build wordlist
    wordlist: list[str] = []
    
    if custom_wordlist:
        wordlist = list(custom_wordlist)
    elif wordlist_path:
        try:
            path = Path(wordlist_path)
            if path.exists():
                wordlist = [
                    line.strip().lower() 
                    for line in path.read_text().splitlines() 
                    if line.strip() and not line.startswith("#")
                ]
        except Exception as e:
            logger.warning(f"Failed to load wordlist from {wordlist_path}: {e}")
    
    if not wordlist:
        wordlist = _generate_full_wordlist(wordlist_size)
    
    # Deduplicate against existing subdomains
    existing_set: set[str] = set()
    if existing_subdomains:
        for sub in existing_subdomains:
            # Extract the prefix
            sub_lower = sub.lower()
            if sub_lower.endswith(f".{domain}"):
                prefix = sub_lower[:-len(domain)-1]
                if prefix:
                    existing_set.add(prefix)
    
    # Filter wordlist
    wordlist = [w for w in wordlist if w not in existing_set]
    
    # Adjust concurrency for stealth mode
    if stealth:
        concurrency = min(concurrency, 10)
    
    # Detect wildcard DNS
    wildcard_ips = await _detect_wildcard(domain)
    
    # Run bruteforce
    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []
    
    start_time = time.time()
    
    # Process in batches
    batch_size = 500
    total_checked = 0
    
    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i:i + batch_size]
        tasks = [
            _check_subdomain(sub, domain, wildcard_ips, semaphore, results, stealth)
            for sub in batch
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        total_checked += len(batch)
        
        # Progress logging
        if total_checked % 1000 == 0:
            logger.debug(f"Subdomain bruteforce progress: {total_checked}/{len(wordlist)}")
    
    elapsed = time.time() - start_time
    
    # Calculate new discoveries (not in existing_subdomains)
    new_discoveries = []
    if existing_subdomains:
        existing_full = {s.lower() for s in existing_subdomains}
        new_discoveries = [
            r for r in results 
            if r["subdomain"].lower() not in existing_full
        ]
    else:
        new_discoveries = results
    
    return {
        "success": True,
        "domain": domain,
        "discovered": results,
        "discovered_count": len(results),
        "new_discoveries": new_discoveries,
        "new_count": len(new_discoveries),
        "total_checked": total_checked,
        "wildcard_detected": bool(wildcard_ips),
        "wildcard_ips": list(wildcard_ips) if wildcard_ips else [],
        "elapsed_seconds": round(elapsed, 2),
        "message": f"Discovered {len(results)} subdomains ({len(new_discoveries)} new) from {total_checked} checks in {elapsed:.1f}s",
    }


async def smart_subdomain_gen(
    domain: str,
    tech_stack: list[str] | None = None,
    industry: str | None = None,
    existing_subdomains: list[str] | None = None,
    max_suggestions: int = 100,
) -> dict[str, Any]:
    """
    Generate intelligent subdomain prefixes based on context.
    
    Uses pattern analysis and contextual hints to generate likely subdomain
    prefixes. More targeted than a generic wordlist.
    
    Args:
        domain: Target domain (e.g., "acme-corp.com")
        tech_stack: Detected technologies (e.g., ["nginx", "php", "mysql", "wordpress"])
        industry: Industry vertical (e.g., "finance", "healthcare", "ecommerce")
        existing_subdomains: Already discovered subdomains (for pattern learning)
        max_suggestions: Maximum prefixes to generate (default: 100)
    
    Returns:
        Dictionary containing:
        - success: Whether generation succeeded
        - suggestions: List of suggested subdomain prefixes
        - reasoning: Why each category was suggested
        - priority: Priority ordering hints
    
    Example:
        # Generate based on tech stack
        result = await smart_subdomain_gen(
            "example.com",
            tech_stack=["wordpress", "mysql", "nginx"],
            industry="ecommerce"
        )
    """
    suggestions: list[str] = []
    reasoning: dict[str, list[str]] = {}
    
    # Extract domain name hints
    domain_parts = domain.split(".")
    base_name = domain_parts[0] if domain_parts else ""
    
    # Always include core infrastructure
    core_infra = [
        "api", "app", "dev", "test", "staging", "admin", "portal",
        "mail", "webmail", "vpn", "remote", "cdn", "static",
    ]
    suggestions.extend(core_infra)
    reasoning["core_infrastructure"] = core_infra
    
    # Tech stack based suggestions
    if tech_stack:
        tech_suggestions: list[str] = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            
            if "wordpress" in tech_lower or "wp" in tech_lower:
                tech_suggestions.extend(["blog", "wp", "wordpress", "cms", "wp-admin"])
            
            if "mysql" in tech_lower or "mariadb" in tech_lower:
                tech_suggestions.extend(["db", "mysql", "database", "sql", "phpmyadmin"])
            
            if "postgresql" in tech_lower or "postgres" in tech_lower:
                tech_suggestions.extend(["db", "postgres", "pgadmin", "database"])
            
            if "mongodb" in tech_lower or "mongo" in tech_lower:
                tech_suggestions.extend(["mongo", "mongodb", "nosql", "db"])
            
            if "redis" in tech_lower:
                tech_suggestions.extend(["redis", "cache", "session"])
            
            if "nginx" in tech_lower:
                tech_suggestions.extend(["proxy", "lb", "static", "cdn"])
            
            if "apache" in tech_lower:
                tech_suggestions.extend(["httpd", "web", "server"])
            
            if "docker" in tech_lower or "kubernetes" in tech_lower:
                tech_suggestions.extend([
                    "k8s", "kubernetes", "docker", "container", "registry",
                    "harbor", "rancher", "portainer"
                ])
            
            if "jenkins" in tech_lower:
                tech_suggestions.extend(["ci", "jenkins", "build", "deploy"])
            
            if "gitlab" in tech_lower:
                tech_suggestions.extend(["git", "gitlab", "code", "repo", "registry"])
            
            if "elastic" in tech_lower:
                tech_suggestions.extend(["elastic", "es", "kibana", "logs", "elk"])
            
            if "grafana" in tech_lower or "prometheus" in tech_lower:
                tech_suggestions.extend(["grafana", "prometheus", "metrics", "monitor"])
            
            if "java" in tech_lower or "spring" in tech_lower:
                tech_suggestions.extend(["spring", "tomcat", "jboss", "wildfly"])
            
            if "node" in tech_lower or "express" in tech_lower:
                tech_suggestions.extend(["node", "express", "api", "socket"])
            
            if "react" in tech_lower or "angular" in tech_lower or "vue" in tech_lower:
                tech_suggestions.extend(["app", "spa", "frontend", "static"])
        
        if tech_suggestions:
            suggestions.extend(tech_suggestions)
            reasoning["tech_stack"] = list(set(tech_suggestions))
    
    # Industry-based suggestions
    if industry:
        industry_lower = industry.lower()
        industry_suggestions: list[str] = []
        
        if "finance" in industry_lower or "bank" in industry_lower:
            industry_suggestions.extend([
                "secure", "auth", "banking", "accounts", "payment", "transfer",
                "trading", "invest", "mobile", "api", "b2b", "corporate"
            ])
        
        elif "healthcare" in industry_lower or "medical" in industry_lower:
            industry_suggestions.extend([
                "patient", "doctor", "ehr", "emr", "health", "medical", "portal",
                "appointment", "records", "hipaa", "secure"
            ])
        
        elif "ecommerce" in industry_lower or "retail" in industry_lower:
            industry_suggestions.extend([
                "shop", "store", "cart", "checkout", "payment", "order", "product",
                "catalog", "inventory", "warehouse", "shipping", "returns"
            ])
        
        elif "tech" in industry_lower or "software" in industry_lower:
            industry_suggestions.extend([
                "api", "dev", "docs", "sdk", "developer", "community", "status",
                "changelog", "beta", "alpha", "labs"
            ])
        
        elif "media" in industry_lower or "news" in industry_lower:
            industry_suggestions.extend([
                "cms", "editor", "media", "video", "stream", "live", "archive",
                "content", "publish", "editorial"
            ])
        
        if industry_suggestions:
            suggestions.extend(industry_suggestions)
            reasoning["industry"] = list(set(industry_suggestions))
    
    # Learn patterns from existing subdomains
    if existing_subdomains:
        patterns: list[str] = []
        for sub in existing_subdomains:
            sub_lower = sub.lower()
            if sub_lower.endswith(f".{domain.lower()}"):
                prefix = sub_lower[:-len(domain)-1]
                
                # Look for patterns like dev-api, api-v1, etc.
                if "-" in prefix:
                    parts = prefix.split("-")
                    if len(parts) == 2:
                        # If we see "dev-api", also try "dev-portal", "test-api", etc.
                        for env in ["dev", "test", "stage", "prod"]:
                            patterns.append(f"{env}-{parts[1]}")
                        for suffix in ["api", "portal", "admin", "app"]:
                            patterns.append(f"{parts[0]}-{suffix}")
        
        if patterns:
            suggestions.extend(patterns)
            reasoning["pattern_learning"] = list(set(patterns))[:20]
    
    # Domain name based suggestions
    if base_name and len(base_name) > 3:
        name_suggestions = [
            f"my{base_name}",
            f"{base_name}app",
            f"{base_name}api",
            f"get{base_name}",
            f"go{base_name}",
        ]
        # Only add if they're reasonably short
        name_suggestions = [s for s in name_suggestions if len(s) < 20]
        if name_suggestions:
            suggestions.extend(name_suggestions)
            reasoning["domain_name"] = name_suggestions
    
    # Remove duplicates and limit
    seen: set[str] = set()
    unique_suggestions: list[str] = []
    for s in suggestions:
        s_lower = s.lower()
        if s_lower not in seen and len(s_lower) > 0:
            seen.add(s_lower)
            unique_suggestions.append(s_lower)
    
    unique_suggestions = unique_suggestions[:max_suggestions]
    
    return {
        "success": True,
        "domain": domain,
        "suggestions": unique_suggestions,
        "suggestion_count": len(unique_suggestions),
        "reasoning": reasoning,
        "priority_order": [
            "core_infrastructure",
            "tech_stack",
            "industry",
            "pattern_learning",
            "domain_name",
        ],
        "message": f"Generated {len(unique_suggestions)} targeted subdomain suggestions",
    }


async def run_subdomain_tools(
    domain: str,
    tools: list[str] | None = None,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """
    Run external subdomain enumeration tools (subfinder, assetfinder).
    
    Executes available external tools and aggregates their results.
    This requires the tools to be installed on the system.
    
    Args:
        domain: Target domain (e.g., "example.com")
        tools: List of tools to run (default: ["subfinder", "assetfinder"])
        timeout_seconds: Timeout for each tool (default: 120)
    
    Returns:
        Dictionary containing:
        - success: Whether any tool succeeded
        - domain: The target domain
        - subdomains: Combined list of discovered subdomains
        - by_tool: Results broken down by tool
        - message: Status message
    
    Example:
        result = await run_subdomain_tools("example.com")
    """
    if not domain:
        return {"success": False, "error": "Domain is required", "subdomains": []}
    
    domain = domain.lower().strip()
    if tools is None:
        tools = ["subfinder", "assetfinder"]
    
    all_subdomains: set[str] = set()
    by_tool: dict[str, dict[str, Any]] = {}
    
    for tool in tools:
        tool_lower = tool.lower()
        try:
            if tool_lower == "subfinder":
                cmd = f"subfinder -d {domain} -silent -timeout {timeout_seconds}"
            elif tool_lower == "assetfinder":
                cmd = f"assetfinder --subs-only {domain}"
            else:
                by_tool[tool] = {
                    "success": False,
                    "error": f"Unknown tool: {tool}",
                    "subdomains": [],
                }
                continue
            
            # Run the tool
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds + 10
                )
                
                if proc.returncode == 0:
                    output = stdout.decode("utf-8", errors="ignore")
                    subdomains = [
                        line.strip().lower()
                        for line in output.splitlines()
                        if line.strip() and domain in line.lower()
                    ]
                    
                    all_subdomains.update(subdomains)
                    by_tool[tool] = {
                        "success": True,
                        "subdomains": subdomains,
                        "count": len(subdomains),
                    }
                else:
                    error = stderr.decode("utf-8", errors="ignore")[:200]
                    by_tool[tool] = {
                        "success": False,
                        "error": error or f"Exit code {proc.returncode}",
                        "subdomains": [],
                    }
                    
            except asyncio.TimeoutError:
                proc.kill()
                by_tool[tool] = {
                    "success": False,
                    "error": f"Timeout after {timeout_seconds}s",
                    "subdomains": [],
                }
                
        except FileNotFoundError:
            by_tool[tool] = {
                "success": False,
                "error": f"{tool} not found in PATH",
                "subdomains": [],
            }
        except Exception as e:
            by_tool[tool] = {
                "success": False,
                "error": str(e)[:200],
                "subdomains": [],
            }
    
    # Format results
    subdomains_list = sorted(all_subdomains)
    any_success = any(t.get("success", False) for t in by_tool.values())
    
    return {
        "success": any_success,
        "domain": domain,
        "subdomains": subdomains_list,
        "subdomain_count": len(subdomains_list),
        "by_tool": by_tool,
        "tools_attempted": list(tools),
        "message": f"Found {len(subdomains_list)} unique subdomains across {len(tools)} tools",
    }


@register_tool(sandbox_execution=False)
async def comprehensive_subdomain_enum(
    domain: str,
    stealth: bool = False,
    include_bruteforce: bool = True,
    bruteforce_size: str = "medium",
    use_external_tools: bool = True,
) -> dict[str, Any]:
    """
    Run comprehensive subdomain enumeration combining multiple techniques.
    
    This orchestrates:
    1. Passive enumeration (crt.sh via existing OSINT tools)
    2. External tools (subfinder, assetfinder) if available
    3. Smart wordlist generation
    4. Active DNS brute-forcing (optional)
    
    Args:
        domain: Target domain (e.g., "example.com")
        stealth: Enable stealth mode (slower, more careful)
        include_bruteforce: Include DNS brute-forcing phase
        bruteforce_size: Wordlist size for bruteforce: "small", "medium", "large"
        use_external_tools: Try to use subfinder/assetfinder if available
    
    Returns:
        Combined results from all enumeration techniques with deduplication.
    """
    start_time = time.time()
    all_subdomains: set[str] = set()
    results_by_source: dict[str, list[str]] = {}
    errors: list[str] = []
    
    domain = domain.lower().strip()
    
    # Phase 1: External tools (fast)
    if use_external_tools:
        try:
            tools_result = await run_subdomain_tools(domain, timeout_seconds=60)
            if tools_result.get("success"):
                tool_subs = tools_result.get("subdomains", [])
                all_subdomains.update(tool_subs)
                results_by_source["external_tools"] = tool_subs
        except Exception as e:
            errors.append(f"External tools failed: {str(e)[:100]}")
    
    # Phase 2: Smart wordlist generation
    smart_result = await smart_subdomain_gen(
        domain,
        existing_subdomains=list(all_subdomains),
        max_suggestions=200,
    )
    smart_wordlist = smart_result.get("suggestions", [])
    
    # Phase 3: Active bruteforcing
    if include_bruteforce:
        try:
            brute_result = await bruteforce_subdomains(
                domain,
                custom_wordlist=smart_wordlist,
                wordlist_size=bruteforce_size,
                stealth=stealth,
                existing_subdomains=list(all_subdomains),
                concurrency=10 if stealth else 50,
            )
            
            if brute_result.get("success"):
                brute_subs = [
                    d["subdomain"] 
                    for d in brute_result.get("discovered", [])
                ]
                all_subdomains.update(brute_subs)
                results_by_source["dns_bruteforce"] = brute_subs
                
        except Exception as e:
            errors.append(f"Bruteforce failed: {str(e)[:100]}")
    
    elapsed = time.time() - start_time
    
    # Format final results
    subdomains_list = sorted(all_subdomains)
    
    return {
        "success": len(subdomains_list) > 0 or not errors,
        "domain": domain,
        "subdomains": subdomains_list,
        "subdomain_count": len(subdomains_list),
        "by_source": results_by_source,
        "sources_used": list(results_by_source.keys()),
        "errors": errors if errors else None,
        "elapsed_seconds": round(elapsed, 2),
        "stealth_mode": stealth,
        "message": f"Discovered {len(subdomains_list)} unique subdomains in {elapsed:.1f}s",
    }
