"""
Directory and File Bruteforce — Priority 3 Enhancement
=======================================================

Async directory/file enumeration with smart wordlist selection,
recursive scanning, and tech-stack-aware path generation.

SECURITY NOTES:
- Active reconnaissance - makes HTTP requests
- Respects stealth mode with reduced concurrency and timing
- Built-in rate limiting to prevent server overload
- Deduplicates findings and tracks coverage
- Integrates with coverage tracker for discovered paths

Tools:
- bruteforce_directories: Async directory/file enumeration
- smart_path_gen: Tech-stack-aware path generation
- recursive_dir_scan: Recursive directory exploration
- comprehensive_dir_enum: Full enumeration pipeline
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

import httpx

from phantom.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Rate limiting state
_RATE_LIMIT_STATE: dict[str, float] = {}
_RATE_LIMIT_INTERVAL = 0.05  # 20 requests/sec in normal mode
_STEALTH_INTERVAL = 0.5  # 2 requests/sec in stealth mode

# Cache for directory results
_DIR_CACHE: dict[str, tuple[Any, float]] = {}
_CACHE_TTL = 1800  # 30 minutes


# ============================================================================
# Wordlist Definitions
# ============================================================================

# Common directories - organized by category
_CORE_DIRECTORIES: list[str] = [
    # Admin/Management
    "admin", "administrator", "admin.php", "admin.html", "admin.asp",
    "admincp", "admin_area", "admin-panel", "admin-console", "adminpanel",
    "manager", "management", "manage", "cpanel", "controlpanel", "panel",
    "dashboard", "console", "portal", "backend", "backoffice", "back-office",
    
    # Authentication
    "login", "signin", "sign-in", "auth", "authenticate", "logout", "signout",
    "register", "signup", "sign-up", "forgot-password", "reset-password",
    "password", "sso", "oauth", "oauth2", "saml", "2fa", "mfa",
    
    # API Endpoints
    "api", "api/v1", "api/v2", "api/v3", "apis", "rest", "graphql",
    "api-docs", "swagger", "swagger-ui", "redoc", "openapi", "openapi.json",
    "swagger.json", "api.json", "spec", "specification",
    
    # Configuration & Backup
    "config", "configuration", "settings", "conf", "cfg",
    "backup", "backups", "bak", "old", "orig", "original", "copy",
    "temp", "tmp", "cache", "caches",
    
    # Uploads & Media
    "upload", "uploads", "file", "files", "media", "images", "img",
    "assets", "static", "public", "content", "contents", "data", "documents",
    "docs", "doc", "downloads", "download", "attachments", "attachment",
    
    # Development & Debug
    "dev", "devel", "development", "debug", "test", "testing", "tests",
    "staging", "stage", "qa", "uat", "demo", "beta", "alpha",
    "sandbox", "playground", "lab", "labs",
    
    # Git & Version Control
    ".git", ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
    ".svn", ".svn/entries", ".hg", ".bzr",
    
    # Web Server Config
    ".htaccess", ".htpasswd", "web.config", "nginx.conf", "httpd.conf",
    "server-status", "server-info", "status", "health", "healthcheck",
    "ping", "version", "info", "phpinfo", "phpinfo.php",
    
    # Database
    "database", "db", "sql", "mysql", "phpmyadmin", "pma", "adminer",
    "pgadmin", "mongodb", "redis", "memcached",
    
    # Logs & Errors
    "log", "logs", "error", "errors", "error_log", "debug.log", "access.log",
    "error.log", "app.log", "application.log",
    
    # CMS Specific
    "wp-admin", "wp-content", "wp-includes", "wp-config.php", "wp-login.php",
    "administrator", "components", "modules", "plugins", "themes", "templates",
    "drupal", "joomla", "magento", "prestashop", "opencart",
    
    # Framework Specific
    "vendor", "node_modules", "bower_components", "packages",
    "artisan", "storage", "bootstrap", "resources", "app",
    ".env", ".env.local", ".env.production", ".env.development",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    
    # Security Files
    "robots.txt", "sitemap.xml", "sitemap.xml.gz", "crossdomain.xml",
    "security.txt", ".well-known", ".well-known/security.txt",
    "humans.txt", "ads.txt", "app-ads.txt",
    
    # Common Files
    "index.php", "index.html", "index.htm", "index.asp", "index.aspx",
    "default.php", "default.html", "default.asp", "default.aspx",
    "home.php", "home.html", "main.php", "main.html",
    "readme", "readme.txt", "readme.md", "README.md", "README.txt",
    "license", "license.txt", "license.md", "LICENSE",
    "changelog", "changelog.txt", "CHANGELOG.md",
    "todo", "todo.txt", "TODO.md",
]

# File extensions to try
_COMMON_EXTENSIONS: list[str] = [
    "", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".do", ".action",
    ".json", ".xml", ".txt", ".log", ".bak", ".old", ".orig", ".copy",
    ".sql", ".db", ".sqlite", ".sqlite3",
    ".zip", ".tar", ".tar.gz", ".gz", ".rar",
    ".conf", ".config", ".cfg", ".ini", ".yaml", ".yml",
    ".key", ".pem", ".crt", ".cer", ".p12",
]

# Tech-stack specific paths
_TECH_STACK_PATHS: dict[str, list[str]] = {
    "php": [
        "info.php", "phpinfo.php", "test.php", "debug.php",
        "config.php", "settings.php", "db.php", "database.php",
        "inc", "include", "includes", "lib", "library", "class", "classes",
        "function", "functions", "common", "core",
    ],
    "asp": [
        "default.asp", "default.aspx", "login.aspx", "admin.aspx",
        "web.config", "machine.config", "App_Data", "App_Code",
        "bin", "Views", "Controllers", "Models",
    ],
    "java": [
        "WEB-INF", "WEB-INF/web.xml", "META-INF", "META-INF/MANIFEST.MF",
        "struts-config.xml", "faces-config.xml", "applicationContext.xml",
        "spring.xml", "beans.xml", "persistence.xml",
        ".do", ".action", ".jsf", ".faces", ".seam",
    ],
    "python": [
        "app.py", "main.py", "wsgi.py", "manage.py", "settings.py",
        "__pycache__", ".pyc", "requirements.txt", "Pipfile", "Pipfile.lock",
        "static", "templates", "migrations", "models.py", "views.py",
    ],
    "node": [
        "server.js", "app.js", "index.js", "main.js", "server.ts", "app.ts",
        "node_modules", "package.json", "package-lock.json", "yarn.lock",
        ".npmrc", ".nvmrc", "ecosystem.config.js",
    ],
    "ruby": [
        "config.ru", "Gemfile", "Gemfile.lock", "Rakefile",
        "config", "config/routes.rb", "config/database.yml", "config/secrets.yml",
        "db", "db/schema.rb", "db/seeds.rb",
    ],
    "wordpress": [
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "wp-content/debug.log", "wp-content/uploads", "wp-content/plugins",
        "wp-content/themes", "wp-content/backup", "wp-admin/install.php",
        "xmlrpc.php", "wp-login.php", "wp-cron.php",
    ],
    "drupal": [
        "sites/default/settings.php", "sites/default/files",
        "CHANGELOG.txt", "INSTALL.txt", "MAINTAINERS.txt",
        "modules", "profiles", "themes", "includes",
    ],
    "laravel": [
        ".env", ".env.backup", ".env.save", "storage/logs/laravel.log",
        "storage/framework/sessions", "storage/app", "bootstrap/cache",
        "artisan", "composer.json", "database/database.sqlite",
    ],
    "django": [
        "settings.py", "urls.py", "wsgi.py", "asgi.py", "manage.py",
        "static", "media", "templates", "migrations",
        "admin", "api", "debug",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        "actuator/configprops", "actuator/beans", "actuator/mappings",
        "actuator/heapdump", "actuator/threaddump", "actuator/logfile",
        "swagger-ui.html", "v2/api-docs", "v3/api-docs",
    ],
}

# Sensitive file patterns
_SENSITIVE_PATTERNS: list[str] = [
    # Backup files
    "backup.sql", "backup.zip", "backup.tar.gz", "site.zip", "db.sql",
    "database.sql", "dump.sql", "mysql.sql", "data.sql",
    "{domain}.sql", "{domain}.zip", "{domain}.tar.gz",
    
    # Config files
    ".env", ".env.bak", ".env.local", ".env.prod", ".env.production",
    "config.php.bak", "config.php~", "config.php.old", "config.php.save",
    "wp-config.php.bak", "wp-config.php~", "settings.py.bak",
    
    # IDE/Editor files
    ".idea", ".vscode", ".sublime-project", ".sublime-workspace",
    "*.swp", "*.swo", "*~", ".DS_Store", "Thumbs.db",
    
    # CI/CD files
    ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile", ".circleci",
    ".github", ".github/workflows", "azure-pipelines.yml",
    "docker-compose.yml", "docker-compose.override.yml", "Dockerfile",
    
    # Keys and Certs
    "id_rsa", "id_rsa.pub", "id_dsa", "id_ed25519",
    "server.key", "server.pem", "server.crt", "ca.pem",
    "private.key", "public.key", "ssl.key", "ssl.crt",
]


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class DirectoryResult:
    """Represents a discovered directory or file."""
    url: str
    status_code: int
    content_length: int = 0
    content_type: str = ""
    redirect_url: str | None = None
    is_directory: bool = False
    is_interesting: bool = False
    reason: str = ""
    response_time_ms: float = 0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
            "is_directory": self.is_directory,
            "is_interesting": self.is_interesting,
            "reason": self.reason,
            "response_time_ms": self.response_time_ms,
        }


@dataclass
class ScanProgress:
    """Tracks scan progress."""
    total: int = 0
    completed: int = 0
    found: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def percent(self) -> float:
        return (self.completed / self.total * 100) if self.total > 0 else 0
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate(self) -> float:
        return self.completed / self.elapsed if self.elapsed > 0 else 0


# ============================================================================
# Helper Functions
# ============================================================================

def _normalize_url(base_url: str, path: str) -> str:
    """Normalize and join URL with path."""
    # Ensure base URL has scheme
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    
    # Ensure base URL ends with /
    if not base_url.endswith('/'):
        base_url += '/'
    
    # Clean path
    path = path.lstrip('/')
    
    return urljoin(base_url, path)


def _is_interesting_status(status: int) -> bool:
    """Check if status code indicates interesting content."""
    # 200 = Found
    # 301, 302, 307, 308 = Redirects (may reveal info)
    # 401 = Auth required (endpoint exists)
    # 403 = Forbidden (endpoint exists but restricted)
    return status in (200, 201, 204, 301, 302, 307, 308, 401, 403)


def _categorize_finding(result: DirectoryResult) -> str:
    """Categorize a finding by its characteristics."""
    url_lower = result.url.lower()
    
    # Check for sensitive patterns
    if any(p in url_lower for p in ['.env', 'config', 'backup', '.git', '.svn']):
        return "sensitive_config"
    
    if any(p in url_lower for p in ['admin', 'panel', 'dashboard', 'console']):
        return "admin_interface"
    
    if any(p in url_lower for p in ['api', 'graphql', 'rest', 'swagger', 'openapi']):
        return "api_endpoint"
    
    if any(p in url_lower for p in ['upload', 'file', 'media', 'attachment']):
        return "file_upload"
    
    if any(p in url_lower for p in ['log', 'debug', 'error', 'trace']):
        return "debug_info"
    
    if any(p in url_lower for p in ['login', 'auth', 'signin', 'register']):
        return "authentication"
    
    if result.status_code == 401:
        return "requires_auth"
    
    if result.status_code == 403:
        return "forbidden"
    
    if result.is_directory:
        return "directory"
    
    return "file"


def _generate_wordlist(
    size: str = "medium",
    tech_stack: list[str] | None = None,
    domain: str | None = None,
    include_extensions: bool = True,
) -> list[str]:
    """Generate a wordlist based on parameters."""
    wordlist: list[str] = []
    
    # Start with core directories
    if size == "small":
        wordlist.extend(_CORE_DIRECTORIES[:50])
    elif size == "medium":
        wordlist.extend(_CORE_DIRECTORIES[:150])
    else:  # large
        wordlist.extend(_CORE_DIRECTORIES)
    
    # Add tech-stack specific paths
    if tech_stack:
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, paths in _TECH_STACK_PATHS.items():
                if key in tech_lower or tech_lower in key:
                    wordlist.extend(paths)
    
    # Add domain-specific variations
    if domain:
        parsed = urlparse(domain if '://' in domain else f'https://{domain}')
        domain_name = parsed.netloc.split(':')[0].split('.')[0]  # Get base name
        
        if domain_name and len(domain_name) > 2:
            wordlist.extend([
                f"{domain_name}-backup",
                f"{domain_name}.sql",
                f"{domain_name}.zip",
                f"{domain_name}-backup.zip",
                f"backup-{domain_name}",
                f"old-{domain_name}",
            ])
    
    # Add extension variations for important paths
    if include_extensions and size != "small":
        base_paths = ["config", "backup", "database", "admin", "test"]
        for base in base_paths:
            if base in wordlist:
                for ext in [".php", ".bak", ".old", ".txt", ".sql"]:
                    wordlist.append(f"{base}{ext}")
    
    # Deduplicate
    return list(dict.fromkeys(wordlist))


async def _check_path(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    results: list[DirectoryResult],
    stealth: bool = False,
    baseline_length: int | None = None,
) -> None:
    """Check if a path exists."""
    async with semaphore:
        # Rate limiting
        if stealth:
            await asyncio.sleep(_STEALTH_INTERVAL + random.uniform(0, 0.3))
        else:
            await asyncio.sleep(_RATE_LIMIT_INTERVAL)
        
        start = time.time()
        
        try:
            response = await client.get(url, follow_redirects=False)
            elapsed_ms = (time.time() - start) * 1000
            
            status = response.status_code
            content_length = len(response.content)
            content_type = response.headers.get("content-type", "")
            redirect_url = response.headers.get("location")
            
            # Skip if content length matches baseline (likely custom 404)
            if baseline_length and abs(content_length - baseline_length) < 50:
                if status == 200:
                    return
            
            # Check if this is an interesting response
            if _is_interesting_status(status):
                is_directory = url.endswith('/') or 'directory' in content_type.lower()
                
                result = DirectoryResult(
                    url=url,
                    status_code=status,
                    content_length=content_length,
                    content_type=content_type,
                    redirect_url=redirect_url,
                    is_directory=is_directory,
                    is_interesting=True,
                    reason=_categorize_finding(DirectoryResult(
                        url=url,
                        status_code=status,
                        content_length=content_length,
                        content_type=content_type,
                        is_directory=is_directory,
                        is_interesting=True,
                        reason="",
                    )),
                    response_time_ms=elapsed_ms,
                )
                results.append(result)
                
        except httpx.TimeoutException:
            pass  # Skip timeouts
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")


async def _get_baseline_response(client: httpx.AsyncClient, base_url: str) -> int | None:
    """Get baseline 404 response length for custom 404 detection."""
    try:
        # Request a definitely non-existent path
        random_path = f"definitely-not-exists-{random.randint(100000, 999999)}"
        response = await client.get(urljoin(base_url, random_path))
        
        if response.status_code == 404:
            return len(response.content)
        elif response.status_code == 200:
            # Custom 404 page - use this as baseline
            return len(response.content)
    except Exception:
        pass
    
    return None


# ============================================================================
# Tool Implementations
# ============================================================================

async def bruteforce_directories(
    url: str,
    wordlist_path: str | None = None,
    wordlist_size: str = "medium",
    extensions: list[str] | None = None,
    concurrency: int = 20,
    stealth: bool = False,
    timeout: float = 10.0,
    custom_wordlist: list[str] | None = None,
    follow_redirects: bool = False,
    exclude_status: list[int] | None = None,
) -> dict[str, Any]:
    """
    Perform async directory/file brute-forcing.
    
    Enumerates directories and files using wordlists, with smart
    detection of custom 404 pages and interesting responses.
    
    Args:
        url: Target base URL (e.g., "https://example.com")
        wordlist_path: Path to custom wordlist file
        wordlist_size: Built-in wordlist size: "small" (50), "medium" (150), "large" (300+)
        extensions: File extensions to try (e.g., [".php", ".bak"])
        concurrency: Max concurrent requests (default: 20, reduced in stealth)
        stealth: Enable stealth mode (slower, randomized timing)
        timeout: Request timeout in seconds
        custom_wordlist: Custom list of paths to test
        follow_redirects: Follow HTTP redirects
        exclude_status: Status codes to exclude from results
    
    Returns:
        Dictionary containing:
        - success: Whether scan completed
        - url: Target URL
        - found: List of discovered paths
        - statistics: Scan statistics
        - message: Status message
    
    Example:
        result = await bruteforce_directories("https://example.com")
    """
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    base_url = url.rstrip('/') + '/'
    
    # Build wordlist
    wordlist: list[str] = []
    
    if custom_wordlist:
        wordlist = list(custom_wordlist)
    elif wordlist_path:
        try:
            path = Path(wordlist_path)
            if path.exists():
                wordlist = [
                    line.strip()
                    for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith('#')
                ]
        except Exception as e:
            logger.warning(f"Failed to load wordlist: {e}")
    
    if not wordlist:
        wordlist = _generate_wordlist(wordlist_size)
    
    # Add extension variants
    if extensions:
        extended: list[str] = []
        for path in wordlist:
            extended.append(path)
            for ext in extensions:
                if not path.endswith(ext):
                    extended.append(path + ext)
        wordlist = extended
    
    # Adjust concurrency for stealth
    if stealth:
        concurrency = min(concurrency, 5)
    
    # Exclude status codes
    exclude_set = set(exclude_status) if exclude_status else set()
    
    # Setup HTTP client
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    
    results: list[DirectoryResult] = []
    progress = ScanProgress(total=len(wordlist))
    
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=headers,
        verify=False,  # Allow self-signed certs
    ) as client:
        # Get baseline for custom 404 detection
        baseline_length = await _get_baseline_response(client, base_url)
        
        # Run enumeration
        semaphore = asyncio.Semaphore(concurrency)
        
        # Process in batches
        batch_size = 100
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = [
                _check_path(
                    client,
                    _normalize_url(base_url, path),
                    semaphore,
                    results,
                    stealth,
                    baseline_length,
                )
                for path in batch
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
            progress.completed += len(batch)
    
    # Filter by exclude_status
    if exclude_set:
        results = [r for r in results if r.status_code not in exclude_set]
    
    # Sort by importance
    def sort_key(r: DirectoryResult) -> tuple[int, int]:
        # Priority: 200s > 401/403 > redirects
        if r.status_code == 200:
            return (0, -r.content_length)
        elif r.status_code in (401, 403):
            return (1, r.status_code)
        else:
            return (2, r.status_code)
    
    results.sort(key=sort_key)
    
    return {
        "success": True,
        "url": base_url,
        "found": [r.to_dict() for r in results],
        "found_count": len(results),
        "statistics": {
            "total_checked": progress.completed,
            "found": len(results),
            "elapsed_seconds": round(progress.elapsed, 2),
            "requests_per_second": round(progress.rate, 2),
            "baseline_404_length": baseline_length,
        },
        "by_status": {
            str(code): len([r for r in results if r.status_code == code])
            for code in set(r.status_code for r in results)
        },
        "by_category": {
            cat: len([r for r in results if r.reason == cat])
            for cat in set(r.reason for r in results)
        },
        "message": f"Found {len(results)} paths from {progress.completed} checks in {progress.elapsed:.1f}s",
    }


async def smart_path_gen(
    url: str,
    tech_stack: list[str] | None = None,
    cms: str | None = None,
    discovered_paths: list[str] | None = None,
    max_paths: int = 200,
) -> dict[str, Any]:
    """
    Generate smart path suggestions based on context.
    
    Analyzes the target and generates likely paths based on
    detected technologies, CMS, and existing findings.
    
    Args:
        url: Target URL
        tech_stack: Detected technologies (e.g., ["php", "mysql", "nginx"])
        cms: Detected CMS (e.g., "wordpress", "drupal", "joomla")
        discovered_paths: Already discovered paths for pattern learning
        max_paths: Maximum paths to generate
    
    Returns:
        Dictionary containing path suggestions organized by category.
    
    Example:
        result = await smart_path_gen(
            "https://example.com",
            tech_stack=["php", "mysql"],
            cms="wordpress"
        )
    """
    suggestions: dict[str, list[str]] = {
        "high_priority": [],
        "tech_specific": [],
        "cms_specific": [],
        "pattern_based": [],
        "sensitive": [],
    }
    
    # Extract domain info
    parsed = urlparse(url if '://' in url else f'https://{url}')
    domain_name = parsed.netloc.split(':')[0].split('.')[0]
    
    # High priority paths (always try these)
    suggestions["high_priority"] = [
        ".env", ".git/config", "robots.txt", "sitemap.xml",
        "admin", "api", "backup", "config", "debug",
    ]
    
    # Tech-stack specific
    if tech_stack:
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, paths in _TECH_STACK_PATHS.items():
                if key in tech_lower or tech_lower in key:
                    suggestions["tech_specific"].extend(paths[:20])
    
    # CMS specific
    if cms:
        cms_lower = cms.lower()
        if cms_lower in _TECH_STACK_PATHS:
            suggestions["cms_specific"].extend(_TECH_STACK_PATHS[cms_lower])
        
        # Generic CMS paths
        suggestions["cms_specific"].extend([
            f"{cms_lower}-admin",
            f"admin/{cms_lower}",
            f"{cms_lower}/admin",
            f"{cms_lower}-backup",
        ])
    
    # Learn patterns from discovered paths
    if discovered_paths:
        patterns: set[str] = set()
        for path in discovered_paths:
            # Extract directory structure
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                # Try other common files in same directory
                base_dir = '/'.join(parts[:-1])
                for common_file in ["index.php", "config.php", ".htaccess", "readme.txt"]:
                    patterns.add(f"{base_dir}/{common_file}")
            
            # Version variants
            if re.search(r'v\d+', path):
                # Try other versions
                for v in range(1, 5):
                    patterns.add(re.sub(r'v\d+', f'v{v}', path))
        
        suggestions["pattern_based"] = list(patterns)[:30]
    
    # Domain-specific sensitive files
    if domain_name:
        suggestions["sensitive"] = [
            f"{domain_name}.sql",
            f"{domain_name}.zip",
            f"{domain_name}-backup.zip",
            f"{domain_name}-backup.sql",
            f"backup-{domain_name}.sql",
            f"{domain_name}.tar.gz",
            f"{domain_name}_backup",
            f"old_{domain_name}",
        ]
    
    # Deduplicate all suggestions
    all_paths: list[str] = []
    seen: set[str] = set()
    
    for category in ["high_priority", "sensitive", "cms_specific", "tech_specific", "pattern_based"]:
        for path in suggestions.get(category, []):
            path_normalized = path.lower().strip('/')
            if path_normalized not in seen:
                seen.add(path_normalized)
                all_paths.append(path)
    
    all_paths = all_paths[:max_paths]
    
    return {
        "success": True,
        "url": url,
        "suggestions": suggestions,
        "all_paths": all_paths,
        "total_count": len(all_paths),
        "by_category": {k: len(v) for k, v in suggestions.items()},
        "message": f"Generated {len(all_paths)} smart path suggestions",
    }


async def recursive_dir_scan(
    url: str,
    max_depth: int = 3,
    concurrency: int = 10,
    stealth: bool = False,
    timeout: float = 10.0,
    extensions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Recursively scan discovered directories.
    
    After initial enumeration, this tool can recursively explore
    discovered directories to find deeper content.
    
    Args:
        url: Target base URL
        max_depth: Maximum recursion depth (default: 3)
        concurrency: Max concurrent requests
        stealth: Enable stealth mode
        timeout: Request timeout
        extensions: File extensions to try
    
    Returns:
        Dictionary with recursive scan results.
    
    Example:
        result = await recursive_dir_scan("https://example.com/api/")
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    base_url = url.rstrip('/') + '/'
    
    all_results: list[DirectoryResult] = []
    visited: set[str] = set()
    to_scan: list[tuple[str, int]] = [(base_url, 0)]
    
    # Small wordlist for recursive scanning
    recursive_wordlist = _generate_wordlist("small")
    
    if extensions:
        extended: list[str] = []
        for path in recursive_wordlist:
            extended.append(path)
            for ext in extensions:
                if not path.endswith(ext):
                    extended.append(path + ext)
        recursive_wordlist = extended
    
    if stealth:
        concurrency = min(concurrency, 3)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    
    start_time = time.time()
    
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers=headers,
        verify=False,
    ) as client:
        while to_scan:
            current_url, depth = to_scan.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            # Scan this directory
            results: list[DirectoryResult] = []
            semaphore = asyncio.Semaphore(concurrency)
            
            baseline = await _get_baseline_response(client, current_url)
            
            tasks = [
                _check_path(
                    client,
                    _normalize_url(current_url, path),
                    semaphore,
                    results,
                    stealth,
                    baseline,
                )
                for path in recursive_wordlist
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Add results and queue directories for recursion
            for result in results:
                all_results.append(result)
                
                # Queue directories for deeper scanning
                if result.is_directory or result.url.endswith('/'):
                    if depth < max_depth:
                        to_scan.append((result.url, depth + 1))
    
    elapsed = time.time() - start_time
    
    return {
        "success": True,
        "url": base_url,
        "found": [r.to_dict() for r in all_results],
        "found_count": len(all_results),
        "directories_scanned": len(visited),
        "max_depth_reached": max_depth,
        "elapsed_seconds": round(elapsed, 2),
        "message": f"Found {len(all_results)} paths in {len(visited)} directories",
    }


@register_tool(sandbox_execution=False)
async def comprehensive_dir_enum(
    url: str,
    tech_stack: list[str] | None = None,
    cms: str | None = None,
    stealth: bool = False,
    include_recursive: bool = False,
    max_depth: int = 2,
    wordlist_size: str = "medium",
) -> dict[str, Any]:
    """
    Perform comprehensive directory enumeration.
    
    This orchestrates the full directory enumeration pipeline:
    1. Smart path generation based on context
    2. Initial directory brute-forcing
    3. Optional recursive scanning of discovered directories
    4. Categorization and prioritization of findings
    
    This is the recommended entry point for directory enumeration.
    
    Args:
        url: Target URL
        tech_stack: Detected technologies
        cms: Detected CMS
        stealth: Enable stealth mode
        include_recursive: Recursively scan discovered directories
        max_depth: Max recursion depth (if recursive enabled)
        wordlist_size: Wordlist size for initial scan
    
    Returns:
        Comprehensive enumeration results.
    
    Example:
        result = await comprehensive_dir_enum(
            "https://example.com",
            tech_stack=["php", "mysql"],
            cms="wordpress"
        )
    """
    start_time = time.time()
    
    # Step 1: Generate smart paths
    smart_result = await smart_path_gen(
        url=url,
        tech_stack=tech_stack,
        cms=cms,
        max_paths=300,
    )
    
    smart_paths = smart_result.get("all_paths", [])
    
    # Step 2: Initial brute-force with combined wordlist
    base_wordlist = _generate_wordlist(wordlist_size, tech_stack)
    combined_wordlist = list(dict.fromkeys(smart_paths + base_wordlist))
    
    brute_result = await bruteforce_directories(
        url=url,
        custom_wordlist=combined_wordlist,
        stealth=stealth,
        concurrency=10 if stealth else 20,
    )
    
    all_findings = brute_result.get("found", [])
    
    # Step 3: Recursive scanning (if enabled)
    if include_recursive and all_findings:
        # Find directories to scan
        directories = [
            f["url"] for f in all_findings
            if f.get("is_directory") or f.get("url", "").endswith('/')
        ]
        
        for dir_url in directories[:5]:  # Limit to prevent explosion
            recursive_result = await recursive_dir_scan(
                url=dir_url,
                max_depth=max_depth,
                stealth=stealth,
                concurrency=5 if stealth else 10,
            )
            all_findings.extend(recursive_result.get("found", []))
    
    # Deduplicate findings
    seen_urls: set[str] = set()
    unique_findings: list[dict[str, Any]] = []
    for finding in all_findings:
        url_key = finding.get("url", "").rstrip('/')
        if url_key not in seen_urls:
            seen_urls.add(url_key)
            unique_findings.append(finding)
    
    elapsed = time.time() - start_time
    
    # Categorize findings
    categories: dict[str, list[dict[str, Any]]] = {
        "sensitive_config": [],
        "admin_interface": [],
        "api_endpoint": [],
        "authentication": [],
        "debug_info": [],
        "file_upload": [],
        "requires_auth": [],
        "forbidden": [],
        "other": [],
    }
    
    for finding in unique_findings:
        category = finding.get("reason", "other")
        if category in categories:
            categories[category].append(finding)
        else:
            categories["other"].append(finding)
    
    # Build priority list (most interesting first)
    priority_findings: list[dict[str, Any]] = []
    for cat in ["sensitive_config", "admin_interface", "api_endpoint", "debug_info", "authentication"]:
        priority_findings.extend(categories[cat])
    
    return {
        "success": True,
        "url": url,
        "findings": unique_findings,
        "findings_count": len(unique_findings),
        "priority_findings": priority_findings,
        "priority_count": len(priority_findings),
        "by_category": {k: len(v) for k, v in categories.items() if v},
        "categories": {k: v for k, v in categories.items() if v},
        "statistics": {
            "paths_checked": brute_result.get("statistics", {}).get("total_checked", 0),
            "elapsed_seconds": round(elapsed, 2),
            "recursive_enabled": include_recursive,
            "tech_stack": tech_stack,
            "cms": cms,
        },
        "message": (
            f"Found {len(unique_findings)} paths "
            f"({len(priority_findings)} high priority) in {elapsed:.1f}s"
        ),
    }
