"""
Scope Validator

Enforces target authorization boundaries for scans.
Prevents accidental scanning of out-of-scope targets.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class ScopeRule:
    """A single scope rule (allow or deny)."""

    pattern: str
    rule_type: str  # "domain", "ip", "cidr", "regex"
    action: str = "allow"  # "allow" or "deny"
    _compiled_regex: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Pre-compile regex pattern at construction time (validates early, avoids per-call cost)."""
        if self.rule_type == "regex":
            # Limit pattern length to mitigate ReDoS from user-supplied patterns
            if len(self.pattern) > 500:
                self._compiled_regex = None
                return
            try:
                self._compiled_regex = re.compile(self.pattern, re.IGNORECASE)
            except re.error:
                self._compiled_regex = None

    def matches(self, target: str) -> bool:
        """Check if a target matches this rule."""
        if self.rule_type == "domain":
            return self._match_domain(target)
        if self.rule_type == "ip":
            return self._match_ip(target)
        if self.rule_type == "cidr":
            return self._match_cidr(target)
        if self.rule_type == "regex":
            return self._match_regex(target)
        return False

    def _match_domain(self, target: str) -> bool:
        host = _extract_host(target).lower()
        pattern = self.pattern.lower()
        # Exact match or wildcard subdomain match
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith(f".{base}")
        return host == pattern

    def _match_ip(self, target: str) -> bool:
        host = _extract_host(target)
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(self.pattern)
        except ValueError:
            return False

    def _match_cidr(self, target: str) -> bool:
        host = _extract_host(target)
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(
                self.pattern, strict=False
            )
        except ValueError:
            return False

    def _match_regex(self, target: str) -> bool:
        try:
            if self._compiled_regex is None:
                return False
            # Length limit to mitigate catastrophic backtracking
            if len(target) > 2048:
                target = target[:2048]
            return bool(self._compiled_regex.search(target))
        except (re.error, RecursionError):
            return False


@dataclass
class ScopeConfig:
    """Scope configuration with allow/deny rules."""

    rules: list[ScopeRule] = field(default_factory=list)
    default_action: str = "deny"  # deny by default (safe)
    strict_mode: bool = True  # fail-closed

    def add_target(self, target: str) -> None:
        """Add a target to the allow list, auto-detecting type."""
        host = _extract_host(target)
        rule_type = _detect_type(host)
        self.rules.append(ScopeRule(pattern=host, rule_type=rule_type, action="allow"))

    def add_deny(self, target: str) -> None:
        """Add a target to the deny list."""
        rule_type = _detect_type(target)
        self.rules.append(ScopeRule(pattern=target, rule_type=rule_type, action="deny"))

    def add_cidr(self, cidr: str) -> None:
        """Add a CIDR range to the allow list."""
        self.rules.append(ScopeRule(pattern=cidr, rule_type="cidr", action="allow"))


class ScopeValidator:
    """
    Validates targets against configured scope rules.

    Enforces:
    - Only authorized targets are scanned
    - Deny rules take precedence over allow rules
    - Strict mode fails closed (unknown targets are denied)
    """

    # v0.9.39: Mapping of tool names → parameter names that contain targets.
    # enforce_scope() checks every value listed here against is_in_scope().
    _SCOPE_CHECKED_PARAMS: dict[str, list[str]] = {
        # HTTP tools
        "http_request": ["url"],
        "http_get": ["url"],
        "http_post": ["url"],
        "fetch_url": ["url"],
        "curl": ["url"],
        # Scanner / recon tools
        "nmap_scan": ["target", "host"],
        "port_scan": ["target", "host"],
        "dns_lookup": ["domain", "target"],
        "subdomain_enum": ["domain", "target"],
        "directory_brute": ["url", "target"],
        "nuclei_scan": ["target", "url"],
        "ffuf_fuzz": ["url", "target"],
        "sqlmap_scan": ["url", "target"],
        "nikto_scan": ["target", "host"],
        "wpscan": ["url"],
        # Browser / proxy tools
        "browse": ["url"],
        "navigate": ["url"],
        "screenshot": ["url"],
        # Network tools
        "connect": ["host", "target"],
        "ssh_connect": ["host"],
        "ftp_connect": ["host"],
        # BUG-004 FIX: terminal_execute must be scope-checked to prevent
        # arbitrary command execution against out-of-scope targets.
        "terminal_execute": ["command"],
        "run_command": ["command"],
    }

    # Generic parameter names that always get checked (fallback for unknown tools)
    _GENERIC_SCOPE_PARAMS: set[str] = {"url", "target", "host", "domain"}

    def __init__(self, config: ScopeConfig | None = None) -> None:
        self.config = config or ScopeConfig()
        self._violation_log: list[dict[str, Any]] = []
        # LOGIC-003 FIX: DNS pin cache — record resolved IPs at first check
        # to detect and prevent DNS rebinding attacks (TOCTOU mitigation).
        # M7 FIX: Bounded to prevent memory exhaustion
        # G-08 FIX: Each entry stores (ips, timestamp) for TTL expiry
        self._dns_pin_cache: dict[str, tuple[set[str], float]] = {}
        self._DNS_PIN_CACHE_MAX = 10_000
        self._DNS_PIN_TTL = 300.0  # G-08 FIX: 5-minute TTL for pinned entries
        # BUG-005 FIX: Primary targets are never evicted from DNS pin cache
        self._protected_dns_pins: set[str] = set()
        # V-MED-003 FIX: Thread lock for DNS pin cache to prevent race
        # conditions during concurrent scope checks (TOCTOU on pin cache).
        import threading as _threading
        self._dns_pin_lock = _threading.Lock()

    @classmethod
    def from_targets(cls, targets: list[str]) -> ScopeValidator:
        """Create a validator from a list of authorized targets."""
        config = ScopeConfig()
        for t in targets:
            config.add_target(t)
        validator = cls(config)
        # BUG-005 FIX: Mark primary targets as protected in DNS pin cache
        for t in targets:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(t if "://" in t else f"https://{t}")
                host = parsed.hostname or t
                validator._protected_dns_pins.add(host.lower())
            except Exception:
                validator._protected_dns_pins.add(t.lower())
        return validator

    @classmethod
    def permissive(cls) -> ScopeValidator:
        """Create a permissive validator (allow all). For testing only."""
        config = ScopeConfig(default_action="allow", strict_mode=False)
        return cls(config)

    def enforce_scope(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        """
        v0.9.39: Per-request scope enforcement for tool invocations.

        Inspects the tool's parameters for URLs/IPs/hostnames and validates
        each one against the configured scope rules (is_in_scope).
        
        FIX-P0-001: Also validates URL schemes against security policy.

        Returns:
            The original tool_args dict (pass-through) if all targets are in scope.

        Raises:
            ScopeViolationError: If any target parameter is out of scope.
            SecurityViolationError: If URL scheme is blocked (FIX-P0-001).
        """
        from phantom.core.exceptions import ScopeViolationError, SecurityViolationError

        # Determine which parameters to check
        params_to_check = self._SCOPE_CHECKED_PARAMS.get(tool_name)
        if params_to_check is None:
            # Fallback: check any generic-named params
            params_to_check = [
                k for k in tool_args if k.lower() in self._GENERIC_SCOPE_PARAMS
            ]

        for param_name in params_to_check:
            value = tool_args.get(param_name)
            if not value or not isinstance(value, str):
                continue

            # Skip empty/placeholder values only — CRIT-04 FIX: never skip localhost/127.0.0.1
            if value.strip() == "":
                continue

            # BUG-004 FIX: For command-type params, extract embedded IPs/URLs
            if param_name == "command":
                self._enforce_scope_on_command(tool_name or "", value)
                continue

            # FIX-P0-001: Validate URL scheme BEFORE scope check
            # This catches dangerous schemes regardless of scope configuration
            if "://" in value or value.startswith("//"):
                scheme_valid, reason = validate_url_scheme(value)
                if not scheme_valid:
                    raise SecurityViolationError(
                        message=f"Tool '{tool_name}' parameter '{param_name}' uses "
                                f"blocked URL pattern: {reason}",
                        violation_type="blocked_url_scheme",
                    )

            if not self.is_in_scope(value):
                raise ScopeViolationError(
                    message=f"Tool '{tool_name}' parameter '{param_name}' targets "
                            f"'{value}' which is outside the declared scope.",
                    tool_name=tool_name,
                    target=value,
                )

        return tool_args

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the defined scope."""
        if not self.config.rules:
            return self.config.default_action == "allow"

        # Deny rules have priority
        for rule in self.config.rules:
            if rule.action == "deny" and rule.matches(target):
                self._log_violation(target, "denied_by_rule", rule.pattern)
                return False

        # Check allow rules first — explicitly listed targets are trusted
        host = _extract_host(target)
        explicitly_allowed = False
        for rule in self.config.rules:
            if rule.action == "allow" and rule.matches(target):
                explicitly_allowed = True
                break

        # PHT-023: DNS rebinding defense — check resolved IPs for non-explicit
        # targets. Explicitly-allowed targets (user directly added the host)
        # bypass the private-IP resolution check because the user authorized it
        # (e.g., host.docker.internal for Docker-hosted targets).
        # Wildcard rules (*.target.com) still get DNS rebinding defense because
        # the user authorized the domain pattern, not specific internal IPs.
        # LOGIC-003 FIX: DNS pinning — record resolved IPs on first check and
        # reject if subsequent resolutions return different IPs (TOCTOU defense).
        _is_exact_allow = explicitly_allowed and not any(
            r.pattern.startswith("*.") for r in self.config.rules
            if r.action == "allow" and r.matches(target)
        )
        if not is_private_ip(host) and not _is_exact_allow:
            import socket as _socket
            try:
                resolved_ips = _socket.getaddrinfo(host, None)
                current_ips = set()
                for _family, _type, _proto, _canonname, sockaddr in resolved_ips:
                    resolved_ip = sockaddr[0]
                    current_ips.add(resolved_ip)
                    if is_private_ip(resolved_ip):
                        self._log_violation(
                            target, "dns_rebinding",
                            f"Hostname {host} resolves to private IP {resolved_ip}"
                        )
                        return False

                # V-MED-003 FIX: All DNS pin cache operations under lock
                # to prevent TOCTOU race conditions during concurrent checks.
                with self._dns_pin_lock:
                    # DNS pinning: compare against cached resolution
                    if host in self._dns_pin_cache:
                        pinned_ips, pin_time = self._dns_pin_cache[host]
                        # G-08 FIX: Expire stale pins after TTL
                        import time as _time
                        if _time.time() - pin_time > self._DNS_PIN_TTL:
                            # Pin expired — re-pin with current resolution
                            del self._dns_pin_cache[host]
                        elif current_ips != pinned_ips:
                            new_ips = current_ips - pinned_ips
                            self._log_violation(
                                target, "dns_pin_violation",
                                f"Hostname {host} resolved to new IPs {new_ips} "
                                f"(pinned: {pinned_ips})"
                            )
                            return False

                    if host not in self._dns_pin_cache:
                        # Pin the first resolution (or refresh after TTL expiry)
                        # M7 FIX: evict oldest entries if cache is full
                        if len(self._dns_pin_cache) >= self._DNS_PIN_CACHE_MAX:
                            # BUG-005 FIX: Only evict non-protected (secondary) entries
                            evicted = False
                            for candidate_key in list(self._dns_pin_cache.keys()):
                                if candidate_key not in self._protected_dns_pins:
                                    del self._dns_pin_cache[candidate_key]
                                    evicted = True
                                    break
                            if not evicted:
                                # All entries are protected — evict oldest anyway
                                oldest_key = next(iter(self._dns_pin_cache))
                                del self._dns_pin_cache[oldest_key]
                        import time as _time
                        self._dns_pin_cache[host] = (current_ips, _time.time())
            except _socket.gaierror:
                pass  # DNS resolution failed — continue with rule-based check

        if explicitly_allowed:
            return True

        # Default action
        if self.config.strict_mode:
            self._log_violation(target, "not_in_scope", "no matching allow rule")
            return False

        return self.config.default_action == "allow"

    # ── BUG-004 FIX: Command scope enforcement ──

    # Regex to extract IPs and URLs from shell commands
    _IP_RE = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    _URL_RE = re.compile(
        r'https?://[^\s\'\"<>|;`]+', re.IGNORECASE
    )
    _HOSTNAME_RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )

    def _enforce_scope_on_command(self, tool_name: str, command: str) -> None:
        """Extract IPs, URLs, and hostnames from a command and validate scope."""
        from phantom.core.exceptions import ScopeViolationError

        targets: set[str] = set()
        # Extract IPs
        targets.update(self._IP_RE.findall(command))
        # Extract URLs
        targets.update(self._URL_RE.findall(command))
        # Extract hostnames (filter out common non-target words)
        for hostname in self._HOSTNAME_RE.findall(command):
            # Exclude common file extensions and command-like patterns
            if hostname.endswith(('.py', '.sh', '.txt', '.log', '.conf', '.yml',
                                  '.json', '.xml', '.md', '.cfg')):
                continue
            targets.add(hostname)

        for target in targets:
            # CRIT-05 FIX: Block internal addresses in command scope checking
            host = _extract_host(target)
            if host in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "169.254.169.254"):
                raise ScopeViolationError(
                    message=(
                        f"Tool '{tool_name}' command targets internal address '{host}' "
                        f"which is blocked by scope policy."
                    ),
                    tool_name=tool_name,
                    target=target,
                )
            if not self.is_in_scope(target):
                raise ScopeViolationError(
                    message=(
                        f"Tool '{tool_name}' command contains target '{target}' "
                        f"which is outside the declared scope."
                    ),
                    tool_name=tool_name,
                    target=target,
                )

    def validate_target(self, target: str) -> dict[str, Any]:
        """Validate a target and return detailed result."""
        in_scope = self.is_in_scope(target)
        host = _extract_host(target)
        target_type = _detect_type(host)

        return {
            "target": target,
            "host": host,
            "type": target_type,
            "in_scope": in_scope,
            "action": "allow" if in_scope else "deny",
            "strict_mode": self.config.strict_mode,
            "rules_count": len(self.config.rules),
        }

    def validate_targets(self, targets: list[str]) -> dict[str, Any]:
        """Validate multiple targets at once."""
        results = [self.validate_target(t) for t in targets]
        allowed = [r for r in results if r["in_scope"]]
        denied = [r for r in results if not r["in_scope"]]

        return {
            "total": len(targets),
            "allowed": len(allowed),
            "denied": len(denied),
            "allowed_targets": [r["target"] for r in allowed],
            "denied_targets": [r["target"] for r in denied],
            "results": results,
        }

    def get_violations(self) -> list[dict[str, Any]]:
        """Return all scope violations logged during this session."""
        return list(self._violation_log)

    def _log_violation(self, target: str, reason: str, detail: str) -> None:
        from datetime import UTC, datetime

        self._violation_log.append(
            {
                "target": target,
                "reason": reason,
                "detail": detail,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
        # MED-28 FIX: Cap violation log to prevent unbounded memory growth
        if len(self._violation_log) > 5000:
            self._violation_log = self._violation_log[-2500:]

    def to_dict(self) -> dict[str, Any]:
        """Serialize scope config for persistence."""
        return {
            "rules": [
                {"pattern": r.pattern, "type": r.rule_type, "action": r.action}
                for r in self.config.rules
            ],
            "default_action": self.config.default_action,
            "strict_mode": self.config.strict_mode,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeValidator:
        """Deserialize scope config."""
        _valid_actions = {"allow", "deny"}
        _valid_types = {"domain", "ip", "cidr", "regex"}
        config = ScopeConfig(
            default_action=data.get("default_action", "deny"),
            strict_mode=data.get("strict_mode", True),
        )
        for rule_data in data.get("rules", []):
            rule_type = rule_data.get("type", "domain")
            action = rule_data.get("action", "allow")
            if rule_type not in _valid_types or action not in _valid_actions:
                continue
            config.rules.append(
                ScopeRule(
                    pattern=rule_data["pattern"],
                    rule_type=rule_type,
                    action=action,
                )
            )
        return cls(config)


# PHT-023: Private/internal IP ranges that must NEVER be in scope
# unless explicitly allowed — prevents SSRF and DNS rebinding attacks
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# FIX-P0-001: Dangerous URL schemes that can be abused for SSRF or local file access
# These MUST be blocked regardless of in-scope status
_BLOCKED_URL_SCHEMES = frozenset({
    "file",       # Local file access
    "gopher",     # Protocol smuggling
    "dict",       # Dictionary server protocol (info leak)
    "ftp",        # Legacy, often misconfigured
    "ldap",       # LDAP injection vector
    "ldaps",      # LDAP over SSL
    "tftp",       # Trivial FTP (unauthenticated)
    "jar",        # Java archive (can trigger deserialization)
    "netdoc",     # Alternative file: scheme
    "data",       # Data URLs can embed arbitrary content
    "mailto",     # Email injection
    "tel",        # Telephone (misuse vector)
    "javascript", # XSS vector
    "vbscript",   # VBScript injection
})

# Whitelist of allowed URL schemes
_ALLOWED_URL_SCHEMES = frozenset({
    "http",
    "https",
})


def validate_url_scheme(url: str) -> tuple[bool, str]:
    """
    FIX-P0-001: Validate URL scheme against security policy.
    
    Checks:
    1. Scheme is in the allowed whitelist (http, https)
    2. Scheme is NOT in the blocked list (file, gopher, data, etc.)
    3. URL does not contain embedded credentials (user:pass@host)
    
    Args:
        url: The URL to validate
        
    Returns:
        Tuple of (is_valid, reason). If is_valid is False, reason explains why.
    """
    if not url or not isinstance(url, str):
        return False, "empty_or_invalid_url"
    
    # Parse URL to extract scheme
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "url_parse_error"
    
    scheme = (parsed.scheme or "").lower()
    
    # Check for missing scheme
    if not scheme:
        # No scheme — allow (will be treated as hostname)
        return True, "no_scheme"
    
    # Check blocked schemes first (explicit deny)
    if scheme in _BLOCKED_URL_SCHEMES:
        return False, f"blocked_scheme_{scheme}"
    
    # Check if scheme is in whitelist
    if scheme not in _ALLOWED_URL_SCHEMES:
        return False, f"unknown_scheme_{scheme}"
    
    # FIX-P0-001: Check for embedded credentials (user:pass@host)
    # This is often used in SSRF attacks to smuggle data
    if parsed.username or parsed.password:
        return False, "embedded_credentials"
    
    # Check for URL with double-encoded characters (bypass attempt)
    if "%25" in url.lower():  # %25 = encoded %
        return False, "double_encoding_detected"
    
    # Check for backslash in URL (URL confusion attacks)
    if "\\" in url:
        return False, "backslash_in_url"
    
    # Check for suspicious port numbers
    if parsed.port:
        # Block commonly abused ports (Redis, Memcached, etc.)
        dangerous_ports = {6379, 11211, 27017, 5432, 3306, 1433, 9200, 2375, 2376}
        if parsed.port in dangerous_ports:
            return False, f"dangerous_port_{parsed.port}"
    
    return True, "valid"


def is_private_ip(host: str) -> bool:
    """Check if a host resolves to a private/internal IP address."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _extract_host(target: str) -> str:
    """Extract hostname/IP from a target string.

    PHT-045: Handles user-info in URLs (e.g., ``http://evil@internal.corp``)
    by stripping the authority component before extracting the hostname.
    """
    # Handle URLs
    if "://" in target:
        parsed = urlparse(target)
        # PHT-045: urlparse.hostname already strips user-info correctly,
        # but we also strip '@' from bare targets below
        return parsed.hostname or target

    # PHT-045: Strip user-info from bare targets (user@host, user:pass@host)
    if "@" in target:
        target = target.rsplit("@", 1)[-1]

    # Handle host:port
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        if len(parts) == 2:
            try:
                int(parts[1])
                return parts[0]
            except ValueError:
                pass

    return target


def _detect_type(target: str) -> str:
    """Auto-detect target type (domain, ip, cidr, regex)."""
    # Check CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return "cidr"
        except ValueError:
            pass

    # Check IP
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    # Check wildcard domain
    if target.startswith("*."):
        return "domain"

    # Check regex (has regex metacharacters)
    if any(c in target for c in r"^$+?{}|()[]\\"):
        return "regex"

    # Default: domain
    return "domain"
