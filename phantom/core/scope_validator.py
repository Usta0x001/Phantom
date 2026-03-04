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

    @classmethod
    def from_targets(cls, targets: list[str]) -> ScopeValidator:
        """Create a validator from a list of authorized targets."""
        config = ScopeConfig()
        for t in targets:
            config.add_target(t)
        return cls(config)

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

        Returns:
            The original tool_args dict (pass-through) if all targets are in scope.

        Raises:
            ScopeViolationError: If any target parameter is out of scope.
        """
        from phantom.core.exceptions import ScopeViolationError

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

            # Skip empty/placeholder values
            if value.strip() in ("", "localhost", "127.0.0.1"):
                continue

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

        # PHT-023: DNS rebinding defense — ALWAYS check resolved IPs.
        # Even explicitly-allowed domains (e.g. *.target.com) must not resolve
        # to private/internal IPs — user authorized the domain, not 10.x/169.254.x.
        # LOGIC-003 FIX: DNS pinning — record resolved IPs on first check and
        # reject if subsequent resolutions return different IPs (TOCTOU defense).
        if not is_private_ip(host):
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
        config = ScopeConfig(
            default_action=data.get("default_action", "deny"),
            strict_mode=data.get("strict_mode", True),
        )
        for rule_data in data.get("rules", []):
            config.rules.append(
                ScopeRule(
                    pattern=rule_data["pattern"],
                    rule_type=rule_data["type"],
                    action=rule_data.get("action", "allow"),
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
