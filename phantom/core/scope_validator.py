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
            compiled = re.compile(self.pattern, re.IGNORECASE)
            # Use match with a length limit to mitigate catastrophic backtracking
            if len(target) > 2048:
                target = target[:2048]
            match = compiled.search(target)
            return bool(match)
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

    def __init__(self, config: ScopeConfig | None = None) -> None:
        self.config = config or ScopeConfig()
        self._violation_log: list[dict[str, Any]] = []

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

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the defined scope."""
        if not self.config.rules:
            return self.config.default_action == "allow"

        # Deny rules have priority
        for rule in self.config.rules:
            if rule.action == "deny" and rule.matches(target):
                self._log_violation(target, "denied_by_rule", rule.pattern)
                return False

        # Check allow rules
        for rule in self.config.rules:
            if rule.action == "allow" and rule.matches(target):
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


def _extract_host(target: str) -> str:
    """Extract hostname/IP from a target string."""
    # Handle URLs
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target

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
