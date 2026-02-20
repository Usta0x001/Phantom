"""Configurable scan profiles with per-mode tool limits, timeouts, and iteration caps.

Each profile defines which security tools to prioritize, max iterations,
sandbox timeout, and LLM reasoning budget for the scan mode.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProfileName(str, Enum):
    """Built-in scan profile identifiers."""

    quick = "quick"
    standard = "standard"
    deep = "deep"
    stealth = "stealth"
    api_only = "api_only"


@dataclass(frozen=False)
class ScanProfile:
    """A concrete scan profile controlling agent behaviour.

    Attributes:
        name:               Human-readable profile name.
        description:        One-line purpose of the profile.
        max_iterations:     Hard cap on agent tool-call cycles.
        sandbox_timeout_s:  Per-tool sandbox execution timeout (seconds).
        reasoning_effort:   LLM reasoning effort (``low`` / ``medium`` / ``high``).
        priority_tools:     Ordered list of tools the agent should favour.
        skip_tools:         Tools that should NOT be used in this profile.
        max_concurrent_tools: How many parallel sandbox slots to allocate.
        enable_browser:     Whether to allow browser-based tools.
        nuclei_severity:    Nuclei severity filter (e.g. ``"medium,high,critical"``).
        custom_flags:       Arbitrary key-value flags for plugins / future use.
    """

    name: str
    description: str = ""
    max_iterations: int = 60
    sandbox_timeout_s: int = 120
    reasoning_effort: str = "high"
    priority_tools: list[str] = field(default_factory=list)
    skip_tools: list[str] = field(default_factory=list)
    max_concurrent_tools: int = 4
    enable_browser: bool = True
    nuclei_severity: str = "low,medium,high,critical"
    custom_flags: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "max_iterations": self.max_iterations,
            "sandbox_timeout_s": self.sandbox_timeout_s,
            "reasoning_effort": self.reasoning_effort,
            "priority_tools": list(self.priority_tools),
            "skip_tools": list(self.skip_tools),
            "max_concurrent_tools": self.max_concurrent_tools,
            "enable_browser": self.enable_browser,
            "nuclei_severity": self.nuclei_severity,
            "custom_flags": dict(self.custom_flags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanProfile":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def merge(self, overrides: dict[str, Any]) -> "ScanProfile":
        """Return a *new* profile with ``overrides`` applied on top."""
        merged = copy.deepcopy(self)
        for k, v in overrides.items():
            if k in self.__dataclass_fields__:
                setattr(merged, k, v)
        return merged


# ======================================================================
# Built-in profile library
# ======================================================================

PROFILES: dict[str, ScanProfile] = {
    # ------------------------------------------------------------------
    ProfileName.quick: ScanProfile(
        name="quick",
        description="Time-boxed rapid assessment (<10 min). High-impact vulns only.",
        max_iterations=20,
        sandbox_timeout_s=60,
        reasoning_effort="low",
        priority_tools=[
            "nuclei_scan",
            "httpx_scan",
            "nmap_scan",
        ],
        skip_tools=[
            "subfinder_scan",
            "sqlmap_scan",
            "create_sub_agent",
        ],
        max_concurrent_tools=2,
        enable_browser=False,
        nuclei_severity="high,critical",
    ),
    # ------------------------------------------------------------------
    ProfileName.standard: ScanProfile(
        name="standard",
        description="Balanced assessment with systematic methodology (~30 min).",
        max_iterations=40,
        sandbox_timeout_s=120,
        reasoning_effort="medium",
        priority_tools=[
            "nuclei_scan",
            "httpx_scan",
            "nmap_scan",
            "ffuf_scan",
            "sqlmap_scan",
        ],
        skip_tools=[],
        max_concurrent_tools=4,
        enable_browser=True,
        nuclei_severity="medium,high,critical",
    ),
    # ------------------------------------------------------------------
    ProfileName.deep: ScanProfile(
        name="deep",
        description="Exhaustive assessment with maximum coverage and vuln chaining.",
        max_iterations=80,
        sandbox_timeout_s=180,
        reasoning_effort="high",
        priority_tools=[
            "nuclei_scan",
            "nuclei_scan_cves",
            "nuclei_scan_misconfigs",
            "httpx_scan",
            "nmap_scan",
            "ffuf_scan",
            "sqlmap_scan",
            "subfinder_scan",
            "create_sub_agent",
        ],
        skip_tools=[],
        max_concurrent_tools=6,
        enable_browser=True,
        nuclei_severity="low,medium,high,critical",
    ),
    # ------------------------------------------------------------------
    ProfileName.stealth: ScanProfile(
        name="stealth",
        description="Low-noise scan to avoid IDS/WAF detection. Slow, rate-limited.",
        max_iterations=30,
        sandbox_timeout_s=60,
        reasoning_effort="medium",
        priority_tools=[
            "httpx_scan",
            "nuclei_scan",
        ],
        skip_tools=[
            "ffuf_scan",        # noisy
            "sqlmap_scan",      # very noisy
            "subfinder_scan",
            "create_sub_agent",
        ],
        max_concurrent_tools=1,
        enable_browser=False,
        nuclei_severity="high,critical",
        custom_flags={"rate_limit": 5, "delay_ms": 2000},
    ),
    # ------------------------------------------------------------------
    ProfileName.api_only: ScanProfile(
        name="api_only",
        description="API-focused assessment. No browser, no subdomain discovery.",
        max_iterations=40,
        sandbox_timeout_s=120,
        reasoning_effort="medium",
        priority_tools=[
            "httpx_scan",
            "ffuf_scan",
            "nuclei_scan",
            "sqlmap_scan",
        ],
        skip_tools=[
            "subfinder_scan",
            "open_browser",
            "browser_navigate",
        ],
        max_concurrent_tools=3,
        enable_browser=False,
        nuclei_severity="medium,high,critical",
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Retrieve a profile by name.  Raises ``KeyError`` on unknown profile."""
    if name not in PROFILES:
        available = ", ".join(sorted(PROFILES))
        raise KeyError(f"Unknown scan profile {name!r}. Available: {available}")
    return copy.deepcopy(PROFILES[name])


def list_profiles() -> list[dict[str, str]]:
    """Return a list of ``{name, description}`` for all built-in profiles."""
    return [{"name": p.name, "description": p.description} for p in PROFILES.values()]


def register_profile(profile: ScanProfile) -> None:
    """Register (or overwrite) a custom profile at runtime."""
    PROFILES[profile.name] = profile
