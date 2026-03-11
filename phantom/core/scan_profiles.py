"""
Phantom scan profiles — named presets that bundle scan mode settings.

Each profile maps onto a scan_mode but also carries ancillary tuning knobs
(max_iterations, sandbox_timeout_s, reasoning_effort, tool hints, …) so the
user can pick a well-calibrated preset rather than tuning individual flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanProfile:
    name: str
    description: str
    scan_mode: str
    max_iterations: int
    sandbox_timeout_s: int
    reasoning_effort: str                    # "low" | "medium" | "high"
    enable_browser: bool = False
    priority_tools: list[str] = field(default_factory=list)
    skip_tools: list[str] = field(default_factory=list)


_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast CI/CD gate — surface-level checks only, no deep crawl.",
        scan_mode="quick",
        max_iterations=50,
        sandbox_timeout_s=300,
        reasoning_effort="low",
        enable_browser=False,
        priority_tools=["nmap", "httpx", "nikto"],
        skip_tools=["sqlmap", "ffuf", "feroxbuster"],
    ),
    "standard": ScanProfile(
        name="standard",
        description="Balanced scan — thorough but time-bounded. Good default.",
        scan_mode="standard",
        max_iterations=150,
        sandbox_timeout_s=600,
        reasoning_effort="medium",
        enable_browser=True,
        priority_tools=["nmap", "httpx", "nuclei", "sqlmap"],
        skip_tools=[],
    ),
    "deep": ScanProfile(
        name="deep",
        description="Full adversarial simulation — maximum depth, no shortcuts.",
        scan_mode="deep",
        max_iterations=300,
        sandbox_timeout_s=1200,
        reasoning_effort="high",
        enable_browser=True,
        priority_tools=["nmap", "httpx", "nuclei", "sqlmap", "ffuf", "nikto"],
        skip_tools=[],
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Low-and-slow — evades IDS/WAF, randomised delays, minimal noise.",
        scan_mode="stealth",
        max_iterations=200,
        sandbox_timeout_s=900,
        reasoning_effort="medium",
        enable_browser=False,
        priority_tools=["nmap", "httpx", "nuclei"],
        skip_tools=["nikto", "ffuf", "feroxbuster"],
    ),
    "api_only": ScanProfile(
        name="api_only",
        description="REST / GraphQL API surface only — no UI or port scanning.",
        scan_mode="api_only",
        max_iterations=100,
        sandbox_timeout_s=600,
        reasoning_effort="medium",
        enable_browser=False,
        priority_tools=["httpx", "nuclei", "sqlmap"],
        skip_tools=["nmap", "nikto", "ffuf", "feroxbuster"],
    ),
}


def list_profiles() -> list[dict[str, str]]:
    """Return a list of profile descriptors (name + description)."""
    return [{"name": p.name, "description": p.description} for p in _PROFILES.values()]


def get_profile(name: str) -> ScanProfile:
    """Return the ScanProfile for *name*, or raise KeyError."""
    key = name.lower()
    if key not in _PROFILES:
        raise KeyError(f"Unknown scan profile '{name}'. Valid: {', '.join(_PROFILES)}")
    return _PROFILES[key]
