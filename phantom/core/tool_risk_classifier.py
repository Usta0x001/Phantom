"""
Tool Risk Classification — V2-DESIGN-003 / FIX-013

Formal risk taxonomy for all registered tools.
Each tool is assigned a risk tier that determines:
- Whether evidence gates are required before execution
- Whether confirmation is needed
- Rate limiting parameters
- Logging verbosity

Tiers:
    PASSIVE    — Read-only reconnaissance, no target interaction risk
    ACTIVE     — Active scanning, may trigger IDS/WAF
    INVASIVE   — Exploitation attempts, data extraction
    DESTRUCTIVE — Modifies target state, credential stuffing
    UNRESTRICTED — Arbitrary execution (terminal, python)
"""

from __future__ import annotations

import logging
from enum import IntEnum
from typing import Any, Final

_logger = logging.getLogger(__name__)


class ToolRiskTier(IntEnum):
    PASSIVE = 0       # httpx, subfinder, dig — no confirmation needed
    ACTIVE = 1        # nmap, nuclei — logged, rate-limited
    INVASIVE = 2      # sqlmap, ffuf — require target confirmation
    DESTRUCTIVE = 3   # sqlmap_dump, hydra — require evidence + confirmation
    UNRESTRICTED = 4  # terminal_execute, python_action — per-invocation checks


# ── Tool → Risk Tier mapping ──
TOOL_RISK_MAP: Final[dict[str, ToolRiskTier]] = {
    # PASSIVE — Safe reconnaissance
    "httpx_probe": ToolRiskTier.PASSIVE,
    "httpx_full_analysis": ToolRiskTier.PASSIVE,
    "subfinder_scan": ToolRiskTier.PASSIVE,
    "whois_lookup": ToolRiskTier.PASSIVE,
    "dns_lookup": ToolRiskTier.PASSIVE,
    "katana_crawl": ToolRiskTier.PASSIVE,

    # ACTIVE — Active scanning
    "nmap_scan": ToolRiskTier.ACTIVE,
    "nmap_vuln_scan": ToolRiskTier.ACTIVE,
    "nuclei_scan": ToolRiskTier.ACTIVE,
    "nuclei_scan_cves": ToolRiskTier.ACTIVE,
    "nuclei_scan_misconfigs": ToolRiskTier.ACTIVE,

    # INVASIVE — Exploitation attempts
    "sqlmap_test": ToolRiskTier.INVASIVE,
    "sqlmap_forms": ToolRiskTier.INVASIVE,
    "ffuf_directory_scan": ToolRiskTier.INVASIVE,
    "ffuf_parameter_fuzz": ToolRiskTier.INVASIVE,
    "ffuf_vhost_fuzz": ToolRiskTier.INVASIVE,
    "send_request": ToolRiskTier.INVASIVE,
    "repeat_request": ToolRiskTier.INVASIVE,

    # DESTRUCTIVE — Data extraction, credential attacks
    "sqlmap_dump_database": ToolRiskTier.DESTRUCTIVE,

    # UNRESTRICTED — Arbitrary execution
    "terminal_execute": ToolRiskTier.UNRESTRICTED,
    "python_action": ToolRiskTier.UNRESTRICTED,
}

# ── Evidence gates: minimum findings before invasive+ tools ──
EVIDENCE_GATES: Final[dict[ToolRiskTier, int]] = {
    ToolRiskTier.PASSIVE: 0,
    ToolRiskTier.ACTIVE: 0,
    ToolRiskTier.INVASIVE: 1,     # At least 1 finding before exploitation
    ToolRiskTier.DESTRUCTIVE: 3,  # At least 3 findings with evidence
    ToolRiskTier.UNRESTRICTED: 1,
}

# ── Per-tier rate limits (max calls per 5-minute window) ──
TIER_RATE_LIMITS: Final[dict[ToolRiskTier, int]] = {
    ToolRiskTier.PASSIVE: 100,
    ToolRiskTier.ACTIVE: 30,
    ToolRiskTier.INVASIVE: 15,
    ToolRiskTier.DESTRUCTIVE: 5,
    ToolRiskTier.UNRESTRICTED: 10,
}


def get_tool_risk_tier(tool_name: str) -> ToolRiskTier:
    """Get the risk tier for a tool. Defaults to ACTIVE for unknown tools."""
    return TOOL_RISK_MAP.get(tool_name, ToolRiskTier.ACTIVE)


def check_evidence_gate(
    tool_name: str,
    findings_count: int,
    verified_count: int = 0,
) -> tuple[bool, str]:
    """Check if sufficient evidence exists to allow tool execution.

    Returns (allowed, reason).
    """
    tier = get_tool_risk_tier(tool_name)
    required = EVIDENCE_GATES.get(tier, 0)

    if tier == ToolRiskTier.DESTRUCTIVE:
        # Destructive tools require verified findings
        if verified_count < required:
            return False, (
                f"Tool '{tool_name}' (DESTRUCTIVE tier) requires at least "
                f"{required} verified findings before execution. "
                f"Currently have {verified_count} verified."
            )
    elif findings_count < required:
        return False, (
            f"Tool '{tool_name}' ({tier.name} tier) requires at least "
            f"{required} finding(s) before execution. "
            f"Currently have {findings_count}."
        )

    return True, ""


def get_rate_limit(tool_name: str) -> int:
    """Get the rate limit for a tool (max calls per 5min window)."""
    tier = get_tool_risk_tier(tool_name)
    return TIER_RATE_LIMITS.get(tier, 30)
