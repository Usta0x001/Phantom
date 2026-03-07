"""
Degradation Handler

Architecture Improvement 9.3: Graceful degradation when LLM providers
or tool backends become unavailable.

Modes:
    FULL    — all capabilities operational
    REDUCED — some providers failed; scan continues with reduced intelligence
    MINIMAL — critical failures; scan operates in safety-only mode
"""

from __future__ import annotations

import logging
import threading
from enum import Enum
from typing import Any

_logger = logging.getLogger(__name__)


class DegradationMode(str, Enum):
    FULL = "full"
    REDUCED = "reduced"
    MINIMAL = "minimal"


class DegradationHandler:
    """Manages graceful degradation of scan capabilities.

    Tracks provider/tool failures and adjusts the degradation mode
    so the agent loop can adapt its behaviour (e.g., skip exploit
    phases, reduce verification depth).

    H-DG-001: Formal transition rules:
      FULL → REDUCED:  1+ provider failure OR 3+ tool failures
      REDUCED → MINIMAL: 2+ provider failures OR 5+ tool failures
      MINIMAL → REDUCED: all providers recovered AND tools < 3
      REDUCED → FULL: all providers + all tools recovered

    H-DG-002: Essential-tools-only filtering in MINIMAL mode.
    """

    # Tools allowed in MINIMAL degradation mode
    _ESSENTIAL_TOOLS: frozenset[str] = frozenset({
        "nmap_scan", "send_request", "repeat_request",
        "finish_scan", "finish_with_report", "think",
    })

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._mode = DegradationMode.FULL
        self._failed_providers: set[str] = set()
        self._failed_tools: set[str] = set()
        self._history: list[dict[str, Any]] = []

    @property
    def mode(self) -> DegradationMode:
        return self._mode

    @property
    def is_degraded(self) -> bool:
        return self._mode != DegradationMode.FULL

    def handle_provider_failure(self, provider: str, error: str = "") -> DegradationMode:
        """Record an LLM provider failure and update mode."""
        with self._lock:
            self._failed_providers.add(provider)
            self._history.append({
                "type": "provider_failure",
                "provider": provider,
                "error": error[:200],
            })
            if len(self._history) > 500:
                self._history = self._history[-250:]
            self._recalculate_mode()
            _logger.warning(
                "DegradationHandler: provider %s failed \u2192 mode=%s",
                provider, self._mode.value,
            )
            return self._mode

    def handle_tool_failure(self, tool_name: str, error: str = "") -> DegradationMode:
        """Record a tool backend failure and update mode."""
        with self._lock:
            self._failed_tools.add(tool_name)
            self._history.append({
                "type": "tool_failure",
                "tool": tool_name,
                "error": error[:200],
            })
            if len(self._history) > 500:
                self._history = self._history[-250:]
            self._recalculate_mode()
            return self._mode

    def recover_provider(self, provider: str) -> DegradationMode:
        """Mark a provider as recovered."""
        with self._lock:
            self._failed_providers.discard(provider)
            self._recalculate_mode()
            _logger.info("DegradationHandler: provider %s recovered \u2192 mode=%s", provider, self._mode.value)
            return self._mode

    def recover_tool(self, tool_name: str) -> DegradationMode:
        """Mark a tool as recovered."""
        with self._lock:
            self._failed_tools.discard(tool_name)
            self._recalculate_mode()
            # LOW-19 FIX: Add log statement matching recover_provider
            _logger.info("DegradationHandler: tool %s recovered → mode=%s", tool_name, self._mode.value)
            return self._mode

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": self._mode.value,
                "failed_providers": sorted(self._failed_providers),
                "failed_tools": sorted(self._failed_tools),
                "history_count": len(self._history),
            }

    def _recalculate_mode(self) -> None:
        """Re-derive mode from current failure state.

        H-DG-001 Transition Rules:
          FULL → REDUCED:  1+ provider failure OR 3+ tool failures
          REDUCED → MINIMAL: 2+ provider failures OR 5+ tool failures
          MINIMAL → REDUCED: all providers recovered AND tools < 3
          REDUCED → FULL: all providers + all tools recovered
        """
        old_mode = self._mode
        pf = len(self._failed_providers)
        tf = len(self._failed_tools)

        if pf >= 2 or tf >= 5:
            self._mode = DegradationMode.MINIMAL
        elif pf >= 1 or tf >= 3:
            self._mode = DegradationMode.REDUCED
        elif pf == 0 and tf == 0:
            self._mode = DegradationMode.FULL
        # else: stay at current mode (hysteresis)

        if self._mode != old_mode:
            _logger.warning(
                "Degradation transition: %s → %s (providers_failed=%d, tools_failed=%d)",
                old_mode.value, self._mode.value, pf, tf,
            )

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed in the current degradation mode (H-DG-002).

        In MINIMAL mode, only essential tools are permitted.
        """
        if self._mode == DegradationMode.MINIMAL:
            return tool_name in self._ESSENTIAL_TOOLS
        return True
