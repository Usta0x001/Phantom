"""
Coverage Tracker — Tracks testing coverage across attack surfaces.

Follows the same pattern as HypothesisLedger:
- Thread-safe with RLock
- Returns FACTS not commands (preserves AI autonomy)
- Serializable for checkpoints
- Injectable into LLM context via to_prompt_summary()

The LLM uses this data to decide what to test next - the tracker
never prescribes actions, only reports coverage state.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class TestedItem:
    """Record of a single test attempt on an attack surface."""

    id: str
    surface: str  # e.g. "/api/login", "POST /users", "input#username"
    surface_type: str  # e.g. "endpoint", "parameter", "form_field", "header"
    vuln_classes_tested: list[str] = field(default_factory=list)  # e.g. ["sqli", "xss"]
    test_count: int = 0
    last_tested: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    notes: list[str] = field(default_factory=list)  # Observations from tests
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    # FEAT-002: Track failure reasons to prevent repeated futile attacks after memory compression
    failure_reasons: list[str] = field(
        default_factory=list
    )  # e.g. ["WAF_BLOCKED", "403_FORBIDDEN", "RATE_LIMITED"]
    # Preserved from DiscoveredSurface when promoted; helps the LLM remember why
    # a surface was interesting in the first place.
    source: str = "manual"
    priority_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # Return copies of mutable containers to prevent external corruption.
        return {
            "id": self.id,
            "surface": self.surface,
            "surface_type": self.surface_type,
            "vuln_classes_tested": list(self.vuln_classes_tested),
            "test_count": self.test_count,
            "last_tested": self.last_tested,
            "notes": list(self.notes),
            "discovered_at": self.discovered_at,
            "failure_reasons": list(self.failure_reasons),
            "source": self.source,
            "priority_hints": list(self.priority_hints),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TestedItem":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class DiscoveredSurface:
    """A surface discovered but not yet tested."""

    id: str
    surface: str
    surface_type: str
    source: str  # How it was discovered (e.g. "crawl", "js_analysis", "response_header")
    priority_hints: list[str] = field(default_factory=list)  # Hints for AI (not commands)
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)  # Extra info about the surface
    notes: list[str] = field(default_factory=list)  # Failure notes for discovered-but-blocked surfaces

    def to_dict(self) -> dict[str, Any]:
        # Return copies of mutable containers to prevent external corruption.
        return {
            "id": self.id,
            "surface": self.surface,
            "surface_type": self.surface_type,
            "source": self.source,
            "priority_hints": list(self.priority_hints),
            "discovered_at": self.discovered_at,
            "metadata": dict(self.metadata),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DiscoveredSurface":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def _make_surface_id(surface: str, surface_type: str) -> str:
    """Generate a deterministic surface ID from surface + type.

    Case-normalised so '/Login' and '/login' map to the same ID.
    """
    surface_key = f"{surface_type}:{surface}".lower()
    return f"S-{hashlib.md5(surface_key.encode()).hexdigest()[:8].upper()}"


class CoverageTracker:
    """
    Thread-safe tracking of attack surface coverage.

    Key principles:
    - Returns FACTS about coverage state (not recommendations)
    - LLM decides what to test based on these facts
    - Survives memory compression (stored outside conversation history)
    - Serializable via to_dict/from_dict
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tested: dict[str, TestedItem] = {}
        self._discovered: dict[str, DiscoveredSurface] = {}
        self._failure_only: dict[str, dict] = {}

    # ── Surface Discovery ─────────────────────────────────────────────────────

    def discover_surface(
        self,
        surface: str,
        surface_type: str,
        source: str = "manual",
        priority_hints: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Record a discovered attack surface. Returns surface ID.

        Args:
            surface: The attack surface identifier (URL, parameter, etc.)
            surface_type: Type classification (endpoint, parameter, form_field, header)
            source: How this surface was discovered
            priority_hints: Hints about why this might be interesting (informational only)
            metadata: Additional context about the surface
        """
        with self._lock:
            surface_id = _make_surface_id(surface, surface_type)

            # Check if already discovered
            if surface_id in self._discovered:
                # Update with new hints if provided
                if priority_hints:
                    existing = self._discovered[surface_id]
                    for hint in priority_hints:
                        if hint not in existing.priority_hints:
                            existing.priority_hints.append(hint)
                return surface_id

            # Check if already tested (promoted from discovered)
            if surface_id in self._tested:
                return surface_id

            self._discovered[surface_id] = DiscoveredSurface(
                id=surface_id,
                surface=surface,
                surface_type=surface_type,
                source=source,
                priority_hints=priority_hints or [],
                metadata=metadata or {},
            )
            return surface_id

    # ── Testing Records ───────────────────────────────────────────────────────

    def record_test(
        self,
        surface: str,
        surface_type: str,
        vuln_class: str,
        note: str | None = None,
    ) -> str:
        """
        Record that a test was performed on a surface.

        Returns the surface ID for reference.

        FIX B13: vuln_class is lowercased before storage and lookup so that
        'SQLi', 'sqli', and 'SQLI' are treated identically.
        """
        # FIX B13: normalise case once at entry
        vuln_class = vuln_class.lower()
        with self._lock:
            surface_id = _make_surface_id(surface, surface_type)

            # Promote from discovered to tested if needed
            if surface_id in self._discovered:
                discovered = self._discovered.pop(surface_id)
                self._tested[surface_id] = TestedItem(
                    id=surface_id,
                    surface=discovered.surface,
                    surface_type=discovered.surface_type,
                    discovered_at=discovered.discovered_at,
                    source=discovered.source,
                    priority_hints=list(discovered.priority_hints),
                    metadata=dict(discovered.metadata),
                )

            # Create new tested item if not exists
            if surface_id not in self._tested:
                self._tested[surface_id] = TestedItem(
                    id=surface_id,
                    surface=surface,
                    surface_type=surface_type,
                )

            tested = self._tested[surface_id]

            # Record the test (already lowercased above)
            if vuln_class not in tested.vuln_classes_tested:
                tested.vuln_classes_tested.append(vuln_class)
            tested.test_count += 1
            tested.last_tested = datetime.now(UTC).isoformat()

            if note:
                tested.notes.append(f"[{vuln_class}] {note}")
                # Keep notes limited
                if len(tested.notes) > 20:
                    tested.notes = tested.notes[-20:]

            return surface_id

    def record_failure(
        self,
        surface: str,
        surface_type: str,
        failure_reason: str,
        vuln_class: str | None = None,
    ) -> str:
        """
        FEAT-002: Record a test failure reason on a surface.

        FIX B-D: Failures are tracked in a separate _failure_only set so
        they do NOT appear in get_tested_surfaces() / has_been_tested().
        A surface blocked by WAF is NOT the same as a surface that was
        successfully tested — they must not be confused.

        This tracks WHY tests failed (WAF blocked, rate limited, 403, etc.) so the
        agent doesn't retry futile attacks after memory compression.

        Returns the surface ID.
        """
        with self._lock:
            surface_id = _make_surface_id(surface, surface_type)

            # FIX B-D: Only annotate _tested if already there. For discovered or
            # unknown surfaces, record in _failure_only so blocked surfaces are tracked.
            reason_with_class = f"[{vuln_class}] {failure_reason}" if vuln_class else failure_reason

            if surface_id in self._tested:
                target = self._tested[surface_id]
                if reason_with_class not in target.failure_reasons:
                    target.failure_reasons.append(reason_with_class)
                    if len(target.failure_reasons) > 10:
                        target.failure_reasons = target.failure_reasons[-10:]
                target.last_tested = datetime.now(UTC).isoformat()
                return surface_id

            # Ensure the surface is visible as blocked
            entry = self._failure_only.setdefault(
                surface_id,
                {"surface": surface, "surface_type": surface_type, "failure_reasons": []},
            )
            if reason_with_class not in entry["failure_reasons"]:
                entry["failure_reasons"].append(reason_with_class)
            return surface_id

    def get_blocked_surfaces(self) -> list[dict[str, Any]]:
        """
        FEAT-002: Return surfaces that have blocking failures (WAF, rate limit, etc.)

        This helps the agent avoid wasting iterations on surfaces that are protected.
        Returns FACTS about what's blocked and why.
        """
        with self._lock:
            blocked = []
            for item in self._tested.values():
                if item.failure_reasons:
                    blocked.append(
                        {
                            "surface": item.surface,
                            "surface_type": item.surface_type,
                            "failure_reasons": list(item.failure_reasons),
                            "test_count": item.test_count,
                        }
                    )
            for item in self._failure_only.values():
                blocked.append(
                    {
                        "surface": item["surface"],
                        "surface_type": item["surface_type"],
                        "failure_reasons": list(item["failure_reasons"]),
                        "test_count": 0,
                    }
                )
            return blocked

    # ── Coverage Queries (return FACTS, not commands) ─────────────────────────

    def get_untested_surfaces(self) -> list[DiscoveredSurface]:
        """Return surfaces that have been discovered but not tested."""
        with self._lock:
            # Return deep copies so callers cannot corrupt internal state.
            return [DiscoveredSurface.from_dict(v.to_dict()) for v in self._discovered.values()]

    def get_tested_surfaces(self) -> list[TestedItem]:
        """Return all surfaces that have been tested."""
        with self._lock:
            # Return deep copies so callers cannot corrupt internal state.
            return [TestedItem.from_dict(v.to_dict()) for v in self._tested.values()]

    def has_been_tested(
        self,
        surface: str,
        surface_type: str,
        vuln_class: str | None = None,
    ) -> bool:
        """Check if a surface has been tested (optionally for a specific vuln class).

        FIX B13: vuln_class lookup is lowercased to match the normalised storage.
        FIX: Also check _failure_only so the agent knows blocked surfaces were
        attempted and should not be retried blindly.
        """
        with self._lock:
            surface_id = _make_surface_id(surface, surface_type)

            if surface_id not in self._tested:
                # A blocked surface in _failure_only was attempted and failed;
                # return True so the agent doesn't waste retries.
                return surface_id in self._failure_only

            if vuln_class is None:
                return True

            # FIX B13: compare lowercase so 'SQLi' == 'sqli'
            return vuln_class.lower() in self._tested[surface_id].vuln_classes_tested

    # ── Prompt Summary (for LLM context injection) ────────────────────────────

    def to_prompt_summary(self, max_items: int = 15) -> str:
        """Return a compact, actionable summary for LLM context injection.

        Blocked surfaces are listed first (most actionable), then untested
        high-priority surfaces, then recently tested surfaces.
        """
        with self._lock:
            tested_list = [
                TestedItem.from_dict(v.to_dict()) for v in self._tested.values()
            ]
            discovered_list = [
                DiscoveredSurface.from_dict(v.to_dict())
                for v in self._discovered.values()
            ]
            blocked_only = {
                sid for sid in self._failure_only if sid not in self._discovered
            }
            blocked_count = len(blocked_only)
            # Build lookups while holding the lock to avoid races.
            tested_failures = {
                sid: list(item.failure_reasons)
                for sid, item in self._tested.items()
                if item.failure_reasons
            }
            failure_only_copy = {
                sid: dict(entry) for sid, entry in self._failure_only.items()
            }

        if not tested_list and not discovered_list and not blocked_count:
            return ""

        lines = ["[COVERAGE — what has been tested and what is blocked]"]

        # ── BLOCKED SURFACES (most actionable — do NOT waste time here) ──
        all_blocked = blocked_only | {
            item.id for item in tested_list if item.failure_reasons
        }
        if all_blocked:
            lines.append(f"BLOCKED ({len(all_blocked)}) — do not retry:")
            shown = 0
            # Show failure-only surfaces first
            for sid in list(blocked_only):
                if shown >= max_items // 3:
                    break
                entry = failure_only_copy.get(sid, {})
                reasons = ", ".join(entry.get("failure_reasons", [])[:2])
                lines.append(f"  {entry.get('surface', '')[:45]} | {reasons}")
                shown += 1
            # Then show tested surfaces that later got blocked
            for item in tested_list:
                if shown >= max_items // 3:
                    break
                if item.id in all_blocked and item.id not in blocked_only:
                    reasons = ", ".join(item.failure_reasons[:2])
                    lines.append(f"  {item.surface[:45]} | {reasons}")
                    shown += 1

        # ── UNTESTED SURFACES (highest priority first) ──
        if discovered_list:
            hinted = [s for s in discovered_list if s.priority_hints]
            no_hints = [s for s in discovered_list if not s.priority_hints]
            to_show = (hinted + no_hints)[: max_items // 3]
            if to_show:
                lines.append(f"UNTESTED ({len(discovered_list)}):")
                for item in to_show:
                    hint = f" | priority: {item.priority_hints[0]}" if item.priority_hints else ""
                    lines.append(
                        f"  {item.surface[:45]}{hint}"
                    )

        # ── RECENTLY TESTED (last tests performed) ──
        if tested_list:
            recent = sorted(tested_list, key=lambda x: x.last_tested, reverse=True)[
                : max_items // 3
            ]
            lines.append(f"RECENTLY TESTED ({len(tested_list)} total):")
            for item in recent:
                vc = ",".join(item.vuln_classes_tested[:2])
                fail = ""
                if item.id in tested_failures:
                    fail = f" | blocked: {tested_failures[item.id][0]}"
                lines.append(
                    f"  {item.surface[:40]} | {vc}{fail}"
                )

        lines.append("[END COVERAGE]")
        return "\n".join(lines)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize for checkpointing/persistence."""
        with self._lock:
            return {
                "tested": {k: v.to_dict() for k, v in self._tested.items()},
                "discovered": {k: v.to_dict() for k, v in self._discovered.items()},
                "failure_only": dict(self._failure_only),
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CoverageTracker":
        """Restore from serialized state."""
        tracker = cls()
        for k, v in d.get("tested", {}).items():
            tracker._tested[k] = TestedItem.from_dict(v)
        for k, v in d.get("discovered", {}).items():
            tracker._discovered[k] = DiscoveredSurface.from_dict(v)
        tracker._failure_only = dict(d.get("failure_only", {}))
        return tracker

    def __len__(self) -> int:
        with self._lock:
            return len(self._tested) + len(self._discovered) + len(self._failure_only)
