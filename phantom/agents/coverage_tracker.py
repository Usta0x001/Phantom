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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "surface_type": self.surface_type,
            "vuln_classes_tested": self.vuln_classes_tested,
            "test_count": self.test_count,
            "last_tested": self.last_tested,
            "notes": self.notes,
            "discovered_at": self.discovered_at,
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "surface_type": self.surface_type,
            "source": self.source,
            "priority_hints": self.priority_hints,
            "discovered_at": self.discovered_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DiscoveredSurface":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class CoverageTracker:
    """
    Thread-safe tracking of attack surface coverage.

    Key principles:
    - Returns FACTS about coverage state (not recommendations)
    - LLM decides what to test based on these facts
    - Survives memory compression (stored outside conversation history)
    - Serializable via to_dict/from_dict
    """

    # Common vulnerability classes for coverage tracking
    COMMON_VULN_CLASSES = frozenset({
        "sqli", "xss", "ssrf", "lfi", "rfi", "rce", "idor",
        "auth_bypass", "injection", "xxe", "ssti", "csrf",
        "open_redirect", "path_traversal", "info_disclosure",
    })

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tested: dict[str, TestedItem] = {}
        self._discovered: dict[str, DiscoveredSurface] = {}
        self._counter: int = 0

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
            # Generate deterministic ID from surface + type
            surface_key = f"{surface_type}:{surface}"
            surface_id = f"S-{hashlib.md5(surface_key.encode()).hexdigest()[:8].upper()}"

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
        """
        with self._lock:
            surface_key = f"{surface_type}:{surface}"
            surface_id = f"S-{hashlib.md5(surface_key.encode()).hexdigest()[:8].upper()}"

            # Promote from discovered to tested if needed
            if surface_id in self._discovered:
                discovered = self._discovered.pop(surface_id)
                self._tested[surface_id] = TestedItem(
                    id=surface_id,
                    surface=discovered.surface,
                    surface_type=discovered.surface_type,
                    discovered_at=discovered.discovered_at,
                )

            # Create new tested item if not exists
            if surface_id not in self._tested:
                self._tested[surface_id] = TestedItem(
                    id=surface_id,
                    surface=surface,
                    surface_type=surface_type,
                )

            tested = self._tested[surface_id]

            # Record the test
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

    # ── Coverage Queries (return FACTS, not commands) ─────────────────────────

    def get_untested_surfaces(self) -> list[DiscoveredSurface]:
        """Return surfaces that have been discovered but not tested."""
        with self._lock:
            return list(self._discovered.values())

    def get_tested_surfaces(self) -> list[TestedItem]:
        """Return all surfaces that have been tested."""
        with self._lock:
            return list(self._tested.values())

    def get_coverage_by_vuln_class(self, vuln_class: str) -> dict[str, Any]:
        """
        Return coverage statistics for a specific vulnerability class.

        Returns FACTS:
        - surfaces_tested: How many surfaces tested for this vuln class
        - surfaces_not_tested: Surfaces known but not tested for this class
        - total_tests: Total test attempts for this class
        """
        with self._lock:
            tested_for_class = []
            not_tested_for_class = []

            for item in self._tested.values():
                if vuln_class in item.vuln_classes_tested:
                    tested_for_class.append(item.surface)
                else:
                    not_tested_for_class.append(item.surface)

            # Discovered but never tested at all
            for item in self._discovered.values():
                not_tested_for_class.append(item.surface)

            return {
                "vuln_class": vuln_class,
                "surfaces_tested": tested_for_class,
                "surfaces_not_tested": not_tested_for_class,
                "tested_count": len(tested_for_class),
                "not_tested_count": len(not_tested_for_class),
            }

    def get_coverage_matrix(self) -> dict[str, Any]:
        """
        Return a coverage matrix showing which surfaces have been tested for which vuln classes.

        This is pure DATA for the LLM to analyze and decide priorities.
        """
        with self._lock:
            matrix: dict[str, dict[str, bool]] = {}
            all_vuln_classes: set[str] = set()

            for item in self._tested.values():
                matrix[item.surface] = {}
                for vc in item.vuln_classes_tested:
                    matrix[item.surface][vc] = True
                    all_vuln_classes.add(vc)

            # Add discovered but untested surfaces
            for item in self._discovered.values():
                matrix[item.surface] = {}

            return {
                "surfaces": list(matrix.keys()),
                "vuln_classes_observed": list(all_vuln_classes),
                "matrix": matrix,
                "total_surfaces": len(matrix),
                "total_tested": len(self._tested),
                "total_untested": len(self._discovered),
            }

    def get_coverage_gaps(self, required_vuln_classes: list[str] | None = None) -> dict[str, Any]:
        """
        Identify coverage gaps - surfaces that haven't been tested for certain vuln classes.

        Args:
            required_vuln_classes: Vuln classes to check coverage for (default: COMMON_VULN_CLASSES)

        Returns FACTS about gaps (LLM decides what to do with this info).
        """
        vuln_classes = required_vuln_classes or list(self.COMMON_VULN_CLASSES)

        with self._lock:
            gaps: dict[str, list[str]] = {}  # surface -> missing vuln classes

            for item in self._tested.values():
                missing = [vc for vc in vuln_classes if vc not in item.vuln_classes_tested]
                if missing:
                    gaps[item.surface] = missing

            # All vuln classes are gaps for untested surfaces
            for item in self._discovered.values():
                gaps[item.surface] = vuln_classes.copy()

            return {
                "gaps": gaps,
                "total_gaps": sum(len(v) for v in gaps.values()),
                "surfaces_with_gaps": len(gaps),
                "checked_vuln_classes": vuln_classes,
            }

    def has_been_tested(
        self,
        surface: str,
        surface_type: str,
        vuln_class: str | None = None,
    ) -> bool:
        """Check if a surface has been tested (optionally for a specific vuln class)."""
        with self._lock:
            surface_key = f"{surface_type}:{surface}"
            surface_id = f"S-{hashlib.md5(surface_key.encode()).hexdigest()[:8].upper()}"

            if surface_id not in self._tested:
                return False

            if vuln_class is None:
                return True

            return vuln_class in self._tested[surface_id].vuln_classes_tested

    # ── Prompt Summary (for LLM context injection) ────────────────────────────

    def to_prompt_summary(self, max_items: int = 15) -> str:
        """
        Return a compact text summary safe to inject into LLM context.

        Reports FACTS about coverage state - no recommendations or commands.
        """
        with self._lock:
            tested_list = list(self._tested.values())
            discovered_list = list(self._discovered.values())

        if not tested_list and not discovered_list:
            return ""

        lines = ["[COVERAGE TRACKER — attack surface coverage state]"]

        # Summary stats
        total_surfaces = len(tested_list) + len(discovered_list)
        lines.append(f"  Surfaces: {total_surfaces} total, {len(tested_list)} tested, {len(discovered_list)} untested")

        # Count unique vuln classes tested
        all_vuln_classes: set[str] = set()
        for item in tested_list:
            all_vuln_classes.update(item.vuln_classes_tested)
        lines.append(f"  Vuln classes tested: {len(all_vuln_classes)} ({', '.join(sorted(all_vuln_classes)[:5])}{'...' if len(all_vuln_classes) > 5 else ''})")

        # Recently tested (most recent first)
        if tested_list:
            lines.append("  Recently tested:")
            sorted_tested = sorted(tested_list, key=lambda x: x.last_tested, reverse=True)[:max_items // 2]
            for item in sorted_tested:
                vc_str = ",".join(item.vuln_classes_tested[:3])
                if len(item.vuln_classes_tested) > 3:
                    vc_str += f"+{len(item.vuln_classes_tested) - 3}"
                lines.append(f"    {item.surface[:40]:40s} | {item.surface_type:12s} | tests={item.test_count} | {vc_str}")

        # Untested surfaces
        if discovered_list:
            lines.append("  Untested surfaces:")
            sorted_discovered = sorted(discovered_list, key=lambda x: x.discovered_at, reverse=True)[:max_items // 2]
            for item in sorted_discovered:
                hints_str = f" hints=[{','.join(item.priority_hints[:2])}]" if item.priority_hints else ""
                lines.append(f"    {item.surface[:40]:40s} | {item.surface_type:12s} | src={item.source}{hints_str}")

        lines.append("[END COVERAGE]")
        return "\n".join(lines)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize for checkpointing/persistence."""
        with self._lock:
            return {
                "counter": self._counter,
                "tested": {k: v.to_dict() for k, v in self._tested.items()},
                "discovered": {k: v.to_dict() for k, v in self._discovered.items()},
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CoverageTracker":
        """Restore from serialized state."""
        tracker = cls()
        tracker._counter = d.get("counter", 0)
        for k, v in d.get("tested", {}).items():
            tracker._tested[k] = TestedItem.from_dict(v)
        for k, v in d.get("discovered", {}).items():
            tracker._discovered[k] = DiscoveredSurface.from_dict(v)
        return tracker

    def __len__(self) -> int:
        with self._lock:
            return len(self._tested) + len(self._discovered)
