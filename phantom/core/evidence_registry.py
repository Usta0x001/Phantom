"""
Evidence Registry

Centralized registry for all evidence collected during a scan.
Each piece of evidence is linked to a vulnerability, host, or finding
and includes provenance (which tool produced it, when, confidence level).

FIX-P2-008: Thread-safe access with threading.Lock
FIX-P2-004: Evidence freshness timestamps + freshness_weight()
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

_logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    """Categories of evidence."""
    SCAN_OUTPUT = "scan_output"       # Raw scanner output (nuclei, nmap)
    HTTP_RESPONSE = "http_response"   # HTTP request/response pair
    EXPLOITATION = "exploitation"     # Successful exploit output
    SCREENSHOT = "screenshot"         # Visual evidence
    MANUAL_NOTE = "manual_note"       # Agent reasoning or manual observation
    CONFIGURATION = "configuration"   # Misconfig evidence
    CREDENTIAL = "credential"         # Discovered credential (redacted)


class EvidenceQuality(str, Enum):
    """Quality rating for evidence."""
    DEFINITIVE = "definitive"   # Conclusive proof (exploit output, data exfil)
    STRONG = "strong"           # High confidence (verified manually)
    MODERATE = "moderate"       # Needs corroboration (single scanner hit)
    WEAK = "weak"               # Possible false positive (heuristic match)


@dataclass
class Evidence:
    """A single piece of evidence."""
    id: str
    evidence_type: EvidenceType
    quality: EvidenceQuality
    source_tool: str
    description: str
    data: str  # The actual evidence content (truncated if large)
    linked_vuln_ids: list[str] = field(default_factory=list)
    linked_host: str | None = None
    linked_endpoint: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    monotonic_ts: float = field(default_factory=time.monotonic)  # FIX-P2-004
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_conclusive(self) -> bool:
        return self.quality in (EvidenceQuality.DEFINITIVE, EvidenceQuality.STRONG)

    def freshness_weight(self, half_life: float = 600.0) -> float:
        """FIX-P2-004: Exponential decay weight based on evidence age.

        Args:
            half_life: Seconds until evidence weight halves (default 10 min).

        Returns:
            Weight in (0, 1] — 1.0 for brand-new evidence.
        """
        age = max(0.0, time.monotonic() - self.monotonic_ts)
        return math.exp(-0.693 * age / half_life)  # ln(2) ≈ 0.693


class EvidenceRegistry:
    """
    Append-only registry of evidence collected during a scan.

    Features:
    - Deduplication by content hash
    - Linkage to vulnerabilities, hosts, endpoints
    - Quality scoring
    - Export for reporting
    - Hard cap to prevent unbounded memory growth (Risk 6 fix)
    """

    _MAX_EVIDENCE = 5000

    def __init__(self) -> None:
        self._lock = threading.Lock()  # FIX-P2-008: Thread safety
        self._evidence: dict[str, Evidence] = {}
        self._content_hashes: set[str] = set()
        self._vuln_index: dict[str, list[str]] = {}  # vuln_id → evidence_ids
        self._host_index: dict[str, list[str]] = {}   # host → evidence_ids

    def add(
        self,
        evidence_type: EvidenceType,
        quality: EvidenceQuality,
        source_tool: str,
        description: str,
        data: str,
        *,
        vuln_ids: list[str] | None = None,
        host: str | None = None,
        endpoint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Add evidence to the registry.

        Returns the evidence ID, or None if duplicate.
        FIX-P2-008: Thread-safe with lock.
        """
        with self._lock:
            # T1-06: Hash computation inside lock to prevent TOCTOU race
            content_hash = hashlib.sha256(data.encode()[:4096]).hexdigest()[:16]
            if content_hash in self._content_hashes:
                return None
            self._content_hashes.add(content_hash)

            # Risk 6 FIX: Hard cap to prevent unbounded memory growth
            if len(self._evidence) >= self._MAX_EVIDENCE:
                _logger.warning(
                    "Evidence registry reached cap (%d). Evicting oldest weak evidence.",
                    self._MAX_EVIDENCE,
                )
                evict_candidates = sorted(
                    [e for e in self._evidence.values()
                     if e.quality in (EvidenceQuality.WEAK, EvidenceQuality.MODERATE)],
                    key=lambda e: e.timestamp,
                )
                if not evict_candidates:
                    evict_candidates = sorted(
                        self._evidence.values(), key=lambda e: e.timestamp,
                    )
                for victim in evict_candidates[:100]:
                    # HIGH-03 FIX: Clean indices and content hashes on eviction
                    victim_id = victim.id
                    for vid, eids in list(self._vuln_index.items()):
                        if victim_id in eids:
                            eids.remove(victim_id)
                            if not eids:
                                del self._vuln_index[vid]
                    for hkey, eids in list(self._host_index.items()):
                        if victim_id in eids:
                            eids.remove(victim_id)
                            if not eids:
                                del self._host_index[hkey]
                    victim_hash = hashlib.sha256(victim.data.encode()[:4096]).hexdigest()[:16]
                    self._content_hashes.discard(victim_hash)
                    del self._evidence[victim_id]

            # Truncate large evidence data
            if len(data) > 10000:
                data = data[:9500] + "\n...[truncated]...\n" + data[-500:]

            eid = f"ev-{content_hash}"
            evidence = Evidence(
                id=eid,
                evidence_type=evidence_type,
                quality=quality,
                source_tool=source_tool,
                description=description[:500],
                data=data,
                linked_vuln_ids=vuln_ids or [],
                linked_host=host,
                linked_endpoint=endpoint,
                metadata=metadata or {},
            )

            self._evidence[eid] = evidence

            # Update indices
            for vid in evidence.linked_vuln_ids:
                self._vuln_index.setdefault(vid, []).append(eid)
            if host:
                self._host_index.setdefault(host, []).append(eid)

            _logger.debug("Evidence added: %s (%s) from %s", eid, evidence_type.value, source_tool)
            return eid

    def get(self, evidence_id: str) -> Evidence | None:
        with self._lock:
            return self._evidence.get(evidence_id)

    def get_for_vuln(self, vuln_id: str) -> list[Evidence]:
        """Get all evidence linked to a vulnerability."""
        with self._lock:
            eids = self._vuln_index.get(vuln_id, [])
            return [self._evidence[eid] for eid in eids if eid in self._evidence]

    def get_for_host(self, host: str) -> list[Evidence]:
        """Get all evidence for a host."""
        with self._lock:
            eids = self._host_index.get(host, [])
            return [self._evidence[eid] for eid in eids if eid in self._evidence]

    def get_conclusive_evidence(self) -> list[Evidence]:
        """Get all definitive/strong evidence."""
        with self._lock:
            return [e for e in self._evidence.values() if e.is_conclusive]

    def has_evidence_for_vuln(self, vuln_id: str) -> bool:
        with self._lock:
            return vuln_id in self._vuln_index and len(self._vuln_index[vuln_id]) > 0

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._evidence)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            by_type = {}
            by_quality = {}
            for e in self._evidence.values():
                by_type[e.evidence_type.value] = by_type.get(e.evidence_type.value, 0) + 1
                by_quality[e.quality.value] = by_quality.get(e.quality.value, 0) + 1
            return {
                "total_evidence": len(self._evidence),
                "by_type": by_type,
                "by_quality": by_quality,
                "linked_vulns": len(self._vuln_index),
                "linked_hosts": len(self._host_index),
            }

    def export_for_report(self) -> list[dict[str, Any]]:
        """Export all evidence for the scan report."""
        with self._lock:
            return [
                {
                    "id": e.id,
                    "type": e.evidence_type.value,
                    "quality": e.quality.value,
                    "source_tool": e.source_tool,
                    "description": e.description,
                    "linked_vulns": e.linked_vuln_ids,
                    "host": e.linked_host,
                    "endpoint": e.linked_endpoint,
                    "timestamp": e.timestamp,
                    # Data truncated for report
                    "data_preview": e.data[:500] if e.data else "",
                }
                for e in sorted(
                    self._evidence.values(),
                    key=lambda x: x.timestamp,
                )
            ]

    def to_dict(self) -> dict[str, Any]:
        """T2-08: Serialize registry state for checkpoint persistence."""
        with self._lock:
            return {
                "evidence": [
                    {
                        "id": e.id,
                        "type": e.evidence_type.value,
                        "quality": e.quality.value,
                        "source_tool": e.source_tool,
                        "description": e.description,
                        "data": e.data[:2000],
                        "linked_vuln_ids": e.linked_vuln_ids,
                        "linked_host": e.linked_host,
                        "linked_endpoint": e.linked_endpoint,
                        "timestamp": e.timestamp,
                    }
                    for e in self._evidence.values()
                ],
                "content_hashes": list(self._content_hashes),
            }
