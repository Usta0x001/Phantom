"""
Confidence Engine

Tracks confidence scores for vulnerabilities based on evidence quality.
Provides the "confidence propagation" missing from the attack graph.

v1.0 UPGRADE: Bayesian confidence model with:
- Time-based decay (half-life configurable)
- Negative evidence support (contradictions reduce confidence)
- Edge-based propagation through attack graph
- Tool reliability weights

Evidence types and their confidence contributions:
- Scanner detection (nuclei, nmap): 0.3 (low — high false-positive rate)
- Manual verification (send_request with proof): 0.6 (medium)
- Exploitation (sqlmap confirmed, shell obtained): 0.9 (high)
- Multi-tool corroboration: +0.1 per corroborating tool (max 1.0)
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

_logger = logging.getLogger(__name__)


# Base confidence scores by evidence type
_EVIDENCE_WEIGHTS: dict[str, float] = {
    "scanner_detection": 0.3,
    "manual_probe": 0.5,
    "manual_verification": 0.6,
    "exploitation_confirmed": 0.9,
    "exploitation_full": 1.0,
}

# Tool-to-evidence-type mapping
_TOOL_EVIDENCE_TYPE: dict[str, str] = {
    "nuclei_scan": "scanner_detection",
    "nuclei_scan_cves": "scanner_detection",
    "nuclei_scan_misconfigs": "scanner_detection",
    "nmap_vuln_scan": "scanner_detection",
    "sqlmap_test": "manual_probe",
    "sqlmap_forms": "manual_probe",
    "send_request": "manual_verification",
    "repeat_request": "manual_verification",
    "sqlmap_dump_database": "exploitation_confirmed",
    "terminal_execute": "manual_verification",
}

# FIX-INTEL-003 / Intelligence Plan 5.2: Tool reliability weights for Bayesian model
TOOL_RELIABILITY: dict[str, float] = {
    "exploit_output": 0.95,
    "poc_replay": 0.90,
    "exploitation_confirmed": 0.90,
    "exploitation_full": 0.95,
    "confirmed_response": 0.85,
    "manual_verification": 0.80,
    "manual_probe": 0.65,
    "scanner_detection": 0.50,
    "banner": 0.40,
    "inference": 0.25,
    "contradiction": 0.80,
}


@dataclass
class EvidenceEntry:
    """A single piece of evidence supporting a vulnerability."""
    tool_name: str
    evidence_type: str
    confidence: float
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    verified: bool = False
    # FIX-INTEL-003: Support for negative (contradicting) evidence
    polarity: float = 1.0  # +1.0 = supporting, -1.0 = contradicting
    monotonic_ts: float = field(default_factory=time.monotonic)


@dataclass
class VulnerabilityConfidence:
    """Aggregated confidence for a vulnerability."""
    vuln_id: str
    evidence: list[EvidenceEntry] = field(default_factory=list)
    final_confidence: float = 0.0
    last_updated: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def recalculate(self) -> float:
        """Recalculate confidence from all evidence.

        HARDENED v0.9.40: Corroboration bonus capped at +0.2 total and
        requires evidence from at least 2 DIFFERENT evidence type categories
        before any bonus is applied.  A single tool invoking the same
        check 10 times no longer inflates confidence.

        Uses max-evidence approach with multi-tool corroboration bonus:
        - Start with the highest single evidence confidence
        - Add +0.05 per distinct corroborating tool (capped at +0.2)
        - Only if evidence comes from >= 2 distinct evidence type categories
        """
        if not self.evidence:
            self.final_confidence = 0.0
            return 0.0

        # Max evidence confidence
        max_conf = max(e.confidence for e in self.evidence)

        # HARDENED v0.9.40: Require evidence diversity — at least 2 distinct
        # evidence TYPE categories (not just different tool names).
        unique_types = set(e.evidence_type for e in self.evidence)
        unique_tools = set(e.tool_name for e in self.evidence)

        if len(unique_types) >= 2:
            # Reduced bonus: +0.05 per unique tool beyond the first, capped at +0.2
            corroboration_bonus = min(0.2, max(0, (len(unique_tools) - 1)) * 0.05)
        else:
            corroboration_bonus = 0.0

        self.final_confidence = min(1.0, max_conf + corroboration_bonus)
        self.last_updated = datetime.now(UTC).isoformat()
        return self.final_confidence

    def recalculate_with_decay(self, decay_half_life: float = 600.0) -> float:
        """FIX-INTEL-003: Recalculate confidence with time-based decay.

        Uses Bayesian log-odds model with:
        - Time-based exponential decay (configurable half-life)
        - Negative evidence support
        - Tool reliability weighting
        """
        if not self.evidence:
            self.final_confidence = 0.0
            return 0.0

        prior = 0.3  # Prior probability of any vulnerability being real
        now = time.monotonic()
        log_odds = math.log(prior / (1.0 - prior))

        for entry in self.evidence:
            age = max(0.0, now - entry.monotonic_ts)
            decay = math.exp(-0.693 * age / decay_half_life)

            # Tool reliability weight
            tool_weight = TOOL_RELIABILITY.get(entry.evidence_type, 0.5)

            # Likelihood ratio with decay
            lr = entry.confidence * tool_weight * decay
            lr = max(lr, 0.01)  # Floor to avoid log(0)

            if entry.polarity > 0:
                log_odds += math.log(lr / (1.0 - lr + 1e-9))
            else:
                log_odds -= math.log(lr / (1.0 - lr + 1e-9))

        # Clamp log-odds to prevent OverflowError in math.exp()
        log_odds = max(-500.0, min(500.0, log_odds))

        # Convert log-odds to probability
        posterior = 1.0 / (1.0 + math.exp(-log_odds))
        self.final_confidence = min(0.99, max(0.01, posterior))
        self.last_updated = datetime.now(UTC).isoformat()
        return self.final_confidence


class ConfidenceEngine:
    """
    Tracks and propagates confidence scores for findings.

    Integrates with the attack graph to propagate confidence through
    vulnerability chains (e.g., confirmed SQLi → downstream data access
    gets high confidence).

    INV-IL-001 (Monotonicity Invariant): After negative evidence is added,
    the confidence for that vuln is capped at its pre-negative level.
    Subsequent positive evidence cannot push it above that ceiling without
    explicit investigator override.
    """

    def __init__(self) -> None:
        self._vulns: dict[str, VulnerabilityConfidence] = {}
        self._global_metrics: dict[str, int] = {
            "evidence_added": 0,
            "vulns_tracked": 0,
            "high_confidence_count": 0,
        }
        # INV-IL-001: Per-vuln confidence ceilings set by negative evidence
        self._confidence_ceilings: dict[str, float] = {}

    def add_evidence(
        self,
        vuln_id: str,
        tool_name: str,
        description: str,
        *,
        evidence_type: str | None = None,
        verified: bool = False,
    ) -> float:
        """Add evidence for a vulnerability and return updated confidence.

        HARDENED v0.9.40: Deduplicates identical evidence entries — the same
        tool producing the same evidence type for the same vulnerability
        cannot inflate the score beyond 1 entry per (tool, evidence_type) pair.

        Args:
            vuln_id: Vulnerability identifier
            tool_name: Tool that produced the evidence
            description: Brief description of the evidence
            evidence_type: Override evidence type (auto-detected from tool if None)
            verified: Whether this evidence was manually verified

        Returns:
            Updated confidence score (0.0 to 1.0)
        """
        if vuln_id not in self._vulns:
            self._vulns[vuln_id] = VulnerabilityConfidence(vuln_id=vuln_id)
            self._global_metrics["vulns_tracked"] += 1

        # Determine evidence type
        etype = evidence_type or _TOOL_EVIDENCE_TYPE.get(tool_name, "scanner_detection")
        confidence = _EVIDENCE_WEIGHTS.get(etype, 0.3)

        # Verified evidence gets a boost
        if verified:
            confidence = min(1.0, confidence + 0.2)

        # HARDENED v0.9.40: Deduplicate — only 1 entry per (tool, evidence_type) pair
        existing = self._vulns[vuln_id].evidence
        for e in existing:
            if e.tool_name == tool_name and e.evidence_type == etype and e.polarity > 0:
                # Already have this evidence — update confidence if higher, don't add duplicate
                if confidence > e.confidence:
                    e.confidence = confidence
                    e.description = description[:300]
                    e.verified = verified or e.verified
                return self._vulns[vuln_id].recalculate_with_decay()

        entry = EvidenceEntry(
            tool_name=tool_name,
            evidence_type=etype,
            confidence=confidence,
            description=description[:300],
            verified=verified,
        )

        self._vulns[vuln_id].evidence.append(entry)
        new_confidence = self._vulns[vuln_id].recalculate_with_decay()

        # INV-IL-001: Enforce monotonicity ceiling
        ceiling = self._confidence_ceilings.get(vuln_id)
        if ceiling is not None and new_confidence > ceiling:
            new_confidence = ceiling
            self._vulns[vuln_id].final_confidence = ceiling
            _logger.debug(
                "INV-IL-001: Capped %s confidence at %.2f (ceiling from negative evidence)",
                vuln_id, ceiling,
            )

        self._global_metrics["evidence_added"] += 1
        self._global_metrics["high_confidence_count"] = sum(
            1 for v in self._vulns.values() if v.final_confidence >= 0.7
        )

        _logger.debug(
            "Evidence added for %s: tool=%s type=%s conf=%.2f → total=%.2f",
            vuln_id, tool_name, etype, confidence, new_confidence,
        )
        return new_confidence

    def get_confidence(self, vuln_id: str) -> float:
        """Get current confidence for a vulnerability."""
        vc = self._vulns.get(vuln_id)
        return vc.final_confidence if vc else 0.0

    def get_all_confidences(self) -> dict[str, float]:
        """Get confidence scores for all tracked vulnerabilities."""
        return {
            vid: vc.final_confidence
            for vid, vc in self._vulns.items()
        }

    def get_high_confidence_vulns(self, threshold: float = 0.7) -> list[str]:
        """Get vulns with confidence above threshold."""
        return [
            vid for vid, vc in self._vulns.items()
            if vc.final_confidence >= threshold
        ]

    def get_low_confidence_vulns(self, threshold: float = 0.4) -> list[str]:
        """Get vulns that need more evidence."""
        return [
            vid for vid, vc in self._vulns.items()
            if vc.final_confidence < threshold
        ]

    def get_evidence_for_vuln(self, vuln_id: str) -> list[dict[str, Any]]:
        """Get all evidence entries for a vulnerability."""
        vc = self._vulns.get(vuln_id)
        if not vc:
            return []
        return [
            {
                "tool": e.tool_name,
                "type": e.evidence_type,
                "confidence": e.confidence,
                "description": e.description,
                "verified": e.verified,
                "timestamp": e.timestamp,
            }
            for e in vc.evidence
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get confidence engine summary."""
        if not self._vulns:
            return {
                "tracked_vulns": 0,
                "avg_confidence": 0.0,
                "high_confidence": 0,
                "needs_evidence": 0,
            }

        confidences = [vc.final_confidence for vc in self._vulns.values()]
        return {
            "tracked_vulns": len(self._vulns),
            "avg_confidence": sum(confidences) / len(confidences),
            "high_confidence": sum(1 for c in confidences if c >= 0.7),
            "needs_evidence": sum(1 for c in confidences if c < 0.4),
            "total_evidence": self._global_metrics["evidence_added"],
        }

    def propagate_to_graph(self, attack_graph: Any) -> None:
        """Propagate confidence scores to the attack graph nodes.

        Updates vulnerability nodes in the graph with confidence-weighted
        risk scores. Intelligence Plan 5.3: Edge-based propagation along
        CHAINS_WITH edges with attenuation.
        """
        if not attack_graph:
            return

        for vuln_id, vc in self._vulns.items():
            node_id = f"vuln:{vuln_id}"
            node = attack_graph._nodes.get(node_id)
            if node:
                # Modulate risk score by confidence
                node.properties["confidence"] = vc.final_confidence
                node.properties["evidence_count"] = len(vc.evidence)

            # Intelligence Plan 5.3: Propagate along CHAINS_WITH edges (attenuated)
            if hasattr(attack_graph, '_graph') and node_id in attack_graph._graph:
                for _, target, data in attack_graph._graph.edges(node_id, data=True):
                    edge_type = data.get("edge_type", "")
                    if edge_type in ("CHAINS_WITH", "LEADS_TO"):
                        target_node = attack_graph._nodes.get(target)
                        if target_node:
                            chained_conf = vc.final_confidence * 0.6  # 40% attenuation per hop
                            current = target_node.properties.get("chained_confidence", 0)
                            target_node.properties["chained_confidence"] = max(current, chained_conf)

    def add_negative_evidence(
        self,
        vuln_id: str,
        tool_name: str,
        description: str,
    ) -> float:
        """FIX-INTEL-003: Record evidence that CONTRADICTS a finding.

        INV-IL-001: Sets a confidence ceiling — subsequent positive evidence
        cannot raise confidence above the pre-negative level.

        Returns updated confidence score, which should decrease.
        """
        if vuln_id not in self._vulns:
            self._vulns[vuln_id] = VulnerabilityConfidence(vuln_id=vuln_id)

        # INV-IL-001: Record the pre-negative confidence as ceiling
        pre_negative = self._vulns[vuln_id].final_confidence
        if vuln_id not in self._confidence_ceilings:
            self._confidence_ceilings[vuln_id] = pre_negative
        else:
            # Further negative evidence lowers the ceiling
            self._confidence_ceilings[vuln_id] = min(
                self._confidence_ceilings[vuln_id], pre_negative
            )

        entry = EvidenceEntry(
            tool_name=tool_name,
            evidence_type="contradiction",
            confidence=0.7,
            description=description[:300],
            polarity=-1.0,
        )
        self._vulns[vuln_id].evidence.append(entry)
        new_confidence = self._vulns[vuln_id].recalculate_with_decay()

        _logger.info(
            "Negative evidence added for %s: tool=%s → confidence=%.2f (ceiling=%.2f)",
            vuln_id, tool_name, new_confidence, self._confidence_ceilings[vuln_id],
        )
        return new_confidence

    def recalculate_all_with_decay(self, decay_half_life: float = 600.0) -> None:
        """FIX-INTEL-003: Recalculate all confidences with time-based decay."""
        for vc in self._vulns.values():
            vc.recalculate_with_decay(decay_half_life)

    def get_stale_vulns(self, max_age: float = 600.0, threshold: float = 0.5) -> list[str]:
        """Get vulns whose confidence has decayed below threshold."""
        result = []
        now = time.monotonic()
        for vid, vc in self._vulns.items():
            if not vc.evidence:
                continue
            newest = max(e.monotonic_ts for e in vc.evidence)
            age = now - newest
            if age > max_age:
                vc.recalculate_with_decay()
                if vc.final_confidence < threshold:
                    result.append(vid)
        return result

    # ------------------------------------------------------------------
    # T2-07: Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize engine state for checkpoint persistence."""
        return {
            "vulns": {
                vid: {
                    "vuln_id": vc.vuln_id,
                    "final_confidence": vc.final_confidence,
                    "last_updated": vc.last_updated,
                    "evidence": [
                        {
                            "tool_name": e.tool_name,
                            "evidence_type": e.evidence_type,
                            "confidence": e.confidence,
                            "description": e.description,
                            "timestamp": e.timestamp,
                            "verified": e.verified,
                            "polarity": e.polarity,
                        }
                        for e in vc.evidence
                    ],
                }
                for vid, vc in self._vulns.items()
            },
            "global_metrics": dict(self._global_metrics),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConfidenceEngine":
        """Restore engine from checkpoint data."""
        engine = cls()
        engine._global_metrics = data.get("global_metrics", engine._global_metrics)
        for vid, vdata in data.get("vulns", {}).items():
            vc = VulnerabilityConfidence(vuln_id=vid)
            vc.final_confidence = vdata.get("final_confidence", 0.0)
            vc.last_updated = vdata.get("last_updated", "")
            for edata in vdata.get("evidence", []):
                entry = EvidenceEntry(
                    tool_name=edata["tool_name"],
                    evidence_type=edata["evidence_type"],
                    confidence=edata["confidence"],
                    description=edata["description"],
                    timestamp=edata.get("timestamp", ""),
                    verified=edata.get("verified", False),
                    polarity=edata.get("polarity", 1.0),
                )
                vc.evidence.append(entry)
            engine._vulns[vid] = vc
        return engine
