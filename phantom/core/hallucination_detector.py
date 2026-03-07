"""
Hallucination Detector (FIX-P0-004, Intelligence Improvement)

Detects likely hallucinated findings by comparing LLM claims against evidence.
Uses multi-layer detection:

Layer 1: Pattern-based rules (fast, regex)
Layer 2: Evidence cross-check (medium, evidence registry)
Layer 3: Semantic detection (optional, embedding-based)

Detection Patterns:
- Severity escalation without evidence
- CVE claims without version match
- Exploitation claims without tool confirmation
- Findings with no evidence trail
- Confidence/evidence mismatch

Usage:
    detector = HallucinationDetector(evidence_registry, confidence_engine)
    warnings = detector.check(finding, evidence_list)
    if warnings:
        logger.warning("Potential hallucination detected: %s", warnings[0].message)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from phantom.core.evidence_registry import EvidenceRegistry
    from phantom.core.confidence_engine import ConfidenceEngine

_logger = logging.getLogger(__name__)


@dataclass
class HallucinationWarning:
    """A detected potential hallucination signal."""
    
    finding_id: str
    pattern: str          # Pattern name that triggered
    message: str          # Human-readable description
    severity: str = "medium"  # "low", "medium", "high"
    confidence: float = 0.0   # Detection confidence (0-1)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "pattern": self.pattern,
            "message": self.message,
            "severity": self.severity,
            "confidence": self.confidence,
        }


@dataclass
class HallucinationPattern:
    """A pattern for detecting hallucination signals."""
    
    name: str
    description: str
    check: Callable[["Finding", list["Evidence"]], bool]
    severity: str = "medium"
    message_template: str = ""
    
    def match(self, finding: dict, evidence: list[dict]) -> HallucinationWarning | None:
        """Check if this pattern matches the finding/evidence combination."""
        if self.check(finding, evidence):
            return HallucinationWarning(
                finding_id=finding.get("id", "unknown"),
                pattern=self.name,
                message=self.message_template.format(
                    severity=finding.get("severity", "unknown"),
                    target=finding.get("target", "unknown"),
                    cve=finding.get("cve", "none"),
                ),
                severity=self.severity,
            )
        return None


class HallucinationDetector:
    """
    Detects potential hallucinations in LLM-generated findings.
    
    Multi-layer detection:
    1. Pattern rules — fast checks for common hallucination signals
    2. Evidence correlation — cross-reference with evidence registry
    3. Semantic analysis — optional embedding-based detection
    """
    
    def __init__(
        self,
        evidence_registry: "EvidenceRegistry | None" = None,
        confidence_engine: "ConfidenceEngine | None" = None,
        enable_semantic: bool = False,
    ) -> None:
        """
        Initialize the detector.
        
        Args:
            evidence_registry: Evidence registry for cross-checking
            confidence_engine: Confidence engine for score lookup
            enable_semantic: Enable semantic detection (requires sentence-transformers)
        """
        self._evidence = evidence_registry
        self._confidence = confidence_engine
        self._enable_semantic = enable_semantic
        self._semantic_model = None
        self._patterns = self._build_patterns()
        
        if enable_semantic:
            self._init_semantic_model()
    
    def _build_patterns(self) -> list[HallucinationPattern]:
        """Build the list of detection patterns."""
        return [
            # Pattern 1: Severity escalation without evidence
            HallucinationPattern(
                name="severity_escalation",
                description="HIGH/CRITICAL severity with only banner evidence",
                check=lambda f, e: (
                    f.get("severity", "").lower() in ("critical", "high") and
                    all(ev.get("evidence_type") == "banner" for ev in e) and
                    len(e) > 0
                ),
                severity="high",
                message_template="{severity} severity claimed with only banner-grab evidence",
            ),
            
            # Pattern 2: CVE without version evidence
            HallucinationPattern(
                name="cve_without_version",
                description="CVE referenced without version evidence",
                check=lambda f, e: (
                    f.get("cve") is not None and
                    not any("version" in str(ev.get("description", "")).lower() for ev in e)
                ),
                severity="medium",
                message_template="CVE '{cve}' referenced but no version evidence found",
            ),
            
            # Pattern 3: Exploitation claim without proof
            HallucinationPattern(
                name="exploit_without_proof",
                description="Exploitation claimed without exploit output",
                check=lambda f, e: (
                    f.get("status", "").lower() in ("exploited", "confirmed") and
                    not any(
                        ev.get("evidence_type") in ("exploitation_confirmed", "exploitation_full", "poc_replay")
                        for ev in e
                    )
                ),
                severity="high",
                message_template="Exploitation claimed but no tool confirmation evidence exists",
            ),
            
            # Pattern 4: Finding with zero evidence
            HallucinationPattern(
                name="no_evidence",
                description="Finding has no associated evidence",
                check=lambda f, e: len(e) == 0,
                severity="high",
                message_template="Finding has no supporting evidence at all",
            ),
            
            # Pattern 5: Scanner detection as confirmed
            HallucinationPattern(
                name="scanner_as_confirmed",
                description="Scanner detection marked as confirmed",
                check=lambda f, e: (
                    f.get("verification_status") == "verified" and
                    all(ev.get("evidence_type") == "scanner_detection" for ev in e) and
                    len(e) > 0
                ),
                severity="medium",
                message_template="Finding marked verified but only has scanner detection evidence",
            ),
            
            # Pattern 6: Generic description with specific claims
            HallucinationPattern(
                name="vague_specific_mismatch",
                description="Vague evidence with very specific vulnerability claims",
                check=lambda f, e: (
                    f.get("cve") is not None and
                    any("potentially" in str(ev.get("description", "")).lower() or
                        "possible" in str(ev.get("description", "")).lower()
                        for ev in e) and
                    len(e) <= 2
                ),
                severity="medium",
                message_template="Specific CVE '{cve}' claimed with vague/uncertain evidence",
            ),
            
            # Pattern 7: Multiple critical vulns on same endpoint
            HallucinationPattern(
                name="stacked_criticals",
                description="Multiple critical/high findings suspiciously stacked",
                check=lambda f, e: False,  # Cross-finding analysis handled in check() caller
                severity="medium",
                message_template="Multiple critical findings reported for same target without corroboration",
            ),
            
            # Pattern 8: Temporal impossibility (H-HD-001)
            # Finding references a tool execution that hasn't happened yet
            # or claims an exploit before recon
            HallucinationPattern(
                name="temporal_impossibility",
                description="Finding implies events that cannot have occurred yet",
                check=lambda f, e: (
                    f.get("status", "").lower() in ("exploited", "confirmed") and
                    any(ev.get("evidence_type") in ("inference", "banner") for ev in e) and
                    not any(ev.get("evidence_type") in (
                        "exploitation_confirmed", "exploitation_full",
                        "poc_replay", "manual_verification"
                    ) for ev in e)
                ),
                severity="high",
                message_template="Finding claims exploitation but evidence is pre-exploitation only (temporal impossibility)",
            ),
            
            # Pattern 9: Unreachable host (H-HD-002)
            # Finding claims vulnerability on a host that wasn't actually reached
            HallucinationPattern(
                name="unreachable_host",
                description="Finding on host with no connectivity evidence",
                check=lambda f, e: (
                    f.get("host") is not None and
                    not any(
                        ev.get("evidence_type") in (
                            "scanner_detection", "manual_probe",
                            "manual_verification", "exploitation_confirmed",
                        ) and f.get("host", "") in str(ev.get("description", ""))
                        for ev in e
                    ) and
                    len(e) == 0
                ),
                severity="high",
                message_template="Finding on target '{target}' but no host-level connectivity evidence exists",
            ),
        ]
    
    def _init_semantic_model(self) -> None:
        """Initialize semantic detection model (optional)."""
        try:
            from sentence_transformers import SentenceTransformer
            self._semantic_model = SentenceTransformer("all-MiniLM-L6-v2")
            _logger.info("Semantic hallucination detection enabled")
        except ImportError:
            _logger.warning(
                "sentence-transformers not available — semantic detection disabled. "
                "Install with: pip install sentence-transformers"
            )
            self._enable_semantic = False
    
    def check(
        self,
        finding: dict[str, Any],
        evidence: list[dict[str, Any]] | None = None,
    ) -> list[HallucinationWarning]:
        """
        Check a finding for hallucination signals.
        
        Args:
            finding: Finding dictionary to check
            evidence: Evidence list (or will be fetched from registry)
            
        Returns:
            List of hallucination warnings (empty if none detected)
        """
        warnings: list[HallucinationWarning] = []
        finding_id = finding.get("id", "unknown")
        
        # Get evidence from registry if not provided
        if evidence is None and self._evidence:
            evidence = self._evidence.get_for_finding(finding_id)
        evidence = evidence or []
        
        # Layer 1: Pattern-based detection
        for pattern in self._patterns:
            warning = pattern.match(finding, evidence)
            if warning:
                warnings.append(warning)
        
        # Layer 2: Confidence/evidence mismatch
        # AGT-002 FIX: This check is now mandatory — runs even without
        # confidence engine by using evidence count as proxy.
        mismatch_warning = self._check_confidence_mismatch(finding, evidence)
        if mismatch_warning:
            warnings.append(mismatch_warning)
        
        # Layer 3: Semantic detection (optional)
        if self._enable_semantic and self._semantic_model:
            semantic_warnings = self._check_semantic(finding, evidence)
            warnings.extend(semantic_warnings)
        
        if warnings:
            _logger.debug(
                "Hallucination check for %s: %d warnings detected",
                finding_id, len(warnings),
            )
        
        return warnings
    
    def _check_confidence_mismatch(
        self,
        finding: dict,
        evidence: list[dict],
    ) -> HallucinationWarning | None:
        """Check for mismatch between claimed confidence and evidence support."""
        finding_id = finding.get("id", "unknown")
        
        # AGT-002 FIX: Use confidence engine if available, otherwise
        # estimate confidence from evidence count as a proxy.
        actual_confidence: float | None = None
        if self._confidence:
            actual_confidence = self._confidence.get_confidence(finding_id)
        
        if actual_confidence is None:
            # Proxy: more evidence = higher confidence
            ev_count = len(evidence)
            if ev_count == 0:
                actual_confidence = 0.0
            elif ev_count == 1:
                actual_confidence = 0.3
            elif ev_count <= 3:
                actual_confidence = 0.5
            else:
                actual_confidence = 0.7
        
        # Claimed confidence
        claimed_confidence = finding.get("confidence", 1.0)
        if claimed_confidence is None:
            claimed_confidence = 0.5  # LOW-32 FIX: Conservative default
        
        # AGT-002 FIX: Lowered threshold from 0.3 to 0.2 for tighter detection
        if claimed_confidence - actual_confidence > 0.2:
            return HallucinationWarning(
                finding_id=finding_id,
                pattern="confidence_overstatement",
                message=f"Claimed confidence ({claimed_confidence:.2f}) exceeds evidence-based confidence ({actual_confidence:.2f})",
                severity="medium",
                confidence=actual_confidence,
            )
        
        return None
    
    def _check_semantic(
        self,
        finding: dict,
        evidence: list[dict],
    ) -> list[HallucinationWarning]:
        """
        Semantic detection using embeddings.
        
        Compares finding description against evidence descriptions.
        High divergence suggests the finding may not be grounded in evidence.
        """
        warnings: list[HallucinationWarning] = []
        
        if not self._semantic_model:
            return warnings
        
        finding_id = finding.get("id", "unknown")
        finding_desc = finding.get("description", "")
        
        if not finding_desc or not evidence:
            return warnings
        
        try:
            import numpy as np
            from sklearn.metrics.pairwise import cosine_similarity
            
            # Embed finding description
            finding_emb = self._semantic_model.encode([finding_desc])
            
            # Embed evidence descriptions
            evidence_descs = [e.get("description", "") for e in evidence if e.get("description")]
            if not evidence_descs:
                return warnings
            
            evidence_emb = self._semantic_model.encode(evidence_descs)
            
            # Calculate similarity
            similarities = cosine_similarity(finding_emb, evidence_emb)[0]
            max_similarity = float(np.max(similarities))
            
            # Low similarity suggests finding is not grounded in evidence
            if max_similarity < 0.4:
                warnings.append(HallucinationWarning(
                    finding_id=finding_id,
                    pattern="semantic_divergence",
                    message=f"Finding description has low semantic similarity ({max_similarity:.2f}) to evidence",
                    severity="medium",
                    confidence=1.0 - max_similarity,
                ))
        except ImportError:
            _logger.debug("scikit-learn not available for semantic similarity")
        except Exception as e:
            _logger.debug("Semantic check failed: %s", e)
        
        return warnings
    
    def check_injection_in_text(self, text: str) -> list[HallucinationWarning]:
        """
        Check text for prompt injection patterns that might cause hallucinations.
        
        This is a secondary defense — primary defense is in output_sanitizer.
        Detects sophisticated injection attempts that might have bypassed sanitization.
        """
        warnings: list[HallucinationWarning] = []
        
        # Patterns that might cause LLM to hallucinate
        injection_patterns = [
            (r"(?i)assume\s+that\s+(the\s+)?(vuln|vulnerability)", "assumption_injection"),
            (r"(?i)pretend\s+this\s+is\s+(vulnerable|exploitable)", "pretend_injection"),
            (r"(?i)for\s+the\s+purpose\s+of\s+this\s+(scan|report)", "context_manipulation"),
            (r"(?i)imagine\s+(a|the)\s+scenario\s+where", "scenario_injection"),
            (r"(?i)let's\s+say\s+(this|the\s+target)\s+has", "hypothetical_injection"),
        ]
        
        for pattern, name in injection_patterns:
            if re.search(pattern, text):
                warnings.append(HallucinationWarning(
                    finding_id="text_check",
                    pattern=name,
                    message=f"Text contains pattern that may induce hallucination: {name}",
                    severity="medium",
                ))
        
        return warnings
    
    def get_statistics(self) -> dict[str, Any]:
        """Get detection statistics."""
        return {
            "patterns_count": len(self._patterns),
            "semantic_enabled": self._enable_semantic,
            "evidence_registry_available": self._evidence is not None,
            "confidence_engine_available": self._confidence is not None,
        }
