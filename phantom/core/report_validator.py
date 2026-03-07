"""
Report Validator (FIX-P1-001, FIX-P1-002)

Validates LLM-generated reports against the evidence registry.
Prevents hallucinated findings, fabricated CVEs, and wrong severities
from appearing in final reports.

Validation Checks:
1. Evidence existence — every finding must have supporting evidence
2. CVE format validation — CVE-YYYY-NNNNN format with valid year
3. Severity consistency — HIGH/CRITICAL requires exploitation evidence
4. Confidence threshold — findings below 0.3 are flagged as low-confidence
5. Duplication check — detect duplicate findings for same target/vuln

Usage:
    validator = ReportValidator(evidence_registry, confidence_engine)
    issues = validator.validate(report_dict)
    if issues.has_errors:
        logger.warning("Report has %d validation errors", issues.error_count)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from phantom.core.evidence_registry import EvidenceRegistry
    from phantom.core.confidence_engine import ConfidenceEngine

_logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """A single validation issue found in a report."""
    
    finding_id: str
    issue_type: str  # See ISSUE_TYPES below
    message: str
    severity: str = "error"  # "error" = must fix, "warning" = advisory
    
    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "issue_type": self.issue_type,
            "message": self.message,
            "severity": self.severity,
        }


# Issue type constants
ISSUE_TYPES = {
    "no_evidence": "Finding has no supporting evidence in the registry",
    "weak_evidence": "Finding has only weak evidence (banner/scanner)",
    "invalid_cve": "CVE identifier does not match standard format",
    "future_cve": "CVE year is in the future",
    "low_confidence": "Finding confidence is below threshold",
    "severity_mismatch": "Claimed severity not supported by evidence",
    "missing_target": "Finding has no target specified",
    "duplicate_finding": "Duplicate of another finding",
    "unverified_critical": "Critical finding is not verified",
    "hallucination_suspect": "Finding characteristics suggest hallucination",
}


@dataclass
class ValidationResult:
    """Aggregated validation result for a report."""
    
    issues: list[ValidationIssue] = field(default_factory=list)
    validated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    
    @property
    def has_errors(self) -> bool:
        """True if any error-severity issues exist."""
        return any(i.severity == "error" for i in self.issues)
    
    @property
    def has_warnings(self) -> bool:
        """True if any warning-severity issues exist."""
        return any(i.severity == "warning" for i in self.issues)
    
    @property
    def error_count(self) -> int:
        """Count of error-severity issues."""
        return sum(1 for i in self.issues if i.severity == "error")
    
    @property
    def warning_count(self) -> int:
        """Count of warning-severity issues."""
        return sum(1 for i in self.issues if i.severity == "warning")
    
    @property
    def is_valid(self) -> bool:
        """True if no errors (warnings are acceptable)."""
        return not self.has_errors
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "validated_at": self.validated_at,
            "is_valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [i.to_dict() for i in self.issues],
        }
    
    def get_issues_for_finding(self, finding_id: str) -> list[ValidationIssue]:
        """Get all issues for a specific finding."""
        return [i for i in self.issues if i.finding_id == finding_id]
    
    def summary(self) -> str:
        """Human-readable summary of validation result."""
        if self.is_valid and not self.has_warnings:
            return "Report validation passed with no issues."
        
        parts = []
        if self.has_errors:
            parts.append(f"{self.error_count} error(s)")
        if self.has_warnings:
            parts.append(f"{self.warning_count} warning(s)")
        
        return f"Report validation: {', '.join(parts)}"


class ReportValidator:
    """
    Validates vulnerability reports against evidence and confidence data.
    
    Prevents common LLM hallucinations:
    - Findings without evidence trail
    - Fabricated CVE identifiers
    - Wrong severity ratings
    - Duplicate findings
    """
    
    # CVE format: CVE-YYYY-NNNNN (4+ digits after year)
    CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
    
    # Minimum CVE year (CVE program started in 1999)
    MIN_CVE_YEAR = 1999
    
    # Default confidence threshold for flagging low-confidence findings
    DEFAULT_CONFIDENCE_THRESHOLD = 0.3
    
    # Evidence types considered "strong" (vs. weak scanner detection)
    STRONG_EVIDENCE_TYPES = frozenset({
        "exploitation_confirmed",
        "exploitation_full",
        "manual_verification",
        "poc_replay",
    })
    
    def __init__(
        self,
        evidence_registry: "EvidenceRegistry | None" = None,
        confidence_engine: "ConfidenceEngine | None" = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        """
        Initialize the validator.
        
        Args:
            evidence_registry: Evidence registry to check against
            confidence_engine: Confidence engine for score lookup
            confidence_threshold: Minimum confidence for findings
        """
        self._evidence = evidence_registry
        self._confidence = confidence_engine
        self._threshold = confidence_threshold
        self._current_year = datetime.now(UTC).year
    
    def validate(self, report: dict[str, Any]) -> ValidationResult:
        """
        Validate a report dictionary.
        
        Args:
            report: Report dictionary with 'vulnerabilities' list
            
        Returns:
            ValidationResult with all issues found
        """
        result = ValidationResult()
        
        vulnerabilities = report.get("vulnerabilities", [])
        if not vulnerabilities:
            # Empty report is valid (no findings to validate)
            return result
        
        seen_targets: dict[str, set[str]] = {}  # target -> set of vuln types
        
        for finding in vulnerabilities:
            finding_id = finding.get("id", "unknown")
            
            # Run all validation checks
            issues = []
            issues.extend(self._check_evidence(finding_id, finding))
            issues.extend(self._check_cve(finding_id, finding))
            issues.extend(self._check_confidence(finding_id, finding))
            issues.extend(self._check_severity(finding_id, finding))
            issues.extend(self._check_target(finding_id, finding))
            issues.extend(self._check_duplicate(finding_id, finding, seen_targets))
            issues.extend(self._check_hallucination_signals(finding_id, finding))
            
            result.issues.extend(issues)
            
            # Track seen targets for duplicate detection
            target = finding.get("target", finding.get("url", ""))
            vuln_type = finding.get("type", finding.get("vulnerability_type", ""))
            if target:
                if target not in seen_targets:
                    seen_targets[target] = set()
                seen_targets[target].add(vuln_type)
        
        if result.issues:
            _logger.info(
                "Report validation completed: %d errors, %d warnings",
                result.error_count, result.warning_count,
            )
        
        return result
    
    def _check_evidence(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """Check that finding has supporting evidence."""
        issues: list[ValidationIssue] = []
        
        if not self._evidence:
            return issues
        
        evidence_entries = self._evidence.get_for_finding(finding_id)
        
        if not evidence_entries:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="no_evidence",
                message=f"Finding '{finding_id}' has no supporting evidence in the registry",
                severity="error",
            ))
            return issues
        
        # Check evidence strength for HIGH/CRITICAL findings
        severity = finding.get("severity", "").lower()
        if severity in ("high", "critical"):
            has_strong = any(
                e.get("evidence_type") in self.STRONG_EVIDENCE_TYPES
                for e in evidence_entries
            )
            if not has_strong:
                issues.append(ValidationIssue(
                    finding_id=finding_id,
                    issue_type="weak_evidence",
                    message=f"{severity.upper()} finding has only weak evidence (scanner detection)",
                    severity="warning",
                ))
        
        return issues
    
    def _check_cve(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """Validate CVE identifier format and year."""
        issues: list[ValidationIssue] = []
        
        cve = finding.get("cve") or finding.get("cve_id")
        if not cve:
            return issues
        
        match = self.CVE_PATTERN.match(str(cve))
        if not match:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="invalid_cve",
                message=f"CVE '{cve}' does not match format CVE-YYYY-NNNN+",
                severity="error",
            ))
            return issues
        
        year = int(match.group(1))
        if year < self.MIN_CVE_YEAR:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="invalid_cve",
                message=f"CVE year {year} is before CVE program start (1999)",
                severity="error",
            ))
        elif year > self._current_year:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="future_cve",
                message=f"CVE year {year} is in the future",
                severity="error",
            ))
        
        return issues
    
    def _check_confidence(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """Check finding confidence against threshold."""
        issues: list[ValidationIssue] = []
        
        # Try to get confidence from engine or from finding itself
        confidence = None
        if self._confidence:
            confidence = self._confidence.get_confidence(finding_id)
        if confidence is None:
            confidence = finding.get("confidence", 1.0)
        
        if confidence < self._threshold:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="low_confidence",
                message=f"Finding confidence {confidence:.2f} is below threshold {self._threshold:.2f}",
                severity="warning",
            ))
        
        return issues
    
    def _check_severity(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """Check severity is supported by evidence type."""
        issues: list[ValidationIssue] = []
        
        if not self._evidence:
            return issues
        
        severity = finding.get("severity", "").lower()
        if severity not in ("high", "critical"):
            return issues
        
        evidence_entries = self._evidence.get_for_finding(finding_id)
        if not evidence_entries:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="severity_mismatch",
                message=f"{severity.upper()} severity claimed with zero evidence",
                severity="error",
            ))
        
        return issues
    
    def _check_target(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """Check that finding has a target specified."""
        issues: list[ValidationIssue] = []
        
        target = finding.get("target") or finding.get("url") or finding.get("host")
        if not target:
            issues.append(ValidationIssue(
                finding_id=finding_id,
                issue_type="missing_target",
                message="Finding has no target/url/host specified",
                severity="warning",
            ))
        
        return issues
    
    def _check_duplicate(
        self,
        finding_id: str,
        finding: dict,
        seen_targets: dict[str, set[str]],
    ) -> list[ValidationIssue]:
        """Check for duplicate findings."""
        issues: list[ValidationIssue] = []
        
        target = finding.get("target") or finding.get("url") or ""
        vuln_type = finding.get("type") or finding.get("vulnerability_type") or ""
        
        if target and vuln_type:
            existing_types = seen_targets.get(target, set())
            if vuln_type in existing_types:
                issues.append(ValidationIssue(
                    finding_id=finding_id,
                    issue_type="duplicate_finding",
                    message=f"Duplicate finding: '{vuln_type}' already reported for target '{target}'",
                    severity="warning",
                ))
        
        return issues
    
    def _check_hallucination_signals(
        self, finding_id: str, finding: dict
    ) -> list[ValidationIssue]:
        """
        Check for signals that suggest hallucinated findings.
        
        Heuristics:
        - Very specific CVE without version evidence
        - Exploitation-level severity without tool confirmation
        - Description contains common hallucination phrases
        """
        issues: list[ValidationIssue] = []
        
        # Signal 1: CVE claim without version in evidence
        cve = finding.get("cve")
        if cve and self._evidence:
            evidence_entries = self._evidence.get_for_finding(finding_id)
            has_version_evidence = any(
                "version" in str(e.get("description", "")).lower()
                for e in evidence_entries
            )
            if not has_version_evidence:
                issues.append(ValidationIssue(
                    finding_id=finding_id,
                    issue_type="hallucination_suspect",
                    message="CVE claimed but no version evidence found",
                    severity="warning",
                ))
        
        # Signal 2: "Confirmed" in description without exploitation evidence
        description = finding.get("description", "").lower()
        severity = finding.get("severity", "").lower()
        
        confirmation_phrases = ["confirmed", "verified", "exploited", "demonstrated"]
        has_confirmation_phrase = any(p in description for p in confirmation_phrases)
        
        if has_confirmation_phrase and severity in ("high", "critical"):
            if self._evidence:
                evidence_entries = self._evidence.get_for_finding(finding_id)
                has_exploitation = any(
                    e.get("evidence_type") in ("exploitation_confirmed", "exploitation_full")
                    for e in evidence_entries
                )
                if not has_exploitation:
                    issues.append(ValidationIssue(
                        finding_id=finding_id,
                        issue_type="hallucination_suspect",
                        message="Description claims confirmation but no exploitation evidence exists",
                        severity="warning",
                    ))
        
        return issues
    
    def validate_single_finding(
        self, finding: dict[str, Any]
    ) -> list[ValidationIssue]:
        """
        Validate a single finding (convenience method).
        
        Args:
            finding: Finding dictionary
            
        Returns:
            List of validation issues
        """
        finding_id = finding.get("id", "unknown")
        issues: list[ValidationIssue] = []
        
        issues.extend(self._check_evidence(finding_id, finding))
        issues.extend(self._check_cve(finding_id, finding))
        issues.extend(self._check_confidence(finding_id, finding))
        issues.extend(self._check_severity(finding_id, finding))
        issues.extend(self._check_target(finding_id, finding))
        issues.extend(self._check_hallucination_signals(finding_id, finding))
        
        return issues
