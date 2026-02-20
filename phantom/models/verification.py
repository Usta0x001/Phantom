"""
Verification Models

Pydantic models for exploit verification and false positive filtering.
Implements the Shannon pattern: verify before report.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    """Status of verification attempt."""
    PENDING = "pending"        # Not yet attempted
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"      # Exploitation successful
    FAILED = "failed"          # Could not verify (false positive or mitigation)
    SKIPPED = "skipped"        # Verification not applicable
    ERROR = "error"            # Verification attempt errored


class ExploitAttempt(BaseModel):
    """Record of an exploitation attempt for verification."""
    
    # Identification
    vulnerability_id: str = Field(..., description="ID of vulnerability being verified")
    attempt_number: int = Field(default=1, description="Attempt number (for retries)")
    
    # Method
    method: str = Field(..., description="Verification method: payload_injection, time_based, oob_interaction, etc.")
    tool: str = Field(..., description="Tool used for verification")
    payload: str = Field(..., description="Exploit payload used")
    
    # Request/Response
    request: str | None = Field(default=None, description="HTTP request or command")
    response: str | None = Field(default=None, description="Response received")
    response_time_ms: float | None = Field(default=None, description="Response time in milliseconds")
    
    # Result
    success: bool = Field(default=False, description="Did exploitation succeed?")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in result")
    evidence: str | None = Field(default=None, description="Evidence of successful exploitation")
    error: str | None = Field(default=None, description="Error if attempt failed")
    
    # Timing
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float | None = Field(default=None)
    
    def to_evidence(self) -> dict[str, Any]:
        """Export as evidence record."""
        return {
            "method": self.method,
            "tool": self.tool,
            "payload": self.payload,
            "success": self.success,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "attempted_at": self.attempted_at.isoformat(),
        }


class VerificationResult(BaseModel):
    """
    Complete verification result for a vulnerability.
    
    Follows Shannon pattern: attempt multiple verification methods
    and only report as verified if exploitation succeeds.
    """
    
    # Identification
    vulnerability_id: str = Field(..., description="ID of vulnerability")
    vulnerability_class: str = Field(..., description="sqli, xss, ssrf, etc.")
    
    # Status
    status: VerificationStatus = Field(default=VerificationStatus.PENDING)
    
    # Attempts
    attempts: list[ExploitAttempt] = Field(default_factory=list)
    max_attempts: int = Field(default=3, description="Max verification attempts")
    
    # Final determination
    is_exploitable: bool = Field(default=False)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    working_payload: str | None = Field(default=None, description="Payload that worked")
    proof_of_exploitation: str | None = Field(default=None, description="Evidence string")
    
    # Timing
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    
    # Notes
    notes: list[str] = Field(default_factory=list)
    
    def start_verification(self) -> None:
        """Mark verification as started."""
        self.status = VerificationStatus.IN_PROGRESS
        self.started_at = datetime.now(UTC)
    
    def add_attempt(self, attempt: ExploitAttempt) -> None:
        """Add an exploitation attempt."""
        self.attempts.append(attempt)
        
        # Update status based on result
        if attempt.success:
            self.status = VerificationStatus.VERIFIED
            self.is_exploitable = True
            self.confidence = max(self.confidence, attempt.confidence)
            self.working_payload = attempt.payload
            self.proof_of_exploitation = attempt.evidence
            self.completed_at = datetime.now(UTC)
    
    def mark_failed(self, reason: str) -> None:
        """Mark as failed to verify (false positive)."""
        self.status = VerificationStatus.FAILED
        self.is_exploitable = False
        self.completed_at = datetime.now(UTC)
        self.notes.append(f"Verification failed: {reason}")
    
    def mark_skipped(self, reason: str) -> None:
        """Mark as skipped (e.g., no safe way to verify)."""
        self.status = VerificationStatus.SKIPPED
        self.completed_at = datetime.now(UTC)
        self.notes.append(f"Verification skipped: {reason}")
    
    def should_continue(self) -> bool:
        """Check if more attempts should be made."""
        if self.status == VerificationStatus.VERIFIED:
            return False  # Already verified
        if len(self.attempts) >= self.max_attempts:
            return False  # Max attempts reached
        return True
    
    def summary(self) -> dict[str, Any]:
        """Export summary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "status": self.status.value,
            "is_exploitable": self.is_exploitable,
            "confidence": self.confidence,
            "attempts": len(self.attempts),
            "working_payload": self.working_payload,
            "proof": self.proof_of_exploitation,
        }


# Verification strategies per vulnerability class
VERIFICATION_STRATEGIES: dict[str, list[str]] = {
    "sqli": [
        "time_based",      # Sleep/delay injection
        "error_based",     # Error message extraction
        "union_based",     # UNION SELECT extraction
        "boolean_based",   # True/false condition check
    ],
    "xss": [
        "dom_reflection",  # Check if payload in DOM
        "alert_trigger",   # Headless browser alert detection
        "cookie_exfil",    # Cookie stealing to OOB server
    ],
    "ssrf": [
        "oob_http",        # Out-of-band HTTP request
        "oob_dns",         # Out-of-band DNS resolution
        "internal_port",   # Internal port scan via SSRF
    ],
    "rce": [
        "oob_dns",         # DNS callback
        "oob_http",        # HTTP callback
        "time_based",      # Sleep command
        "file_write",      # Write marker file
    ],
    "lfi": [
        "known_file",      # Read /etc/passwd or win.ini
        "proc_self",       # Read /proc/self/cmdline
        "log_poison",      # Log poisoning + execution
    ],
    "ssti": [
        "math_eval",       # {{7*7}} = 49
        "oob_http",        # HTTP callback from template
    ],
    "xxe": [
        "oob_http",        # External entity callback
        "oob_dns",         # DNS callback
        "file_read",       # Read local file via XXE
    ],
    "idor": [
        "resource_access", # Access another user's resource
        "data_leak",       # Extract unauthorized data
    ],
}


def get_verification_strategy(vuln_class: str) -> list[str]:
    """Get verification methods for a vulnerability class."""
    return VERIFICATION_STRATEGIES.get(vuln_class.lower(), ["manual_review"])
