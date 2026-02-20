# Phantom Models Package
# Pydantic models for structured security findings

from .vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityEvidence,
)
from .host import (
    Host,
    Port,
    Service,
    Technology,
)
from .scan import (
    ScanResult,
    ScanPhase,
    ScanStatus,
    FindingSummary,
)
from .verification import (
    VerificationResult,
    VerificationStatus,
    ExploitAttempt,
)

__all__ = [
    # Vulnerability
    "Vulnerability",
    "VulnerabilitySeverity", 
    "VulnerabilityStatus",
    "VulnerabilityEvidence",
    # Host
    "Host",
    "Port",
    "Service",
    "Technology",
    # Scan
    "ScanResult",
    "ScanPhase",
    "ScanStatus",
    "FindingSummary",
    # Verification
    "VerificationResult",
    "VerificationStatus",
    "ExploitAttempt",
]
