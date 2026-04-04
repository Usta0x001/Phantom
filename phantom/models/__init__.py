"""
Phantom Data Models

Core domain models for scan tracking, vulnerabilities, hosts, and results.
"""

from .scan import ScanPhase, ScanStatus, ScanResult
from .vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from .host import Host

__all__ = [
    "ScanPhase",
    "ScanStatus",
    "ScanResult",
    "Vulnerability",
    "VulnerabilitySeverity",
    "VulnerabilityStatus",
    "Host",
]
