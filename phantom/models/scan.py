"""
Scan Result Models

Pydantic models for tracking scan execution, phases, and aggregated results.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ScanPhase(str, Enum):
    """Scan execution phases."""
    RECON = "recon"           # Subdomain enum, port scan, tech detection
    SCANNING = "scanning"      # Vulnerability scanning (nuclei, etc.)
    FUZZING = "fuzzing"        # Directory/parameter fuzzing
    EXPLOITATION = "exploitation"  # SQLi, XSS, etc. exploitation
    VERIFICATION = "verification"  # Confirming findings
    REPORTING = "reporting"    # Generating reports


class ScanStatus(str, Enum):
    """Overall scan status."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSummary(BaseModel):
    """Summary statistics for findings."""
    
    total: int = Field(default=0)
    critical: int = Field(default=0)
    high: int = Field(default=0)
    medium: int = Field(default=0)
    low: int = Field(default=0)
    info: int = Field(default=0)
    verified: int = Field(default=0)
    false_positives: int = Field(default=0)
    
    def add_finding(self, severity: str, verified: bool = False) -> None:
        """Increment counters for a finding."""
        self.total += 1
        severity_lower = severity.lower()
        if severity_lower == "critical":
            self.critical += 1
        elif severity_lower == "high":
            self.high += 1
        elif severity_lower == "medium":
            self.medium += 1
        elif severity_lower == "low":
            self.low += 1
        else:
            self.info += 1
        
        if verified:
            self.verified += 1
    
    def verification_rate(self) -> float:
        """Calculate verification rate."""
        if self.total == 0:
            return 0.0
        return self.verified / self.total
    
    def to_dict(self) -> dict[str, int | float]:
        """Export as dict."""
        return {
            "total": self.total,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "verified": self.verified,
            "false_positives": self.false_positives,
            "verification_rate": round(self.verification_rate() * 100, 2),
        }


class PhaseResult(BaseModel):
    """Result of a scan phase."""
    
    phase: ScanPhase
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    duration_seconds: float | None = Field(default=None)
    
    # Phase-specific outputs
    hosts_discovered: int = Field(default=0)
    ports_discovered: int = Field(default=0)
    vulnerabilities_found: int = Field(default=0)
    endpoints_fuzzed: int = Field(default=0)
    
    errors: list[str] = Field(default_factory=list)
    
    def start(self) -> None:
        """Mark phase as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(UTC)
    
    def complete(self) -> None:
        """Mark phase as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()
    
    def fail(self, error: str) -> None:
        """Mark phase as failed."""
        self.status = ScanStatus.FAILED
        self.errors.append(error)
        self.completed_at = datetime.now(UTC)


class ScanResult(BaseModel):
    """
    Complete scan result model.
    
    Aggregates all findings, hosts, and phase results for a scan.
    """
    
    # Identity
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Primary target (URL or domain)")
    targets: list[str] = Field(default_factory=list, description="All targets")
    
    # Status
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    current_phase: ScanPhase = Field(default=ScanPhase.RECON)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    
    # Phase tracking
    phases: dict[str, PhaseResult] = Field(default_factory=dict)
    
    # Aggregated results
    hosts: list[str] = Field(default_factory=list, description="Discovered host IPs/hostnames")
    subdomains: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list, description="Discovered endpoints/paths")
    
    # Vulnerability IDs (actual Vulnerability objects stored separately)
    vulnerability_ids: list[str] = Field(default_factory=list)
    finding_summary: FindingSummary = Field(default_factory=FindingSummary)
    
    # Execution metadata
    tools_used: list[str] = Field(default_factory=list)
    total_requests: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)
    
    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
    )
    
    def start_scan(self) -> None:
        """Initialize scan start."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(UTC)
    
    def start_phase(self, phase: ScanPhase) -> PhaseResult:
        """Start a new phase."""
        self.current_phase = phase
        phase_result = PhaseResult(phase=phase)
        phase_result.start()
        self.phases[phase.value] = phase_result
        return phase_result
    
    def complete_phase(self, phase: ScanPhase) -> None:
        """Complete a phase."""
        if phase.value in self.phases:
            self.phases[phase.value].complete()
    
    def complete_scan(self) -> None:
        """Mark scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
    
    def fail_scan(self, error: str) -> None:
        """Mark scan as failed."""
        self.status = ScanStatus.FAILED
        self.errors.append(error)
        self.completed_at = datetime.now(UTC)
    
    def add_vulnerability(self, vuln_id: str, severity: str, verified: bool = False) -> None:
        """Register a vulnerability."""
        if vuln_id not in self.vulnerability_ids:
            self.vulnerability_ids.append(vuln_id)
            self.finding_summary.add_finding(severity, verified)
    
    def add_host(self, host: str) -> None:
        """Register discovered host."""
        if host not in self.hosts:
            self.hosts.append(host)
    
    def add_subdomain(self, subdomain: str) -> None:
        """Register discovered subdomain."""
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
    
    def add_endpoint(self, endpoint: str) -> None:
        """Register discovered endpoint."""
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
    
    def add_tool(self, tool: str) -> None:
        """Track tool usage."""
        if tool not in self.tools_used:
            self.tools_used.append(tool)
    
    def duration_seconds(self) -> float | None:
        """Calculate total scan duration."""
        if self.started_at:
            end = self.completed_at or datetime.now(UTC)
            return (end - self.started_at).total_seconds()
        return None
    
    def to_report(self) -> dict[str, Any]:
        """Export for reporting."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds(),
            "hosts_count": len(self.hosts),
            "subdomains_count": len(self.subdomains),
            "endpoints_count": len(self.endpoints),
            "findings": self.finding_summary.to_dict(),
            "phases": {
                name: {
                    "status": phase.status.value,
                    "duration_seconds": phase.duration_seconds,
                }
                for name, phase in self.phases.items()
            },
            "tools_used": self.tools_used,
            "errors": self.errors,
        }
