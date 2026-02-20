"""
Enhanced Agent State

Extended agent state with integrated vulnerability tracking, host discovery,
and verification capabilities. Bridges the agent with core models.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from phantom.agents.state import AgentState
from phantom.models.vulnerability import Vulnerability, VulnerabilitySeverity
from phantom.models.host import Host
from phantom.models.scan import ScanResult, ScanPhase, ScanStatus
from phantom.core.priority_queue import VulnerabilityPriorityQueue, ScanOrchestrator


class EnhancedAgentState(AgentState):
    """
    Extended agent state with security-specific tracking.
    
    Integrates:
    - Vulnerability discovery and verification
    - Host/service enumeration
    - Scan progress tracking
    - Priority-based action queuing
    """
    
    # Scan tracking
    scan_id: str | None = None
    scan_result: ScanResult | None = None
    current_phase: ScanPhase = ScanPhase.RECON
    
    # Discovered assets
    hosts: dict[str, Host] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    
    # Vulnerabilities
    vulnerabilities: dict[str, Vulnerability] = Field(default_factory=dict)
    verified_vulns: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    
    # Verification queue (IDs awaiting verification)
    pending_verification: list[str] = Field(default_factory=list)
    
    # Statistics
    vuln_stats: dict[str, int] = Field(default_factory=lambda: {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "verified": 0,
        "false_positive": 0,
    })
    
    # Tool usage tracking
    tools_used: dict[str, int] = Field(default_factory=dict)
    
    def initialize_scan(self, target: str, scan_id: str | None = None) -> ScanResult:
        """Initialize a new scan."""
        import uuid
        
        self.scan_id = scan_id or f"scan_{uuid.uuid4().hex[:8]}"
        self.scan_result = ScanResult(
            scan_id=self.scan_id,
            target=target,
            targets=[target],
        )
        self.scan_result.start_scan()
        self.current_phase = ScanPhase.RECON
        
        self.update_context("scan_id", self.scan_id)
        self.update_context("target", target)
        
        return self.scan_result
    
    def add_host(self, host: Host) -> None:
        """Register discovered host."""
        key = host.ip or host.hostname or "unknown"
        
        if key in self.hosts:
            # Merge with existing
            existing = self.hosts[key]
            for port in host.ports:
                existing.add_port(port)
            for tech in host.technologies:
                existing.add_technology(tech)
            if host.os and not existing.os:
                existing.os = host.os
        else:
            self.hosts[key] = host
        
        if self.scan_result:
            self.scan_result.add_host(key)
    
    def add_subdomain(self, subdomain: str) -> None:
        """Register discovered subdomain."""
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
            if self.scan_result:
                self.scan_result.add_subdomain(subdomain)
    
    def add_endpoint(self, endpoint: str) -> None:
        """Register discovered endpoint."""
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
            if self.scan_result:
                self.scan_result.add_endpoint(endpoint)
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Register discovered vulnerability."""
        if vuln.id in self.vulnerabilities:
            return  # Duplicate
        
        self.vulnerabilities[vuln.id] = vuln
        self.pending_verification.append(vuln.id)
        
        # Update stats
        self.vuln_stats["total"] += 1
        severity_key = vuln.severity.value.lower()
        if severity_key in self.vuln_stats:
            self.vuln_stats[severity_key] += 1
        
        # Update scan result
        if self.scan_result:
            self.scan_result.add_vulnerability(
                vuln.id,
                vuln.severity.value,
                vuln.status.value == "verified",
            )
        
        # Add observation
        self.add_observation({
            "type": "vulnerability_found",
            "vuln_id": vuln.id,
            "name": vuln.name,
            "severity": vuln.severity.value,
            "target": vuln.target,
        })
    
    def mark_vuln_verified(self, vuln_id: str) -> None:
        """Mark vulnerability as verified."""
        if vuln_id in self.vulnerabilities:
            self.verified_vulns.append(vuln_id)
            self.vuln_stats["verified"] += 1
            
            if vuln_id in self.pending_verification:
                self.pending_verification.remove(vuln_id)
    
    def mark_vuln_false_positive(self, vuln_id: str) -> None:
        """Mark vulnerability as false positive."""
        if vuln_id in self.vulnerabilities:
            self.false_positives.append(vuln_id)
            self.vuln_stats["false_positive"] += 1
            
            if vuln_id in self.pending_verification:
                self.pending_verification.remove(vuln_id)
    
    def get_next_to_verify(self) -> Vulnerability | None:
        """Get next vulnerability to verify (highest severity first)."""
        if not self.pending_verification:
            return None
        
        # Sort by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        sorted_ids = sorted(
            self.pending_verification,
            key=lambda vid: severity_order.index(
                self.vulnerabilities[vid].severity.value.lower()
            ) if vid in self.vulnerabilities else 999
        )
        
        return self.vulnerabilities.get(sorted_ids[0]) if sorted_ids else None
    
    def track_tool_usage(self, tool_name: str) -> None:
        """Track tool usage for statistics."""
        self.tools_used[tool_name] = self.tools_used.get(tool_name, 0) + 1
        
        if self.scan_result:
            self.scan_result.add_tool(tool_name)
    
    def set_phase(self, phase: ScanPhase) -> None:
        """Update current scan phase."""
        self.current_phase = phase
        
        if self.scan_result:
            self.scan_result.current_phase = phase
            self.scan_result.start_phase(phase)
        
        self.add_observation({
            "type": "phase_change",
            "phase": phase.value,
        })
    
    def complete_phase(self) -> None:
        """Mark current phase as complete."""
        if self.scan_result:
            self.scan_result.complete_phase(self.current_phase)
    
    def complete_scan(self) -> dict[str, Any]:
        """Complete scan and return summary."""
        if self.scan_result:
            self.scan_result.complete_scan()
        
        summary = self.get_scan_summary()
        self.set_completed(summary)
        
        return summary
    
    def get_scan_summary(self) -> dict[str, Any]:
        """Get current scan summary."""
        return {
            "scan_id": self.scan_id,
            "phase": self.current_phase.value,
            "hosts_found": len(self.hosts),
            "subdomains_found": len(self.subdomains),
            "endpoints_found": len(self.endpoints),
            "vulnerabilities": self.vuln_stats.copy(),
            "tools_used": list(self.tools_used.keys()),
            "iterations": self.iteration,
            "errors": len(self.errors),
        }
    
    def get_critical_findings(self) -> list[Vulnerability]:
        """Get critical and high severity verified vulnerabilities."""
        return [
            v for v in self.vulnerabilities.values()
            if v.severity in {VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH}
            and v.id in self.verified_vulns
        ]
    
    def to_report_data(self) -> dict[str, Any]:
        """Export all data for report generation."""
        return {
            "scan_id": self.scan_id,
            "target": self.context.get("target", "unknown"),
            "started_at": self.start_time,
            "completed_at": self.last_updated,
            "status": "completed" if self.completed else "in_progress",
            "phase": self.current_phase.value,
            "summary": self.get_scan_summary(),
            "hosts": [h.to_summary() for h in self.hosts.values()],
            "subdomains": self.subdomains,
            "endpoints": self.endpoints[:100],  # Limit for report
            "vulnerabilities": [
                v.to_report_dict() for v in self.vulnerabilities.values()
            ],
            "verified_count": len(self.verified_vulns),
            "false_positive_count": len(self.false_positives),
            "tools_used": self.tools_used,
            "errors": self.errors,
        }
