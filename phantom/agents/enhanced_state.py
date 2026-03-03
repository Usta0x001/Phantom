"""
Enhanced Agent State

Extended agent state with integrated vulnerability tracking, host discovery,
and verification capabilities. Bridges the agent with core models.
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from phantom.agents.state import AgentState
from phantom.models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from phantom.models.host import Host
from phantom.models.scan import ScanResult, ScanPhase, ScanStatus
from phantom.core.priority_queue import VulnerabilityPriorityQueue, ScanPriorityQueue

_logger = logging.getLogger(__name__)


class EnhancedAgentState(AgentState):
    """
    Extended agent state with security-specific tracking.
    
    Integrates:
    - Vulnerability discovery and verification
    - Host/service enumeration
    - Scan progress tracking
    - Priority-based action queuing (VulnerabilityPriorityQueue + ScanPriorityQueue)
    """
    
    # Scan tracking
    scan_id: str | None = None
    scan_result: ScanResult | None = None
    current_phase: ScanPhase = ScanPhase.RECON
    
    # Discovered assets
    hosts: dict[str, Host] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    
    # Tested endpoint tracking for deduplication
    # Key: "METHOD URL PARAM" (e.g. "POST /login email"), Value: list of test descriptions
    tested_endpoints: dict[str, list[str]] = Field(default_factory=dict)
    
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
        """Initialize a new scan with priority queues."""
        import uuid
        
        self.scan_id = scan_id or f"scan_{uuid.uuid4().hex[:8]}"
        self.scan_result = ScanResult(
            scan_id=self.scan_id,
            target=target,
            targets=[target],
        )
        self.scan_result.start_scan()
        self.current_phase = ScanPhase.RECON
        
        # Initialize priority queues
        self._vuln_queue = VulnerabilityPriorityQueue()
        self._scan_queue = ScanPriorityQueue()
        self._scan_queue.create_recon_tasks(target)
        
        self.update_context("scan_id", self.scan_id)
        self.update_context("target", target)
        
        return self.scan_result
    
    # -- Priority queue accessors --
    
    @property
    def vuln_queue(self) -> VulnerabilityPriorityQueue:
        """Get the vulnerability priority queue (lazy-init)."""
        if not hasattr(self, "_vuln_queue") or self._vuln_queue is None:
            self._vuln_queue = VulnerabilityPriorityQueue()
        return self._vuln_queue
    
    @property
    def scan_queue(self) -> ScanPriorityQueue:
        """Get the scan task priority queue (lazy-init)."""
        if not hasattr(self, "_scan_queue") or self._scan_queue is None:
            self._scan_queue = ScanPriorityQueue()
        return self._scan_queue
    
    def get_next_scan_task(self) -> Any:
        """Pop the highest-priority scan task whose dependencies are met."""
        return self.scan_queue.pop()
    
    def complete_scan_task(self, task_id: str) -> None:
        """Mark a scan task as completed so dependent tasks become eligible."""
        self.scan_queue.mark_completed(task_id)
    
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
        """Register discovered endpoint (capped at 10,000 to prevent unbounded growth)."""
        if endpoint not in self.endpoints:
            if len(self.endpoints) >= 10_000:
                return  # silently cap
            self.endpoints.append(endpoint)
            if self.scan_result:
                self.scan_result.add_endpoint(endpoint)
    
    def mark_endpoint_tested(
        self, url: str, method: str = "GET", parameter: str = "", test_type: str = ""
    ) -> bool:
        """Mark an endpoint+param as tested.  Returns True if it was already
        tested (i.e. duplicate), False if this is the first test.
        
        The agent should call this BEFORE running an exploit against an
        endpoint to avoid wasting iterations on repeated tests.
        Capped at 10,000 entries to prevent unbounded growth.
        """
        key = f"{method.upper()} {url} {parameter}".strip()
        if key in self.tested_endpoints:
            self.tested_endpoints[key].append(test_type)
            return True  # duplicate
        if len(self.tested_endpoints) >= 10_000:
            return False  # silently cap
        self.tested_endpoints[key] = [test_type]
        return False
    
    def get_tested_endpoints_summary(self) -> str:
        """Return a compact summary of tested endpoints for the agent."""
        if not self.tested_endpoints:
            return ""
        lines = []
        for key, tests in list(self.tested_endpoints.items())[:50]:
            lines.append(f"  {key} ({len(tests)}x: {', '.join(tests[:3])})")
        return f"Already tested ({len(self.tested_endpoints)} total):\n" + "\n".join(lines)
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Register discovered vulnerability and enqueue for priority processing."""
        if vuln.id in self.vulnerabilities:
            return  # Duplicate
        
        # Check knowledge store for known false positives
        try:
            from phantom.core.knowledge_store import get_knowledge_store
            store = get_knowledge_store()
            fp_sig = f"{vuln.detected_by}:{vuln.vulnerability_class}:{vuln.target}"
            if store.is_false_positive(fp_sig):
                # Skip known false positives — don't clutter results
                self.add_observation({
                    "type": "false_positive_skipped",
                    "vuln_id": vuln.id,
                    "name": vuln.name,
                    "reason": "Known false-positive signature in knowledge store",
                })
                return
        except Exception:
            pass  # Knowledge store unavailable — continue normally
        
        self.vulnerabilities[vuln.id] = vuln
        self.pending_verification.append(vuln.id)
        
        # Enqueue into priority queue for severity-ordered processing
        self.vuln_queue.push(vuln)
        
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
        if vuln_id in self.vulnerabilities and vuln_id not in self.verified_vulns:
            self.vulnerabilities[vuln_id].status = VulnerabilityStatus.VERIFIED
            self.verified_vulns.append(vuln_id)
            self.vuln_stats["verified"] += 1
            
            if vuln_id in self.pending_verification:
                self.pending_verification.remove(vuln_id)
    
    def mark_vuln_false_positive(self, vuln_id: str) -> None:
        """Mark vulnerability as false positive and persist to knowledge store."""
        if vuln_id in self.vulnerabilities and vuln_id not in self.false_positives:
            vuln = self.vulnerabilities[vuln_id]
            vuln.status = VulnerabilityStatus.FALSE_POSITIVE
            self.false_positives.append(vuln_id)
            self.vuln_stats["false_positive"] += 1
            # Decrement total and severity count since this is not a real vuln
            self.vuln_stats["total"] = max(0, self.vuln_stats["total"] - 1)
            severity_key = vuln.severity.value.lower()
            if severity_key in self.vuln_stats:
                self.vuln_stats[severity_key] = max(0, self.vuln_stats[severity_key] - 1)
            
            # Also update scan_result.finding_summary to stay in sync
            if self.scan_result:
                self.scan_result.remove_vulnerability(vuln.id, vuln.severity.value)
            
            if vuln_id in self.pending_verification:
                self.pending_verification.remove(vuln_id)
            
            # Persist FP signature to knowledge store for future scans
            try:
                from phantom.core.knowledge_store import get_knowledge_store
                store = get_knowledge_store()
                fp_sig = f"{vuln.detected_by}:{vuln.vulnerability_class}:{vuln.target}"
                store.mark_false_positive(fp_sig)
            except Exception:
                pass  # Knowledge store unavailable
    
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

    # ------------------------------------------------------------------
    # Checkpoint / Scan Resume
    # ------------------------------------------------------------------

    def save_checkpoint(self, run_dir: str | Path) -> Path:
        """Persist current scan state to *run_dir*/checkpoint.json.

        Called periodically (e.g. every N iterations) so a crashed scan can
        be resumed from the last checkpoint instead of restarting.
        """
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = run_dir / "checkpoint.json"

        data = {
            "scan_id": self.scan_id,
            "target": self.context.get("target", "unknown"),
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,  # BUG-05 FIX: Persist max_iterations
            "phase": self.current_phase.value,
            "hosts": {k: h.to_summary() for k, h in self.hosts.items()},
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "tested_endpoints": self.tested_endpoints,
            "vulnerabilities": {
                vid: v.to_report_dict() for vid, v in self.vulnerabilities.items()
            },
            "verified_vulns": self.verified_vulns,
            "false_positives": self.false_positives,
            "vuln_stats": self.vuln_stats,
            "tools_used": self.tools_used,
            # BUG-09 FIX: Persist findings_ledger so scan resume retains all discoveries
            "findings_ledger": list(getattr(self, "findings_ledger", [])),
            "saved_at": datetime.now(UTC).isoformat(),
        }

        checkpoint_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        _logger.debug("Checkpoint saved to %s (iteration %d)", checkpoint_path, self.iteration)
        return checkpoint_path

    @classmethod
    def from_checkpoint(cls, checkpoint_path: str | Path) -> "EnhancedAgentState":
        """Restore an EnhancedAgentState from a previously saved checkpoint.

        PHT-019 FIX: Validates checkpoint data before applying it.
        Rejects unknown keys, enforces type constraints, and limits sizes
        to prevent deserialization-based attacks.

        The returned state will have iteration, phase, discovered assets,
        and vulnerability data pre-populated so the agent can continue
        where it left off.
        """
        checkpoint_path = Path(checkpoint_path)
        data = json.loads(checkpoint_path.read_text(encoding="utf-8"))

        # ---- PHT-019 FIX: checkpoint validation ----
        _ALLOWED_TOP_KEYS = {
            "scan_id", "target", "iteration", "max_iterations", "phase", "hosts",
            "subdomains", "endpoints", "tested_endpoints",
            "vulnerabilities", "verified_vulns", "false_positives",
            "vuln_stats", "tools_used", "findings_ledger", "saved_at",
        }
        unexpected = set(data.keys()) - _ALLOWED_TOP_KEYS
        if unexpected:
            _logger.warning("Checkpoint contains unexpected keys (dropped): %s", unexpected)
            for k in unexpected:
                del data[k]

        # Type guards
        if not isinstance(data.get("iteration", 0), int):
            data["iteration"] = 0
        if not isinstance(data.get("max_iterations", 300), int):
            data["max_iterations"] = 300
        if not isinstance(data.get("subdomains", []), list):
            data["subdomains"] = []
        if not isinstance(data.get("endpoints", []), list):
            data["endpoints"] = []
        if not isinstance(data.get("vulnerabilities", {}), dict):
            data["vulnerabilities"] = {}
        if not isinstance(data.get("hosts", {}), dict):
            data["hosts"] = {}
        if not isinstance(data.get("tools_used", {}), dict):
            data["tools_used"] = {}

        # Size guards – refuse absurdly large payloads
        MAX_LIST_LEN = 50_000
        MAX_DICT_LEN = 10_000
        for key in ("subdomains", "endpoints", "verified_vulns", "false_positives"):
            lst = data.get(key, [])
            if isinstance(lst, list) and len(lst) > MAX_LIST_LEN:
                _logger.warning("Checkpoint list '%s' truncated (%d > %d)", key, len(lst), MAX_LIST_LEN)
                data[key] = lst[:MAX_LIST_LEN]
        for key in ("vulnerabilities", "hosts", "tested_endpoints", "tools_used"):
            d = data.get(key, {})
            if isinstance(d, dict) and len(d) > MAX_DICT_LEN:
                _logger.warning("Checkpoint dict '%s' truncated (%d > %d)", key, len(d), MAX_DICT_LEN)
                data[key] = dict(list(d.items())[:MAX_DICT_LEN])
        # ---- end PHT-019 validation ----

        # BUG-14 FIX: Restore max_iterations from checkpoint (default 300)
        state = cls(
            agent_name="Root Agent (resumed)",
            max_iterations=data.get("max_iterations", 300),
        )

        state.scan_id = data.get("scan_id")
        state.iteration = data.get("iteration", 0)
        state.subdomains = data.get("subdomains", [])
        state.endpoints = data.get("endpoints", [])
        state.tested_endpoints = data.get("tested_endpoints", {})
        state.verified_vulns = data.get("verified_vulns", [])
        state.false_positives = data.get("false_positives", [])
        state.vuln_stats = data.get("vuln_stats", state.vuln_stats)
        state.tools_used = data.get("tools_used", {})

        # BUG-09 FIX: Restore findings_ledger from checkpoint
        restored_ledger = data.get("findings_ledger", [])
        if isinstance(restored_ledger, list):
            state.findings_ledger = restored_ledger[:50_000]  # size guard

        # Restore phase
        phase_str = data.get("phase", "recon")
        try:
            state.current_phase = ScanPhase(phase_str)
        except (ValueError, KeyError):
            state.current_phase = ScanPhase.RECON

        # Restore vulnerabilities from checkpoint dicts
        vuln_dicts = data.get("vulnerabilities", {})
        for vid, vdict in vuln_dicts.items():
            try:
                sev = vdict.get("severity", "medium")
                severity = VulnerabilitySeverity(sev) if isinstance(sev, str) else VulnerabilitySeverity.MEDIUM
                status_str = vdict.get("status", "detected")
                status = VulnerabilityStatus(status_str) if isinstance(status_str, str) else VulnerabilityStatus.DETECTED
                vuln = Vulnerability(
                    id=vid,
                    name=vdict.get("name", vdict.get("class", "Unknown")),
                    vulnerability_class=vdict.get("class", "other"),
                    severity=severity,
                    status=status,
                    cvss_score=vdict.get("cvss"),
                    target=vdict.get("target", "unknown"),
                    endpoint=vdict.get("endpoint"),
                    parameter=vdict.get("parameter"),
                    description=vdict.get("description", "Restored from checkpoint"),
                    payload=vdict.get("payload"),
                    cve_ids=vdict.get("cve_ids", []),
                    cwe_ids=vdict.get("cwe_ids", []),
                    remediation=vdict.get("remediation"),
                    detected_by=vdict.get("detected_by", "checkpoint"),
                )
                state.vulnerabilities[vid] = vuln
            except Exception as exc:
                _logger.debug("Could not restore vulnerability %s from checkpoint: %s", vid, exc)

        # Restore hosts as summary dicts (full Host reconstruction is lossy,
        # but we at least keep the keys so host-count is accurate).
        host_dicts = data.get("hosts", {})
        for hkey, hdict in host_dicts.items():
            try:
                host = Host(
                    ip=hdict.get("ip"),
                    hostname=hdict.get("hostname"),
                    os=hdict.get("os"),
                )
                state.hosts[hkey] = host
            except Exception as exc:
                _logger.debug("Could not restore host %s from checkpoint: %s", hkey, exc)

        # Context
        target = data.get("target", "unknown")
        state.update_context("scan_id", state.scan_id)
        state.update_context("target", target)

        _logger.info(
            "Restored checkpoint: scan=%s iteration=%d phase=%s vulns=%d hosts=%d",
            state.scan_id,
            state.iteration,
            state.current_phase.value,
            state.vuln_stats.get("total", 0),
            len(state.hosts),
        )
        return state
