"""
Knowledge Persistence

Saves and loads discovered hosts, vulnerabilities, and scan history.
Enables learning from past scans and avoiding redundant work.
"""

import contextlib
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from phantom.models.host import Host, Port, Technology
from phantom.models.scan import ScanResult, ScanPhase, ScanStatus


logger = logging.getLogger(__name__)


class KnowledgeStore:
    """
    Persistent knowledge store for scan data.
    
    Saves:
    - Discovered hosts with services
    - Vulnerability findings
    - Scan history and statistics
    
    Enables:
    - Cross-scan correlation
    - Avoiding re-scanning known endpoints
    - False positive tracking
    """
    
    def __init__(self, store_path: str | Path = "phantom_knowledge"):
        self.store_path = Path(store_path)
        self.store_path.mkdir(parents=True, exist_ok=True)
        
        self.hosts_file = self.store_path / "hosts.json"
        self.vulns_file = self.store_path / "vulnerabilities.json"
        self.history_file = self.store_path / "scan_history.json"
        self.fp_file = self.store_path / "false_positives.json"
        
        # Thread-safe lock for all data mutations
        self._lock = threading.Lock()
        
        # In-memory caches
        self._hosts: dict[str, dict[str, Any]] = {}
        self._vulns: dict[str, dict[str, Any]] = {}
        self._history: list[dict[str, Any]] = []
        self._false_positives: set[str] = set()
        
        # Load existing data
        self._load_all()
    
    def _load_all(self) -> None:
        """Load all persisted data."""
        try:
            if self.hosts_file.exists():
                with open(self.hosts_file, encoding="utf-8") as f:
                    self._hosts = json.load(f)
                logger.debug(f"Loaded {len(self._hosts)} hosts")
        except Exception as e:
            logger.warning(f"Failed to load hosts: {e}")
        
        try:
            if self.vulns_file.exists():
                with open(self.vulns_file, encoding="utf-8") as f:
                    self._vulns = json.load(f)
                logger.debug(f"Loaded {len(self._vulns)} vulnerabilities")
        except Exception as e:
            logger.warning(f"Failed to load vulnerabilities: {e}")
        
        try:
            if self.history_file.exists():
                with open(self.history_file, encoding="utf-8") as f:
                    self._history = json.load(f)
                logger.debug(f"Loaded {len(self._history)} scan history entries")
        except Exception as e:
            logger.warning(f"Failed to load history: {e}")
        
        try:
            if self.fp_file.exists():
                with open(self.fp_file, encoding="utf-8") as f:
                    self._false_positives = set(json.load(f))
                logger.debug(f"Loaded {len(self._false_positives)} false positive signatures")
        except Exception as e:
            logger.warning(f"Failed to load false positives: {e}")
    
    def _save_hosts(self) -> None:
        """Persist hosts data atomically."""
        self._atomic_write(self.hosts_file, self._hosts)
    
    def _save_vulns(self) -> None:
        """Persist vulnerability data atomically."""
        self._atomic_write(self.vulns_file, self._vulns)
    
    def _save_history(self) -> None:
        """Persist scan history atomically."""
        self._atomic_write(self.history_file, self._history)
    
    def _save_false_positives(self) -> None:
        """Persist false positive signatures atomically."""
        self._atomic_write(self.fp_file, list(self._false_positives))

    @staticmethod
    def _atomic_write(path: Path, data: Any) -> None:
        """Write data to file atomically via temp file + rename."""
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=path.parent, suffix=".tmp", prefix=path.stem
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp_path, path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
    
    # Host Management
    
    def save_host(self, host: Host) -> None:
        """Save or update a host (thread-safe)."""
        with self._lock:
            self._save_host_unlocked(host)

    def _save_host_unlocked(self, host: Host) -> None:
        """Internal: save host without acquiring lock."""
        key = host.ip or host.hostname or "unknown"
        
        if key in self._hosts:
            # Merge with existing
            existing = self._hosts[key]
            
            # Merge ports
            existing_ports = {(p["number"], p["protocol"]) for p in existing.get("ports", [])}
            for port in host.ports:
                port_key = (port.number, port.protocol)
                if port_key not in existing_ports:
                    existing.setdefault("ports", []).append({
                        "number": port.number,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.service,
                        "version": port.version,
                    })
            
            # Merge technologies
            existing_techs = {t["name"].lower() for t in existing.get("technologies", [])}
            for tech in host.technologies:
                if tech.name.lower() not in existing_techs:
                    existing.setdefault("technologies", []).append({
                        "name": tech.name,
                        "version": tech.version,
                    })
            
            # Update OS if not set
            if host.os and not existing.get("os"):
                existing["os"] = host.os
            
            existing["last_seen"] = datetime.now(UTC).isoformat()
        else:
            # New host
            self._hosts[key] = {
                "ip": host.ip,
                "hostname": host.hostname,
                "hostnames": host.hostnames,
                "os": host.os,
                "ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                    }
                    for p in host.ports
                ],
                "technologies": [
                    {"name": t.name, "version": t.version}
                    for t in host.technologies
                ],
                "first_seen": datetime.now(UTC).isoformat(),
                "last_seen": datetime.now(UTC).isoformat(),
            }
        
        self._save_hosts()
    
    def get_host(self, key: str) -> Host | None:
        """Retrieve a host by IP or hostname."""
        with self._lock:
            data = self._hosts.get(key)
        if not data:
            return None
        
        return Host(
            ip=data.get("ip", ""),
            hostname=data.get("hostname"),
            hostnames=data.get("hostnames", []),
            os=data.get("os"),
            ports=[
                Port(
                    number=p["number"],
                    protocol=p["protocol"],
                    state=p.get("state", "open"),
                    service=p.get("service"),
                    version=p.get("version"),
                )
                for p in data.get("ports", [])
            ],
            technologies=[
                Technology(name=t["name"], version=t.get("version"))
                for t in data.get("technologies", [])
            ],
        )
    
    def get_all_hosts(self) -> list[Host]:
        """Get all known hosts."""
        with self._lock:
            keys = list(self._hosts.keys())
        return [self.get_host(k) for k in keys if self.get_host(k)]
    
    def host_exists(self, key: str) -> bool:
        """Check if host is known."""
        return key in self._hosts
    
    # Vulnerability Management
    
    def save_vulnerability(self, vuln: Vulnerability) -> None:
        """Save or update a vulnerability (thread-safe)."""
        with self._lock:
            self._vulns[vuln.id] = {
            "id": vuln.id,
            "name": vuln.name,
            "class": vuln.vulnerability_class,
            "severity": vuln.severity.value,
            "status": vuln.status.value,
            "cvss_score": vuln.cvss_score,
            "target": vuln.target,
            "endpoint": vuln.endpoint,
            "parameter": vuln.parameter,
            "description": vuln.description,
            "payload": vuln.payload,
            "cve_ids": vuln.cve_ids,
            "cwe_ids": vuln.cwe_ids,
            "remediation": vuln.remediation,
            "detected_by": vuln.detected_by,
            "detected_at": vuln.detected_at.isoformat(),
            "verified_by": vuln.verified_by,
            "verified_at": vuln.verified_at.isoformat() if vuln.verified_at else None,
        }
        
        self._save_vulns()
    
    def get_vulnerability(self, vuln_id: str) -> Vulnerability | None:
        """Retrieve a vulnerability by ID."""
        data = self._vulns.get(vuln_id)
        if not data:
            return None
        
        severity_map = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO,
        }
        
        status_map = {
            "detected": VulnerabilityStatus.DETECTED,
            "verified": VulnerabilityStatus.VERIFIED,
            "exploited": VulnerabilityStatus.EXPLOITED,
            "false_positive": VulnerabilityStatus.FALSE_POSITIVE,
            "mitigated": VulnerabilityStatus.MITIGATED,
        }
        
        return Vulnerability(
            id=data["id"],
            name=data["name"],
            vulnerability_class=data["class"],
            severity=severity_map.get(data.get("severity", "medium"), VulnerabilitySeverity.MEDIUM),
            status=status_map.get(data.get("status", "detected"), VulnerabilityStatus.DETECTED),
            cvss_score=data.get("cvss_score"),
            target=data["target"],
            endpoint=data.get("endpoint"),
            parameter=data.get("parameter"),
            description=data.get("description", ""),
            payload=data.get("payload"),
            cve_ids=data.get("cve_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            remediation=data.get("remediation"),
            detected_by=data.get("detected_by", "unknown"),
        )
    
    def get_vulns_for_target(self, target: str) -> list[Vulnerability]:
        """Get all vulnerabilities for a target."""
        return [
            self.get_vulnerability(vid)
            for vid, data in self._vulns.items()
            if target in data.get("target", "")
            and self.get_vulnerability(vid) is not None
        ]
    
    def get_vulns_by_severity(self, severity: str) -> list[Vulnerability]:
        """Get vulnerabilities by severity."""
        return [
            self.get_vulnerability(vid)
            for vid, data in self._vulns.items()
            if data.get("severity") == severity.lower()
            and self.get_vulnerability(vid) is not None
        ]
    
    # False Positive Management
    
    def mark_false_positive(self, signature: str) -> None:
        """
        Mark a finding signature as false positive.
        
        Signature format: "{tool}:{vuln_class}:{target_pattern}"
        Example: "nuclei:xss:*.example.com/search*"
        """
        with self._lock:
            self._false_positives.add(signature)
            self._save_false_positives()
    
    def is_false_positive(self, signature: str) -> bool:
        """Check if a signature is known false positive."""
        return signature in self._false_positives
    
    def get_false_positive_count(self) -> int:
        """Get count of known false positives."""
        return len(self._false_positives)
    
    # Scan History
    
    def record_scan(
        self,
        scan_id: str,
        target: str,
        status: str,
        vulns_found: int,
        vulns_verified: int,
        hosts_found: int,
        duration_seconds: float | None = None,
        tools_used: list[str] | None = None,
    ) -> None:
        """Record a completed scan in history (thread-safe)."""
        entry = {
            "scan_id": scan_id,
            "target": target,
            "status": status,
            "completed_at": datetime.now(UTC).isoformat(),
            "vulns_found": vulns_found,
            "vulns_verified": vulns_verified,
            "hosts_found": hosts_found,
            "duration_seconds": duration_seconds,
            "tools_used": tools_used or [],
        }
        
        with self._lock:
            self._history.append(entry)
            
            # Keep last 100 scans
            if len(self._history) > 100:
                self._history = self._history[-100:]
            
            self._save_history()
    
    def get_scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent scan history."""
        return self._history[-limit:]
    
    def get_scans_for_target(self, target: str) -> list[dict[str, Any]]:
        """Get all scans for a specific target."""
        return [
            s for s in self._history
            if target in s.get("target", "")
        ]
    
    # Statistics
    
    def get_statistics(self) -> dict[str, Any]:
        """Get overall knowledge store statistics."""
        vuln_by_severity: dict[str, int] = {}
        for data in self._vulns.values():
            sev = data.get("severity", "unknown")
            vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1
        
        verified_count = sum(
            1 for data in self._vulns.values()
            if data.get("status") == "verified"
        )
        
        return {
            "total_hosts": len(self._hosts),
            "total_vulnerabilities": len(self._vulns),
            "verified_vulnerabilities": verified_count,
            "false_positives": len(self._false_positives),
            "total_scans": len(self._history),
            "vulns_by_severity": vuln_by_severity,
        }
    
    # Utility
    
    def clear_all(self) -> None:
        """Clear all stored data (use with caution)."""
        self._hosts.clear()
        self._vulns.clear()
        self._history.clear()
        self._false_positives.clear()
        
        for f in [self.hosts_file, self.vulns_file, self.history_file, self.fp_file]:
            if f.exists():
                f.unlink()
        
        logger.info("Cleared all knowledge store data")
    
    def export_all(self) -> dict[str, Any]:
        """Export all data as a single dict."""
        return {
            "hosts": self._hosts,
            "vulnerabilities": self._vulns,
            "scan_history": self._history,
            "false_positives": list(self._false_positives),
            "exported_at": datetime.now(UTC).isoformat(),
        }
    
    def import_data(self, data: dict[str, Any]) -> None:
        """Import data from export."""
        if "hosts" in data:
            self._hosts.update(data["hosts"])
            self._save_hosts()
        
        if "vulnerabilities" in data:
            self._vulns.update(data["vulnerabilities"])
            self._save_vulns()
        
        if "false_positives" in data:
            self._false_positives.update(data["false_positives"])
            self._save_false_positives()
        
        logger.info("Imported knowledge data")


# Global singleton with thread-safe initialization
_knowledge_store: KnowledgeStore | None = None
_knowledge_store_lock = threading.Lock()


def get_knowledge_store(store_path: str | Path = "phantom_knowledge") -> KnowledgeStore:
    """Get or create the global knowledge store (thread-safe)."""
    global _knowledge_store
    
    if _knowledge_store is None:
        with _knowledge_store_lock:
            # Double-check inside lock
            if _knowledge_store is None:
                _knowledge_store = KnowledgeStore(store_path)
    
    return _knowledge_store
