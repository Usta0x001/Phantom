"""
Host and Service Models

Pydantic models for representing discovered hosts, ports, and services.
"""

from datetime import UTC, datetime
from typing import Any
from pydantic import BaseModel, Field


class Technology(BaseModel):
    """Detected technology/framework."""
    
    name: str = Field(..., description="Technology name (e.g., nginx, WordPress)")
    version: str | None = Field(default=None, description="Version if detected")
    category: str | None = Field(default=None, description="Category: server, cms, framework, etc.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")
    detected_by: str = Field(default="httpx", description="Tool that detected this")


class Port(BaseModel):
    """Discovered port with service information."""
    
    number: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", description="tcp or udp")
    state: str = Field(default="open", description="open, closed, filtered")
    service: str | None = Field(default=None, description="Service name (http, ssh, etc.)")
    version: str | None = Field(default=None, description="Service version")
    banner: str | None = Field(default=None, description="Service banner")
    scripts: dict[str, str] = Field(default_factory=dict, description="NSE script results")
    
    def is_web(self) -> bool:
        """Check if this is a web service port."""
        web_services = {"http", "https", "http-proxy", "http-alt"}
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        return self.service in web_services or self.number in web_ports


class Service(BaseModel):
    """High-level service abstraction."""
    
    name: str = Field(..., description="Service name")
    port: int = Field(...)
    protocol: str = Field(default="tcp")
    version: str | None = Field(default=None)
    product: str | None = Field(default=None, description="Product name (e.g., Apache httpd)")
    os_type: str | None = Field(default=None, description="Likely OS: linux, windows")
    technologies: list[Technology] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list, description="Vulnerability IDs found on this service")


class Host(BaseModel):
    """
    Discovered host model.
    
    Aggregates all information discovered about a target host:
    - Network information (IP, hostname, ports)
    - Services and technologies
    - OS detection
    - Associated vulnerabilities
    """
    
    # Identity
    ip: str = Field(..., description="IP address")
    hostname: str | None = Field(default=None, description="Resolved hostname")
    hostnames: list[str] = Field(default_factory=list, description="All discovered hostnames")
    
    # Network
    ports: list[Port] = Field(default_factory=list, description="Discovered ports")
    services: list[Service] = Field(default_factory=list, description="Discovered services")
    
    # OS & Tech
    os: str | None = Field(default=None, description="Detected OS")
    os_accuracy: int | None = Field(default=None, ge=0, le=100, description="OS detection accuracy %")
    technologies: list[Technology] = Field(default_factory=list, description="Web technologies detected")
    
    # Status
    is_alive: bool = Field(default=True, description="Host responds to probes")
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    # Associations
    vulnerability_ids: list[str] = Field(default_factory=list, description="Vulnerability IDs on this host")
    subdomain_of: str | None = Field(default=None, description="Parent domain if this is a subdomain")
    
    # Raw data
    raw_nmap: dict[str, Any] | None = Field(default=None, exclude=True)
    raw_httpx: dict[str, Any] | None = Field(default=None, exclude=True)
    
    def add_port(self, port: Port) -> None:
        """Add port, merging if it already exists."""
        existing = next((p for p in self.ports if p.number == port.number and p.protocol == port.protocol), None)
        if existing:
            # Merge information
            if port.service and not existing.service:
                existing.service = port.service
            if port.version and not existing.version:
                existing.version = port.version
            if port.banner and not existing.banner:
                existing.banner = port.banner
            existing.scripts.update(port.scripts)
        else:
            self.ports.append(port)
    
    def add_technology(self, tech: Technology) -> None:
        """Add technology, avoiding duplicates."""
        existing = next((t for t in self.technologies if t.name.lower() == tech.name.lower()), None)
        if not existing:
            self.technologies.append(tech)
        elif tech.version and not existing.version:
            existing.version = tech.version
    
    def get_web_ports(self) -> list[Port]:
        """Get all web service ports."""
        return [p for p in self.ports if p.is_web()]
    
    def get_urls(self, scheme: str | None = None) -> list[str]:
        """Generate URLs for web ports."""
        urls = []
        hostname = self.hostname or self.ip
        
        for port in self.get_web_ports():
            if port.number == 443 or port.service == "https":
                if scheme is None or scheme == "https":
                    urls.append(f"https://{hostname}" if port.number == 443 else f"https://{hostname}:{port.number}")
            else:
                if scheme is None or scheme == "http":
                    urls.append(f"http://{hostname}" if port.number == 80 else f"http://{hostname}:{port.number}")
        
        return urls
    
    def to_summary(self) -> dict[str, Any]:
        """Export host summary for reporting."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "open_ports": [p.number for p in self.ports if p.state == "open"],
            "services": [s.name for s in self.services],
            "technologies": [t.name for t in self.technologies],
            "vulnerability_count": len(self.vulnerability_ids),
        }
    
    @classmethod
    def from_nmap(cls, nmap_host: dict[str, Any]) -> "Host":
        """Create from nmap parsed output."""
        ports = []
        for port_data in nmap_host.get("ports", []):
            ports.append(Port(
                number=port_data.get("port", 0),
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state", "unknown"),
                service=port_data.get("service"),
                version=port_data.get("version"),
            ))
        
        return cls(
            ip=nmap_host.get("ip", "unknown"),
            hostname=nmap_host.get("hostname"),
            os=nmap_host.get("os"),
            ports=ports,
            raw_nmap=nmap_host,
        )
    
    @classmethod
    def from_httpx(cls, httpx_result: dict[str, Any]) -> "Host":
        """Create from httpx probe result."""
        url = httpx_result.get("url", "")
        host = httpx_result.get("host", "")
        
        # Parse port from URL
        port_num = 443 if url.startswith("https") else 80
        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            try:
                port_num = int(parts[1])
            except ValueError:
                pass
        
        technologies = []
        for tech in httpx_result.get("tech", []):
            technologies.append(Technology(
                name=tech,
                detected_by="httpx",
            ))
        
        port = Port(
            number=port_num,
            protocol="tcp",
            state="open",
            service="https" if port_num == 443 else "http",
        )
        
        return cls(
            ip=httpx_result.get("a", [host])[0] if httpx_result.get("a") else host,
            hostname=host,
            ports=[port],
            technologies=technologies,
            raw_httpx=httpx_result,
        )
