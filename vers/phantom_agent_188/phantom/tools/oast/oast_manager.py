"""
OAST Manager — Manages out-of-band interaction tracking.

This manager handles:
- Generating unique callback URLs and payloads
- Tracking interactions from OAST servers (Burp Collaborator-style)
- Thread-safe interaction storage
- Configurable OAST server endpoints
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from phantom.config import Config


OASTType = Literal["http", "dns", "smtp", "ldap"]


@dataclass
class OASTPayload:
    """A generated OAST payload for blind vulnerability testing."""

    id: str
    payload_type: OASTType
    token: str  # Unique identifier embedded in the payload
    callback_url: str  # The full callback URL to use
    raw_payload: str  # The payload string to inject
    context: str  # What vulnerability this is testing (e.g., "ssrf", "xxe", "rce")
    target_surface: str  # Where the payload will be injected
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    interactions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "payload_type": self.payload_type,
            "token": self.token,
            "callback_url": self.callback_url,
            "raw_payload": self.raw_payload,
            "context": self.context,
            "target_surface": self.target_surface,
            "created_at": self.created_at,
            "interactions": self.interactions,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OASTPayload":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class OASTManager:
    """
    Thread-safe manager for OAST payload generation and interaction tracking.

    The manager is a pure executor:
    - Generates unique callback URLs/payloads
    - Tracks interactions
    - Returns DATA (what interactions occurred) not commands

    The LLM decides:
    - When to generate payloads
    - What context/target to use
    - How to interpret interactions
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._payloads: dict[str, OASTPayload] = {}
        self._counter: int = 0

        # OAST server configuration from environment/config
        # Default to interact.sh style URLs if not configured
        self._oast_server = Config.get("phantom_oast_server") or "oast.pro"
        self._oast_token_prefix = Config.get("phantom_oast_token") or self._generate_session_prefix()

    def _generate_session_prefix(self) -> str:
        """Generate a unique session prefix for this scan."""
        return secrets.token_hex(4)

    def _generate_token(self) -> str:
        """Generate a unique token for a payload."""
        self._counter += 1
        unique = f"{self._oast_token_prefix}-{self._counter}-{secrets.token_hex(4)}"
        return unique

    def generate_payload(
        self,
        payload_type: OASTType,
        context: str,
        target_surface: str,
    ) -> dict[str, Any]:
        """
        Generate an OAST payload for blind vulnerability testing.

        Args:
            payload_type: Type of callback (http, dns, smtp, ldap)
            context: What vuln is being tested (ssrf, xxe, rce, sqli_oob, etc.)
            target_surface: Where the payload will be injected

        Returns:
            Dict with payload details including the callback URL and raw payload
        """
        with self._lock:
            token = self._generate_token()
            payload_id = f"OAST-{hashlib.md5(token.encode()).hexdigest()[:8].upper()}"

            # Generate callback URL based on type
            if payload_type == "http":
                callback_url = f"http://{token}.{self._oast_server}"
                raw_payload = callback_url
            elif payload_type == "dns":
                callback_url = f"{token}.{self._oast_server}"
                raw_payload = callback_url
            elif payload_type == "smtp":
                callback_url = f"{token}@{self._oast_server}"
                raw_payload = callback_url
            elif payload_type == "ldap":
                callback_url = f"ldap://{token}.{self._oast_server}/obj"
                raw_payload = callback_url
            else:
                callback_url = f"http://{token}.{self._oast_server}"
                raw_payload = callback_url

            payload = OASTPayload(
                id=payload_id,
                payload_type=payload_type,
                token=token,
                callback_url=callback_url,
                raw_payload=raw_payload,
                context=context,
                target_surface=target_surface,
            )

            self._payloads[payload_id] = payload

            return {
                "payload_id": payload_id,
                "payload_type": payload_type,
                "token": token,
                "callback_url": callback_url,
                "raw_payload": raw_payload,
                "context": context,
                "target_surface": target_surface,
                "instructions": self._get_usage_instructions(payload_type, context),
            }

    def _get_usage_instructions(self, payload_type: OASTType, context: str) -> str:
        """Generate context-specific usage hints for the payload."""
        instructions = {
            ("http", "ssrf"): "Inject the callback URL in URL parameters or request bodies that might be fetched server-side",
            ("http", "xxe"): "Use in XXE payload: <!ENTITY xxe SYSTEM \"CALLBACK_URL\">",
            ("http", "rce"): "Use in command injection: curl CALLBACK_URL || wget CALLBACK_URL",
            ("dns", "ssrf"): "Use DNS callback when HTTP is blocked: ping CALLBACK_URL",
            ("dns", "rce"): "Use nslookup or dig: nslookup CALLBACK_URL || dig CALLBACK_URL",
            ("dns", "sqli_oob"): "SQL Server: master..xp_dirtree '\\\\CALLBACK_URL\\x'; MySQL: LOAD_FILE('\\\\\\\\CALLBACK_URL\\\\x')",
            ("ldap", "log4j"): "Use in Log4j payload: ${jndi:CALLBACK_URL}",
        }
        key = (payload_type, context)
        return instructions.get(key, f"Inject the callback URL where {context} might cause server-side requests")

    def record_interaction(
        self,
        payload_id: str,
        interaction_type: str,
        source_ip: str | None = None,
        raw_data: str | None = None,
        timestamp: str | None = None,
    ) -> bool:
        """
        Record an interaction with an OAST payload.

        This is called when the OAST server reports a callback.

        Returns:
            True if the interaction was recorded, False if payload not found
        """
        with self._lock:
            if payload_id not in self._payloads:
                return False

            interaction = {
                "type": interaction_type,
                "source_ip": source_ip,
                "raw_data": raw_data,
                "timestamp": timestamp or datetime.now(UTC).isoformat(),
            }

            self._payloads[payload_id].interactions.append(interaction)
            return True

    def check_interactions(
        self,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Check for interactions on OAST payloads.

        Args:
            payload_id: Specific payload to check, or None for all

        Returns:
            Dict with interaction data - FACTS not commands
        """
        with self._lock:
            if payload_id:
                if payload_id not in self._payloads:
                    return {"error": f"Payload {payload_id} not found", "interactions": []}

                payload = self._payloads[payload_id]
                return {
                    "payload_id": payload_id,
                    "context": payload.context,
                    "target_surface": payload.target_surface,
                    "interactions": payload.interactions,
                    "interaction_count": len(payload.interactions),
                    "has_interactions": len(payload.interactions) > 0,
                }

            # Check all payloads
            all_interactions: list[dict[str, Any]] = []
            payloads_with_interactions: list[str] = []

            for pid, payload in self._payloads.items():
                if payload.interactions:
                    payloads_with_interactions.append(pid)
                    for interaction in payload.interactions:
                        all_interactions.append({
                            "payload_id": pid,
                            "context": payload.context,
                            "target_surface": payload.target_surface,
                            **interaction,
                        })

            return {
                "total_payloads": len(self._payloads),
                "payloads_with_interactions": payloads_with_interactions,
                "interaction_count": len(all_interactions),
                "interactions": all_interactions,
                "has_any_interactions": len(all_interactions) > 0,
            }

    def list_payloads(self) -> dict[str, Any]:
        """
        List all generated OAST payloads.

        Returns FACTS about payloads - LLM decides what to do with them.
        """
        with self._lock:
            payloads = []
            for payload in self._payloads.values():
                payloads.append({
                    "payload_id": payload.id,
                    "payload_type": payload.payload_type,
                    "context": payload.context,
                    "target_surface": payload.target_surface,
                    "callback_url": payload.callback_url,
                    "interaction_count": len(payload.interactions),
                    "has_interactions": len(payload.interactions) > 0,
                    "created_at": payload.created_at,
                })

            return {
                "total_payloads": len(payloads),
                "payloads": payloads,
                "oast_server": self._oast_server,
            }

    def clear_payloads(self, older_than_hours: float | None = None) -> dict[str, Any]:
        """
        Clear OAST payloads.

        Args:
            older_than_hours: If set, only clear payloads older than this

        Returns:
            Summary of cleared payloads
        """
        with self._lock:
            if older_than_hours is None:
                count = len(self._payloads)
                self._payloads.clear()
                return {"cleared_count": count, "remaining_count": 0}

            now = datetime.now(UTC)
            to_remove: list[str] = []

            for pid, payload in self._payloads.items():
                try:
                    created = datetime.fromisoformat(payload.created_at)
                    age_hours = (now - created).total_seconds() / 3600
                    if age_hours > older_than_hours:
                        to_remove.append(pid)
                except (ValueError, TypeError):
                    pass

            for pid in to_remove:
                del self._payloads[pid]

            return {
                "cleared_count": len(to_remove),
                "remaining_count": len(self._payloads),
            }

    def to_dict(self) -> dict[str, Any]:
        """Serialize for checkpointing."""
        with self._lock:
            return {
                "counter": self._counter,
                "oast_token_prefix": self._oast_token_prefix,
                "payloads": {k: v.to_dict() for k, v in self._payloads.items()},
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OASTManager":
        """Restore from serialized state."""
        manager = cls()
        manager._counter = d.get("counter", 0)
        manager._oast_token_prefix = d.get("oast_token_prefix", manager._oast_token_prefix)
        for k, v in d.get("payloads", {}).items():
            manager._payloads[k] = OASTPayload.from_dict(v)
        return manager


# Global manager instance
_oast_manager: OASTManager | None = None
_manager_lock = threading.Lock()


def get_oast_manager() -> OASTManager:
    """Get or create the global OAST manager instance."""
    global _oast_manager
    with _manager_lock:
        if _oast_manager is None:
            _oast_manager = OASTManager()
        return _oast_manager
