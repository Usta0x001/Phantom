"""Notification hooks — send alerts on critical findings via webhooks,
Slack, or custom callables.

Usage::

    from phantom.core.notifier import Notifier, WebhookChannel, SlackChannel

    n = Notifier()
    n.add_channel(WebhookChannel("https://example.com/hook"))
    n.add_channel(SlackChannel("https://hooks.slack.com/services/T00/B00/xxx"))
    n.notify_finding({"title": "SQL Injection", "severity": "critical", ...})
    n.notify_scan_complete(scan_id="abc", findings_count=5, critical=2)
"""

from __future__ import annotations

import json
import logging
import os
import ipaddress
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)


def _validate_url(url: str) -> bool:
    """Reject URLs pointing to private/loopback addresses (SSRF protection)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block obviously internal hostnames
        if hostname in ("localhost", "0.0.0.0"):
            return False
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return False
        except ValueError:
            pass  # hostname is a domain name, allow
        return True
    except Exception:
        return False


# ======================================================================
# Channel interface
# ======================================================================

class NotificationChannel(ABC):
    """Base class for notification delivery channels."""

    @abstractmethod
    def send(self, payload: dict[str, Any]) -> bool:
        """Deliver *payload*.  Return ``True`` on success."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ======================================================================
# Webhook channel (generic HTTP POST)
# ======================================================================

@dataclass
class WebhookChannel(NotificationChannel):
    """POST JSON to an arbitrary webhook URL."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_s: int = 10

    @property
    def name(self) -> str:
        return f"webhook:{self.url[:40]}"

    def send(self, payload: dict[str, Any]) -> bool:
        if not _validate_url(self.url):
            _logger.warning("Blocked webhook to private/internal URL: %s", self.url)
            return False
        try:
            body = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", **self.headers}
            req = urllib.request.Request(
                self.url, data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:
            _logger.warning("Webhook delivery failed for %s: %s", self.url, exc)
            return False


# ======================================================================
# Slack channel (Incoming Webhook)
# ======================================================================

@dataclass
class SlackChannel(NotificationChannel):
    """Send rich Slack messages via Incoming Webhook."""

    webhook_url: str
    channel: str = ""
    username: str = "Phantom Scanner"
    icon_emoji: str = ":ghost:"
    timeout_s: int = 10

    @property
    def name(self) -> str:
        return f"slack:{self.channel or 'default'}"

    def send(self, payload: dict[str, Any]) -> bool:
        slack_msg = self._format_slack(payload)
        try:
            body = json.dumps(slack_msg).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:
            _logger.warning("Slack delivery failed: %s", exc)
            return False

    def _format_slack(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Convert a Phantom notification payload into a Slack Block Kit message."""
        event_type = payload.get("event", "notification")
        text_fallback = payload.get("text", event_type)

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":ghost: Phantom — {event_type.replace('_', ' ').title()}",
                },
            }
        ]

        # Finding notification
        if event_type == "finding":
            finding = payload.get("finding", {})
            sev = (finding.get("severity") or "info").upper()
            colour_map = {
                "CRITICAL": ":red_circle:",
                "HIGH": ":large_orange_circle:",
                "MEDIUM": ":large_yellow_circle:",
                "LOW": ":large_blue_circle:",
            }
            icon = colour_map.get(sev, ":white_circle:")
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{icon} *{sev}* — {finding.get('title', 'N/A')}\n"
                            f"Endpoint: `{finding.get('endpoint', 'N/A')}`\n"
                            f"CVE: {finding.get('cve') or 'N/A'}"
                        ),
                    },
                }
            )

        # Scan complete
        elif event_type == "scan_complete":
            summary = payload.get("summary", {})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Scan ID:* {summary.get('scan_id', 'N/A')}\n"
                            f"*Findings:* {summary.get('findings_count', 0)}\n"
                            f"*Critical:* {summary.get('critical', 0)} | "
                            f"*High:* {summary.get('high', 0)}\n"
                            f"*Duration:* {summary.get('duration', 'N/A')}"
                        ),
                    },
                }
            )

        else:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": json.dumps(payload, indent=2)[:2900]},
                }
            )

        msg: dict[str, Any] = {"text": text_fallback, "blocks": blocks}
        if self.channel:
            msg["channel"] = self.channel
        if self.username:
            msg["username"] = self.username
        if self.icon_emoji:
            msg["icon_emoji"] = self.icon_emoji
        return msg


# ======================================================================
# Callable channel (for testing / custom pipelines)
# ======================================================================

@dataclass
class CallableChannel(NotificationChannel):
    """Invoke a user-supplied callable.  Useful for testing or piping to queues."""

    callback: Callable[[dict[str, Any]], bool] = field(default=lambda p: True)
    _name: str = "callable"

    @property
    def name(self) -> str:
        return self._name

    def send(self, payload: dict[str, Any]) -> bool:
        try:
            return bool(self.callback(payload))
        except Exception as exc:
            _logger.warning("Callable channel '%s' failed: %s", self._name, exc)
            return False


# ======================================================================
# Notifier — orchestrates multiple channels
# ======================================================================

class Notifier:
    """Fan-out notification dispatcher.

    Parameters:
        min_severity:  Only send finding alerts at or above this level.
                       One of ``critical``, ``high``, ``medium``, ``low``, ``info``.
    """

    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, *, min_severity: str = "high") -> None:
        self.channels: list[NotificationChannel] = []
        self.min_severity = min_severity.lower()
        self._sent_count = 0

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------

    def add_channel(self, channel: NotificationChannel) -> None:
        self.channels.append(channel)

    @classmethod
    def from_env(cls) -> "Notifier":
        """Auto-configure from environment variables.

        Supported env vars:
            ``PHANTOM_WEBHOOK_URL``  — generic webhook endpoint
            ``PHANTOM_SLACK_WEBHOOK`` — Slack incoming webhook URL
            ``PHANTOM_NOTIFY_SEVERITY`` — minimum severity (default ``high``)
        """
        severity = os.getenv("PHANTOM_NOTIFY_SEVERITY", "high")
        notifier = cls(min_severity=severity)

        webhook_url = os.getenv("PHANTOM_WEBHOOK_URL")
        if webhook_url:
            notifier.add_channel(WebhookChannel(url=webhook_url))

        slack_url = os.getenv("PHANTOM_SLACK_WEBHOOK")
        if slack_url:
            notifier.add_channel(
                SlackChannel(
                    webhook_url=slack_url,
                    channel=os.getenv("PHANTOM_SLACK_CHANNEL", ""),
                )
            )

        return notifier

    # ------------------------------------------------------------------
    # Notification methods
    # ------------------------------------------------------------------

    def notify_finding(self, finding: dict[str, Any]) -> int:
        """Send a finding alert if it meets the severity threshold.

        Returns the number of channels that received the notification.
        """
        sev = (finding.get("severity") or "info").lower()
        if self._SEVERITY_ORDER.get(sev, 0) < self._SEVERITY_ORDER.get(
            self.min_severity, 0
        ):
            return 0

        payload = {
            "event": "finding",
            "text": f"[{sev.upper()}] {finding.get('title', 'N/A')}",
            "finding": finding,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._fan_out(payload)

    def notify_scan_complete(
        self,
        *,
        scan_id: str = "",
        findings_count: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        duration: str = "",
    ) -> int:
        """Send a scan-completion summary to all channels."""
        payload = {
            "event": "scan_complete",
            "text": f"Scan {scan_id} complete — {findings_count} findings ({critical} critical)",
            "summary": {
                "scan_id": scan_id,
                "findings_count": findings_count,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "duration": duration,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._fan_out(payload)

    def notify_custom(self, event_name: str, data: dict[str, Any]) -> int:
        """Send an arbitrary custom notification."""
        payload = {
            "event": event_name,
            "text": event_name,
            **data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._fan_out(payload)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def sent_count(self) -> int:
        return self._sent_count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fan_out(self, payload: dict[str, Any]) -> int:
        delivered = 0
        for ch in self.channels:
            try:
                if ch.send(payload):
                    delivered += 1
            except Exception as exc:
                _logger.error("Channel %s failed: %s", ch.name, exc)
        self._sent_count += delivered
        return delivered
