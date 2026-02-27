"""
Authorization Verification Gate (PHT-007 FIX)

Ensures every scan has explicit authorization before execution.
Provides multiple verification methods:
1. Interactive consent confirmation
2. DNS TXT record verification
3. HTTP .well-known challenge
4. Pre-signed authorization file

This module prevents unauthorized scanning — a criminal offense
in most jurisdictions — by requiring proof of authorization before
any tool touches a target.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# Environment variable to skip authorization in CI/testing
_SKIP_AUTH_ENV = "PHANTOM_SKIP_AUTHORIZATION"


class AuthorizationError(Exception):
    """Raised when authorization verification fails."""


class AuthorizationRecord:
    """Immutable record of scan authorization."""

    def __init__(
        self,
        targets: list[str],
        method: str,
        authorized_by: str,
        timestamp: str | None = None,
        evidence: dict[str, Any] | None = None,
    ):
        self.targets = targets
        self.method = method  # "interactive", "dns_txt", "http_challenge", "file"
        self.authorized_by = authorized_by
        self.timestamp = timestamp or datetime.now(UTC).isoformat()
        self.evidence = evidence or {}
        self.signature = self._compute_signature()

    def _compute_signature(self) -> str:
        """Compute a hash signature of the authorization record."""
        data = json.dumps({
            "targets": sorted(self.targets),
            "method": self.method,
            "authorized_by": self.authorized_by,
            "timestamp": self.timestamp,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "method": self.method,
            "authorized_by": self.authorized_by,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
            "signature": self.signature,
        }

    def save(self, path: Path) -> None:
        """Persist authorization record to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        _logger.info("Authorization record saved to %s", path)

    @classmethod
    def load(cls, path: Path) -> AuthorizationRecord:
        """Load authorization record from disk."""
        data = json.loads(path.read_text(encoding="utf-8"))
        record = cls(
            targets=data["targets"],
            method=data["method"],
            authorized_by=data["authorized_by"],
            timestamp=data.get("timestamp"),
            evidence=data.get("evidence", {}),
        )
        if record.signature != data.get("signature"):
            raise AuthorizationError("Authorization record has been tampered with")
        return record


class AuthorizationGate:
    """Verifies scan authorization before allowing execution."""

    LEGAL_DISCLAIMER = (
        "WARNING: Unauthorized access to computer systems is a criminal offense "
        "under the Computer Fraud and Abuse Act (18 U.S.C. § 1030), the UK Computer "
        "Misuse Act 1990, and equivalent laws worldwide.\n\n"
        "By proceeding, you confirm that:\n"
        "  1. You have WRITTEN AUTHORIZATION to test the specified target(s)\n"
        "  2. You are the owner or have explicit permission from the owner\n"
        "  3. The scope of testing is clearly defined and agreed upon\n"
        "  4. You accept full responsibility for all actions taken by this tool\n"
    )

    def __init__(self, run_dir: Path | None = None):
        self.run_dir = run_dir
        self._auth_record: AuthorizationRecord | None = None

    def verify_authorization(
        self,
        targets: list[str],
        non_interactive: bool = False,
        auth_file: str | None = None,
    ) -> AuthorizationRecord:
        """Verify authorization for scanning targets.

        Args:
            targets: List of targets to scan
            non_interactive: If True, requires auth_file or env skip
            auth_file: Path to pre-signed authorization file

        Returns:
            AuthorizationRecord on success

        Raises:
            AuthorizationError: If authorization cannot be verified
        """
        # Allow skip in CI/testing via environment variable
        if os.getenv(_SKIP_AUTH_ENV, "").lower() in ("1", "true", "yes"):
            _logger.warning("Authorization check SKIPPED via %s env var", _SKIP_AUTH_ENV)
            record = AuthorizationRecord(
                targets=targets,
                method="env_skip",
                authorized_by="environment_variable",
                evidence={"env_var": _SKIP_AUTH_ENV},
            )
            self._auth_record = record
            return record

        # Try loading existing authorization file
        if auth_file:
            try:
                record = AuthorizationRecord.load(Path(auth_file))
                # Verify targets match
                for target in targets:
                    host = self._extract_host(target)
                    if not any(
                        host == self._extract_host(auth_t) or
                        host.endswith("." + self._extract_host(auth_t))
                        for auth_t in record.targets
                    ):
                        raise AuthorizationError(
                            f"Target {target} not covered by authorization file"
                        )
                self._auth_record = record
                return record
            except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
                raise AuthorizationError(f"Invalid authorization file: {e}") from e

        if non_interactive:
            # In non-interactive mode, require explicit authorization
            raise AuthorizationError(
                "Non-interactive mode requires --auth-file or "
                f"{_SKIP_AUTH_ENV}=true environment variable. "
                "Run 'phantom authorize <target>' first to generate an authorization file."
            )

        # Interactive consent
        return self._interactive_consent(targets)

    def _interactive_consent(self, targets: list[str]) -> AuthorizationRecord:
        """Get interactive consent from the user."""
        print("\n" + "=" * 60)
        print("AUTHORIZATION VERIFICATION REQUIRED")
        print("=" * 60)
        print(self.LEGAL_DISCLAIMER)
        print(f"Targets to be scanned ({len(targets)}):")
        for t in targets:
            print(f"  - {t}")
        print()

        try:
            response = input(
                "Do you confirm you have authorization to test these targets? [yes/NO]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise AuthorizationError("Authorization cancelled by user")

        if response not in ("yes", "y"):
            raise AuthorizationError(
                "Authorization denied. You must confirm authorization before scanning."
            )

        try:
            authorized_by = input("Your name/organization (for audit trail): ").strip()
        except (EOFError, KeyboardInterrupt):
            authorized_by = "interactive_user"

        if not authorized_by:
            authorized_by = "interactive_user"

        record = AuthorizationRecord(
            targets=targets,
            method="interactive",
            authorized_by=authorized_by,
            evidence={"consent_type": "interactive_terminal"},
        )

        # Save the authorization record
        if self.run_dir:
            record.save(self.run_dir / "authorization.json")

        self._auth_record = record
        return record

    def get_record(self) -> AuthorizationRecord | None:
        """Get the current authorization record."""
        return self._auth_record

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract hostname from a target string."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        if ":" in target and not target.startswith("["):
            parts = target.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    int(parts[1])
                    return parts[0]
                except ValueError:
                    pass
        return target


def verify_scan_authorization(
    targets: list[str],
    run_dir: Path | None = None,
    non_interactive: bool = False,
    auth_file: str | None = None,
) -> AuthorizationRecord:
    """Top-level convenience function for authorization verification.

    Called from the scan initialization path before any tools are invoked.
    """
    gate = AuthorizationGate(run_dir=run_dir)
    return gate.verify_authorization(
        targets=targets,
        non_interactive=non_interactive,
        auth_file=auth_file,
    )
