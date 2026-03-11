"""PostHog telemetry — permanently disabled (no-op stubs kept for import compatibility)."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phantom.telemetry.tracer import Tracer


def start(
    model: str | None = None,
    scan_mode: str | None = None,
    is_whitebox: bool = False,
    interactive: bool = True,
    has_instructions: bool = False,
) -> None:
    pass


def finding(severity: str) -> None:
    pass


def end(tracer: "Tracer", exit_reason: str = "completed") -> None:
    pass


def error(error_type: str, error_msg: str | None = None) -> None:
    pass
