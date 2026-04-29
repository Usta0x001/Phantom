"""
Scan tracking models
"""

from enum import Enum
from typing import Any
from datetime import datetime
from pydantic import BaseModel, Field


class ScanPhase(str, Enum):
    """Scan activity state — no waterfall phases."""
    ACTIVE = "active"
    COMPLETED = "completed"


class ScanStatus(str, Enum):
    """Overall scan status"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanResult(BaseModel):
    """Complete scan result metadata"""
    scan_id: str
    target: str | list[str]
    status: ScanStatus = ScanStatus.INITIALIZING
    phase: ScanPhase = ScanPhase.ACTIVE
    start_time: datetime | None = None
    end_time: datetime | None = None
    vuln_count: int = 0
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
