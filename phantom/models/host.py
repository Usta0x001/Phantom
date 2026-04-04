"""
Host models
"""

from typing import Any
from pydantic import BaseModel, Field


class Host(BaseModel):
    """Discovered host information"""
    ip: str
    hostname: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: dict[int, str] = Field(default_factory=dict)  # port -> service name
    os_info: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
