"""
Pentager imports for Phantom v2.

This module contains ports of Pentager's key efficiency features:
- Reflector pattern for empty responses

Import from: Pentager's Go codebase
"""
from phantom.llm.pentager.reflector import (
    Reflector,
    get_reflector,
)

__all__ = [
    "Reflector",
    "get_reflector",
]
