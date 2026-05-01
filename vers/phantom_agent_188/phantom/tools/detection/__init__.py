"""
Detection Module

Provides vulnerability detection and confirmation tools.
"""

from .detector import (
    VulnerabilityDetector,
    DetectionResult,
    DetectionType,
    detect_pattern,
    detect_error_based,
    detect_timing_based,
    detect_differential,
)

__all__ = [
    "VulnerabilityDetector",
    "DetectionResult",
    "DetectionType",
    "detect_pattern",
    "detect_error_based",
    "detect_timing_based",
    "detect_differential",
]
