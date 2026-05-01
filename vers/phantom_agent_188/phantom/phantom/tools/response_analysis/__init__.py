"""
Response Analysis Tools - Phase 2 Enhancement
==============================================

HTTP response analysis for vulnerability detection, error parsing,
and information disclosure identification.
"""

from phantom.tools.response_analysis.response_analysis_actions import (
    analyze_response,
    detect_errors,
    extract_secrets,
    identify_tech_stack,
)

__all__ = [
    "analyze_response",
    "detect_errors",
    "extract_secrets",
    "identify_tech_stack",
]
