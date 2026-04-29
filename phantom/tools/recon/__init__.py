"""
Phantom Reconnaissance Tools
============================

Active and passive reconnaissance tools for web application security testing.

Modules:
- js_analysis_actions: JavaScript endpoint and secret extraction
- directory_bruteforce: Directory and file enumeration

Usage:
    from phantom.tools.recon import comprehensive_js_analysis, comprehensive_dir_enum
    
    # JS Analysis
    result = await comprehensive_js_analysis("https://example.com")
    
    # Directory Enumeration
    result = await comprehensive_dir_enum("https://example.com", tech_stack=["php"])
"""

from phantom.tools.recon.js_analysis_actions import (
    comprehensive_js_analysis,
)

from phantom.tools.recon.directory_bruteforce import (
    comprehensive_dir_enum,
)

__all__ = [
    "comprehensive_js_analysis",
    "comprehensive_dir_enum",
]
