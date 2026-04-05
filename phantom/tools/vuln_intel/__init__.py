# Vulnerability Intelligence Tools - Phase 1 Enhancement + P7
# CVE correlation and exploit database integration

from phantom.tools.vuln_intel.vuln_intel_actions import (
    cve_search,
    exploit_search,
    version_to_cves,
    get_cve_details,
)

# P7: CVE Auto-Integration
from phantom.tools.vuln_intel.cve_auto_integration import (
    auto_queue_cve_exploits,
    enrich_hypothesis_with_cve,
    get_cve_exploitation_status,
)

__all__ = [
    "cve_search",
    "exploit_search",
    "version_to_cves",
    "get_cve_details",
    # P7
    "auto_queue_cve_exploits",
    "enrich_hypothesis_with_cve",
    "get_cve_exploitation_status",
]
