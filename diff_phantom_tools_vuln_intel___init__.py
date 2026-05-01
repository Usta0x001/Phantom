diff --git a/phantom/tools/vuln_intel/__init__.py b/phantom/tools/vuln_intel/__init__.py
index 297ad62..4a33597 100644
--- a/phantom/tools/vuln_intel/__init__.py
+++ b/phantom/tools/vuln_intel/__init__.py
@@ -1,4 +1,4 @@
-# Vulnerability Intelligence Tools - Phase 1 Enhancement + P7
+# Vulnerability Intelligence Tools - Phase 1 Enhancement
 # CVE correlation and exploit database integration
 
 from phantom.tools.vuln_intel.vuln_intel_actions import (
@@ -8,27 +8,9 @@ from phantom.tools.vuln_intel.vuln_intel_actions import (
     get_cve_details,
 )
 
-# P7: CVE Auto-Integration
-from phantom.tools.vuln_intel.cve_auto_integration import (
-    auto_queue_cve_exploits,
-    enrich_hypothesis_with_cve,
-    get_cve_exploitation_status,
-)
-
-from phantom.tools.vuln_intel.vuln_intel_actions import (
-    cve_search as _cve_search_import,
-    exploit_search as _exploit_search_import,
-    version_to_cves as _version_to_cves_import,
-    get_cve_details as _get_cve_details_import,
-)
-
 __all__ = [
     "cve_search",
     "exploit_search",
     "version_to_cves",
     "get_cve_details",
-    # P7
-    "auto_queue_cve_exploits",
-    "enrich_hypothesis_with_cve",
-    "get_cve_exploitation_status",
 ]
