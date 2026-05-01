diff --git a/phantom/tools/recon/__init__.py b/phantom/tools/recon/__init__.py
index 010860c..4b95dae 100644
--- a/phantom/tools/recon/__init__.py
+++ b/phantom/tools/recon/__init__.py
@@ -19,36 +19,14 @@ Usage:
 """
 
 from phantom.tools.recon.js_analysis_actions import (
-    fetch_js_files,
-    extract_endpoints,
-    analyze_js_frameworks,
     comprehensive_js_analysis,
 )
 
 from phantom.tools.recon.directory_bruteforce import (
-    bruteforce_directories,
-    smart_path_gen,
-    recursive_dir_scan,
     comprehensive_dir_enum,
 )
 
-from phantom.tools.recon.js_analysis_actions import (
-    fetch_js_files as _fetch_js_files_import,
-    extract_endpoints as _extract_endpoints_import,
-    analyze_secrets as _analyze_secrets_import,
-    analyze_js_frameworks as _analyze_js_frameworks_import,
-    comprehensive_js_analysis as _comprehensive_js_analysis_import,
-)
-
 __all__ = [
-    # JS Analysis
-    "fetch_js_files",
-    "extract_endpoints",
-    "analyze_js_frameworks",
     "comprehensive_js_analysis",
-    # Directory Enumeration
-    "bruteforce_directories",
-    "smart_path_gen",
-    "recursive_dir_scan",
     "comprehensive_dir_enum",
 ]
