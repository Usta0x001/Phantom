diff --git a/phantom/tools/response_analysis/__init__.py b/phantom/tools/response_analysis/__init__.py
index 186ebca..35d349a 100644
--- a/phantom/tools/response_analysis/__init__.py
+++ b/phantom/tools/response_analysis/__init__.py
@@ -8,14 +8,8 @@ and information disclosure identification.
 
 from phantom.tools.response_analysis.response_analysis_actions import (
     analyze_response,
-    detect_errors,
-    extract_secrets,
-    identify_tech_stack,
 )
 
 __all__ = [
     "analyze_response",
-    "detect_errors",
-    "extract_secrets",
-    "identify_tech_stack",
 ]
