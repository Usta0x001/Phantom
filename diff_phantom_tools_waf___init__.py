diff --git a/phantom/tools/waf/__init__.py b/phantom/tools/waf/__init__.py
index 1ce12d2..1ef258d 100644
--- a/phantom/tools/waf/__init__.py
+++ b/phantom/tools/waf/__init__.py
@@ -3,10 +3,8 @@
 
 from phantom.tools.waf.waf_actions import (
     detect_waf,
-    get_waf_evasion_strategies,
 )
 
 __all__ = [
     "detect_waf",
-    "get_waf_evasion_strategies",
 ]
