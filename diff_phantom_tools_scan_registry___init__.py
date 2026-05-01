diff --git a/phantom/tools/scan_registry/__init__.py b/phantom/tools/scan_registry/__init__.py
index 8fb3fea..7813a21 100644
--- a/phantom/tools/scan_registry/__init__.py
+++ b/phantom/tools/scan_registry/__init__.py
@@ -1,10 +1,12 @@
 from .scan_registry_actions import (
-    check_scan_registry,
-    register_scan_target,
+    is_registered,
+    register,
+    clear_registry,
 )
 
 
 __all__ = [
-    "check_scan_registry",
-    "register_scan_target",
+    "is_registered",
+    "register",
+    "clear_registry",
 ]
