diff --git a/phantom/tools/proxy/__init__.py b/phantom/tools/proxy/__init__.py
index 8785288..2c13f7c 100644
--- a/phantom/tools/proxy/__init__.py
+++ b/phantom/tools/proxy/__init__.py
@@ -1,20 +1,15 @@
 from .proxy_actions import (
     list_requests,
-    list_sitemap,
+    view_request,
+    send_request,
     repeat_request,
     scope_rules,
-    send_request,
-    view_request,
-    view_sitemap_entry,
 )
 
-
 __all__ = [
     "list_requests",
-    "list_sitemap",
+    "view_request",
+    "send_request",
     "repeat_request",
     "scope_rules",
-    "send_request",
-    "view_request",
-    "view_sitemap_entry",
 ]
