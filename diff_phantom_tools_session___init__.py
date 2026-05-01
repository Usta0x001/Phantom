diff --git a/phantom/tools/session/__init__.py b/phantom/tools/session/__init__.py
index fe268d8..c418250 100644
--- a/phantom/tools/session/__init__.py
+++ b/phantom/tools/session/__init__.py
@@ -1,17 +1,11 @@
 from .session_actions import (
     clear_sessions,
     get_session,
-    session_get,
-    session_login,
-    session_refresh,
     store_session,
 )
 
 __all__ = [
     "clear_sessions",
     "get_session",
-    "session_get",
-    "session_login",
-    "session_refresh",
     "store_session",
 ]
