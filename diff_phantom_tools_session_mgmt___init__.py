diff --git a/phantom/tools/session_mgmt/__init__.py b/phantom/tools/session_mgmt/__init__.py
index 68b2e2f..b576968 100644
--- a/phantom/tools/session_mgmt/__init__.py
+++ b/phantom/tools/session_mgmt/__init__.py
@@ -9,7 +9,6 @@ Manages cookies, tokens, and session state across requests.
 from phantom.tools.session_mgmt.session_mgmt_actions import (
     create_session,
     update_session,
-    get_session_info,
     extract_csrf_token,
     manage_cookies,
 )
@@ -17,20 +16,13 @@ from phantom.tools.session_mgmt.session_mgmt_actions import (
 from phantom.tools.session_mgmt.auth_automation import (
     automate_login,
     refresh_jwt_token,
-    extract_jwt_from_response,
-    check_jwt_expiration,
-    multi_step_login,
 )
 
 __all__ = [
     "create_session",
     "update_session",
-    "get_session_info",
     "extract_csrf_token",
     "manage_cookies",
     "automate_login",
     "refresh_jwt_token",
-    "extract_jwt_from_response",
-    "check_jwt_expiration",
-    "multi_step_login",
 ]
