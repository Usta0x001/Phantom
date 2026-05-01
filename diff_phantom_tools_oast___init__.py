diff --git a/phantom/tools/oast/__init__.py b/phantom/tools/oast/__init__.py
index 5a8beaa..958ecf2 100644
--- a/phantom/tools/oast/__init__.py
+++ b/phantom/tools/oast/__init__.py
@@ -14,13 +14,9 @@ Key features:
 from .oast_actions import (
     generate_oast_payload,
     check_oast_interactions,
-    list_oast_payloads,
-    clear_oast_payloads,
 )
 
 __all__ = [
     "generate_oast_payload",
     "check_oast_interactions",
-    "list_oast_payloads",
-    "clear_oast_payloads",
 ]
