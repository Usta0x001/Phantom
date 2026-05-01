diff --git a/phantom/tools/payload_gen/__init__.py b/phantom/tools/payload_gen/__init__.py
index e4c9b70..35e77fa 100644
--- a/phantom/tools/payload_gen/__init__.py
+++ b/phantom/tools/payload_gen/__init__.py
@@ -13,17 +13,9 @@ SECURITY NOTES:
 """
 
 from phantom.tools.payload_gen.payload_gen_actions import (
-    generate_xss_payloads,
-    generate_sqli_payloads,
-    generate_xxe_payloads,
-    generate_ssti_payloads,
-    generate_cmd_injection_payloads,
+    generate_smart_payloads,
 )
 
 __all__ = [
-    "generate_xss_payloads",
-    "generate_sqli_payloads",
-    "generate_xxe_payloads",
-    "generate_ssti_payloads",
-    "generate_cmd_injection_payloads",
+    "generate_smart_payloads",
 ]
