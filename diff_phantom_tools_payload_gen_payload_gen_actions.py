diff --git a/phantom/tools/payload_gen/payload_gen_actions.py b/phantom/tools/payload_gen/payload_gen_actions.py
index f519728..b0e3542 100644
--- a/phantom/tools/payload_gen/payload_gen_actions.py
+++ b/phantom/tools/payload_gen/payload_gen_actions.py
@@ -1247,7 +1247,6 @@ async def generate_smart_payloads(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def generate_xss_payloads(
     context: str = "html",
     waf_type: str | None = None,
@@ -1312,7 +1311,6 @@ async def generate_xss_payloads(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def generate_sqli_payloads(
     db_type: str = "all",
     injection_type: str = "all",
@@ -1383,7 +1381,6 @@ async def generate_sqli_payloads(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def generate_xxe_payloads(
     target_os: str = "linux",
     xxe_type: str = "all",
@@ -1460,7 +1457,6 @@ async def generate_xxe_payloads(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def generate_ssti_payloads(
     template_engine: str = "all",
     payload_type: str = "all",
@@ -1535,7 +1531,6 @@ async def generate_ssti_payloads(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def generate_cmd_injection_payloads(
     target_os: str = "linux",
     injection_type: str = "all",
