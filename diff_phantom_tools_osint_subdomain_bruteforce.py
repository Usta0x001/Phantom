diff --git a/phantom/tools/osint/subdomain_bruteforce.py b/phantom/tools/osint/subdomain_bruteforce.py
index c1b524f..7e8a6fa 100644
--- a/phantom/tools/osint/subdomain_bruteforce.py
+++ b/phantom/tools/osint/subdomain_bruteforce.py
@@ -233,7 +233,6 @@ async def _detect_wildcard(domain: str) -> set[str]:
     return set()
 
 
-@register_tool(sandbox_execution=False)
 async def bruteforce_subdomains(
     domain: str,
     wordlist_path: str | None = None,
@@ -386,7 +385,6 @@ async def bruteforce_subdomains(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def smart_subdomain_gen(
     domain: str,
     tech_stack: list[str] | None = None,
@@ -599,7 +597,6 @@ async def smart_subdomain_gen(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def run_subdomain_tools(
     domain: str,
     tools: list[str] | None = None,
