diff --git a/phantom/tools/vuln_intel/vuln_intel_actions.py b/phantom/tools/vuln_intel/vuln_intel_actions.py
index 3142b26..4ec40fa 100644
--- a/phantom/tools/vuln_intel/vuln_intel_actions.py
+++ b/phantom/tools/vuln_intel/vuln_intel_actions.py
@@ -199,7 +199,7 @@ async def cve_search(
         headers = {
             "User-Agent": "Phantom-Scanner/1.0",
         }
-        if api_key:
+        if api_key and api_key != "NOT_SET":
             headers["apiKey"] = api_key
         
         async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
@@ -384,8 +384,8 @@ async def exploit_search(
     try:
         # Try Vulners API first (if API key available)
         vulners_api_key = Config.get("phantom_vulners_api_key")
-        
-        if vulners_api_key:
+
+        if vulners_api_key and vulners_api_key != "NOT_SET":
             _rate_limit("vulners")
             
             async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
@@ -684,7 +684,7 @@ async def get_cve_details(cve_id: str) -> dict[str, Any]:
     try:
         api_key = Config.get("phantom_nvd_api_key")
         headers = {"User-Agent": "Phantom-Scanner/1.0"}
-        if api_key:
+        if api_key and api_key != "NOT_SET":
             headers["apiKey"] = api_key
         
         async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
