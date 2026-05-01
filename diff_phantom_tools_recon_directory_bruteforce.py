diff --git a/phantom/tools/recon/directory_bruteforce.py b/phantom/tools/recon/directory_bruteforce.py
index 7969394..0f1eae1 100644
--- a/phantom/tools/recon/directory_bruteforce.py
+++ b/phantom/tools/recon/directory_bruteforce.py
@@ -482,7 +482,6 @@ async def _get_baseline_response(client: httpx.AsyncClient, base_url: str) -> in
 # Tool Implementations
 # ============================================================================
 
-@register_tool(sandbox_execution=False)
 async def bruteforce_directories(
     url: str,
     wordlist_path: str | None = None,
@@ -646,7 +645,6 @@ async def bruteforce_directories(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def smart_path_gen(
     url: str,
     tech_stack: list[str] | None = None,
@@ -774,7 +772,6 @@ async def smart_path_gen(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def recursive_dir_scan(
     url: str,
     max_depth: int = 3,
