diff --git a/phantom/tools/recon/js_analysis_actions.py b/phantom/tools/recon/js_analysis_actions.py
index 7064eb3..ec1638e 100644
--- a/phantom/tools/recon/js_analysis_actions.py
+++ b/phantom/tools/recon/js_analysis_actions.py
@@ -542,7 +542,6 @@ def _detect_frameworks(content: str) -> list[FrameworkInfo]:
 # Tool Implementations
 # ============================================================================
 
-@register_tool(sandbox_execution=False)
 async def fetch_js_files(
     url: str,
     use_browser: bool = False,
@@ -694,7 +693,6 @@ async def fetch_js_files(
         }
 
 
-@register_tool(sandbox_execution=False)
 async def extract_endpoints(
     content: str | None = None,
     url: str | None = None,
@@ -785,7 +783,6 @@ async def extract_endpoints(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def analyze_secrets(
     content: str | None = None,
     url: str | None = None,
@@ -868,7 +865,6 @@ async def analyze_secrets(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def analyze_js_frameworks(
     content: str | None = None,
     url: str | None = None,
