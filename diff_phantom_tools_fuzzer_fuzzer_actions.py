diff --git a/phantom/tools/fuzzer/fuzzer_actions.py b/phantom/tools/fuzzer/fuzzer_actions.py
index 3d4615d..abed52e 100644
--- a/phantom/tools/fuzzer/fuzzer_actions.py
+++ b/phantom/tools/fuzzer/fuzzer_actions.py
@@ -12,7 +12,8 @@ from phantom.tools.registry import register_tool
 InjectionPoint = Literal["param", "header", "body", "path"]
 
 
-@register_tool
+# NOTE: fuzzer module not available in sandbox container.
+# Re-add @register_tool decorator if container is rebuilt with fuzzer support.
 def execute_fuzz_batch(
     base_url: str,
     method: str,
@@ -65,43 +66,5 @@ def execute_fuzz_batch(
     )
 
 
-@register_tool
-def get_fuzz_results(
-    batch_id: str | None = None,
-) -> dict[str, Any]:
-    """
-    Get results from previous fuzz batches.
-
-    Use this to retrieve detailed results for analysis.
-
-    Args:
-        batch_id: Specific batch to retrieve, or None for all batches
-
-    Returns:
-        Fuzz results with status codes, response times, lengths, and markers
-    """
-    from .fuzzer_manager import get_fuzzer_manager
-
-    manager = get_fuzzer_manager()
-    return manager.get_results(batch_id=batch_id)
 
 
-@register_tool
-def clear_fuzz_results(
-    batch_id: str | None = None,
-) -> dict[str, Any]:
-    """
-    Clear fuzzing results to free memory.
-
-    Use this to clean up old batch results that are no longer needed.
-
-    Args:
-        batch_id: Specific batch to clear, or None to clear all
-
-    Returns:
-        Summary of cleared results
-    """
-    from .fuzzer_manager import get_fuzzer_manager
-
-    manager = get_fuzzer_manager()
-    return manager.clear_results(batch_id=batch_id)
