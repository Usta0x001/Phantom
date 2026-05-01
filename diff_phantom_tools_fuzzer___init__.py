diff --git a/phantom/tools/fuzzer/__init__.py b/phantom/tools/fuzzer/__init__.py
index 8a208a7..2ba87e2 100644
--- a/phantom/tools/fuzzer/__init__.py
+++ b/phantom/tools/fuzzer/__init__.py
@@ -7,12 +7,8 @@ NO STATIC PAYLOAD LISTS - LLM creates all payloads.
 
 from .fuzzer_actions import (
     execute_fuzz_batch,
-    get_fuzz_results,
-    clear_fuzz_results,
 )
 
 __all__ = [
     "execute_fuzz_batch",
-    "get_fuzz_results",
-    "clear_fuzz_results",
 ]
