diff --git a/phantom/llm/dedupe.py b/phantom/llm/dedupe.py
index 2766936..e066037 100644
--- a/phantom/llm/dedupe.py
+++ b/phantom/llm/dedupe.py
@@ -101,17 +101,17 @@ _REPORT_SANITIZATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
 
 def _sanitize_report_field(value: str) -> str:
     """SECURITY FIX: Sanitize report field to remove prompt injection attempts.
-    
+
     This prevents malicious vulnerability reports from injecting prompts that
     could manipulate the deduplication LLM into making incorrect decisions.
     """
     if not isinstance(value, str):
         return str(value) if value is not None else ""
-    
+
     sanitized = value
     for pattern, replacement in _REPORT_SANITIZATION_PATTERNS:
         sanitized = pattern.sub(replacement, sanitized)
-    
+
     return sanitized
 
 
@@ -212,7 +212,8 @@ def check_duplicate(
     if not has_any_surface_overlap and candidate_endpoint:
         logger.info(
             "A6: Heuristic dedupe skip ΓÇö no surface overlap for endpoint=%s param=%s",
-            candidate_endpoint[:60], candidate_param[:30],
+            candidate_endpoint[:60],
+            candidate_param[:30],
         )
         return {
             "is_duplicate": False,
@@ -247,9 +248,12 @@ def check_duplicate(
         # Fix 7: Use a dedicated cheaper model for deduplication if configured
         dedupe_model = Config.get("phantom_dedupe_llm")
         if dedupe_model:
-            litellm_model, dedupe_api_key = resolve_phantom_model(dedupe_model)
+            # FIX: resolve_phantom_model returns (api_model, canonical_model).
+            # The 2nd element is a model NAME, not an API key. Using it as api_key
+            # caused guaranteed auth failures, breaking deduplication entirely.
+            litellm_model, _canonical = resolve_phantom_model(dedupe_model)
             litellm_model = litellm_model or dedupe_model
-            api_key = dedupe_api_key or Config.get("phantom_dedupe_api_key") or api_key
+            api_key = Config.get("phantom_dedupe_api_key") or api_key
             api_base = Config.get("phantom_dedupe_api_base") or api_base
         else:
             litellm_model, _ = resolve_phantom_model(model_name)
@@ -297,12 +301,8 @@ def check_duplicate(
 
     except Exception as e:
         logger.exception("Error during vulnerability deduplication check")
-        return {
-            "is_duplicate": False,
-            "duplicate_id": "",
-            "confidence": 0.0,
-            "reason": f"Deduplication check failed: {e}",
-            "error": str(e),
-        }
+        # QUICK WIN: fail-closed ΓÇö if deduplication crashes, we MUST NOT accept
+        # the report blindly. Raise so the caller knows deduplication is broken.
+        raise RuntimeError(f"Deduplication subsystem failed: {e}") from e
     else:
         return result
