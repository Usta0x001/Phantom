diff --git a/phantom/tools/response_analysis/response_analysis_actions.py b/phantom/tools/response_analysis/response_analysis_actions.py
index d1ef571..b2f0bb2 100644
--- a/phantom/tools/response_analysis/response_analysis_actions.py
+++ b/phantom/tools/response_analysis/response_analysis_actions.py
@@ -199,13 +199,13 @@ def _normalize_for_xss_check(text: str) -> str:
     # URL decode
     try:
         text = url_unquote(text)
-    except Exception:
+    except (TypeError, ValueError):
         pass
     
     # Decode common HTML entities
     try:
         text = html_module.unescape(text)
-    except Exception:
+    except (TypeError, ValueError):
         pass
     
     return text
@@ -267,7 +267,7 @@ def _check_reflection_with_context(content: str, payload: str) -> dict[str, Any]
                 "is_executable": ctx.is_executable,
                 "details": ctx.details,
             })
-    except Exception as e:
+    except (TypeError, ValueError, RecursionError) as e:
         logger.debug(f"HTML parsing failed: {e}")
     
     if not contexts:
@@ -590,7 +590,6 @@ async def analyze_response(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def detect_errors(
     content: str,
     error_types: list[str] | None = None,
@@ -619,8 +618,12 @@ async def detect_errors(
         
         for pattern_info in _ERROR_PATTERNS[error_type]:
             flags = pattern_info.get("flags", 0)
+            pattern = pattern_info["pattern"]
             try:
-                matches = re.findall(pattern_info["pattern"], content, flags)
+                full_matches = []
+                for match in re.finditer(pattern, content, flags):
+                    full_matches.append(match.group(0))
+                matches = full_matches
                 if matches:
                     error_data = {
                         "error_type": error_type,
@@ -659,7 +662,6 @@ async def detect_errors(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def extract_secrets(
     content: str,
     secret_types: list[str] | None = None,
@@ -712,7 +714,6 @@ async def extract_secrets(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def identify_tech_stack(
     content: str,
     headers: dict[str, str] | None = None,
