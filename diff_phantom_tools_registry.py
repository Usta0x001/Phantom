diff --git a/phantom/tools/registry.py b/phantom/tools/registry.py
index a783829..f56e26d 100644
--- a/phantom/tools/registry.py
+++ b/phantom/tools/registry.py
@@ -18,13 +18,12 @@ logger = logging.getLogger(__name__)
 
 RICH_TOOL_NAMES = {
     "create_vulnerability_report",
-    "create_elite_report",
     "generate_smart_payloads",
-    "auto_queue_cve_exploits",
     "agent_finish",
     "browser_action",
 }
 
+
 class ImplementedInClientSideOnlyError(Exception):
     def __init__(
         self,
@@ -49,10 +48,13 @@ def _process_dynamic_content(content: str) -> str:
             )
 
     return content
+
+
 _TOOL_BLOCK_RE = re.compile(r'<tool\b[^>]*\bname="([^"]+)"[^>]*>(.*?)</tool>', re.DOTALL)
-_PARAM_BLOCK_RE = re.compile(r'<parameter\b(?![^>]*\/>)' r'([^>]*)>(.*?)</parameter>', re.IGNORECASE | re.DOTALL)
-_SELF_CLOSING_PARAM_RE = re.compile(r'<parameter\b([^>]*)\s*/>', re.IGNORECASE | re.DOTALL)
-_EXAMPLE_BLOCK_RE = re.compile(r'<examples?>.*?</examples?>', re.IGNORECASE | re.DOTALL)
+_PARAM_BLOCK_RE = re.compile(
+    r"<parameter\b(?![^>]*\/>)" r"([^>]*)>(.*?)</parameter>", re.IGNORECASE | re.DOTALL
+)
+_SELF_CLOSING_PARAM_RE = re.compile(r"<parameter\b([^>]*)\s*/>", re.IGNORECASE | re.DOTALL)
 
 
 def _load_xml_schema(path: Path) -> Any:
@@ -62,7 +64,6 @@ def _load_xml_schema(path: Path) -> Any:
         content = path.read_text(encoding="utf-8")
 
         content = _process_dynamic_content(content)
-        content = _EXAMPLE_BLOCK_RE.sub("", content)
         tools_dict: dict[str, str] = {}
 
         for tool_match in _TOOL_BLOCK_RE.finditer(content):
@@ -105,7 +106,9 @@ def _parse_param_schema(tool_xml: str) -> dict[str, Any]:
         if required_match:
             is_required = required_match.group(1).strip().lower() == "true"
         else:
-            nested_required = re.search(r'<required>\s*(true|false)\s*</required>', body_text, re.IGNORECASE)
+            nested_required = re.search(
+                r"<required>\s*(true|false)\s*</required>", body_text, re.IGNORECASE
+            )
             if nested_required:
                 is_required = nested_required.group(1).strip().lower() == "true"
 
@@ -121,6 +124,28 @@ def _parse_param_schema(tool_xml: str) -> dict[str, Any]:
     return {"params": params, "required": required, "has_params": bool(params or required)}
 
 
+def _infer_param_schema_from_signature(func: Callable[..., Any]) -> dict[str, Any]:
+    params: set[str] = set()
+    required: set[str] = set()
+
+    try:
+        sig = signature(func)
+    except (TypeError, ValueError):
+        return {"params": set(), "required": set(), "has_params": False}
+
+    for name, param in sig.parameters.items():
+        if name == "agent_state":
+            continue
+        if param.kind in {param.VAR_POSITIONAL, param.VAR_KEYWORD}:
+            continue
+
+        params.add(name)
+        if param.default is inspect._empty:
+            required.add(name)
+
+    return {"params": params, "required": required, "has_params": bool(params or required)}
+
+
 def _get_module_name(func: Callable[..., Any]) -> str:
     module = inspect.getmodule(func)
     if not module:
@@ -213,7 +238,7 @@ def register_tool(
                     func_dict["xml_schema"] = schema_xml
                 else:
                     func_dict["xml_schema"] = (
-                        f'<tool name="{f.__name__}">' 
+                        f'<tool name="{f.__name__}">'
                         "<description>Schema not found for tool.</description>"
                         "</tool>"
                     )
@@ -228,6 +253,8 @@ def register_tool(
         if not sandbox_mode:
             xml_schema = func_dict.get("xml_schema")
             param_schema = _parse_param_schema(xml_schema if isinstance(xml_schema, str) else "")
+            if not param_schema.get("has_params"):
+                param_schema = _infer_param_schema_from_signature(f)
             _tool_param_schemas[str(func_dict["name"])] = param_schema
 
         tools.append(func_dict)
@@ -237,9 +264,11 @@ def register_tool(
         # returns True for async tools ΓÇö needed by tool_server._run_tool and
         # by _execute_tool_locally to correctly await results.
         if inspect.iscoroutinefunction(f):
+
             @wraps(f)
             async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                 return await f(*args, **kwargs)
+
             return async_wrapper
 
         @wraps(f)
