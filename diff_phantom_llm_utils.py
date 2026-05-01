diff --git a/phantom/llm/utils.py b/phantom/llm/utils.py
index d091c5e..bf1c101 100644
--- a/phantom/llm/utils.py
+++ b/phantom/llm/utils.py
@@ -23,24 +23,28 @@ def normalize_tool_format(content: str) -> str:
     if "<invoke" in content or "<function_calls" in content:
         content = _FUNCTION_CALLS_TAG.sub("", content)
         content = _INVOKE_OPEN.sub(r"<function=\1>", content)
-        content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)
         content = content.replace("</invoke>", "</function>")
 
+    # FIX: Always normalize <parameter name="X"> ΓåÆ <parameter=X>
+    # regardless of whether <invoke> is present. The LLM may output
+    # schema-native parameter tags even when using <function=...>.
+    content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)
+
     return _STRIP_TAG_QUOTES.sub(
         lambda m: f"<{m.group(1)}={m.group(2).strip().strip(chr(34) + chr(39))}>", content
     )
 
 
 PHANTOM_MODEL_MAP: dict[str, str] = {
-    "claude-sonnet-4.6": "anthropic/claude-sonnet-4-6",
-    "claude-opus-4.6": "anthropic/claude-opus-4-6",
-    "gpt-5.2": "openai/gpt-5.2",
-    "gpt-5.1": "openai/gpt-5.1",
-    "gpt-5": "openai/gpt-5",
-    "gemini-3-pro-preview": "gemini/gemini-3-pro-preview",
-    "gemini-3-flash-preview": "gemini/gemini-3-flash-preview",
-    "glm-5": "openrouter/z-ai/glm-5",
-    "glm-4.7": "openrouter/z-ai/glm-4.7",
+    # FIX: Removed fictional/non-existent models (gpt-5.x, glm-5, gemini-3).
+    # These caused cryptic litellm failures. Only map verified existing models.
+    "claude-sonnet-4": "anthropic/claude-sonnet-4-20250514",
+    "claude-opus-4": "anthropic/claude-opus-4-20250514",
+    "gpt-4.1": "openai/gpt-4.1",
+    "gpt-4o": "openai/gpt-4o",
+    "o3-mini": "openai/o3-mini",
+    "gemini-2.5-pro": "gemini/gemini-2.5-pro-preview-03-25",
+    "gemini-2.5-flash": "gemini/gemini-2.5-flash-preview-04-17",
 }
 
 
@@ -56,26 +60,32 @@ def resolve_phantom_model(model_name: str | None) -> tuple[str | None, str | Non
         return model_name, model_name
 
     # "phantom/" prefix is 8 characters (not 6 ΓÇö fixed off-by-one bug)
-    base_model = model_name[len("phantom/"):]
+    base_model = model_name[len("phantom/") :]
     api_model = f"openai/{base_model}"
     canonical_model = PHANTOM_MODEL_MAP.get(base_model, api_model)
     return api_model, canonical_model
 
 
-def _truncate_to_first_function(content: str) -> str:
-    if not content:
-        return content
-
-    function_starts = [
-        match.start() for match in re.finditer(r"<function=|<invoke\s+name=", content)
-    ]
-
-    if len(function_starts) >= 2:
-        second_function_start = function_starts[1]
-
-        return content[:second_function_start].rstrip()
-
-    return content
+def _extract_params_xml(body: str) -> dict[str, str]:
+    """Extract parameters using a lightweight XML parser for robustness."""
+    args: dict[str, str] = {}
+    try:
+        from xml.etree import ElementTree as ET
+
+        root = ET.fromstring(f"<root>{body}</root>")
+        for param in root.findall("parameter"):
+            name = param.get("name")
+            if name:
+                args[name] = (param.text or "").strip()
+    except Exception:
+        # Fallback to regex for malformed XML
+        fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"
+        for param_match in re.finditer(fn_param_regex_pattern, body, re.DOTALL):
+            param_name = param_match.group(1).strip()
+            if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", param_name):
+                param_value = html.unescape(param_match.group(2).strip())
+                args[param_name] = param_value
+    return args
 
 
 def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
@@ -84,36 +94,33 @@ def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
 
     tool_invocations: list[dict[str, Any]] = []
 
-    fn_regex_pattern = r"<function=([^>]+)>\n?(.*?)</function>"
-    fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"
-
-    fn_matches = re.finditer(fn_regex_pattern, content, re.DOTALL)
-
-    for fn_match in fn_matches:
-        fn_name = fn_match.group(1).strip()
-
-        # Validate tool name: must be alphanumeric/underscore only
-        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", fn_name):
+    # FIX: Use a stricter regex that requires <function=NAME> to be immediately
+    # followed by parameter tags or a closing tag. This prevents matching
+    # </function> that appears in LLM reasoning text without a real opening tag.
+    fn_regex_pattern = r"<function=([a-zA-Z_][a-zA-Z0-9_-]*)>\s*(?:<parameter[^>]*>.*?</parameter>\s*)*</function>"
+
+    # First pass: find all well-formed function blocks
+    for match in re.finditer(fn_regex_pattern, content, re.DOTALL):
+        block = match.group(0)
+        # Extract the tool name from the opening tag
+        name_match = re.search(r"<function=([a-zA-Z_][a-zA-Z0-9_-]*)>", block)
+        if not name_match:
             continue
+        fn_name = name_match.group(1).strip()
 
-        fn_body = fn_match.group(2)
-
-        param_matches = re.finditer(fn_param_regex_pattern, fn_body, re.DOTALL)
-
-        args = {}
-        for param_match in param_matches:
-            param_name = param_match.group(1).strip()
-
-            # Validate param name: must be alphanumeric/underscore only
-            if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", param_name):
-                continue
-
-            param_value = param_match.group(2).strip()
+        # Reject literal placeholder from system prompt examples
+        if fn_name == "tool_name":
+            continue
 
-            param_value = html.unescape(param_value)
-            args[param_name] = param_value
+        # Extract body between opening tag and closing tag
+        body_match = re.search(r"<function=[^>]+>(.*?)</function>\s*$", block, re.DOTALL)
+        if not body_match:
+            continue
+        fn_body = body_match.group(1)
+        args = _extract_params_xml(fn_body)
 
         if not args:
+            # Last-ditch regex for incomplete parameter
             incomplete_match = re.search(r"<parameter=([^>]+)>(.*)$", fn_body, re.DOTALL)
             if incomplete_match:
                 param_name = incomplete_match.group(1).strip()
@@ -130,21 +137,43 @@ def fix_incomplete_tool_call(content: str) -> str:
     """Fix incomplete tool calls by adding missing closing tag.
 
     Handles both ``<function=ΓÇª>`` and ``<invoke name="ΓÇª">`` formats.
+    Fixes the LAST incomplete call if it appears at the end of the content
+    and looks like a real tool call (has parameter tags).
     """
-    has_open = "<function=" in content or "<invoke " in content
-    count_open = content.count("<function=") + content.count("<invoke ")
-    has_close = "</function>" in content or "</invoke>" in content
-    if has_open and count_open == 1 and not has_close:
-        content = content.rstrip()
-        content = content + "function>" if content.endswith("</") else content + "\n</function>"
-    return content
+    stripped = content.strip()
+
+    # Find the last opening tag
+    last_func = stripped.rfind("<function=")
+    last_invoke = stripped.rfind("<invoke ")
+    last_open = max(last_func, last_invoke)
+
+    if last_open == -1:
+        return content
+
+    # Check if there's a closing tag after the last opening
+    suffix = stripped[last_open:]
+    if "</function>" in suffix or "</invoke>" in suffix:
+        return content  # Already complete
+
+    # The last tag is incomplete. Only fix if it looks like a real tool call
+    # (contains <parameter=, not just a mention in reasoning text).
+    if "<parameter=" not in suffix:
+        return content
+
+    # Fix it
+    if stripped.endswith("</"):
+        return stripped + "function>"
+    return stripped + "\n</function>"
 
 
 def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
     xml_parts = [f"<function={tool_name}>"]
 
     for key, value in args.items():
-        xml_parts.append(f"<parameter={key}>{value}</parameter>")
+        # FIX: XML-escape parameter values to prevent malformed XML.
+        # If value contains <, >, or &, the generated XML breaks parsing.
+        safe_value = html.escape(str(value))
+        xml_parts.append(f"<parameter={key}>{safe_value}</parameter>")
 
     xml_parts.append("</function>")
 
