diff --git a/phantom/tools/dynamic_tools.py b/phantom/tools/dynamic_tools.py
index ee73e93..0d3f9c6 100644
--- a/phantom/tools/dynamic_tools.py
+++ b/phantom/tools/dynamic_tools.py
@@ -43,36 +43,12 @@ TOOL_CATEGORIES = {
         "search_files",
         "str_replace_editor",
     ],
-    "notes": [
-        "create_note",
-        "list_notes",
-        "update_note",
-        "delete_note",
-    ],
-    "todo": [
-        "create_todo",
-        "list_todos",
-        "update_todo",
-        "delete_todo",
-    ],
-    "thinking": [
-        "think",
-    ],
     "web_search": [
         "web_search",
     ],
     "python": [
         "python_action",
     ],
-    "session": [
-        "session_login",
-        "session_get",
-        "session_refresh",
-    ],
-    "scan_registry": [
-        "check_scan_registry",
-        "register_scan_target",
-    ],
     "memory": [
         "get_scan_status",
         "add_hypothesis",
@@ -96,7 +72,6 @@ TOOL_SUBSET_CATEGORIES = {
         "agent_management",
         "memory",
         "files",
-        "thinking",
         "python",
     ],
     "core-fast": [
@@ -117,7 +92,6 @@ TOOL_SUBSET_CATEGORIES = {
         "agent_management",
         "memory",
         "files",
-        "thinking",
         "python",
         "web_search",
     ],
@@ -128,7 +102,16 @@ DEFAULT_TOOL_CATEGORIES = {
     # FIX-5: Excluded 'files', 'notes', 'todo' from the default main_agent schema.
     # These are low-signal for pentesting but cost ~5K tokens per LLM call to describe.
     # 300 iterations * 5K tokens = 1.5M tokens saved per scan.
-    "main_agent": ["web_testing", "terminal", "browser", "reporting", "agent_management", "memory", "files", "notes", "todo"],
+    # notes and todo excluded: low pentesting signal, ~4K tokens wasted per call
+    "main_agent": [
+        "web_testing",
+        "terminal",
+        "browser",
+        "reporting",
+        "agent_management",
+        "memory",
+        "files",
+    ],
     "sub_agent": ["web_testing", "terminal", "browser", "files", "memory"],
     "quick_scan": ["web_testing", "terminal", "reporting", "memory"],
 }
@@ -142,47 +125,51 @@ def get_tools_for_context(
 ) -> list[str]:
     """
     Select tools based on agent context available at init time.
-    
+
     This is the key integration point - it uses available context to choose
     a minimal but sufficient tool set instead of loading all 37 tools.
     """
     _excluded = set(excluded_modules or [])
-    
+
     # Determine which categories to include
     categories = set()
-    
+
     if is_subagent:
-        categories.update(DEFAULT_TOOL_CATEGORIES.get("sub_agent", DEFAULT_TOOL_CATEGORIES["main_agent"]))
+        categories.update(
+            DEFAULT_TOOL_CATEGORIES.get("sub_agent", DEFAULT_TOOL_CATEGORIES["main_agent"])
+        )
     elif scan_mode == "quick":
-        categories.update(DEFAULT_TOOL_CATEGORIES.get("quick_scan", DEFAULT_TOOL_CATEGORIES["main_agent"]))
+        categories.update(
+            DEFAULT_TOOL_CATEGORIES.get("quick_scan", DEFAULT_TOOL_CATEGORIES["main_agent"])
+        )
     else:
-        categories.update(DEFAULT_TOOL_CATEGORIES.get("main_agent", DEFAULT_TOOL_CATEGORIES["main_agent"]))
-    
+        categories.update(
+            DEFAULT_TOOL_CATEGORIES.get("main_agent", DEFAULT_TOOL_CATEGORIES["main_agent"])
+        )
+
     # Handle excluded modules from the caller
     if "finish" in _excluded or "reporting" in _excluded:
         categories.discard("reporting")
-    if "todo" in _excluded:
-        categories.discard("todo")
-    if "notes" in _excluded:
-        categories.discard("notes")
-    
+
     # Collect tools from selected categories
     needed_tools = set()
     for cat in categories:
         if cat in TOOL_CATEGORIES:
             needed_tools.update(TOOL_CATEGORIES[cat])
-    
+
     return list(needed_tools)
 
 
-def get_tools_for_task(task_description: str, available_tools: list[str] | None = None) -> list[str]:
+def get_tools_for_task(
+    task_description: str, available_tools: list[str] | None = None
+) -> list[str]:
     """
     Analyze the task description and return only the tools needed.
-    
+
     This uses simple keyword matching to determine which tools are relevant.
     """
     task_lower = task_description.lower()
-    
+
     # Map keywords to tool categories
     keyword_map = {
         "sqli": ["web_testing", "terminal"],
@@ -226,25 +213,29 @@ def get_tools_for_task(task_description: str, available_tools: list[str] | None
         "pollution": ["web_testing", "browser"],
         "web": ["web_testing", "browser"],
     }
-    
+
     # Determine which categories to include
     categories = set()
-    categories.add("agent_management")  # Always include for orchestration
-    
+    # Only include agent_management for orchestrator/coordinator tasks, not leaf agents.
+    # Leaf agents (fuzzing, validation) don't need create_agent/view_agent_graph.
+    orchestrator_keywords = ["scan", "agent", "spawn", "coordinat", "orchestrat"]
+    if any(kw in task_lower for kw in orchestrator_keywords):
+        categories.add("agent_management")
+
     for keyword, cats in keyword_map.items():
         if keyword in task_lower:
             categories.update(cats)
-    
+
     # Collect tools from selected categories
     needed_tools = set()
     for cat in categories:
         if cat in TOOL_CATEGORIES:
             needed_tools.update(TOOL_CATEGORIES[cat])
-    
+
     # If available_tools specified, filter to only those
     if available_tools:
         needed_tools = needed_tools.intersection(set(available_tools))
-    
+
     return list(needed_tools)
 
 
@@ -298,26 +289,39 @@ def get_minimal_tools() -> list[str]:
     ]
 
 
-def get_tools_prompt_subset(tool_names: list[str]) -> str:
+def get_tools_prompt_subset(tool_names: list[str], use_compact: bool = True) -> str:
     """
     Get tool schemas for only the specified tools.
-    
-    This is the key function that replaces the full get_tools_prompt().
+
+    use_compact=True (default): single-line compact entries (~60-100 chars each)
+    use_compact=False: full verbose XML schema entries (~500-2000 chars each)
+
+    Compact format: 10-15 tools per 1K chars ΓåÆ 109 tools Γëê 7-10K chars (2K tokens)
+    XML format: ~500-1000 chars per tool ΓåÆ 109 tools Γëê 55-110K chars (14-27K tokens)
+
+    Compact mode enables ALL 109 registered tools within a ~10K token budget.
     """
+    if not tool_names:
+        return "<tool_catalog_note>No tools available.</tool_catalog_note>"
+
+    if use_compact:
+        return get_compact_tools_prompt_subset(list(tool_names))
+
     from phantom.tools.registry import tools
-    
-    xml_sections = []
-    
-    # Group tools by module
+
+    tool_name_set = set(str(n) for n in tool_names)
+    by_name = {str(t.get("name", "")): t for t in tools}
+
     tools_by_module: dict[str, list[dict[str, Any]]] = {}
-    
     for tool in tools:
-        if tool.get("name") in tool_names:
+        name = str(tool.get("name", ""))
+        if name in tool_name_set:
             module = tool.get("module", "unknown")
             if module not in tools_by_module:
                 tools_by_module[module] = []
             tools_by_module[module].append(tool)
-    
+
+    xml_sections = []
     for module, module_tools in sorted(tools_by_module.items()):
         section_parts = [f"<!-- {module} tools -->"]
         for tool in module_tools:
@@ -327,12 +331,14 @@ def get_tools_prompt_subset(tool_names: list[str]) -> str:
                 section_parts.append(indented_tool)
         section_parts.append(f"<!-- end {module} tools -->")
         xml_sections.append("\n".join(section_parts))
-    
+
     return "\n\n".join(xml_sections)
 
 
 _TOOL_NAME_RE = re.compile(r'<tool\b[^>]*\bname="([^"]+)"', re.IGNORECASE)
-_TAG_TEXT_RE = re.compile(r'<(?P<tag>description|details)\b[^>]*>(.*?)</(?P=tag)>', re.IGNORECASE | re.DOTALL)
+_TAG_TEXT_RE = re.compile(
+    r"<(?P<tag>description|details)\b[^>]*>(.*?)</(?P=tag)>", re.IGNORECASE | re.DOTALL
+)
 _PARAM_RE = re.compile(
     r'<parameter\b[^>]*\bname="([^"]+)"[^>]*\brequired="([^"]+)"',
     re.IGNORECASE,
@@ -341,17 +347,17 @@ _PARAM_RE = re.compile(
 
 def _normalize_prompt_text(text: str, max_chars: int = 140) -> str:
     text = html_unescape(text)
-    text = re.sub(r'<[^>]+>', ' ', text)
-    text = re.sub(r'\s+', ' ', text).strip()
-    text = text.replace('<', '').replace('>', '')
+    text = re.sub(r"<[^>]+>", " ", text)
+    text = re.sub(r"\s+", " ", text).strip()
+    text = text.replace("<", "").replace(">", "")
     if len(text) > max_chars:
-        text = text[: max_chars - 1].rstrip() + 'ΓÇª'
+        text = text[: max_chars - 1].rstrip() + "ΓÇª"
     return text
 
 
 def _first_tag_text(xml: str, tag: str) -> str:
     match = re.search(
-        rf'<{tag}\b[^>]*>(.*?)</{tag}>',
+        rf"<{tag}\b[^>]*>(.*?)</{tag}>",
         xml,
         re.IGNORECASE | re.DOTALL,
     )
@@ -399,8 +405,12 @@ def _compact_tool_entry(tool: dict[str, Any]) -> str:
 
         param_schema = get_tool_param_schema(tool_name) or {}
         required_params = sorted(str(p) for p in param_schema.get("required", set()))
-        optional_params = sorted(str(p) for p in param_schema.get("params", set()) - param_schema.get("required", set()))
-        params = [(name, True) for name in required_params] + [(name, False) for name in optional_params]
+        optional_params = sorted(
+            str(p) for p in param_schema.get("params", set()) - param_schema.get("required", set())
+        )
+        params = [(name, True) for name in required_params] + [
+            (name, False) for name in optional_params
+        ]
 
     param_text = ", ".join(f"{name}{'*' if required else ''}" for name, required in params)
     example = _build_compact_tool_example(tool_name, params)
@@ -416,11 +426,7 @@ def get_compact_tools_prompt_subset(tool_names: list[str]) -> str:
 
     selected = [name for name in tool_names if name]
     by_name = {str(tool.get("name")): tool for tool in tools}
-    entries = [
-        _compact_tool_entry(by_name[name])
-        for name in selected
-        if name in by_name
-    ]
+    entries = [_compact_tool_entry(by_name[name]) for name in selected if name in by_name]
 
     if not entries:
         return "<tool_catalog_note>Use exact tool names. * = required. Example shows the canonical call form.</tool_catalog_note>"
