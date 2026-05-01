diff --git a/phantom/tools/browser/browser_actions.py b/phantom/tools/browser/browser_actions.py
index af6e09c..f0ce330 100644
--- a/phantom/tools/browser/browser_actions.py
+++ b/phantom/tools/browser/browser_actions.py
@@ -1,12 +1,8 @@
-import importlib.util
 from typing import TYPE_CHECKING, Any, Literal, NoReturn
 
 from phantom.tools.registry import register_tool
 
 
-_PLAYWRIGHT_AVAILABLE = importlib.util.find_spec("playwright") is not None
-
-
 if TYPE_CHECKING:
     from .tab_manager import BrowserTabManager
 
@@ -33,11 +29,6 @@ BrowserAction = Literal[
     "view_source",
     "close",
     "list_tabs",
-    # CSS Selector-based actions (more reliable than coordinates)
-    "click_selector",
-    "fill_selector",
-    "wait_for_selector",
-    "query_selector_all",
 ]
 
 
@@ -81,37 +72,6 @@ def _validate_file_path(action_name: str, file_path: str | None) -> None:
         raise ValueError(f"file_path parameter is required for {action_name} action")
 
 
-def _validate_selector(action_name: str, selector: str | None) -> None:
-    if not selector:
-        raise ValueError(f"selector parameter is required for {action_name} action")
-
-
-def _resolve_action_name(
-    action: str,
-    coordinate: str | None = None,
-    selector: str | None = None,
-) -> str:
-    action_name = (action or "").strip().strip('"').strip("'").strip().lower()
-
-    alias_map = {
-        "fill": "fill_selector",
-        "input": "fill_selector",
-        "type_selector": "fill_selector",
-        "click_element": "click_selector",
-        "tap_selector": "click_selector",
-        "wait_selector": "wait_for_selector",
-        "query_selector": "query_selector_all",
-    }
-    action_name = alias_map.get(action_name, action_name)
-
-    if action_name == "click" and not coordinate and selector:
-        return "click_selector"
-    if action_name == "type" and selector:
-        return "fill_selector"
-
-    return action_name
-
-
 def _handle_navigation_actions(
     manager: "BrowserTabManager",
     action: str,
@@ -122,6 +82,7 @@ def _handle_navigation_actions(
         return manager.launch_browser(url)
     if action == "goto":
         _validate_url(action, url)
+        assert url is not None
         return manager.goto_url(url, tab_id)
     if action == "back":
         return manager.back(tab_id)
@@ -140,6 +101,7 @@ def _handle_interaction_actions(
 ) -> dict[str, Any]:
     if action in {"click", "double_click", "hover"}:
         _validate_coordinate(action, coordinate)
+        assert coordinate is not None
         action_map = {
             "click": manager.click,
             "double_click": manager.double_click,
@@ -153,9 +115,11 @@ def _handle_interaction_actions(
 
     if action == "type":
         _validate_text(action, text)
+        assert text is not None
         return manager.type_text(text, tab_id)
     if action == "press_key":
         _validate_key(action, key)
+        assert key is not None
         return manager.press_key(key, tab_id)
 
     raise ValueError(f"Unknown interaction action: {action}")
@@ -175,9 +139,11 @@ def _handle_tab_actions(
         return manager.new_tab(url)
     if action == "switch_tab":
         _validate_tab_id(action, tab_id)
+        assert tab_id is not None
         return manager.switch_tab(tab_id)
     if action == "close_tab":
         _validate_tab_id(action, tab_id)
+        assert tab_id is not None
         return manager.close_tab(tab_id)
     if action == "list_tabs":
         return manager.list_tabs()
@@ -195,12 +161,15 @@ def _handle_utility_actions(
 ) -> dict[str, Any]:
     if action == "wait":
         _validate_duration(action, duration)
+        assert duration is not None
         return manager.wait_browser(duration, tab_id)
     if action == "execute_js":
         _validate_js_code(action, js_code)
+        assert js_code is not None
         return manager.execute_js(js_code, tab_id)
     if action == "save_pdf":
         _validate_file_path(action, file_path)
+        assert file_path is not None
         return manager.save_pdf(file_path, tab_id)
     if action == "get_console_logs":
         return manager.get_console_logs(tab_id, clear)
@@ -211,40 +180,7 @@ def _handle_utility_actions(
     raise ValueError(f"Unknown utility action: {action}")
 
 
-def _handle_selector_actions(
-    manager: "BrowserTabManager",
-    action: str,
-    selector: str | None = None,
-    text: str | None = None,
-    tab_id: str | None = None,
-    timeout: float | None = None,
-    wait_state: str | None = None,
-) -> dict[str, Any]:
-    """Handle CSS selector-based browser actions."""
-    _validate_selector(action, selector)
-
-    # Default timeout is 5 seconds for most actions, 10 for wait_for_selector
-    default_timeout = 10.0 if action == "wait_for_selector" else 5.0
-    effective_timeout = timeout if timeout is not None else default_timeout
-
-    if action == "click_selector":
-        return manager.click_selector(selector, tab_id, effective_timeout)
-
-    if action == "fill_selector":
-        _validate_text(action, text)
-        return manager.fill_selector(selector, text, tab_id, effective_timeout)
-
-    if action == "wait_for_selector":
-        effective_state = wait_state if wait_state else "visible"
-        return manager.wait_for_selector(selector, tab_id, effective_timeout, effective_state)
-
-    if action == "query_selector_all":
-        return manager.query_selector_all(selector, tab_id)
-
-    raise ValueError(f"Unknown selector action: {action}")
-
-
-@register_tool(sandbox_execution=False)
+@register_tool(sandbox_execution=True)
 def browser_action(
     action: BrowserAction,
     url: str | None = None,
@@ -256,23 +192,10 @@ def browser_action(
     key: str | None = None,
     file_path: str | None = None,
     clear: bool = False,
-    # CSS Selector parameters
-    selector: str | None = None,
-    timeout: float | None = None,
-    wait_state: str | None = None,
 ) -> dict[str, Any]:
-    if not _PLAYWRIGHT_AVAILABLE:
-        return {
-            "error": "Playwright is not installed. Install with: pip install playwright",
-            "tab_id": tab_id,
-            "screenshot": "",
-            "is_running": False,
-        }
-
     from .tab_manager import get_browser_tab_manager
 
     manager = get_browser_tab_manager()
-    resolved_action = _resolve_action_name(action, coordinate, selector)
 
     try:
         navigation_actions = {"launch", "goto", "back", "forward"}
@@ -294,48 +217,19 @@ def browser_action(
             "view_source",
             "close",
         }
-        selector_actions = {
-            "click_selector",
-            "fill_selector",
-            "wait_for_selector",
-            "query_selector_all",
-        }
 
-        if resolved_action in navigation_actions:
-            return _handle_navigation_actions(manager, resolved_action, url, tab_id)
-        if resolved_action in interaction_actions:
-            return _handle_interaction_actions(
-                manager,
-                resolved_action,
-                coordinate,
-                text,
-                key,
-                tab_id,
-            )
-        if resolved_action in tab_actions:
-            return _handle_tab_actions(manager, resolved_action, url, tab_id)
-        if resolved_action in utility_actions:
+        if action in navigation_actions:
+            return _handle_navigation_actions(manager, action, url, tab_id)
+        if action in interaction_actions:
+            return _handle_interaction_actions(manager, action, coordinate, text, key, tab_id)
+        if action in tab_actions:
+            return _handle_tab_actions(manager, action, url, tab_id)
+        if action in utility_actions:
             return _handle_utility_actions(
-                manager,
-                resolved_action,
-                duration,
-                js_code,
-                file_path,
-                tab_id,
-                clear,
-            )
-        if resolved_action in selector_actions:
-            return _handle_selector_actions(
-                manager,
-                resolved_action,
-                selector,
-                text,
-                tab_id,
-                timeout,
-                wait_state,
+                manager, action, duration, js_code, file_path, tab_id, clear
             )
 
-        _raise_unknown_action(resolved_action)
+        _raise_unknown_action(action)
 
     except (ValueError, RuntimeError) as e:
         return {
