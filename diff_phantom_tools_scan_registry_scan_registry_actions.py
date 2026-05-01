diff --git a/phantom/tools/scan_registry/scan_registry_actions.py b/phantom/tools/scan_registry/scan_registry_actions.py
index f190b19..44a0813 100644
--- a/phantom/tools/scan_registry/scan_registry_actions.py
+++ b/phantom/tools/scan_registry/scan_registry_actions.py
@@ -14,9 +14,6 @@ import threading
 from datetime import UTC, datetime
 from typing import Any
 
-from phantom.tools.registry import register_tool
-
-
 # ΓöÇΓöÇ Process-wide state ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 _LOCK = threading.RLock()
 
@@ -60,81 +57,5 @@ def clear_registry() -> None:
 
 # ΓöÇΓöÇ Tool implementations ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
-@register_tool(sandbox_execution=False)
-def check_scan_registry(
-    agent_state: Any,
-    target: str,
-) -> dict[str, Any]:
-    """Check whether *target* has already been scanned in this run.
-
-    Returns ``{"already_scanned": True, "details": {...}}`` if it has, or
-    ``{"already_scanned": False}`` if it has not ΓÇö in which case you should
-    proceed with the scan and call ``register_scan_target`` afterwards.
-    """
-    try:
-        key = _canonical(target)
-        with _LOCK:
-            entry = _REGISTRY.get(key)
-        if entry:
-            return {
-                "success": True,
-                "already_scanned": True,
-                "details": entry,
-                "message": (
-                    f"Target '{target}' was already scanned by agent "
-                    f"'{entry.get('agent_name', 'unknown')}' "
-                    f"({entry.get('scan_type', 'unknown')} scan) at "
-                    f"{entry.get('registered_at', 'unknown')}. "
-                    "Skip this scan to avoid duplicate work."
-                ),
-            }
-        return {
-            "success": True,
-            "already_scanned": False,
-            "message": f"Target '{target}' has not been scanned yet ΓÇö safe to proceed.",
-        }
-    except Exception as exc:
-        return {"success": False, "error": str(exc), "already_scanned": False}
-
-
-@register_tool(sandbox_execution=False)
-def register_scan_target(
-    agent_state: Any,
-    target: str,
-    scan_type: str = "general",
-) -> dict[str, Any]:
-    """Register *target* as scanned so other agents can skip it.
-
-    Call this immediately before (or immediately after) running a scan so
-    that concurrent or future agents don't duplicate the work.
-
-    ``scan_type`` should be a short label such as ``"port_scan"``,
-    ``"directory_fuzz"``, ``"sqli"``, ``"xss"``, etc.
-    """
-    try:
-        key = _canonical(target)
-        agent_name = getattr(agent_state, "agent_name", "unknown")
-        with _LOCK:
-            already = key in _REGISTRY
-            if not already:
-                _REGISTRY[key] = {
-                    "target": target,
-                    "scan_type": scan_type,
-                    "agent_name": agent_name,
-                    "registered_at": datetime.now(UTC).isoformat(),
-                }
-        if already:
-            return {
-                "success": True,
-                "registered": False,
-                "message": f"Target '{target}' was already in the registry ΓÇö no change made.",
-            }
-        return {
-            "success": True,
-            "registered": True,
-            "message": (
-                f"Registered '{target}' as scanned ({scan_type}) by agent '{agent_name}'."
-            ),
-        }
-    except Exception as exc:
-        return {"success": False, "error": str(exc), "registered": False}
+
+
