diff --git a/phantom/tools/oast/oast_actions.py b/phantom/tools/oast/oast_actions.py
index da075be..d74ea97 100644
--- a/phantom/tools/oast/oast_actions.py
+++ b/phantom/tools/oast/oast_actions.py
@@ -13,7 +13,8 @@ from phantom.tools.registry import register_tool
 OASTType = Literal["http", "dns", "smtp", "ldap"]
 
 
-@register_tool
+# NOTE: oast module not available in sandbox container.
+# Re-add @register_tool decorator if container is rebuilt with oast support.
 def generate_oast_payload(
     payload_type: OASTType,
     context: str,
@@ -39,7 +40,8 @@ def generate_oast_payload(
     return manager.generate_payload(payload_type, context, target_surface)
 
 
-@register_tool
+# NOTE: oast module not available in sandbox container.
+# Re-add @register_tool decorator if container is rebuilt with oast support.
 def check_oast_interactions(
     payload_id: str | None = None,
 ) -> dict[str, Any]:
@@ -62,39 +64,5 @@ def check_oast_interactions(
     return manager.check_interactions(payload_id)
 
 
-@register_tool
-def list_oast_payloads() -> dict[str, Any]:
-    """
-    List all generated OAST payloads and their interaction status.
-
-    Use this to review what OAST payloads have been generated and which ones
-    have received interactions.
-
-    Returns:
-        List of all payloads with their callback URLs and interaction counts
-    """
-    from .oast_manager import get_oast_manager
-
-    manager = get_oast_manager()
-    return manager.list_payloads()
 
 
-@register_tool
-def clear_oast_payloads(
-    older_than_hours: float | None = None,
-) -> dict[str, Any]:
-    """
-    Clear OAST payloads from tracking.
-
-    Use this to clean up old payloads that are no longer needed.
-
-    Args:
-        older_than_hours: Only clear payloads older than this (None = clear all)
-
-    Returns:
-        Summary of cleared and remaining payloads
-    """
-    from .oast_manager import get_oast_manager
-
-    manager = get_oast_manager()
-    return manager.clear_payloads(older_than_hours)
