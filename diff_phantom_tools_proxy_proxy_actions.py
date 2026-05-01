diff --git a/phantom/tools/proxy/proxy_actions.py b/phantom/tools/proxy/proxy_actions.py
index 523c25b..dd29507 100644
--- a/phantom/tools/proxy/proxy_actions.py
+++ b/phantom/tools/proxy/proxy_actions.py
@@ -91,7 +91,6 @@ def scope_rules(
     return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)
 
 
-@register_tool
 def list_sitemap(
     scope_id: str | None = None,
     parent_id: str | None = None,
@@ -104,7 +103,6 @@ def list_sitemap(
     return manager.list_sitemap(scope_id, parent_id, depth, page)
 
 
-@register_tool
 def view_sitemap_entry(
     entry_id: str,
 ) -> dict[str, Any]:
