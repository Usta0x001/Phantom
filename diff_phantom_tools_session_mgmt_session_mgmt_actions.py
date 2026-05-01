diff --git a/phantom/tools/session_mgmt/session_mgmt_actions.py b/phantom/tools/session_mgmt/session_mgmt_actions.py
index f3daffe..c047c02 100644
--- a/phantom/tools/session_mgmt/session_mgmt_actions.py
+++ b/phantom/tools/session_mgmt/session_mgmt_actions.py
@@ -191,7 +191,6 @@ async def update_session(
     }
 
 
-@register_tool(sandbox_execution=False)
 async def get_session_info(
     session_id: str | None = None,
     list_all: bool = False,
