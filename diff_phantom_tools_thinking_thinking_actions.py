diff --git a/phantom/tools/thinking/thinking_actions.py b/phantom/tools/thinking/thinking_actions.py
index b805d64..0db0902 100644
--- a/phantom/tools/thinking/thinking_actions.py
+++ b/phantom/tools/thinking/thinking_actions.py
@@ -1,9 +1,6 @@
 from typing import Any
 
-from phantom.tools.registry import register_tool
 
-
-@register_tool(sandbox_execution=False)
 def think(thought: str) -> dict[str, Any]:
     try:
         if not thought or not thought.strip():
