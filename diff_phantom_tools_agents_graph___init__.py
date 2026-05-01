diff --git a/phantom/tools/agents_graph/__init__.py b/phantom/tools/agents_graph/__init__.py
index d4cd095..a2ccc41 100644
--- a/phantom/tools/agents_graph/__init__.py
+++ b/phantom/tools/agents_graph/__init__.py
@@ -4,6 +4,8 @@ from .agents_graph_actions import (
     send_message_to_agent,
     view_agent_graph,
     wait_for_message,
+    wait_for_agents,
+    reset_all_state,
 )
 
 
@@ -13,4 +15,6 @@ __all__ = [
     "send_message_to_agent",
     "view_agent_graph",
     "wait_for_message",
+    "wait_for_agents",
+    "reset_all_state",
 ]
