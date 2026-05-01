diff --git a/phantom/tools/finish/finish_actions.py b/phantom/tools/finish/finish_actions.py
index 14ecb00..ee78a14 100644
--- a/phantom/tools/finish/finish_actions.py
+++ b/phantom/tools/finish/finish_actions.py
@@ -28,6 +28,7 @@ def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
 
         active_agents = []
         stopping_agents = []
+        waiting_agents = []
 
         for agent_id, node in _agent_graph["nodes"].items():
             if agent_id == current_agent_id:
@@ -52,8 +53,17 @@ def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
                         "status": status,
                     }
                 )
+            elif status == "waiting":
+                waiting_agents.append(
+                    {
+                        "id": agent_id,
+                        "name": node.get("name", "Unknown"),
+                        "task": node.get("task", "Unknown task")[:300],
+                        "status": status,
+                    }
+                )
 
-        if active_agents or stopping_agents:
+        if active_agents or stopping_agents or waiting_agents:
             response: dict[str, Any] = {
                 "success": False,
                 "error": "agents_still_active",
@@ -66,13 +76,16 @@ def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
             if stopping_agents:
                 response["stopping_agents"] = stopping_agents
 
+            if waiting_agents:
+                response["waiting_agents"] = waiting_agents
+
             response["suggestions"] = [
                 "Use wait_for_message to wait for all agents to complete",
                 "Use send_message_to_agent if you need agents to complete immediately",
                 "Check agent_status to see current agent states",
             ]
 
-            response["total_active"] = len(active_agents) + len(stopping_agents)
+            response["total_active"] = len(active_agents) + len(stopping_agents) + len(waiting_agents)
 
             return response
 
