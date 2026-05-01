diff --git a/phantom/tools/agents_graph/agents_graph_actions.py b/phantom/tools/agents_graph/agents_graph_actions.py
index a252159..95055d1 100644
--- a/phantom/tools/agents_graph/agents_graph_actions.py
+++ b/phantom/tools/agents_graph/agents_graph_actions.py
@@ -29,8 +29,6 @@ _agent_instances: dict[str, Any] = {}
 
 _agent_states: dict[str, Any] = {}
 
-# Rec 9 (SF-004): Total-agent counter for cascade-bomb prevention.
-_total_agents_created: int = 0
 
 # Rec 9 ΓÇö sentinel names that mark a validation agent (case-insensitive).
 _VALIDATION_AGENT_KEYWORDS = frozenset({
@@ -78,7 +76,7 @@ def cleanup_old_agents() -> int:
 
 def reset_all_state() -> None:
     """Reset all global state (call between scans)."""
-    global _total_agents_created, _root_agent_id
+    global _root_agent_id
     with _GRAPH_LOCK:
         _agent_graph["nodes"].clear()
         _agent_graph["edges"].clear()
@@ -86,7 +84,6 @@ def reset_all_state() -> None:
         _running_agents.clear()
         _agent_instances.clear()
         _agent_states.clear()
-        _total_agents_created = 0
         _root_agent_id = None
 
 
@@ -272,7 +269,6 @@ def create_agent(
     skills: str | None = None,
 ) -> dict[str, Any]:
     try:
-        global _total_agents_created  # Rec 9 (SF-004)
 
         parent_id = agent_state.agent_id
 
@@ -353,7 +349,6 @@ def create_agent(
                 1 for n in _agent_graph["nodes"].values()
                 if n.get("status") in {"running", "waiting"}
             )
-            _current_total = _total_agents_created
 
         if _running_now >= _max_concurrent:
             return {
@@ -365,15 +360,6 @@ def create_agent(
                 ),
                 "agent_id": None,
             }
-        if _current_total >= _max_total:
-            return {
-                "success": False,
-                "error": (
-                    f"Total agent limit reached: {_current_total} agents created "
-                    f"(PHANTOM_MAX_TOTAL_AGENTS={_max_total})."
-                ),
-                "agent_id": None,
-            }
 
         # Depth check: walk from parent to root counting hops
         _depth = 0
@@ -512,8 +498,6 @@ def create_agent(
 
         with _GRAPH_LOCK:  # Rec 1 (B-01)
             _agent_instances[state.agent_id] = agent
-            _total_agents_created += 1  # Rec 9 (SF-004)
-
         thread = threading.Thread(
             target=_run_agent_in_thread,
             args=(agent, state, inherited_messages),
@@ -681,14 +665,20 @@ def agent_finish(
 
             with _GRAPH_LOCK:  # Rec 1 (B-01)
                 if parent_id in _agent_graph["nodes"]:
-                    findings_xml = "\n".join(
-                        f"        <finding>{html.escape(str(finding))}</finding>"
-                        for finding in (findings or [])
-                    )
-                    recommendations_xml = "\n".join(
-                        f"        <recommendation>{html.escape(str(rec))}</recommendation>"
-                        for rec in (final_recommendations or [])
-                    )
+                    def _truncate(text: Any, max_len: int = 500) -> str:
+                        text_str = str(text) if text is not None else ""
+                        if len(text_str) > max_len:
+                            return text_str[:max_len] + f"...[omitted {len(text_str)-max_len} chars for size]"
+                        return text_str
+
+                    safe_findings = [html.escape(_truncate(f, 600)) for f in (findings or [])[:8]]
+                    if len(findings or []) > 8:
+                        safe_findings.append(f"...and {len(findings or []) - 8} additional findings truncated to prevent token bloat.")
+                        
+                    safe_recs = [html.escape(_truncate(r, 400)) for r in (final_recommendations or [])[:5]]
+                    
+                    findings_xml = "\n".join(f"        <finding>{f}</finding>" for f in safe_findings)
+                    recommendations_xml = "\n".join(f"        <recommendation>{r}</recommendation>" for r in safe_recs)
 
                     report_message = f"""<agent_completion_report>
     <agent_info>
@@ -699,7 +689,7 @@ def agent_finish(
         <completion_time>{agent_node["finished_at"]}</completion_time>
     </agent_info>
     <results>
-        <summary>{html.escape(result_summary)}</summary>
+        <summary>{html.escape(_truncate(result_summary, 1200))}</summary>
         <findings>
 {findings_xml}
         </findings>
