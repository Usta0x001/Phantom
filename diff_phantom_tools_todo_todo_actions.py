diff --git a/phantom/tools/todo/todo_actions.py b/phantom/tools/todo/todo_actions.py
index cb7e11a..59c80c4 100644
--- a/phantom/tools/todo/todo_actions.py
+++ b/phantom/tools/todo/todo_actions.py
@@ -158,7 +158,6 @@ def _normalize_bulk_todos(raw_todos: Any) -> list[dict[str, Any]]:
     return normalized
 
 
-@register_tool(sandbox_execution=False)
 def create_todo(
     agent_state: Any,
     title: str | None = None,
@@ -233,7 +232,6 @@ def create_todo(
         return response
 
 
-@register_tool(sandbox_execution=False)
 def list_todos(
     agent_state: Any,
     status: str | None = None,
@@ -341,7 +339,6 @@ def _apply_single_update(
     return None
 
 
-@register_tool(sandbox_execution=False)
 def update_todo(
     agent_state: Any,
     todo_id: str | None = None,
@@ -413,113 +410,10 @@ def update_todo(
         return response
 
 
-@register_tool(sandbox_execution=False)
-def mark_todo_done(
-    agent_state: Any,
-    todo_id: str | None = None,
-    todo_ids: Any | None = None,
-) -> dict[str, Any]:
-    try:
-        agent_id = agent_state.agent_id
-        agent_todos = _get_agent_todos(agent_id)
-
-        ids_to_mark: list[str] = []
-        if todo_ids is not None:
-            ids_to_mark.extend(_normalize_todo_ids(todo_ids))
-        if todo_id is not None:
-            ids_to_mark.append(todo_id)
-
-        if not ids_to_mark:
-            return {"success": False, "error": "Provide todo_id or todo_ids to mark as done."}
 
-        marked: list[str] = []
-        errors: list[dict[str, Any]] = []
-        timestamp = datetime.now(UTC).isoformat()
 
-        for tid in ids_to_mark:
-            if tid not in agent_todos:
-                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
-                continue
-
-            todo = agent_todos[tid]
-            todo["status"] = "done"
-            todo["completed_at"] = timestamp
-            todo["updated_at"] = timestamp
-            marked.append(tid)
-
-        todos_list = _sorted_todos(agent_id)
-
-        response: dict[str, Any] = {
-            "success": len(errors) == 0,
-            "marked_done": marked,
-            "marked_count": len(marked),
-            "todos": todos_list,
-            "total_count": len(todos_list),
-        }
-
-        if errors:
-            response["errors"] = errors
-
-    except (ValueError, TypeError) as e:
-        return {"success": False, "error": str(e)}
-    else:
-        return response
-
-
-@register_tool(sandbox_execution=False)
-def mark_todo_pending(
-    agent_state: Any,
-    todo_id: str | None = None,
-    todo_ids: Any | None = None,
-) -> dict[str, Any]:
-    try:
-        agent_id = agent_state.agent_id
-        agent_todos = _get_agent_todos(agent_id)
-
-        ids_to_mark: list[str] = []
-        if todo_ids is not None:
-            ids_to_mark.extend(_normalize_todo_ids(todo_ids))
-        if todo_id is not None:
-            ids_to_mark.append(todo_id)
-
-        if not ids_to_mark:
-            return {"success": False, "error": "Provide todo_id or todo_ids to mark as pending."}
-
-        marked: list[str] = []
-        errors: list[dict[str, Any]] = []
-        timestamp = datetime.now(UTC).isoformat()
-
-        for tid in ids_to_mark:
-            if tid not in agent_todos:
-                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
-                continue
-
-            todo = agent_todos[tid]
-            todo["status"] = "pending"
-            todo["completed_at"] = None
-            todo["updated_at"] = timestamp
-            marked.append(tid)
-
-        todos_list = _sorted_todos(agent_id)
-
-        response: dict[str, Any] = {
-            "success": len(errors) == 0,
-            "marked_pending": marked,
-            "marked_count": len(marked),
-            "todos": todos_list,
-            "total_count": len(todos_list),
-        }
-
-        if errors:
-            response["errors"] = errors
-
-    except (ValueError, TypeError) as e:
-        return {"success": False, "error": str(e)}
-    else:
-        return response
 
 
-@register_tool(sandbox_execution=False)
 def delete_todo(
     agent_state: Any,
     todo_id: str | None = None,
