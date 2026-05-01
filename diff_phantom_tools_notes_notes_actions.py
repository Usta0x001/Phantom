diff --git a/phantom/tools/notes/notes_actions.py b/phantom/tools/notes/notes_actions.py
index d889f20..5147f1f 100644
--- a/phantom/tools/notes/notes_actions.py
+++ b/phantom/tools/notes/notes_actions.py
@@ -39,7 +39,6 @@ def _filter_notes(
     return filtered_notes
 
 
-@register_tool(sandbox_execution=False)
 def create_note(
     title: str,
     content: str,
@@ -85,7 +84,6 @@ def create_note(
         }
 
 
-@register_tool(sandbox_execution=False)
 def list_notes(
     category: str | None = None,
     tags: list[str] | None = None,
@@ -109,56 +107,5 @@ def list_notes(
         }
 
 
-@register_tool(sandbox_execution=False)
-def update_note(
-    note_id: str,
-    title: str | None = None,
-    content: str | None = None,
-    tags: list[str] | None = None,
-) -> dict[str, Any]:
-    try:
-        if note_id not in _notes_storage:
-            return {"success": False, "error": f"Note with ID '{note_id}' not found"}
-
-        note = _notes_storage[note_id]
-
-        if title is not None:
-            if not title.strip():
-                return {"success": False, "error": "Title cannot be empty"}
-            note["title"] = title.strip()
-
-        if content is not None:
-            if not content.strip():
-                return {"success": False, "error": "Content cannot be empty"}
-            note["content"] = content.strip()
-
-        if tags is not None:
-            note["tags"] = tags
-
-        note["updated_at"] = datetime.now(UTC).isoformat()
-
-        return {
-            "success": True,
-            "message": f"Note '{note['title']}' updated successfully",
-        }
-
-    except (ValueError, TypeError) as e:
-        return {"success": False, "error": f"Failed to update note: {e}"}
-
-
-@register_tool(sandbox_execution=False)
-def delete_note(note_id: str) -> dict[str, Any]:
-    try:
-        if note_id not in _notes_storage:
-            return {"success": False, "error": f"Note with ID '{note_id}' not found"}
 
-        note_title = _notes_storage[note_id]["title"]
-        del _notes_storage[note_id]
 
-    except (ValueError, TypeError) as e:
-        return {"success": False, "error": f"Failed to delete note: {e}"}
-    else:
-        return {
-            "success": True,
-            "message": f"Note '{note_title}' deleted successfully",
-        }
