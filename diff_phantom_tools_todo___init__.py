diff --git a/phantom/tools/todo/__init__.py b/phantom/tools/todo/__init__.py
index cbca538..58bf813 100644
--- a/phantom/tools/todo/__init__.py
+++ b/phantom/tools/todo/__init__.py
@@ -1,18 +1,3 @@
-from .todo_actions import (
-    create_todo,
-    delete_todo,
-    list_todos,
-    mark_todo_done,
-    mark_todo_pending,
-    update_todo,
-)
+from .todo_actions import create_todo, list_todos
 
-
-__all__ = [
-    "create_todo",
-    "delete_todo",
-    "list_todos",
-    "mark_todo_done",
-    "mark_todo_pending",
-    "update_todo",
-]
+__all__ = ["create_todo", "list_todos"]
