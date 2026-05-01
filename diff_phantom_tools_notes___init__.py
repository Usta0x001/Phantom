diff --git a/phantom/tools/notes/__init__.py b/phantom/tools/notes/__init__.py
index ebcbbca..8db93b6 100644
--- a/phantom/tools/notes/__init__.py
+++ b/phantom/tools/notes/__init__.py
@@ -1,14 +1,3 @@
-from .notes_actions import (
-    create_note,
-    delete_note,
-    list_notes,
-    update_note,
-)
+from .notes_actions import create_note, list_notes
 
-
-__all__ = [
-    "create_note",
-    "delete_note",
-    "list_notes",
-    "update_note",
-]
+__all__ = ["create_note", "list_notes"]
