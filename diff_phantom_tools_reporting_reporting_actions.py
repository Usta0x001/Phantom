diff --git a/phantom/tools/reporting/reporting_actions.py b/phantom/tools/reporting/reporting_actions.py
index 6b3a47b..9f09e73 100644
--- a/phantom/tools/reporting/reporting_actions.py
+++ b/phantom/tools/reporting/reporting_actions.py
@@ -1,7 +1,7 @@
 import contextlib
 import json
 import re
-from pathlib import PurePosixPath
+from pathlib import Path
 from typing import Any
 
 from phantom.tools.registry import register_tool
@@ -222,10 +222,11 @@ def parse_code_locations_xml(xml_str: str) -> list[dict[str, Any]] | None:
 def _validate_file_path(path: str) -> str | None:
     if not path or not path.strip():
         return "file path cannot be empty"
-    p = PurePosixPath(path)
+    p = Path(path)
     if p.is_absolute():
         return f"file path must be relative, got absolute: '{path}'"
-    if ".." in p.parts:
+    parts = p.parts
+    if ".." in parts:
         return f"file path must not contain '..': '{path}'"
     return None
 
