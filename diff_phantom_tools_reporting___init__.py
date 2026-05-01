diff --git a/phantom/tools/reporting/__init__.py b/phantom/tools/reporting/__init__.py
index 9a00e5f..6412f18 100644
--- a/phantom/tools/reporting/__init__.py
+++ b/phantom/tools/reporting/__init__.py
@@ -1,14 +1,5 @@
 from .reporting_actions import create_vulnerability_report
 
-# P8: Elite Reporting
-from .elite_reporting import (
-    create_elite_report,
-    export_elite_report,
-)
-
 __all__ = [
     "create_vulnerability_report",
-    # P8
-    "create_elite_report",
-    "export_elite_report",
 ]
