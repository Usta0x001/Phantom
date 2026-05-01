diff --git a/phantom/core/__init__.py b/phantom/core/__init__.py
index 40d84f4..f877cfe 100644
--- a/phantom/core/__init__.py
+++ b/phantom/core/__init__.py
@@ -2,6 +2,7 @@
 
 from .attack_graph import (
     AttackGraph,
+    AttackPlan,
     AttackNodeType,
     AttackEdgeType,
     AttackNode,
@@ -11,6 +12,7 @@ from .attack_graph import (
 
 __all__ = [
     "AttackGraph",
+    "AttackPlan",
     "AttackNodeType",
     "AttackEdgeType",
     "AttackNode",
