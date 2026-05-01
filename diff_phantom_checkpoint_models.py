diff --git a/phantom/checkpoint/models.py b/phantom/checkpoint/models.py
index be95643..adeaa8f 100644
--- a/phantom/checkpoint/models.py
+++ b/phantom/checkpoint/models.py
@@ -68,10 +68,7 @@ class CheckpointData(BaseModel):
     
     # Coverage tracker state (attack surfaces tested per vuln class)
     coverage_tracker_state: dict[str, Any] = Field(default_factory=dict)
-    
-    # Correlation engine state (detected vuln chains and relationships)
-    correlation_engine_state: dict[str, Any] = Field(default_factory=dict)
-    
+
     # FIX 5: Attack graph state (vulnerability relationships and attack paths)
     # Preserves multi-step attack chain analysis across checkpoint restarts.
     attack_graph_state: dict[str, Any] = Field(default_factory=dict)
