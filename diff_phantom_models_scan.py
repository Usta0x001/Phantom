diff --git a/phantom/models/scan.py b/phantom/models/scan.py
index 0c6860d..40884eb 100644
--- a/phantom/models/scan.py
+++ b/phantom/models/scan.py
@@ -9,12 +9,9 @@ from pydantic import BaseModel, Field
 
 
 class ScanPhase(str, Enum):
-    """Current phase of penetration test"""
-    RECON = "recon"
-    ENUMERATION = "enumeration"
-    EXPLOITATION = "exploitation"
-    POST_EXPLOITATION = "post_exploitation"
-    REPORTING = "reporting"
+    """Scan activity state ΓÇö no waterfall phases."""
+    ACTIVE = "active"
+    COMPLETED = "completed"
 
 
 class ScanStatus(str, Enum):
@@ -31,7 +28,7 @@ class ScanResult(BaseModel):
     scan_id: str
     target: str | list[str]
     status: ScanStatus = ScanStatus.INITIALIZING
-    phase: ScanPhase = ScanPhase.RECON
+    phase: ScanPhase = ScanPhase.ACTIVE
     start_time: datetime | None = None
     end_time: datetime | None = None
     vuln_count: int = 0
