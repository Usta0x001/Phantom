diff --git a/phantom/telemetry/__init__.py b/phantom/telemetry/__init__.py
index f9e52f8..f7d934e 100644
--- a/phantom/telemetry/__init__.py
+++ b/phantom/telemetry/__init__.py
@@ -1,6 +1,11 @@
+import logging
+
+_logger = logging.getLogger(__name__)
+
 try:
     from .tracer import Tracer, clear_global_tracer, get_global_tracer, set_global_tracer
-except Exception:  # noqa: BLE001
+except ImportError as _e:
+    _logger.warning("Telemetry tracer unavailable: %s", _e)
     Tracer = None  # type: ignore[assignment]
 
     def get_global_tracer() -> None:
