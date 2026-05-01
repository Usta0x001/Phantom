diff --git a/phantom/runtime/tool_server.py b/phantom/runtime/tool_server.py
index 488afa2..4669711 100644
--- a/phantom/runtime/tool_server.py
+++ b/phantom/runtime/tool_server.py
@@ -15,8 +15,10 @@ from pydantic import BaseModel, ValidationError
 
 
 SANDBOX_MODE = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
-if not SANDBOX_MODE:
-    raise RuntimeError("Tool server should only run in sandbox mode (PHANTOM_SANDBOX_MODE=true)")
+
+# Module-level defaults so the module can be imported without running the server.
+EXPECTED_TOKEN: str = ""
+REQUEST_TIMEOUT: int = 120
 
 parser = argparse.ArgumentParser(description="Start Phantom tool server")
 parser.add_argument("--token", default=None, help="Authentication token (prefer --token-file)")
@@ -31,33 +33,10 @@ parser.add_argument("--port", type=int, required=True, help="Port to bind to")
 parser.add_argument(
     "--timeout",
     type=int,
-    default=120,
-    help="Hard timeout in seconds for each request execution (default: 120)",
+    default=300,
+    help="Hard timeout in seconds for each request execution (default: 300)",
 )
 
-args = parser.parse_args()
-
-# H-06: prefer token-file over plaintext token to keep secret off cmdline/env
-if args.token_file:
-    try:
-        with open(args.token_file) as _tf:
-            EXPECTED_TOKEN = _tf.read().strip()
-    except OSError as _e:
-        raise RuntimeError(f"Cannot read token file {args.token_file!r}: {_e}") from _e
-    # Shred the token file immediately so it doesn't persist on disk
-    try:
-        # Overwrite with zeros before unlinking (best-effort on all platforms)
-        with open(args.token_file, "w") as _tf:
-            _tf.write("\x00" * len(EXPECTED_TOKEN))
-        os.unlink(args.token_file)
-    except OSError:
-        pass  # non-fatal; file may already be gone or read-only
-elif args.token:
-    EXPECTED_TOKEN = args.token
-else:
-    raise RuntimeError("Either --token or --token-file must be provided")
-REQUEST_TIMEOUT = args.timeout
-
 app = FastAPI()
 security = HTTPBearer()
 security_dependency = Depends(security)
@@ -72,6 +51,7 @@ _MIN_REQUEST_INTERVAL = 0.1  # minimum 100ms between requests per agent
 def _check_rate_limit(agent_id: str) -> None:
     """Enforce a minimum interval between requests from the same agent."""
     import time
+
     now = time.monotonic()
     last = _agent_last_request.get(agent_id, 0.0)
     if now - last < _MIN_REQUEST_INTERVAL:
@@ -163,7 +143,8 @@ async def execute_tool(
         return ToolExecutionResponse(result=result)
 
     except asyncio.CancelledError:
-        return ToolExecutionResponse(error="Cancelled by newer request")
+        # Re-raise so asyncio task cancellation propagates correctly
+        raise
 
     except TimeoutError:
         return ToolExecutionResponse(error=f"Tool timed out after {REQUEST_TIMEOUT}s")
@@ -211,5 +192,32 @@ if hasattr(signal, "SIGPIPE"):
 signal.signal(signal.SIGTERM, signal_handler)
 signal.signal(signal.SIGINT, signal_handler)
 
+
 if __name__ == "__main__":
+    if not SANDBOX_MODE:
+        raise RuntimeError("Tool server should only run in sandbox mode (PHANTOM_SANDBOX_MODE=true)")
+
+    args = parser.parse_args()
+
+    # H-06: prefer token-file over plaintext token to keep secret off cmdline/env
+    if args.token_file:
+        try:
+            with open(args.token_file) as _tf:
+                EXPECTED_TOKEN = _tf.read().strip()
+        except OSError as _e:
+            raise RuntimeError(f"Cannot read token file {args.token_file!r}: {_e}") from _e
+        # Shred the token file immediately so it doesn't persist on disk
+        try:
+            # Overwrite with zeros before unlinking (best-effort on all platforms)
+            with open(args.token_file, "w") as _tf:
+                _tf.write("\x00" * len(EXPECTED_TOKEN))
+            os.unlink(args.token_file)
+        except OSError:
+            pass  # non-fatal; file may already be gone or read-only
+    elif args.token:
+        EXPECTED_TOKEN = args.token
+    else:
+        raise RuntimeError("Either --token or --token-file must be provided")
+    REQUEST_TIMEOUT = args.timeout
+
     uvicorn.run(app, host=args.host, port=args.port, log_level="info")
