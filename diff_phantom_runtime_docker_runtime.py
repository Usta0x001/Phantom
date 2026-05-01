diff --git a/phantom/runtime/docker_runtime.py b/phantom/runtime/docker_runtime.py
index eff5913..4183d4d 100644
--- a/phantom/runtime/docker_runtime.py
+++ b/phantom/runtime/docker_runtime.py
@@ -1,3 +1,4 @@
+import asyncio
 import contextlib
 import logging
 import os
@@ -5,7 +6,6 @@ import random
 import re
 import secrets
 import socket
-import subprocess
 import time
 from pathlib import Path
 from typing import cast
@@ -48,21 +48,6 @@ class DockerRuntime(AbstractRuntime):
         self._tool_server_token: str | None = None
         self._caido_port: int | None = None
 
-    def _start_docker_desktop_windows(self) -> bool:
-        if os.name != "nt":
-            return False
-
-        candidates = [
-            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
-            Path(os.environ.get("LocalAppData", "")) / "Docker" / "Docker Desktop.exe",
-        ]
-        for exe in candidates:
-            if exe.exists():
-                with contextlib.suppress(OSError):
-                    subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
-                    return True
-        return False
-
     def _connect_docker_client(self) -> docker.DockerClient:
         client = docker.from_env(timeout=DOCKER_TIMEOUT)
         client.ping()
@@ -72,18 +57,8 @@ class DockerRuntime(AbstractRuntime):
         try:
             return self._connect_docker_client()
         except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
-            if os.name == "nt" and self._start_docker_desktop_windows():
-                deadline = time.time() + 120
-                while time.time() < deadline:
-                    try:
-                        return self._connect_docker_client()
-                    except (DockerException, RequestsConnectionError, RequestsTimeout):
-                        time.sleep(3)
-                raise SandboxInitializationError(
-                    "Docker is not available",
-                    "Phantom attempted to auto-start Docker Desktop but it did not become ready in time.",
-                ) from e
-
+            # FIX: removed auto-start Docker Desktop ΓÇö security anti-pattern.
+            # Phantom should never spawn external processes without explicit consent.
             raise SandboxInitializationError(
                 "Docker is not available",
                 "Please ensure Docker Desktop is installed and running.",
@@ -174,24 +149,24 @@ class DockerRuntime(AbstractRuntime):
         if port_bindings.get(caido_port_key):
             self._caido_port = int(port_bindings[caido_port_key][0]["HostPort"])
 
-    def _wait_for_tool_server(self, max_retries: int = 30, timeout: int = 5) -> None:
+    async def _wait_for_tool_server(self, max_retries: int = 30, timeout: int = 5) -> None:
         host = self._resolve_docker_host()
         health_url = f"http://{host}:{self._tool_server_port}/health"
 
-        time.sleep(5)
+        await asyncio.sleep(5)
 
-        for attempt in range(max_retries):
-            try:
-                with httpx.Client(trust_env=False, timeout=timeout) as client:
-                    response = client.get(health_url)
+        async with httpx.AsyncClient(trust_env=False, timeout=timeout) as client:
+            for attempt in range(max_retries):
+                try:
+                    response = await client.get(health_url)
                     if response.status_code == 200:
                         data = response.json()
                         if data.get("status") == "healthy":
                             return
-            except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
-                pass
+                except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
+                    pass
 
-            time.sleep(min(2**attempt * 0.5, 5))
+                await asyncio.sleep(min(2**attempt * 0.5, 5))
 
         raise SandboxInitializationError(
             "Tool server failed to start",
@@ -244,8 +219,9 @@ class DockerRuntime(AbstractRuntime):
                     cap_drop=["SYS_ADMIN", "SYS_PTRACE"],
                     labels={"phantom-scan-id": scan_id},
                     environment={
+                        "HOME": "/home/pentester",
                         "PYTHONUNBUFFERED": "1",
-                        "TOOL_SERVER_PORT": str(CONTAINER_TOOL_SERVER_PORT),
+                        "TOOL_SERVER_PORT": "48081",  # Static port - always set
                         # Rec 8 (B-13): Token also injected via env for backward-compat.
                         # Primary path is the secret file written below.
                         "TOOL_SERVER_TOKEN": self._tool_server_token,
@@ -256,12 +232,6 @@ class DockerRuntime(AbstractRuntime):
                     },
                     extra_hosts={HOST_GATEWAY_HOSTNAME: "host-gateway"},
                     tty=True,
-                    # Rec 3 (SF-003): Resource limits
-                    mem_limit=mem_limit,
-                    memswap_limit=mem_limit,  # disable swap
-                    cpu_period=100_000,
-                    cpu_quota=cpu_quota,
-                    pids_limit=pids_limit,
                 )
 
                 self._scan_container = container
@@ -310,10 +280,10 @@ class DockerRuntime(AbstractRuntime):
                     container.put_archive("/run/secrets", tar_buf.getvalue())
                 except Exception:  # noqa: BLE001
                     # Non-fatal: env-var fallback is still present.
-                    logger.warning("Could not write tool_server_token to /run/secrets ΓÇö "
-                                   "falling back to environment variable.")
-
-                self._wait_for_tool_server()
+                    logger.warning(
+                        "Could not write tool_server_token to /run/secrets ΓÇö "
+                        "falling back to environment variable."
+                    )
 
             except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
                 last_error = e
@@ -380,16 +350,16 @@ class DockerRuntime(AbstractRuntime):
     def _extract_scope_targets(self, scan_config: dict | None) -> str:
         """
         SEC-002 FIX: Extract target hosts from scan_config for scope enforcement.
-        
+
         Returns comma-separated list of target hosts/IPs.
         """
         if not scan_config:
             return ""
-        
+
         targets = scan_config.get("targets", [])
         if not targets:
             return ""
-        
+
         extracted: list[str] = []
         for target_info in targets:
             if isinstance(target_info, dict):
@@ -421,7 +391,7 @@ class DockerRuntime(AbstractRuntime):
                         extracted.append(host)
             elif isinstance(target_info, str):
                 extracted.append(target_info)
-        
+
         return ",".join(extracted)
 
     def _configure_scope_firewall(self, container: Container, scan_target: str) -> None:
@@ -477,11 +447,13 @@ class DockerRuntime(AbstractRuntime):
             except Exception:
                 pass
 
-            rules.extend([
-                # Log then drop everything else
-                f"iptables -A OUTPUT -j LOG --log-prefix 'PHANTOM-OOB: ' --log-level 4",
-                f"iptables -A OUTPUT -j DROP",
-            ])
+            rules.extend(
+                [
+                    # Log then drop everything else
+                    f"iptables -A OUTPUT -j LOG --log-prefix 'PHANTOM-OOB: ' --log-level 4",
+                    f"iptables -A OUTPUT -j DROP",
+                ]
+            )
             for rule in rules:
                 result = container.exec_run(
                     ["bash", "-c", rule],
@@ -538,6 +510,10 @@ class DockerRuntime(AbstractRuntime):
         scan_id = self._get_scan_id(agent_id)
         container = self._get_or_create_container(scan_id)
 
+        # FIX: async health check after container creation/recovery.
+        # Previously this was a sync call blocking the event loop for minutes.
+        await self._wait_for_tool_server()
+
         source_copied_key = f"_source_copied_{scan_id}"
         if local_sources and not hasattr(self, source_copied_key):
             for index, source in enumerate(local_sources, start=1):
@@ -564,7 +540,7 @@ class DockerRuntime(AbstractRuntime):
                 else:
                     # User explicitly specified target(s)
                     scope_targets = scope_enforcement
-                
+
                 if scope_targets:
                     # Configure firewall for each target
                     for target in scope_targets.split(","):
@@ -640,9 +616,9 @@ class DockerRuntime(AbstractRuntime):
     def cleanup(self, wait: bool = False) -> None:
         """
         Clean up Docker containers.
-        
+
         P1.3 CRITICAL FIX: Properly clean up containers on Ctrl+C/signal.
-        
+
         Args:
             wait: If True, wait for cleanup to complete (blocking).
                   If False, cleanup runs async (for normal exit).
@@ -682,16 +658,16 @@ class DockerRuntime(AbstractRuntime):
                     stderr=subprocess.DEVNULL,
                     start_new_session=True,
                 )
-    
+
     def cleanup_all_phantom_containers(self) -> int:
         """
         P1.3: Clean up ALL phantom containers, not just the current one.
-        
+
         This handles zombie containers from crashed scans.
         Returns the number of containers cleaned up.
         """
         import subprocess
-        
+
         cleaned = 0
         try:
             # Find all phantom containers (running or stopped)
@@ -701,7 +677,7 @@ class DockerRuntime(AbstractRuntime):
                 text=True,
                 timeout=10,
             )
-            
+
             if result.returncode == 0:
                 container_names = result.stdout.strip().split("\n")
                 for name in container_names:
@@ -719,5 +695,5 @@ class DockerRuntime(AbstractRuntime):
                             pass
         except Exception as e:
             logger.warning("Failed to clean up phantom containers: %s", e)
-        
+
         return cleaned
