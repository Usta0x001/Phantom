diff --git a/phantom/telemetry/tracer.py b/phantom/telemetry/tracer.py
index 9c59b24..3289ab8 100644
--- a/phantom/telemetry/tracer.py
+++ b/phantom/telemetry/tracer.py
@@ -35,6 +35,7 @@ _OTEL_BOOTSTRAP_LOCK = threading.Lock()
 _OTEL_BOOTSTRAPPED = False
 _OTEL_REMOTE_ENABLED = False
 
+
 def get_global_tracer() -> Optional["Tracer"]:
     return _global_tracer
 
@@ -56,6 +57,8 @@ class Tracer:
         self.start_time = datetime.now(UTC).isoformat()
         self.end_time: str | None = None
 
+        # FIX: protect mutable containers from concurrent async mutations
+        self._lock = threading.Lock()
         self.agents: dict[str, dict[str, Any]] = {}
         self.tool_executions: dict[int, dict[str, Any]] = {}
         self.chat_messages: list[dict[str, Any]] = []
@@ -102,6 +105,7 @@ class Tracer:
         # ΓöÇΓöÇ Audit logger: initialise per-run audit log (PHANTOM_AUDIT_LOG=true) ΓöÇΓöÇ
         try:
             from phantom.logging.audit import init_audit_logger as _init_audit
+
             _init_audit(run_id=self.run_id, run_dir=self.get_run_dir())
         except Exception:  # noqa: BLE001
             pass
@@ -340,6 +344,7 @@ class Tracer:
         # Reinit audit logger for the new run name / directory
         try:
             from phantom.logging.audit import init_audit_logger as _init_audit
+
             _init_audit(run_id=self.run_id, run_dir=self.get_run_dir())
         except Exception:  # noqa: BLE001
             pass
@@ -462,7 +467,7 @@ class Tracer:
         confidence: str | None = None,
     ) -> None:
         """Update an existing vulnerability report with replay verification results.
-        
+
         Args:
             title: Title of the vulnerability to update
             replay_status: Replay status (PASSED, FAILED, ERROR, etc.)
@@ -472,11 +477,13 @@ class Tracer:
         if not isinstance(title, str):
             logger.error(f"Invalid title type: {type(title).__name__} - expected str")
             return
-        
+
         if not isinstance(replay_status, str):
-            logger.error(f"Invalid replay_status type: {type(replay_status).__name__} - expected str")
+            logger.error(
+                f"Invalid replay_status type: {type(replay_status).__name__} - expected str"
+            )
             return
-        
+
         # Validate replay_status against allowed values
         valid_statuses = {
             "PASSED",
@@ -493,21 +500,21 @@ class Tracer:
                 f"Replay status '{replay_status}' not in valid set: {valid_statuses}. "
                 "Accepting anyway for forward compatibility."
             )
-        
+
         # Find the vulnerability by title
         for report in self.vulnerability_reports:
             if report.get("title") == title:
                 # Update replay status
                 report["replay_status"] = replay_status
-                
+
                 # Update confidence if provided
                 if confidence:
                     report["confidence"] = confidence
-                
+
                 logger.info(
                     f"Updated vulnerability replay: {report['id']} - {title} -> {replay_status}"
                 )
-                
+
                 # Emit telemetry event
                 self._emit_event(
                     "finding.replay.updated",
@@ -520,11 +527,11 @@ class Tracer:
                     status=replay_status.lower(),
                     source="phantom.findings",
                 )
-                
+
                 # Save the updated data
                 self.save_run_data()
                 return
-        
+
         # Log warning if vulnerability not found
         logger.warning(f"Could not find vulnerability with title: {title}")
 
@@ -589,7 +596,7 @@ class Tracer:
             "created_at": datetime.now(UTC).isoformat(),
             "updated_at": datetime.now(UTC).isoformat(),
             "tool_executions": [],
-            "phase": "recon",  # FIX: Add phase tracking for status bar badge
+            "phase": "active",
         }
 
         self.agents[agent_id] = agent_data
@@ -608,19 +615,20 @@ class Tracer:
         agent_id: str | None = None,
         metadata: dict[str, Any] | None = None,
     ) -> int:
-        message_id = self._next_message_id
-        self._next_message_id += 1
-
-        message_data = {
-            "message_id": message_id,
-            "content": content,
-            "role": role,
-            "agent_id": agent_id,
-            "timestamp": datetime.now(UTC).isoformat(),
-            "metadata": metadata or {},
-        }
+        with self._lock:
+            message_id = self._next_message_id
+            self._next_message_id += 1
+
+            message_data = {
+                "message_id": message_id,
+                "content": content,
+                "role": role,
+                "agent_id": agent_id,
+                "timestamp": datetime.now(UTC).isoformat(),
+                "metadata": metadata or {},
+            }
 
-        self.chat_messages.append(message_data)
+            self.chat_messages.append(message_data)
         self._emit_event(
             "chat.message",
             actor={"agent_id": agent_id, "role": role},
@@ -636,26 +644,27 @@ class Tracer:
         tool_name: str,
         args: dict[str, Any],
     ) -> int:
-        execution_id = self._next_execution_id
-        self._next_execution_id += 1
-
-        now = datetime.now(UTC).isoformat()
-        execution_data = {
-            "execution_id": execution_id,
-            "agent_id": agent_id,
-            "tool_name": tool_name,
-            "args": args,
-            "status": "running",
-            "result": None,
-            "timestamp": now,
-            "started_at": now,
-            "completed_at": None,
-        }
+        with self._lock:
+            execution_id = self._next_execution_id
+            self._next_execution_id += 1
+
+            now = datetime.now(UTC).isoformat()
+            execution_data = {
+                "execution_id": execution_id,
+                "agent_id": agent_id,
+                "tool_name": tool_name,
+                "args": args,
+                "status": "running",
+                "result": None,
+                "timestamp": now,
+                "started_at": now,
+                "completed_at": None,
+            }
 
-        self.tool_executions[execution_id] = execution_data
+            self.tool_executions[execution_id] = execution_data
 
-        if agent_id in self.agents:
-            self.agents[agent_id]["tool_executions"].append(execution_id)
+            if agent_id in self.agents:
+                self.agents[agent_id]["tool_executions"].append(execution_id)
 
         self._emit_event(
             "tool.execution.started",
@@ -677,13 +686,14 @@ class Tracer:
         status: str,
         result: Any | None = None,
     ) -> None:
-        if execution_id not in self.tool_executions:
-            return
+        with self._lock:
+            if execution_id not in self.tool_executions:
+                return
 
-        tool_data = self.tool_executions[execution_id]
-        tool_data["status"] = status
-        tool_data["result"] = result
-        tool_data["completed_at"] = datetime.now(UTC).isoformat()
+            tool_data = self.tool_executions[execution_id]
+            tool_data["status"] = status
+            tool_data["result"] = result
+            tool_data["completed_at"] = datetime.now(UTC).isoformat()
 
         tool_name = str(tool_data.get("tool_name", "unknown"))
         agent_id = str(tool_data.get("agent_id", "unknown"))
@@ -719,11 +729,12 @@ class Tracer:
         status: str,
         error_message: str | None = None,
     ) -> None:
-        if agent_id in self.agents:
-            self.agents[agent_id]["status"] = status
-            self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
-            if error_message:
-                self.agents[agent_id]["error_message"] = error_message
+        with self._lock:
+            if agent_id in self.agents:
+                self.agents[agent_id]["status"] = status
+                self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
+                if error_message:
+                    self.agents[agent_id]["error_message"] = error_message
 
         self._emit_event(
             "agent.status.updated",
@@ -739,7 +750,7 @@ class Tracer:
         if agent_id in self.agents:
             self.agents[agent_id]["phase"] = phase
             self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
-        
+
         self._emit_event(
             "agent.phase.updated",
             actor={"agent_id": agent_id},
@@ -896,9 +907,17 @@ class Tracer:
                     import csv
 
                     fieldnames = [
-                        "id", "title", "severity", "confidence", "cvss",
-                        "target", "endpoint", "method", "parameter",
-                        "timestamp", "file",
+                        "id",
+                        "title",
+                        "severity",
+                        "confidence",
+                        "cvss",
+                        "target",
+                        "endpoint",
+                        "method",
+                        "parameter",
+                        "timestamp",
+                        "file",
                     ]
                     writer = csv.DictWriter(f, fieldnames=fieldnames)
                     writer.writeheader()
@@ -911,7 +930,11 @@ class Tracer:
                                 "title": report["title"],
                                 "severity": report["severity"].upper(),
                                 "confidence": report.get("confidence", "UNKNOWN"),
-                                "cvss": cvss_score.get("score") if isinstance(cvss_score, dict) else (cvss_score if isinstance(cvss_score, (int, float)) else "N/A"),
+                                "cvss": cvss_score.get("score")
+                                if isinstance(cvss_score, dict)
+                                else (
+                                    cvss_score if isinstance(cvss_score, (int, float)) else "N/A"
+                                ),
                                 "target": report.get("target", ""),
                                 "endpoint": report.get("endpoint", ""),
                                 "method": report.get("method", ""),
@@ -930,14 +953,30 @@ class Tracer:
                 logger.info("Updated vulnerability index: %s", vuln_csv_file)
 
             logger.info("≡ƒôè Essential scan data saved to: %s", run_dir)
-            
-            # FIX: Always generate scan_stats.json regardless of completion status
+
+            # FIX: Always generate scan_stats.json regardless of completion status.
+            # Previously used self.scan_id and self.target which don't exist on Tracer,
+            # causing AttributeError on every save. Use run_id and extract target from
+            # scan_config instead.
             scan_stats_file = run_dir / "scan_stats.json"
             try:
+                target = "unknown"
+                if self.scan_config:
+                    targets = self.scan_config.get("targets", [])
+                    if targets:
+                        first = targets[0]
+                        if isinstance(first, dict):
+                            target = (
+                                first.get("details", {}).get("target_url")
+                                or first.get("details", {}).get("target_repo")
+                                or str(first)
+                            )
+                        else:
+                            target = str(first)
                 stats_data = {
                     "status": self.run_metadata.get("status", "unknown"),
-                    "scan_id": self.scan_id,
-                    "target": self.target,
+                    "scan_id": self.run_id,
+                    "target": target,
                     "start_time": self.start_time,
                     "end_time": self.end_time,
                     "duration_seconds": self._calculate_duration(),
@@ -947,11 +986,12 @@ class Tracer:
                 }
                 with scan_stats_file.open("w", encoding="utf-8") as f:
                     import json
+
                     json.dump(stats_data, f, indent=2, default=str)
                 logger.info("Saved scan stats to: %s", scan_stats_file)
             except Exception as e:
                 logger.warning("Failed to save scan_stats.json: %s", e)
-            
+
             if mark_complete and not self._run_completed_emitted:
                 self._emit_event(
                     "run.completed",
@@ -993,23 +1033,23 @@ class Tracer:
         )
 
     def get_total_llm_stats(self) -> dict[str, Any]:
-        from phantom.llm.llm import _GLOBAL_STATS_LOCK, _GLOBAL_TOTAL_STATS
-
-        with _GLOBAL_STATS_LOCK:
-            stats = _GLOBAL_TOTAL_STATS
-            total_stats = {
-                "input_tokens": stats.input_tokens,
-                "output_tokens": stats.output_tokens,
-                "cached_tokens": stats.cached_tokens,
-                "cost": round(stats.cost, 4),
-                "requests": stats.requests,
-                "completed_requests": stats.completed_requests,
-            }
+        # FIX: use the new SharedLLMState instead of removed module-level globals.
+        from phantom.llm.llm import _DEFAULT_SHARED_STATE
+
+        stats = _DEFAULT_SHARED_STATE.total_stats
+        total_stats = {
+            "input_tokens": stats.input_tokens,
+            "output_tokens": stats.output_tokens,
+            "cached_tokens": stats.cached_tokens,
+            "cost": round(stats.cost, 4),
+            "requests": stats.requests,
+            "completed_requests": stats.completed_requests,
+        }
 
-            return {
-                "total": total_stats,
-                "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
-            }
+        return {
+            "total": total_stats,
+            "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
+        }
 
     def _get_vuln_severity_counts(self) -> dict[str, int]:
         """Count vulnerabilities by severity level."""
@@ -1024,20 +1064,20 @@ class Tracer:
 
     def get_per_model_stats(self) -> dict[str, dict[str, Any]]:
         """Aggregate per-model RequestStats, deduplicating shared RequestStats objects."""
-        from phantom.llm.llm import _GLOBAL_PER_MODEL_STATS, _GLOBAL_STATS_LOCK
-
-        with _GLOBAL_STATS_LOCK:
-            result: dict[str, dict[str, Any]] = {}
-            for model_name, stats in _GLOBAL_PER_MODEL_STATS.items():
-                result[model_name] = {
-                    "input_tokens": stats.input_tokens,
-                    "output_tokens": stats.output_tokens,
-                    "cached_tokens": stats.cached_tokens,
-                    "cost": round(stats.cost, 4),
-                    "requests": stats.requests,
-                    "completed_requests": stats.completed_requests,
-                }
-            return result
+        # FIX: use the new SharedLLMState instead of removed module-level globals.
+        from phantom.llm.llm import _DEFAULT_SHARED_STATE
+
+        result: dict[str, dict[str, Any]] = {}
+        for model_name, stats in _DEFAULT_SHARED_STATE.per_model_stats.items():
+            result[model_name] = {
+                "input_tokens": stats.input_tokens,
+                "output_tokens": stats.output_tokens,
+                "cached_tokens": stats.cached_tokens,
+                "cost": round(stats.cost, 4),
+                "requests": stats.requests,
+                "completed_requests": stats.completed_requests,
+            }
+        return result
 
     @property
     def compression_calls(self) -> int:
@@ -1045,7 +1085,11 @@ class Tracer:
         from phantom.tools.agents_graph.agents_graph_actions import _agent_instances
 
         return sum(
-            getattr(getattr(inst, "llm", None) and getattr(inst.llm, "memory_compressor", None), "compression_calls", 0)
+            getattr(
+                getattr(inst, "llm", None) and getattr(inst.llm, "memory_compressor", None),
+                "compression_calls",
+                0,
+            )
             for inst in _agent_instances.values()
         )
 
@@ -1098,18 +1142,22 @@ class Tracer:
         }
 
     def update_streaming_content(self, agent_id: str, content: str) -> None:
-        self.streaming_content[agent_id] = content
+        with self._lock:
+            self.streaming_content[agent_id] = content
 
     def clear_streaming_content(self, agent_id: str) -> None:
-        self.streaming_content.pop(agent_id, None)
+        with self._lock:
+            self.streaming_content.pop(agent_id, None)
 
     def get_streaming_content(self, agent_id: str) -> str | None:
-        return self.streaming_content.get(agent_id)
+        with self._lock:
+            return self.streaming_content.get(agent_id)
 
     def finalize_streaming_as_interrupted(self, agent_id: str) -> str | None:
-        content = self.streaming_content.pop(agent_id, None)
-        if content and content.strip():
-            self.interrupted_content[agent_id] = content
+        with self._lock:
+            content = self.streaming_content.pop(agent_id, None)
+            if content and content.strip():
+                self.interrupted_content[agent_id] = content
             self.log_chat_message(
                 content=content,
                 role="assistant",
