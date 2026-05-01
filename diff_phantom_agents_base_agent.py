diff --git a/phantom/agents/base_agent.py b/phantom/agents/base_agent.py
index c11f036..d00ebd4 100644
--- a/phantom/agents/base_agent.py
+++ b/phantom/agents/base_agent.py
@@ -1,5 +1,4 @@
 import asyncio
-import contextlib
 import json
 import logging
 import os
@@ -18,7 +17,7 @@ from jinja2 import (
 
 from phantom.agents.hypothesis_ledger import HypothesisLedger  # Rec 6 (SF-005)
 from phantom.agents.coverage_tracker import CoverageTracker  # Enhancement: Coverage tracking
-from phantom.agents.correlation_engine import CorrelationEngine  # Enhancement: Vulnerability chains
+
 from phantom.llm import LLM, LLMConfig, LLMRequestFailedError
 from phantom.llm.pentager.reflector import get_reflector
 from phantom.llm.utils import clean_content
@@ -29,6 +28,7 @@ from phantom.utils.resource_paths import get_phantom_resource_path
 
 from .state import AgentState
 
+from phantom.logging.audit import get_audit_logger as _get_audit_logger
 
 logger = logging.getLogger(__name__)
 
@@ -56,6 +56,11 @@ class AgentMeta(type):
 
 class BaseAgent(metaclass=AgentMeta):
     max_iterations = 300
+
+    # ΓöÇΓöÇ Stall-detection constants (were magic numbers) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+    _NO_ACTION_STALL_WARN: int = 3  # iterations without actions before warning
+    _NO_ACTION_STALL_ABORT: int = 8  # iterations without actions before aborting
+    # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
     agent_name: str = ""
     jinja_env: Environment
     default_llm_config: LLMConfig | None = None
@@ -77,20 +82,52 @@ class BaseAgent(metaclass=AgentMeta):
         if state_from_config is not None:
             self.state = state_from_config
         else:
-            self.state = AgentState(
-                agent_name="Root Agent",
-                max_iterations=self.max_iterations,
-            )
+            # FIX: Attempt to resume from checkpoint if one exists.
+            # Previously checkpointing was write-only: state was saved but never
+            # restored, making long scans unrecoverable after crashes.
+            checkpoint_mgr = config.get("_checkpoint_manager")
+            restored_state = None
+            if checkpoint_mgr is not None:
+                try:
+                    cp = checkpoint_mgr.load()
+                    if cp is not None and cp.root_agent_state:
+                        restored_state = AgentState.model_validate(cp.root_agent_state)
+                        logger.info(
+                            "Resumed agent from checkpoint (iteration=%d, msgs=%d)",
+                            restored_state.iteration,
+                            len(restored_state.messages),
+                        )
+                except Exception:
+                    logger.warning("Failed to load checkpoint, starting fresh", exc_info=True)
+            if restored_state is not None:
+                self.state = restored_state
+            else:
+                self.state = AgentState(
+                    agent_name="Root Agent",
+                    max_iterations=self.max_iterations,
+                )
 
         self.state.scan_mode = str(getattr(self.llm_config, "scan_mode", "deep") or "deep")
 
         self.llm = LLM(self.llm_config, agent_name=self.agent_name)
         setattr(self.state, "_runtime_llm", self.llm)
 
-        with contextlib.suppress(Exception):
+        try:
             self.llm.set_agent_identity(self.state.agent_name, self.state.agent_id)
-        with contextlib.suppress(Exception):
+        except Exception:
+            logger.exception(
+                "Failed to set agent identity on LLM (agent=%s agent_id=%s)",
+                self.state.agent_name,
+                self.state.agent_id,
+            )
+        try:
             self.llm.set_agent_state(self.state)
+        except Exception:
+            logger.exception(
+                "Failed to set agent state on LLM (agent=%s agent_id=%s)",
+                self.state.agent_name,
+                self.state.agent_id,
+            )
         self._current_task: asyncio.Task[Any] | None = None
         self._force_stop = False
         self._recent_action_batches: list[str] = []
@@ -100,31 +137,21 @@ class BaseAgent(metaclass=AgentMeta):
         # survives context compression and prevents redundant payload testing.
         # Root agents get a fresh ledger; sub-agents share the ledger if one is
         # passed via config (enabling cross-agent deduplication).
-        self.hypothesis_ledger: HypothesisLedger = config.get(
-            "hypothesis_ledger"
-        ) or HypothesisLedger()
+        self.hypothesis_ledger: HypothesisLedger = (
+            config.get("hypothesis_ledger") or HypothesisLedger()
+        )
 
         # Enhancement: Coverage Tracker - tracks what attack surfaces have been
         # tested for which vulnerability classes. Returns FACTS not commands.
         # Root agents get a fresh tracker; sub-agents share if passed via config.
-        self.coverage_tracker: CoverageTracker = config.get(
-            "coverage_tracker"
-        ) or CoverageTracker()
-
-        # Enhancement: Correlation Engine - identifies potential vulnerability chains.
-        # Returns SUGGESTIONS not commands - LLM decides whether to pursue chains.
-        # Root agents get a fresh engine; sub-agents share if passed via config.
-        self.correlation_engine: CorrelationEngine = config.get(
-            "correlation_engine"
-        ) or CorrelationEngine()
-        with contextlib.suppress(Exception):
-            self.hypothesis_ledger.set_correlation_engine(self.correlation_engine)
+        self.coverage_tracker: CoverageTracker = config.get("coverage_tracker") or CoverageTracker()
 
         # FIX 5: Attack Graph - visualizes vulnerability relationships and attack paths.
         # Enables critical node identification and multi-step attack chain analysis.
         # Root agents get a fresh graph; sub-agents share if passed via config.
         try:
             from phantom.core.attack_graph import AttackGraph
+
             self.attack_graph: AttackGraph | None = config.get("attack_graph") or AttackGraph()
         except ImportError:
             # NetworkX not installed - attack graph unavailable
@@ -137,35 +164,49 @@ class BaseAgent(metaclass=AgentMeta):
             try:
                 from phantom.tools.agents_graph import agents_graph_actions
 
-                agents_graph_actions.reset_all_state()
+                # FIX: only reset graph state if no other agents are active,
+                # to avoid destroying a previous root agent's graph.
+                # _agent_instances tracks live agent objects; if non-empty, another
+                # agent is still running and we must not wipe its graph.
+                if not getattr(agents_graph_actions, "_agent_instances", None):
+                    agents_graph_actions.reset_all_state()
+                elif len(agents_graph_actions._agent_instances) == 0:
+                    agents_graph_actions.reset_all_state()
             except Exception:
-                pass
+                logger.exception(
+                    "Failed to reset agent graph state (agent=%s agent_id=%s)",
+                    self.state.agent_name,
+                    self.state.agent_id,
+                )
 
         # C1: Wire hypothesis ledger to the tool so the LLM can interact with it
         try:
-            from phantom.tools.hypothesis.hypothesis_actions import set_correlation_engine, set_ledger
+            from phantom.tools.hypothesis.hypothesis_actions import set_ledger
 
             set_ledger(self.hypothesis_ledger, self.state.agent_id)
-            set_correlation_engine(self.correlation_engine, self.state.agent_id)
         except ImportError as e:
-            # Tool module not available in this environment
-            logging.warning(f"Hypothesis ledger tool not available: {e}")
-            pass
+            logging.warning(
+                "Hypothesis ledger tool not available: %s (agent=%s)",
+                e,
+                self.state.agent_name,
+            )
 
         # AUDIT-FIX: Wire scan_status tool with all context
         try:
             from phantom.tools.scan_status.scan_status_actions import set_scan_status_context
+
             set_scan_status_context(
                 hypothesis_ledger=self.hypothesis_ledger,
                 coverage_tracker=self.coverage_tracker,
-                correlation_engine=self.correlation_engine,
-                attack_graph=self.attack_graph if hasattr(self, 'attack_graph') else None,  # FIX 5
+                attack_graph=self.attack_graph if hasattr(self, "attack_graph") else None,  # FIX 5
                 agent_state=self.state,
             )
         except ImportError as e:
-            # Tool module not available in this environment
-            logging.warning(f"Scan status tool not available: {e}")
-            pass
+            logging.warning(
+                "Scan status tool not available: %s (agent=%s)",
+                e,
+                self.state.agent_name,
+            )
 
         from phantom.telemetry.tracer import get_global_tracer
 
@@ -201,8 +242,7 @@ class BaseAgent(metaclass=AgentMeta):
         self._add_to_agents_graph()
 
         # ΓöÇΓöÇ Audit: log agent creation ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-        from phantom.logging.audit import get_audit_logger as _get_audit
-        _audit = _get_audit()
+        _audit = _get_audit_logger()
         if _audit:
             _audit.log_agent_created(
                 agent_id=self.state.agent_id,
@@ -247,7 +287,7 @@ class BaseAgent(metaclass=AgentMeta):
             with agents_graph_actions._ROOT_AGENT_LOCK:
                 agents_graph_actions._root_agent_id = self.state.agent_id
 
-    def _restore_sub_agents_from_checkpoint(self) -> None:
+    async def _restore_sub_agents_from_checkpoint(self) -> None:
         restored = self.config.get("_restored_sub_agent_states")
         if not isinstance(restored, dict) or not restored:
             return
@@ -257,6 +297,7 @@ class BaseAgent(metaclass=AgentMeta):
             from phantom.agents.state import AgentState
             from phantom.tools.agents_graph import agents_graph_actions
         except Exception:
+            logger.exception("Failed to import sub-agent restore modules")
             return
 
         parent_id = self.state.agent_id
@@ -277,15 +318,22 @@ class BaseAgent(metaclass=AgentMeta):
             try:
                 sub_state = AgentState.model_validate(state_payload)
             except Exception:
+                logger.warning(
+                    "Failed to deserialize sub-agent state for id=%s, skipping",
+                    sub_agent_id,
+                )
                 continue
 
             sub_state.clear_sandbox()
             if not sub_state.parent_id:
                 sub_state.parent_id = parent_id
 
-            with agents_graph_actions._GRAPH_LOCK:
-                if sub_state.agent_id in agents_graph_actions._agent_graph["nodes"]:
-                    continue
+            def _check_existing() -> bool:
+                with agents_graph_actions._GRAPH_LOCK:
+                    return sub_state.agent_id in agents_graph_actions._agent_graph["nodes"]
+
+            if await asyncio.to_thread(_check_existing):
+                continue
 
             sub_llm_config = LLMConfig(
                 skills=list(self.llm_config.skills or []),
@@ -299,7 +347,6 @@ class BaseAgent(metaclass=AgentMeta):
                 "local_sources": self.local_sources,
                 "hypothesis_ledger": self.hypothesis_ledger,
                 "coverage_tracker": self.coverage_tracker,
-                "correlation_engine": self.correlation_engine,
                 "attack_graph": self.attack_graph,
             }
 
@@ -317,13 +364,16 @@ class BaseAgent(metaclass=AgentMeta):
                     }
                 )
 
-            with agents_graph_actions._GRAPH_LOCK:
-                node = agents_graph_actions._agent_graph["nodes"].get(sub_state.agent_id)
-                if node is not None:
-                    node["status"] = "running"
-                    node["finished_at"] = None
-                    node["result"] = None
-                    node["task"] = sub_state.task
+            def _update_node() -> None:
+                with agents_graph_actions._GRAPH_LOCK:
+                    node = agents_graph_actions._agent_graph["nodes"].get(sub_state.agent_id)
+                    if node is not None:
+                        node["status"] = "running"
+                        node["finished_at"] = None
+                        node["result"] = None
+                        node["task"] = sub_state.task
+
+            await asyncio.to_thread(_update_node)
 
             import threading
 
@@ -334,8 +384,12 @@ class BaseAgent(metaclass=AgentMeta):
                 name=f"Agent-{sub_state.agent_name}-{sub_state.agent_id}-resumed",
             )
             thread.start()
-            with agents_graph_actions._GRAPH_LOCK:
-                agents_graph_actions._running_agents[sub_state.agent_id] = thread
+
+            def _register_running() -> None:
+                with agents_graph_actions._GRAPH_LOCK:
+                    agents_graph_actions._running_agents[sub_state.agent_id] = thread
+
+            await asyncio.to_thread(_register_running)
 
     async def agent_loop(self, task: str) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
         import time as _time_mod
@@ -358,13 +412,32 @@ class BaseAgent(metaclass=AgentMeta):
 
         _rl_consecutive = 0  # consecutive rate-limit hits for exponential backoff
         _no_action_streak = 0
+        # FIX: hard wall-clock timeout so a scan cannot run forever
+        _scan_wall_clock_limit = float(Config.get("phantom_scan_wall_timeout") or "7200")
+        _scan_deadline = _time_mod.monotonic() + _scan_wall_clock_limit
         while True:
+            # FIX: Stop-signal race condition. Previously _force_stop was cleared
+            # immediately, so a second stop request arriving before the next loop
+            # iteration was lost. Now we clear only after successfully entering
+            # the waiting state, and re-check immediately after.
             if self._force_stop:
-                self._force_stop = False
                 await self._enter_waiting_state(tracer, was_cancelled=True)
+                self._force_stop = False
                 continue
 
-            self._check_agent_messages(self.state)
+            # FIX: wall-clock timeout ΓÇö abort if scan has exceeded hard time limit
+            if _time_mod.monotonic() > _scan_deadline:
+                _timeout_msg = (
+                    f"Scan aborted: wall-clock timeout ({_scan_wall_clock_limit:.0f}s) exceeded."
+                )
+                logger.error(_timeout_msg)
+                self.state.set_completed({"success": False, "error": _timeout_msg})
+                if tracer:
+                    tracer.update_agent_status(self.state.agent_id, "failed")
+                self._maybe_save_checkpoint(tracer, force=True)
+                return self.state.final_result or {"success": False, "error": _timeout_msg}
+
+            await self._check_agent_messages(self.state)
 
             if self.state.is_waiting_for_input():
                 await self._wait_for_input()
@@ -376,10 +449,7 @@ class BaseAgent(metaclass=AgentMeta):
                     if tracer:
                         tracer.update_agent_status(self.state.agent_id, "failed")
 
-                if self.non_interactive:
-                    return self.state.final_result or {}
-                await self._enter_waiting_state(tracer)
-                continue
+                return self.state.final_result or {}
 
             if self.state.llm_failed:
                 await self._wait_for_input()
@@ -388,8 +458,7 @@ class BaseAgent(metaclass=AgentMeta):
             self.state.increment_iteration()
 
             # ΓöÇΓöÇ Audit: log iteration ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-            from phantom.logging.audit import get_audit_logger as _get_audit_it
-            _audit_it = _get_audit_it()
+            _audit_it = _get_audit_logger()
             if _audit_it:
                 _audit_it.log_agent_iteration(
                     self.state.agent_id, self.state.iteration, self.state.max_iterations
@@ -439,8 +508,9 @@ class BaseAgent(metaclass=AgentMeta):
                     self.state.add_message(
                         "user",
                         "No actionable progress detected for multiple iterations. "
-                        "Stop repeating prior reconnaissance and pivot to a new exploit path "
-                        "or report validated findings now.",
+                        "If the scan is complete, call finish_scan to end. "
+                        "Otherwise, pivot to a new exploit path or continue reconnaissance. "
+                        "Do NOT output natural language without a tool call.",
                     )
                 if _no_action_streak >= 8 and self.non_interactive:
                     _stall_msg = (
@@ -452,46 +522,39 @@ class BaseAgent(metaclass=AgentMeta):
                         tracer.update_agent_status(self.state.agent_id, "failed")
                     return self.state.final_result or {"success": False, "error": _stall_msg}
 
-                # Periodic checkpoint save ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                self._maybe_save_checkpoint(tracer)
-                # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
                 if should_finish:
-                    if self.non_interactive:
-                        self.state.set_completed({"success": True})
-                        if tracer:
-                            tracer.update_agent_status(self.state.agent_id, "completed")
-                        # ΓöÇΓöÇ Audit: log agent completed ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        from phantom.logging.audit import get_audit_logger as _get_audit_done
-                        _audit_done = _get_audit_done()
-                        _scan_duration = (_time_mod.monotonic() - self._agent_start_time) * 1000
-                        if _audit_done:
-                            _audit_done.log_agent_completed(
-                                agent_id=self.state.agent_id,
-                                name=self.state.agent_name,
-                                task=self.state.task,
-                                result=self.state.final_result,
-                                iterations=self.state.iteration,
-                                duration_ms=_scan_duration,
-                            )
-                            # ΓöÇΓöÇ EFFICIENCY REC HIGH-2: Log cache statistics ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                            try:
-                                from phantom.tools.cache import get_tool_cache
-                                _cache = get_tool_cache()
-                                if _cache and _cache.enabled:
-                                    _cache_stats = _cache.get_stats_summary()
-                                    _audit_done.log_cache_stats(
-                                        agent_id=self.state.agent_id,
-                                        cache_stats=_cache_stats,
-                                        scan_duration_ms=_scan_duration,
-                                    )
-                            except Exception:  # noqa: BLE001
-                                pass  # Non-critical ΓÇö don't fail scan if cache reporting fails
-                            # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        return self.state.final_result or {}
-                    await self._enter_waiting_state(tracer, task_completed=True)
-                    continue
+                    self.state.set_completed({"success": True})
+                    if tracer:
+                        tracer.update_agent_status(self.state.agent_id, "completed")
+                    # ΓöÇΓöÇ Audit: log agent completed ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                    _audit_done = _get_audit_logger()
+                    _scan_duration = (_time_mod.monotonic() - self._agent_start_time) * 1000
+                    if _audit_done:
+                        _audit_done.log_agent_completed(
+                            agent_id=self.state.agent_id,
+                            name=self.state.agent_name,
+                            task=self.state.task,
+                            result=self.state.final_result,
+                            iterations=self.state.iteration,
+                            duration_ms=_scan_duration,
+                        )
+                        # ΓöÇΓöÇ EFFICIENCY REC HIGH-2: Log cache statistics ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                        try:
+                            from phantom.tools.cache import get_tool_cache
+
+                            _cache = get_tool_cache()
+                            if _cache and _cache.enabled:
+                                _cache_stats = _cache.get_stats_summary()
+                                _audit_done.log_cache_stats(
+                                    agent_id=self.state.agent_id,
+                                    cache_stats=_cache_stats,
+                                    scan_duration_ms=_scan_duration,
+                                )
+                        except Exception:  # noqa: BLE001
+                            pass  # Non-critical ΓÇö don't fail scan if cache reporting fails
+                        # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                    # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                    return self.state.final_result or {}
 
             except asyncio.CancelledError:
                 self._current_task = None
@@ -501,16 +564,17 @@ class BaseAgent(metaclass=AgentMeta):
                         self.state.add_message(
                             "assistant", f"{partial_content}\n\n[ABORTED BY USER]"
                         )
-                if self.non_interactive:
-                    raise
-                await self._enter_waiting_state(tracer, error_occurred=False, was_cancelled=True)
-                continue
+                raise
 
             except LLMRequestFailedError as e:
                 # Rate-limit errors are transient ΓÇö pause and retry the agent loop
                 # rather than aborting (applies in both interactive and non-interactive modes).
                 error_lower = str(e).lower()
-                if "rate limit" in error_lower or "ratelimit" in error_lower or "rate_limit" in error_lower:
+                if (
+                    "rate limit" in error_lower
+                    or "ratelimit" in error_lower
+                    or "rate_limit" in error_lower
+                ):
                     _rl_consecutive += 1
                     # H-03 follow-up: hard cap ΓÇö abort if API key appears revoked/exhausted
                     _rl_max = int(Config.get("phantom_llm_ratelimit_max_agent_retries") or "10")
@@ -523,9 +587,10 @@ class BaseAgent(metaclass=AgentMeta):
                         )
                         logger.error(_abort_msg)
                         # ΓöÇΓöÇ Audit: log RL abort ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        from phantom.logging.audit import get_audit_logger as _get_audit_rl
-                        _audit_rl = _get_audit_rl()
-                        _model_name = getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
+                        _audit_rl = _get_audit_logger()
+                        _model_name = (
+                            getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
+                        )
                         if _audit_rl:
                             _audit_rl.log_rate_limit_abort(
                                 agent_id=self.state.agent_id,
@@ -541,8 +606,7 @@ class BaseAgent(metaclass=AgentMeta):
                         # S-03: Emergency checkpoint save before abort so work is not lost.
                         self._maybe_save_checkpoint(tracer, force=True)
                         # ΓöÇΓöÇ Audit: log agent failed (RL abort) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        from phantom.logging.audit import get_audit_logger as _get_audit_rla
-                        _audit_rla = _get_audit_rla()
+                        _audit_rla = _get_audit_logger()
                         if _audit_rla:
                             _audit_rla.log_agent_failed(
                                 agent_id=self.state.agent_id,
@@ -564,9 +628,10 @@ class BaseAgent(metaclass=AgentMeta):
                         _sleep,
                     )
                     # ΓöÇΓöÇ Audit: log RL backoff hit ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                    from phantom.logging.audit import get_audit_logger as _get_audit_rlh
-                    _audit_rlh = _get_audit_rlh()
-                    _model_name = getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
+                    _audit_rlh = _get_audit_logger()
+                    _model_name = (
+                        getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
+                    )
                     if _audit_rlh:
                         _audit_rlh.log_rate_limit_hit(
                             agent_id=self.state.agent_id,
@@ -583,28 +648,28 @@ class BaseAgent(metaclass=AgentMeta):
                     return result
                 continue
 
-            except (RuntimeError, ValueError, TypeError) as e:
-                if not await self._handle_iteration_error(e, tracer):
-                    if self.non_interactive:
-                        self.state.set_completed({"success": False, "error": str(e)})
-                        if tracer:
-                            tracer.update_agent_status(self.state.agent_id, "failed")
-                        # ΓöÇΓöÇ Audit: log agent failed (unhandled error) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        from phantom.logging.audit import get_audit_logger as _get_audit_err
-                        _audit_err = _get_audit_err()
-                        if _audit_err:
-                            _audit_err.log_agent_failed(
-                                agent_id=self.state.agent_id,
-                                name=self.state.agent_name,
-                                agent_type=self.__class__.__name__,
-                                error=str(e),
-                                iterations=self.state.iteration,
-                                duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
-                            )
-                        # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-                        raise
-                    await self._enter_waiting_state(tracer, error_occurred=True)
-                    continue
+            except Exception as e:
+                _handled = await self._handle_iteration_error(e, tracer)
+                if _handled:
+                    # CancelledError was caught and handled ΓÇö propagate it
+                    # so outer cancellation logic can clean up properly.
+                    raise
+                self.state.set_completed({"success": False, "error": str(e)})
+                if tracer:
+                    tracer.update_agent_status(self.state.agent_id, "failed")
+                # ΓöÇΓöÇ Audit: log agent failed (unhandled error) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                _audit_err = _get_audit_logger()
+                if _audit_err:
+                    _audit_err.log_agent_failed(
+                        agent_id=self.state.agent_id,
+                        name=self.state.agent_name,
+                        agent_type=self.__class__.__name__,
+                        error=str(e),
+                        iterations=self.state.iteration,
+                        duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
+                    )
+                # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
+                return self.state.final_result or {"success": False, "error": str(e)}
 
     async def _wait_for_input(self) -> None:
         if self._force_stop:
@@ -702,7 +767,7 @@ class BaseAgent(metaclass=AgentMeta):
             self.state.task = task
 
         if self.state.parent_id is None:
-            self._restore_sub_agents_from_checkpoint()
+            await self._restore_sub_agents_from_checkpoint()
 
         # Only add the initial task message when the history is fresh.
         # When resuming from a checkpoint, messages are already populated.
@@ -734,14 +799,18 @@ class BaseAgent(metaclass=AgentMeta):
         if should_inject_status:
             try:
                 from phantom.tools.scan_status.scan_status_actions import get_scan_status
+
                 status = get_scan_status(
                     include_recommendations=False,
                     agent_id=self.state.agent_id,
                 )
-                
-                # Format as compact message
+
                 status_msg = self._format_scan_status(status)
-                self.state.add_message("user", status_msg)
+                # FIX: simple string comparison instead of expensive SHA-256
+                last_status = getattr(self.state, "_last_status_msg", None)
+                if status_msg != last_status:
+                    setattr(self.state, "_last_status_msg", status_msg)
+                    self.state.add_message("user", status_msg)
             except Exception as e:
                 logging.debug(f"Failed to inject scan status: {e}")
                 if tracer:
@@ -771,12 +840,20 @@ class BaseAgent(metaclass=AgentMeta):
                     "call create_vulnerability_report as soon as possible, then prepare to finish the scan."
                 )
             if _gate_msg:
-                self.state.add_message("user", _gate_msg)
+                # FIX: inject as system guidance, not user input
+                self.state.add_message("system", _gate_msg)
 
-        async for response in self.llm.generate(self._build_hypothesis_context()):
-            final_response = response
-            if tracer and response.content:
-                tracer.update_streaming_content(self.state.agent_id, response.content)
+        # FIX: wrap LLM stream in a timeout to prevent infinite hangs
+        # when the provider accepts the connection but never sends chunks.
+        _llm_timeout = float(Config.get("phantom_llm_stream_timeout") or "300")
+        try:
+            async for response in self.llm.generate(self._build_hypothesis_context()):
+                final_response = response
+                if tracer and response.content:
+                    tracer.update_streaming_content(self.state.agent_id, response.content)
+        except asyncio.TimeoutError:
+            logger.error("LLM stream timed out after %.0fs (agent=%s iter=%d)", _llm_timeout, self.state.agent_name, self.state.iteration)
+            self.state.add_message("user", f"[SYSTEM: LLM response timed out after {_llm_timeout}s. Retry with a simpler request.]")
 
         if final_response is None:
             self._last_iteration_action_count = 0
@@ -799,10 +876,16 @@ class BaseAgent(metaclass=AgentMeta):
                         self._cleanup_message_history(tracer)
                         return False
                 except Exception:
-                    pass
-            # B2: Compact corrective message (was ~200 tokens, now ~30)
+                    logger.exception(
+                        "Reflector failed on empty response (agent=%s iter=%d)",
+                        self.state.agent_name,
+                        self.state.iteration,
+                    )
             corrective_message = (
-                "Empty response. You MUST call a tool. Try: terminal_execute, send_request, or create_vulnerability_report."
+                "Empty response. You MUST call a tool. "
+                "If the scan is complete, call finish_scan to end. "
+                "Otherwise, continue with the next recon or exploitation step. "
+                "NEVER output natural language without a tool call."
             )
             self.state.add_message("user", corrective_message)
             self._cleanup_message_history(tracer)
@@ -838,21 +921,28 @@ class BaseAgent(metaclass=AgentMeta):
                 if suggestion:
                     self.state.add_message("user", f"Reflector note: {suggestion}")
             except Exception:
-                pass
-
-        self._last_iteration_action_count = 0
+                logger.exception(
+                    "Reflector failed on no-action response (agent=%s iter=%d)",
+                    self.state.agent_name,
+                    self.state.iteration,
+                )
         self._cleanup_message_history(tracer)
         return False
 
     async def _execute_actions(self, actions: list[Any], tracer: Optional["Tracer"]) -> bool:
         """Execute actions and return True if agent should finish."""
+
         # Avoid blind repetition of identical action batches across consecutive iterations.
         # This reduces dead-end payload retries without changing tool semantics.
         def _strip(v):
-            if isinstance(v, str): return v.strip()
-            if isinstance(v, dict): return {k: _strip(val) for k, val in v.items()}
-            if isinstance(v, list): return [_strip(val) for val in v]
+            if isinstance(v, str):
+                return v.strip()
+            if isinstance(v, dict):
+                return {k: _strip(val) for k, val in v.items()}
+            if isinstance(v, list):
+                return [_strip(val) for val in v]
             return v
+
         try:
             batch_signature = json.dumps(
                 [
@@ -868,19 +958,18 @@ class BaseAgent(metaclass=AgentMeta):
             batch_signature = ""
 
         if batch_signature:
-            # AUDIT-FIX-10: Only block repeated batches when the previous
-            # identical call SUCCEEDED. If it errored/timed-out, allow retry.
-            _recent = self._recent_action_results[-2:] if len(self._recent_action_results) >= 2 else []
-            if _recent and all(
-                sig == batch_signature and succeeded
-                for sig, succeeded in _recent
-            ):
-                self.state.add_message(
-                    "user",
-                    "You repeated the exact same tool action batch multiple times with no new "
-                    "signal. Change payload/target/vector before retrying.",
-                )
-                return False
+            # Block repeated batches when the previous identical call SUCCEEDED.
+            # If it errored/timed-out, allow retry.
+            # FIX: Check last call only (was checking last 2, allowing 2nd duplicate through).
+            if self._recent_action_results:
+                last_sig, last_succeeded = self._recent_action_results[-1]
+                if last_sig == batch_signature and last_succeeded:
+                    self.state.add_message(
+                        "user",
+                        "You just executed this exact action and it succeeded. "
+                        "Do NOT repeat it. Move to the next target, payload, or vector.",
+                    )
+                    return False
             # NOTE: _recent_action_results is appended AFTER execution below
             if len(self._recent_action_batches) > 8:
                 self._recent_action_batches = self._recent_action_batches[-8:]
@@ -888,10 +977,12 @@ class BaseAgent(metaclass=AgentMeta):
         for action in actions:
             self.state.add_action(action)
 
-        conversation_history = self.state.get_conversation_history()
+        # FIX: save checkpoint BEFORE executing tools so that if the agent
+        # crashes during tool execution (OOM, sandbox death, power loss) the
+        # checkpoint reflects the state with the tool plan already recorded.
+        self._maybe_save_checkpoint(tracer)
 
-        llm_obj = getattr(self, "llm", None)
-        allowed_tools = set(getattr(llm_obj, "runtime_allowed_tools", set()) or set())
+        conversation_history = self.state.get_conversation_history()
 
         tool_task = asyncio.create_task(
             process_tool_invocations(
@@ -899,7 +990,6 @@ class BaseAgent(metaclass=AgentMeta):
                 conversation_history,
                 self.state,
                 self,
-                allowed_tools=allowed_tools,
             )
         )
         self._current_task = tool_task
@@ -909,7 +999,9 @@ class BaseAgent(metaclass=AgentMeta):
             self._current_task = None
             batch_succeeded = True
             if hasattr(self.state, "context"):
-                batch_succeeded = not bool(self.state.context.get("last_tool_batch_had_error", False))
+                batch_succeeded = not bool(
+                    self.state.context.get("last_tool_batch_had_error", False)
+                )
 
             # AUDIT-FIX-10: Record signature outcome for dedup tracking
             if batch_signature:
@@ -917,7 +1009,7 @@ class BaseAgent(metaclass=AgentMeta):
                 if len(self._recent_action_results) > 8:
                     self._recent_action_results = self._recent_action_results[-8:]
 
-# Runtime guardrail: SSRF block removed - allow all URLs
+            # Runtime guardrail: SSRF block removed - allow all URLs
             pass
         except asyncio.CancelledError:
             self._current_task = None
@@ -929,7 +1021,9 @@ class BaseAgent(metaclass=AgentMeta):
                     self._recent_action_results = self._recent_action_results[-8:]
             raise
 
-        self.state.messages = conversation_history
+        # FIX: Do NOT revert state.messages to the pre-tool snapshot.
+        # process_tool_invocations already appends tool results to state.messages.
+        # Reverting here was permanently discarding all tool output, making the LLM blind.
 
         if should_agent_finish:
             self.state.set_completed({"success": True})
@@ -941,70 +1035,82 @@ class BaseAgent(metaclass=AgentMeta):
 
         return False
 
-    def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
+    async def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
         try:
-            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages
+            from phantom.tools.agents_graph.agents_graph_actions import (
+                _agent_graph,
+                _agent_messages,
+                _GRAPH_LOCK,
+            )
 
             agent_id = state.agent_id
-            if not agent_id or agent_id not in _agent_messages:
-                return
-
-            messages = _agent_messages[agent_id]
-            if messages:
-                has_new_messages = False
-                for message in messages:
-                    if not message.get("read", False):
-                        sender_id = message.get("from")
-
-                        if state.is_waiting_for_input():
-                            if state.llm_failed:
-                                if sender_id == "user":
-                                    state.resume_from_waiting()
-                                    has_new_messages = True
 
-                                    from phantom.telemetry.tracer import get_global_tracer
+            def _sync_check() -> None:
+                _GRAPH_LOCK.acquire()
+                try:
+                    if not agent_id or agent_id not in _agent_messages:
+                        return
 
-                                    tracer = get_global_tracer()
-                                    if tracer:
-                                        tracer.update_agent_status(state.agent_id, "running")
-                            else:
-                                state.resume_from_waiting()
-                                has_new_messages = True
+                    messages = _agent_messages[agent_id]
+                    if messages:
+                        has_new_messages = False
+                        for message in messages:
+                            if not message.get("read", False):
+                                sender_id = message.get("from")
 
-                                from phantom.telemetry.tracer import get_global_tracer
+                                if state.is_waiting_for_input():
+                                    if state.llm_failed:
+                                        if sender_id == "user":
+                                            state.resume_from_waiting()
+                                            has_new_messages = True
 
-                                tracer = get_global_tracer()
-                                if tracer:
-                                    tracer.update_agent_status(state.agent_id, "running")
+                                            from phantom.telemetry.tracer import get_global_tracer
 
-                        if sender_id == "user":
-                            sender_name = "User"
-                            state.add_message("user", message.get("content", ""))
-                        else:
-                            # BUG FIX B: initialise sender_name with a safe fallback
-                            # so the f-string below never raises NameError when
-                            # sender_id is absent from the agent graph.
-                            sender_name = sender_id or "unknown-agent"
-                            if sender_id and sender_id in _agent_graph.get("nodes", {}):
-                                sender_name = _agent_graph["nodes"][sender_id]["name"]
+                                            tracer = get_global_tracer()
+                                            if tracer:
+                                                tracer.update_agent_status(state.agent_id, "running")
+                                    else:
+                                        state.resume_from_waiting()
+                                        has_new_messages = True
 
-                            # B3: Compact inter-agent message format (was ~400 tokens XML, now ~50 tokens)
-                            import html as _html
+                                        from phantom.telemetry.tracer import get_global_tracer
 
-                            safe_sender_name = _html.escape(str(sender_name))
-                            safe_content = _html.escape(str(message.get("content", ""))[:200])
+                                        tracer = get_global_tracer()
+                                        if tracer:
+                                            tracer.update_agent_status(state.agent_id, "running")
 
-                            message_content = f"[From {safe_sender_name}]: {safe_content}"
-                            state.add_message("user", message_content.strip())
+                                if sender_id == "user":
+                                    sender_name = "User"
+                                    state.add_message("user", message.get("content", ""))
+                                else:
+                                    sender_name = sender_id or "unknown-agent"
+                                    if sender_id and sender_id in _agent_graph.get("nodes", {}):
+                                        sender_name = _agent_graph["nodes"][sender_id]["name"]
 
-                        message["read"] = True
+                                    import html as _html
 
-                if has_new_messages and not state.is_waiting_for_input():
-                    from phantom.telemetry.tracer import get_global_tracer
+                                    safe_sender_name = _html.escape(str(sender_name))
 
-                    tracer = get_global_tracer()
-                    if tracer:
-                        tracer.update_agent_status(agent_id, "running")
+                                    raw_content = str(message.get("content", ""))
+                                    safe_content = _html.escape(raw_content)
+                                    if len(safe_content) > 200:
+                                        safe_content = safe_content[:197] + "..."
+
+                                    message_content = f"[From {safe_sender_name}]: {safe_content}"
+                                    state.add_message("user", message_content.strip())
+
+                                message["read"] = True
+
+                        if has_new_messages and not state.is_waiting_for_input():
+                            from phantom.telemetry.tracer import get_global_tracer
+
+                            tracer = get_global_tracer()
+                            if tracer:
+                                tracer.update_agent_status(agent_id, "running")
+                finally:
+                    _GRAPH_LOCK.release()
+
+            await asyncio.to_thread(_sync_check)
 
         except (AttributeError, KeyError, TypeError) as e:
             logger.warning("Error checking agent messages: %s", e)
@@ -1027,19 +1133,17 @@ class BaseAgent(metaclass=AgentMeta):
                 state=self.state,
                 tracer=tracer,
                 scan_config=tracer.scan_config or {} if tracer else {},
-                # P4: Include hypothesis ledger, coverage tracker, and correlation engine
+                # P4: Include hypothesis ledger, coverage tracker
                 hypothesis_ledger=self.hypothesis_ledger,
                 coverage_tracker=self.coverage_tracker,
-                correlation_engine=self.correlation_engine,
                 # FIX 5: Include attack graph for vulnerability chain analysis
-                attack_graph=self.attack_graph if hasattr(self, 'attack_graph') else None,
+                attack_graph=self.attack_graph if hasattr(self, "attack_graph") else None,
                 # Wave D: Persist active sub-agent states for resume continuity
                 active_sub_agents=self._collect_active_sub_agent_states(),
             )
             checkpoint_mgr.save(cp)
             # ΓöÇΓöÇ Audit: log checkpoint saved ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-            from phantom.logging.audit import get_audit_logger as _get_audit_ck
-            _audit_ck = _get_audit_ck()
+            _audit_ck = _get_audit_logger()
             if _audit_ck:
                 _audit_ck.log_checkpoint(
                     agent_id=self.state.agent_id,
@@ -1079,6 +1183,10 @@ class BaseAgent(metaclass=AgentMeta):
 
             return collected
         except Exception:
+            logger.exception(
+                "Failed to collect active sub-agent states (agent=%s)",
+                self.state.agent_name,
+            )
             return {}
 
     def _cleanup_message_history(self, tracer: Optional["Tracer"]) -> None:
@@ -1087,14 +1195,25 @@ class BaseAgent(metaclass=AgentMeta):
         This keeps the full raw history available to compression/anchor extraction
         for the current turn, then bounds the retained state once the turn is done.
         """
+        # FIX: reduce cleanup frequency to avoid conflict with memory_compressor.
+        # The compressor in _prepare_messages is the primary truncation mechanism;
+        # this cleanup is a safety valve only.
         max_before_cleanup = int(getattr(self.state, "MAX_MESSAGES_BEFORE_CLEANUP", 50) or 50)
-        scan_mode = str(getattr(self.state, "scan_mode", "") or getattr(self.llm_config, "scan_mode", "")).lower()
-        cleanup_multiplier = 4 if scan_mode == "deep" else 2
+        scan_mode = str(
+            getattr(self.state, "scan_mode", "") or getattr(self.llm_config, "scan_mode", "")
+        ).lower()
+        cleanup_multiplier = 6 if scan_mode == "deep" else 4
         cleanup_threshold = max_before_cleanup * cleanup_multiplier
         message_count = len(self.state.get_conversation_history())
         if message_count <= cleanup_threshold or not hasattr(self.state, "cleanup_old_messages"):
             return
 
+        # Only clean up every 10 iterations to avoid fighting the compressor
+        last_cleanup_iter = getattr(self, "_last_cleanup_iteration", 0)
+        if self.state.iteration - last_cleanup_iter < 10:
+            return
+        self._last_cleanup_iteration = self.state.iteration
+
         removed = self.state.cleanup_old_messages()
         if removed > 0 and tracer:
             tracer.record_runtime_event(
@@ -1131,7 +1250,11 @@ class BaseAgent(metaclass=AgentMeta):
                     if hid:
                         hypothesis_ids.add(hid)
         except Exception:
-            pass
+            logger.warning(
+                "Failed to access hypothesis ledger (agent=%s iter=%d)",
+                self.state.agent_name,
+                self.state.iteration,
+            )
 
         if not active_surface and not active_vclass:
             return history
@@ -1167,11 +1290,15 @@ class BaseAgent(metaclass=AgentMeta):
                         }
                     )
         except Exception:
+            logger.warning(
+                "Failed to extract supporting evidence (agent=%s)",
+                self.state.agent_name,
+            )
             supporting = []
 
         scoped: list[dict[str, Any]] = []
         from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS
-        
+
         for msg in history:
             content = msg.get("content", "")
             text = content if isinstance(content, str) else str(content)
@@ -1183,14 +1310,17 @@ class BaseAgent(metaclass=AgentMeta):
                     mentions_other_hypothesis = True
                     break
 
-            if mentions_other_hypothesis:
-                continue
-            
-            # FIX A1: If it contains a core finding anchor, always keep it regardless of surface
+            # FIX: Check for anchors BEFORE skipping other-hypothesis messages.
+            # Confirmed findings for other hypotheses must survive context filtering
+            # so the agent can chain multi-step exploits (e.g. IDOR ΓåÆ admin panel).
             has_anchor = any(k in lowered for k in _ANCHOR_KEYWORDS)
             if has_anchor:
                 keep = True
-                
+
+            # Only skip non-anchor messages about other hypotheses.
+            if mentions_other_hypothesis and not has_anchor:
+                continue
+
             if active_surface and active_surface.lower() in lowered:
                 keep = True
             if active_vclass and active_vclass.lower() in lowered:
@@ -1205,7 +1335,7 @@ class BaseAgent(metaclass=AgentMeta):
             # FIX A1 (cont): Override exclusion if it's a finding anchor
             if has_anchor:
                 keep = True
-                
+
             if "<finding_anchors>" in lowered or "<pinned_facts>" in lowered:
                 keep = True
             if msg.get("role") == "system":
@@ -1213,10 +1343,18 @@ class BaseAgent(metaclass=AgentMeta):
             if keep:
                 scoped.append(msg)
 
-        if not scoped:
+        # FIX: Always retain the last 15 messages as a "broad context" buffer
+        # so the LLM can pivot between hypotheses and see recent tool results.
+        broad_buffer = history[-15:] if len(history) > 15 else list(history)
+        broad_ids = {id(m) for m in broad_buffer}
+        for msg in scoped:
+            if id(msg) not in broad_ids:
+                broad_buffer.append(msg)
+
+        if not broad_buffer:
             return [hypothesis_block, *supporting, *history[-20:]]
 
-        return [hypothesis_block, *supporting, *scoped[-40:]]
+        return [hypothesis_block, *supporting, *broad_buffer[-55:]]
 
     def _format_scan_status(self, status: dict[str, Any]) -> str:
         """Format scan status into a compact message for LLM injection."""
@@ -1230,10 +1368,9 @@ class BaseAgent(metaclass=AgentMeta):
         chains = status.get("chain_opportunities", [])
         recommendation = status.get("recommended_next_action")
         warnings = status.get("warnings", [])
-        
+
         lines = ["[AUTO-STATUS ΓÇö Scan Progress Update]"]
         lines.append(
-            f"Phase: {progress.get('phase')} | "
             f"Iteration {progress.get('iteration')}/{progress.get('max_iterations')} "
             f"({progress.get('percent_complete')}%)"
         )
@@ -1251,10 +1388,10 @@ class BaseAgent(metaclass=AgentMeta):
         if blocked_surfaces:
             lines.append(f"Blocked: {len(blocked_surfaces)} surfaces")
             for blocked in blocked_surfaces[:2]:
-                reasons = ", ".join(str(reason) for reason in blocked.get("failure_reasons", [])[:2])
-                lines.append(
-                    f"  - {str(blocked.get('surface', ''))[:45]} | {reasons[:70]}"
+                reasons = ", ".join(
+                    str(reason) for reason in blocked.get("failure_reasons", [])[:2]
                 )
+                lines.append(f"  - {str(blocked.get('surface', ''))[:45]} | {reasons[:70]}")
 
         if top_hypotheses:
             if isinstance(top_hypotheses, str):
@@ -1283,23 +1420,41 @@ class BaseAgent(metaclass=AgentMeta):
                 if critical_bits:
                     lines.append(f"  Critical: {', '.join(critical_bits)}")
 
+            top_attack_plans = attack_graph.get("top_attack_plans", [])
+            if top_attack_plans:
+                lines.append(f"  Top Plans: {len(top_attack_plans)}")
+                for plan in top_attack_plans[:2]:
+                    if not isinstance(plan, dict):
+                        continue
+                    path = plan.get("path") or []
+                    if not isinstance(path, list) or not path:
+                        continue
+                    path_preview = " -> ".join(str(p) for p in path[:4])
+                    if len(path) > 4:
+                        path_preview = f"{path_preview} -> ..."
+                    lines.append(
+                        "  - "
+                        f"p={plan.get('probability')} "
+                        f"cost={plan.get('cost')} "
+                        f"score={plan.get('score')} "
+                        f"path={path_preview}"
+                    )
+
         if archived_messages:
-            lines.append(
-                f"Archived history: {archived_messages.get('count', 0)} messages retained"
-            )
-        
+            lines.append(f"Archived history: {archived_messages.get('count', 0)} messages retained")
+
         if chains:
             lines.append(f"Chain Opportunities: {len(chains)}")
             for chain in chains[:2]:
                 lines.append(f"  - {chain.get('chain')}: {chain.get('description', '')[:50]}")
-        
+
         if recommendation:
             lines.append(f"Recommended: {recommendation}")
-        
+
         if warnings:
             for warning in warnings:
                 lines.append(f"[!] {warning}")
-        
+
         lines.append("[END STATUS]")
         return "\n".join(lines)
 
@@ -1312,7 +1467,7 @@ class BaseAgent(metaclass=AgentMeta):
         error_details = error.details
         self.state.add_error(error_msg)
 
-        if self.non_interactive:
+        if self.non_interactive:  # Restored interactive fallback
             self.state.set_completed({"success": False, "error": error_msg})
             if tracer:
                 tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
@@ -1324,8 +1479,7 @@ class BaseAgent(metaclass=AgentMeta):
                     )
                     tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
             # ΓöÇΓöÇ Audit: log agent failed (sandbox error) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-            from phantom.logging.audit import get_audit_logger as _get_audit_sb
-            _audit_sb = _get_audit_sb()
+            _audit_sb = _get_audit_logger()
             if _audit_sb:
                 _audit_sb.log_agent_failed(
                     agent_id=self.state.agent_id,
@@ -1333,7 +1487,11 @@ class BaseAgent(metaclass=AgentMeta):
                     agent_type=self.__class__.__name__,
                     error=error_msg,
                     iterations=self.state.iteration,
-                    duration_ms=(__import__('time').monotonic() - getattr(self, '_agent_start_time', __import__('time').monotonic())) * 1000,
+                    duration_ms=(
+                        __import__("time").monotonic()
+                        - getattr(self, "_agent_start_time", __import__("time").monotonic())
+                    )
+                    * 1000,
                 )
             # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
             return {"success": False, "error": error_msg, "details": error_details}
@@ -1360,7 +1518,7 @@ class BaseAgent(metaclass=AgentMeta):
         error_details = getattr(error, "details", None)
         self.state.add_error(error_msg)
 
-        if self.non_interactive:
+        if self.non_interactive:  # Restored interactive fallback
             self.state.set_completed({"success": False, "error": error_msg})
             if tracer:
                 tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
@@ -1372,8 +1530,7 @@ class BaseAgent(metaclass=AgentMeta):
                     )
                     tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
             # ΓöÇΓöÇ Audit: log agent failed (LLM error) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-            from phantom.logging.audit import get_audit_logger as _get_audit_llme
-            _audit_llme = _get_audit_llme()
+            _audit_llme = _get_audit_logger()
             if _audit_llme:
                 _audit_llme.log_agent_failed(
                     agent_id=self.state.agent_id,
@@ -1381,7 +1538,11 @@ class BaseAgent(metaclass=AgentMeta):
                     agent_type=self.__class__.__name__,
                     error=error_msg,
                     iterations=self.state.iteration,
-                    duration_ms=(__import__('time').monotonic() - getattr(self, '_agent_start_time', __import__('time').monotonic())) * 1000,
+                    duration_ms=(
+                        __import__("time").monotonic()
+                        - getattr(self, "_agent_start_time", __import__("time").monotonic())
+                    )
+                    * 1000,
                 )
             # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
             return {"success": False, "error": error_msg}
@@ -1401,7 +1562,7 @@ class BaseAgent(metaclass=AgentMeta):
 
     async def _handle_iteration_error(
         self,
-        error: RuntimeError | ValueError | TypeError | asyncio.CancelledError,
+        error: Exception,
         tracer: Optional["Tracer"],
     ) -> bool:
         error_msg = f"Error in iteration {self.state.iteration}: {error!s}"
