diff --git a/phantom/tools/scan_status/scan_status_actions.py b/phantom/tools/scan_status/scan_status_actions.py
index a7fae86..2488b3f 100644
--- a/phantom/tools/scan_status/scan_status_actions.py
+++ b/phantom/tools/scan_status/scan_status_actions.py
@@ -16,7 +16,6 @@ from phantom.tools.registry import register_tool
 if TYPE_CHECKING:
     from phantom.agents.hypothesis_ledger import HypothesisLedger
     from phantom.agents.coverage_tracker import CoverageTracker
-    from phantom.agents.correlation_engine import CorrelationEngine
     from phantom.core.attack_graph import AttackGraph
 
 
@@ -36,8 +35,7 @@ def clear_scan_status_context(agent_id: str | None = None) -> None:
 def set_scan_status_context(
     hypothesis_ledger: HypothesisLedger | None = None,
     coverage_tracker: CoverageTracker | None = None,
-    correlation_engine: CorrelationEngine | None = None,
-    attack_graph: Any | None = None,  # FIX 5: AttackGraph
+    attack_graph: Any | None = None,
     agent_state: Any | None = None,
 ) -> None:
     """Set the global context for scan status queries."""
@@ -49,13 +47,12 @@ def set_scan_status_context(
         _CONTEXT_BY_AGENT[agent_id] = {
             "hypothesis_ledger": hypothesis_ledger,
             "coverage_tracker": coverage_tracker,
-            "correlation_engine": correlation_engine,
             "attack_graph": attack_graph,
             "agent_state": agent_state,
         }
 
 
-def _resolve_context(agent_id: str | None = None) -> tuple[Any, Any, Any, Any, Any]:
+def _resolve_context(agent_id: str | None = None) -> tuple[Any, Any, Any, Any]:
     if not agent_id:
         agent_id = "default"
     with _CONTEXT_LOCK:
@@ -64,7 +61,6 @@ def _resolve_context(agent_id: str | None = None) -> tuple[Any, Any, Any, Any, A
             return (
                 ctx.get("hypothesis_ledger"),
                 ctx.get("coverage_tracker"),
-                ctx.get("correlation_engine"),
                 ctx.get("attack_graph"),
                 ctx.get("agent_state"),
             )
@@ -144,13 +140,19 @@ def get_scan_status(include_recommendations: bool = True, agent_id: str | None =
     Example:
         get_scan_status(include_recommendations=True)
     """
+    explicit_agent_requested = bool(agent_id and str(agent_id).strip())
     agent_id = _resolve_effective_agent_id(agent_id)
 
     # Get references (agent-scoped only)
     try:
-        hypothesis_ledger, coverage_tracker, correlation_engine, attack_graph, state = _resolve_context(agent_id)
-    except ValueError:
-        return _empty_scan_status(include_recommendations=include_recommendations)
+        hypothesis_ledger, coverage_tracker, attack_graph, state = _resolve_context(agent_id)
+    except (ValueError, AttributeError):
+        if explicit_agent_requested:
+            return _empty_scan_status(include_recommendations=include_recommendations)
+        hypothesis_ledger = None
+        coverage_tracker = None
+        attack_graph = None
+        state = None
     
     # Compute phase
     iteration = getattr(state, "iteration", 0) if state else 0
@@ -162,7 +164,11 @@ def get_scan_status(include_recommendations: bool = True, agent_id: str | None =
     if hypothesis_ledger:
         all_hyps = hypothesis_ledger.get_all()
         hyp_stats["confirmed_count"] = sum(1 for h in all_hyps.values() if h.status == "confirmed")
-        hyp_stats["testing_count"] = sum(1 for h in all_hyps.values() if h.status == "testing")
+        hyp_stats["testing_count"] = sum(
+            1
+            for h in all_hyps.values()
+            if h.status in {"testing", "partial", "inconclusive", "underdetermined"}
+        )
         hyp_stats["open_count"] = sum(1 for h in all_hyps.values() if h.status == "open")
     
     confirmed = hyp_stats.get("confirmed_count", 0)
@@ -179,14 +185,14 @@ def get_scan_status(include_recommendations: bool = True, agent_id: str | None =
         cov_stats = {"tested": tested, "untested": untested}
         try:
             blocked_surfaces = coverage_tracker.get_blocked_surfaces()[:5]
-        except Exception:  # noqa: BLE001
+        except (AttributeError, TypeError, ValueError):  # noqa: BLE001
             blocked_surfaces = []
 
     top_hypotheses = []
     if hypothesis_ledger:
         try:
             top_hypotheses = hypothesis_ledger.get_scored_hypotheses()[:5]
-        except Exception:  # noqa: BLE001
+        except (AttributeError, TypeError, ValueError):  # noqa: BLE001
             top_hypotheses = []
 
     if state and hasattr(state, "get_archived_messages"):
@@ -196,35 +202,30 @@ def get_scan_status(include_recommendations: bool = True, agent_id: str | None =
                 "count": len(archived),
                 "recent": [str(msg.get("content", ""))[:120] for msg in archived[-2:]],
             }
-        except Exception:  # noqa: BLE001
+        except (AttributeError, TypeError, ValueError, KeyError):  # noqa: BLE001
             archived_messages = {"count": 0, "recent": []}
     
-    # Get chain opportunities
-    chains = []
-    correlation_learning = None
-    if correlation_engine is not None:
-        active = correlation_engine.get_active_suggestions()
-        chains = [
-            {
-                "chain": s.chain_name,
-                "surface": (
-                    next((f.surface for f in correlation_engine.get_findings() if f.id == s.trigger_finding_id), s.trigger_vuln_class)
-                ),
-                "description": s.description[:60]
-            }
-            for s in active[:3]
-        ]
-        try:
-            correlation_learning = correlation_engine.get_learning_metrics(top_n=3)
-        except Exception:  # noqa: BLE001
-            correlation_learning = None
-    
     # FIX 5: Get attack graph metrics
+    chains: list[dict[str, Any]] = []
+    correlation_learning: dict[str, Any] | None = None
     attack_graph_summary = None
     if attack_graph:
         try:
             surface = attack_graph.get_attack_surface()
             critical = attack_graph.get_critical_vulnerabilities(top_n=3)
+            top_attack_plans = []
+            planner_traces: list[dict[str, Any]] = []
+            try:
+                plans = attack_graph.get_ranked_attack_plans(max_plans=3, cutoff=4)
+                top_attack_plans = [p.to_dict() for p in plans]
+            except (AttributeError, TypeError, ValueError):  # noqa: BLE001
+                top_attack_plans = []
+            try:
+                raw_traces = attack_graph.metadata.get("planner_traces", [])
+                if isinstance(raw_traces, list):
+                    planner_traces = [t for t in raw_traces if isinstance(t, dict)][-3:]
+            except (AttributeError, TypeError, ValueError, KeyError):  # noqa: BLE001
+                planner_traces = []
             attack_graph_summary = {
                 "total_nodes": surface.get("total_nodes", 0),
                 "total_vulnerabilities": surface.get("total_vulnerabilities", 0),
@@ -234,16 +235,33 @@ def get_scan_status(include_recommendations: bool = True, agent_id: str | None =
                     {"id": v[0], "centrality": round(v[1], 4)} 
                     for v in critical
                 ],
+                "top_attack_plans": top_attack_plans,
+                "planner_traces": planner_traces,
             }
-        except Exception:  # noqa: BLE001
+        except (AttributeError, TypeError, ValueError, KeyError):  # noqa: BLE001
             pass  # Attack graph analysis failed - continue without it
     
     # Compute recommendation
     recommendation = None
     if include_recommendations:
         recommendation = _compute_recommendation(
-            hypothesis_ledger, coverage_tracker, correlation_engine, phase
+            hypothesis_ledger, coverage_tracker, phase
         )
+        if attack_graph is not None:
+            try:
+                plans = attack_graph.get_ranked_attack_plans(max_plans=1, cutoff=4)
+                if plans:
+                    top_plan = plans[0]
+                    path = " -> ".join(str(node) for node in top_plan.path[:5])
+                    if len(top_plan.path) > 5:
+                        path = f"{path} -> ..."
+                    recommendation = (
+                        "Prioritize top attack chain "
+                        f"(score={top_plan.score:.3f}, p={top_plan.probability:.3f}, cost={top_plan.cost:.2f}): "
+                        f"{path}"
+                    )
+            except (AttributeError, TypeError, ValueError):  # noqa: BLE001
+                pass
     
     result = {
         "scan_progress": {
@@ -294,29 +312,9 @@ def _compute_phase(iteration: int, max_iter: int) -> str:
 def _compute_recommendation(
     hyp_ledger: HypothesisLedger | None,
     cov_tracker: CoverageTracker | None,
-    corr_engine: CorrelationEngine | None,
     phase: str
 ) -> str:
     """Compute a recommendation string without taking execution decisions."""
-    # Priority 1: Confirmed vulns with chains
-    if corr_engine is not None:
-        active_chains = corr_engine.get_active_suggestions()
-        if active_chains:
-            top = active_chains[0]
-            top_surface = None
-            for finding in corr_engine.get_findings():
-                if finding.id == top.trigger_finding_id:
-                    top_surface = finding.surface
-                    break
-            score = corr_engine.get_surface_success_score(
-                top.trigger_vuln_class,
-                top_surface or top.trigger_vuln_class,
-            )
-            return (
-                f"Chain suggestions available: {len(active_chains)} "
-                f"(score: {score:.2f})"
-            )
-    
     # Hypothesis ledger facts only
     if hyp_ledger:
         summary = hyp_ledger.get_summary()
