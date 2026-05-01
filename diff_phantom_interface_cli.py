diff --git a/phantom/interface/cli.py b/phantom/interface/cli.py
index 887e7f6..9294779 100644
--- a/phantom/interface/cli.py
+++ b/phantom/interface/cli.py
@@ -12,7 +12,7 @@ from rich.live import Live
 from rich.panel import Panel
 from rich.text import Text
 
-from .tui_design_system import ACTION_BLUE, DANGER_CRIMSON, INFO_BLUE, WARNING_ORANGE
+from .tui_design_system import ACTION_BLUE, DANGER_CRIMSON, INFO_BLUE
 
 from phantom.agents.PhantomAgent import PhantomAgent
 from phantom.llm.config import LLMConfig
@@ -28,7 +28,7 @@ logger = logging.getLogger(__name__)
 
 def _build_resume_diff_text(cp: Any) -> str:
     """Format a human-readable summary of a loaded checkpoint for display at resume time."""
-    from datetime import UTC, datetime
+    from datetime import datetime
 
     lines = [
         f"  Resuming run  {cp.run_name}",
@@ -100,11 +100,10 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
         # creates a fresh container instead of trying to connect to a dead one.
         restored_state.clear_sandbox()
         
-        # P1.2 CRITICAL FIX: Restore hypothesis ledger, coverage tracker, and correlation engine
-        # Without this, resumed scans lose all testing progress and vulnerability chains
+        # P1.2 CRITICAL FIX: Restore hypothesis ledger, coverage tracker, and attack graph
+        # Without this, resumed scans lose all testing progress
         restored_hypothesis_ledger = None
         restored_coverage_tracker = None
-        restored_correlation_engine = None
         restored_attack_graph = None
 
         if cp.hypothesis_ledger_state:
@@ -126,14 +125,6 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
             except Exception as e:
                 logger.warning("Failed to restore coverage tracker: %s", e)
 
-        if cp.correlation_engine_state:
-            try:
-                from phantom.agents.correlation_engine import CorrelationEngine
-                restored_correlation_engine = CorrelationEngine.from_dict(cp.correlation_engine_state)
-                logger.info("Restored correlation engine from checkpoint")
-            except Exception as e:
-                logger.warning("Failed to restore correlation engine: %s", e)
-
         # FIX: Restore attack graph state if present
         if cp.attack_graph_state:
             try:
@@ -146,7 +137,6 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
         # Store restored components in args to pass to agent config
         args._restored_hypothesis_ledger = restored_hypothesis_ledger  # type: ignore[attr-defined]
         args._restored_coverage_tracker = restored_coverage_tracker  # type: ignore[attr-defined]
-        args._restored_correlation_engine = restored_correlation_engine  # type: ignore[attr-defined]
         args._restored_attack_graph = restored_attack_graph  # type: ignore[attr-defined]
 
         # FIX ISSUE#6: Restore sub-agent states from checkpoint
@@ -258,8 +248,6 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
         agent_config["hypothesis_ledger"] = args._restored_hypothesis_ledger
     if getattr(args, "_restored_coverage_tracker", None):
         agent_config["coverage_tracker"] = args._restored_coverage_tracker
-    if getattr(args, "_restored_correlation_engine", None):
-        agent_config["correlation_engine"] = args._restored_correlation_engine
     if getattr(args, "_restored_attack_graph", None):
         agent_config["attack_graph"] = args._restored_attack_graph
 
@@ -287,6 +275,8 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
 
     tracer = Tracer(args.run_name)
     tracer.set_scan_config(scan_config)
+    # FIX: register tracer globally so base_agent.py can retrieve it
+    set_global_tracer(tracer)
 
     # Restore previously found vulnerabilities into tracer so they show in live view
     if resume_run and cp is not None:
@@ -332,7 +322,6 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
                 interruption_reason=reason,
                 hypothesis_ledger=getattr(agent, "hypothesis_ledger", None),
                 coverage_tracker=getattr(agent, "coverage_tracker", None),
-                correlation_engine=getattr(agent, "correlation_engine", None),
                 attack_graph=getattr(agent, "attack_graph", None),
                 active_sub_agents=getattr(agent, "_collect_active_sub_agent_states", lambda: {})(),
             )
@@ -456,7 +445,9 @@ async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
                     "tool_executions": len(tracer.tool_executions),
                 }
             }
-            print(json.dumps(output, indent=2))
+            import sys
+
+            sys.stdout.write(json.dumps(output, indent=2) + "\n")
         elif quiet_mode:
             # Quiet mode: just print vuln count
             console.print(f"\nScan complete: {len(tracer.vulnerability_reports)} vulnerabilities found")
