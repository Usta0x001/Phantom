diff --git a/phantom/tools/hypothesis/hypothesis_actions.py b/phantom/tools/hypothesis/hypothesis_actions.py
index ffee1e3..8efa146 100644
--- a/phantom/tools/hypothesis/hypothesis_actions.py
+++ b/phantom/tools/hypothesis/hypothesis_actions.py
@@ -1,15 +1,9 @@
 """
 Hypothesis Ledger Tools ΓÇö LLM-Accessible Interface
-===================================================
+==================================================
 
 Exposes the hypothesis ledger to the LLM via tool calls, allowing
 the agent to query, add, and update hypotheses during a scan.
-
-FIX 4: Integrated with correlation engine to enable automatic
-vulnerability chain detection when hypotheses are confirmed.
-
-This solves the import error in base_agent.py and provides a clean
-interface for hypothesis management.
 """
 
 from __future__ import annotations
@@ -22,12 +16,10 @@ from phantom.tools.registry import register_tool
 
 if TYPE_CHECKING:
     from phantom.agents.hypothesis_ledger import HypothesisLedger
-    from phantom.agents.correlation_engine import CorrelationEngine
 
 # FIX Bug #3: Use dict keyed by agent_id instead of single global.
-# This prevents sub-agents from overwriting each other's ledgers/engines.
-_LEDGERS_BY_AGENT: dict[str, HypothesisLedger] = {}
-_CORRELATION_BY_AGENT: dict[str, CorrelationEngine] = {}
+# This prevents sub-agents from overwriting each other's ledgers.
+_LEDGERS_BY_AGENT: dict[str, "HypothesisLedger"] = {}
 _HYPOTHESIS_CONTEXT_LOCK = threading.RLock()
 
 
@@ -42,14 +34,14 @@ def _resolve_agent_id(agent_id: str | None = None) -> str:
     return "default"
 
 
-def set_correlation_engine(engine: CorrelationEngine, agent_id: str | None = None) -> None:
-    """Set the correlation engine for a specific agent context."""
-    resolved = _resolve_agent_id(agent_id)
-    with _HYPOTHESIS_CONTEXT_LOCK:
-        _CORRELATION_BY_AGENT[resolved] = engine
+def _require_active_ledger() -> HypothesisLedger:
+    ledger = _get_active_ledger()
+    if ledger is None:
+        raise ValueError("agent_id required")
+    return ledger
 
 
-def set_ledger(ledger: HypothesisLedger, agent_id: str | None = None) -> None:
+def set_ledger(ledger: "HypothesisLedger", agent_id: str | None = None) -> None:
     """Set the hypothesis ledger instance for a specific agent.
     
     Args:
@@ -80,25 +72,16 @@ def get_ledger(agent_id: str | None = None) -> HypothesisLedger | None:
         return _LEDGERS_BY_AGENT.get(resolved)
 
 
-def get_correlation_engine(agent_id: str | None = None) -> CorrelationEngine | None:
-    """Get the correlation engine for a specific agent context."""
-    resolved = _resolve_agent_id(agent_id)
-    with _HYPOTHESIS_CONTEXT_LOCK:
-        return _CORRELATION_BY_AGENT.get(resolved)
-
-
 def clear_hypothesis_context(agent_id: str | None = None) -> None:
-    """Clear hypothesis/correlation context (all or one agent)."""
+    """Clear hypothesis context (all or one agent)."""
     if agent_id is None:
         with _HYPOTHESIS_CONTEXT_LOCK:
             _LEDGERS_BY_AGENT.clear()
-            _CORRELATION_BY_AGENT.clear()
         return
 
     resolved = _resolve_agent_id(agent_id)
     with _HYPOTHESIS_CONTEXT_LOCK:
         _LEDGERS_BY_AGENT.pop(resolved, None)
-        _CORRELATION_BY_AGENT.pop(resolved, None)
 
 
 def _get_active_ledger() -> HypothesisLedger | None:
@@ -112,15 +95,9 @@ def _get_active_ledger() -> HypothesisLedger | None:
     return get_ledger(current_agent_id or "default")
 
 
-def _get_active_correlation_engine() -> CorrelationEngine | None:
-    """Get correlation engine for the current agent context."""
-    try:
-        from phantom.tools.context import get_current_agent_id
-
-        current_agent_id = get_current_agent_id()
-    except Exception:
-        current_agent_id = None
-    return get_correlation_engine(current_agent_id or "default")
+def _get_active_correlation_engine() -> None:
+    """Correlation engine removed."""
+    return None
 
 
 @register_tool(sandbox_execution=False)
@@ -149,13 +126,7 @@ def add_hypothesis(surface: str, vuln_class: str) -> dict[str, Any]:
         )
     """
     # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-            "hypothesis_id": None,
-        }
+    _ledger = _require_active_ledger()
     
     # Check if already exists
     existing = _ledger.find_by_surface_and_class(surface, vuln_class)
@@ -208,12 +179,7 @@ async def record_payload_test(
         )
     """
     # FIX Bug #4: Use _get_active_ledger() with proper validation
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-        }
+    _ledger = _require_active_ledger()
     
     # FIX Bug #4: Validate hypothesis_id exists before recording
     hyp = _ledger.get(hypothesis_id)
@@ -228,24 +194,10 @@ async def record_payload_test(
     
     # Add evidence
     if outcome == "success" and evidence:
-        await _ledger.add_evidence_for(hypothesis_id, evidence, outcome)
+        _ledger.add_evidence_for(hypothesis_id, evidence, outcome)
     elif outcome == "failure" and evidence:
-        await _ledger.add_evidence_against(hypothesis_id, evidence, outcome)
-
-    active_correlation = _get_active_correlation_engine()
-    if active_correlation is not None and hyp:
-        payload_family = _ledger._make_payload_family(hyp.vuln_class, payload)
-        learned_outcome = "testing"
-        if str(outcome).strip().lower() == "failure":
-            learned_outcome = "rejected"
-        active_correlation.record_outcome(
-            vuln_class=hyp.vuln_class,
-            surface=hyp.surface,
-            outcome=learned_outcome,
-            payload_family=payload_family,
-            evidence_strength=1.0,
-        )
-    
+        _ledger.add_evidence_against(hypothesis_id, evidence, outcome)
+
     # Get current status
     hyp = _ledger.get(hypothesis_id)
     status = hyp.status if hyp else "unknown"
@@ -265,9 +217,6 @@ async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any
     """
     Confirm a hypothesis as a valid vulnerability.
     
-    FIX 4: Now automatically adds the finding to the correlation engine
-    to enable vulnerability chain detection (e.g., SSRF ΓåÆ cloud metadata).
-    
     Args:
         hypothesis_id: The hypothesis ID (e.g., "H-0001")
         evidence: Evidence confirming the vulnerability
@@ -282,12 +231,7 @@ async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any
         )
     """
     # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-        }
+    _ledger = _require_active_ledger()
     
     # FIX Bug #4: Validate hypothesis_id exists
     hyp = _ledger.get(hypothesis_id)
@@ -297,50 +241,11 @@ async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any
             "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
         }
     
-    await _ledger.confirm(hypothesis_id, evidence)
-    
-    # FIX 4: Add finding to correlation engine for chain detection
-    new_chains = []
-    active_correlation = _get_active_correlation_engine()
-    if active_correlation is not None:
-        hyp = _ledger.get(hypothesis_id)
-        if hyp:
-            # Determine severity from vulnerability class
-            severity_map = {
-                "sqli": "high",
-                "rce": "critical",
-                "cmd_injection": "critical",
-                "ssti": "critical",
-                "ssrf": "high",
-                "xxe": "high",
-                "lfi": "high",
-                "xss": "medium",
-                "idor": "medium",
-                "auth_bypass": "critical",
-            }
-            severity = severity_map.get(hyp.vuln_class.lower(), "medium")
-            
-            result = active_correlation.add_finding(
-                vuln_class=hyp.vuln_class.lower(),
-                surface=hyp.surface,
-                severity=severity,
-                details={
-                    "hypothesis_id": hypothesis_id,
-                    "evidence": evidence,
-                    "outcome": "confirmed",
-                    "payload_family": (
-                        _ledger._make_payload_family(
-                            hyp.vuln_class,
-                            hyp.successful_payloads[-1],
-                        )
-                        if hyp.successful_payloads
-                        else None
-                    ),
-                    "tested_at": hyp.last_updated,  # FIX Bug #2: Use last_updated instead of non-existent tested_at
-                }
-            )
-            new_chains = result.get("new_suggestions", [])
+    _ledger.confirm(hypothesis_id, evidence)
     
+    hyp = _ledger.get(hypothesis_id)
+    status = hyp.status if hyp else "unknown"
+
     response = {
         "success": True,
         "hypothesis_id": hypothesis_id,
@@ -348,14 +253,7 @@ async def confirm_hypothesis(hypothesis_id: str, evidence: str) -> dict[str, Any
         "message": f"Confirmed {hypothesis_id} as valid vulnerability",
     }
     
-    # FIX 4: Include chain suggestions in response
-    if new_chains:
-        response["chain_opportunities"] = new_chains
-        response["message"] += f" | {len(new_chains)} vulnerability chain(s) detected!"
-    
     return response
-    # FIX Bug #1: DELETE unreachable dead code below (lines 282-289)
-    # This code was unreachable because return statement above exits function
 
 
 @register_tool(sandbox_execution=False)
@@ -377,12 +275,7 @@ async def reject_hypothesis(hypothesis_id: str, reason: str) -> dict[str, Any]:
         )
     """
     # FIX Bug #3 & #4: Use _get_active_ledger() with proper validation
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-        }
+    _ledger = _require_active_ledger()
     
     # FIX Bug #4: Validate hypothesis_id exists
     hyp = _ledger.get(hypothesis_id)
@@ -392,17 +285,7 @@ async def reject_hypothesis(hypothesis_id: str, reason: str) -> dict[str, Any]:
             "error": f"Invalid hypothesis_id: {hypothesis_id}. Hypothesis not found.",
         }
     
-    await _ledger.reject(hypothesis_id, reason)
-
-    active_correlation = _get_active_correlation_engine()
-    if active_correlation is not None and hyp:
-        active_correlation.record_outcome(
-            vuln_class=hyp.vuln_class,
-            surface=hyp.surface,
-            outcome="rejected",
-            payload_family=None,
-            evidence_strength=1.0,
-        )
+    _ledger.reject(hypothesis_id, reason)
     
     return {
         "success": True,
@@ -443,13 +326,7 @@ def query_hypotheses(
         query_hypotheses(status="confirmed")
     """
     # Get all hypotheses
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-            "hypotheses": [],
-        }
+    _ledger = _require_active_ledger()
     
     all_hyps = list(_ledger.get_all().values())
     
@@ -491,12 +368,7 @@ def get_hypothesis_summary() -> dict[str, Any]:
     Example:
         get_hypothesis_summary()
     """
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-        }
+    _ledger = _require_active_ledger()
     
     summary = _ledger.get_summary()
     
@@ -542,13 +414,7 @@ def has_tested_payload(surface: str, vuln_class: str, payload: str) -> dict[str,
             payload="' OR 1=1--"
         )
     """
-    _ledger = _get_active_ledger()
-    if _ledger is None:
-        return {
-            "success": False,
-            "error": "Hypothesis ledger not initialized",
-            "tested": False,
-        }
+    _ledger = _require_active_ledger()
     
     tested = _ledger.has_tested(surface, vuln_class, payload)
     
