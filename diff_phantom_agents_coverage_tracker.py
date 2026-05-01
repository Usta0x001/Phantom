diff --git a/phantom/agents/coverage_tracker.py b/phantom/agents/coverage_tracker.py
index 8926dba..d406ac4 100644
--- a/phantom/agents/coverage_tracker.py
+++ b/phantom/agents/coverage_tracker.py
@@ -33,7 +33,9 @@ class TestedItem:
     notes: list[str] = field(default_factory=list)  # Observations from tests
     discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
     # FEAT-002: Track failure reasons to prevent repeated futile attacks after memory compression
-    failure_reasons: list[str] = field(default_factory=list)  # e.g. ["WAF_BLOCKED", "403_FORBIDDEN", "RATE_LIMITED"]
+    failure_reasons: list[str] = field(
+        default_factory=list
+    )  # e.g. ["WAF_BLOCKED", "403_FORBIDDEN", "RATE_LIMITED"]
 
     def to_dict(self) -> dict[str, Any]:
         return {
@@ -93,11 +95,25 @@ class CoverageTracker:
     """
 
     # Common vulnerability classes for coverage tracking
-    COMMON_VULN_CLASSES = frozenset({
-        "sqli", "xss", "ssrf", "lfi", "rfi", "rce", "idor",
-        "auth_bypass", "injection", "xxe", "ssti", "csrf",
-        "open_redirect", "path_traversal", "info_disclosure",
-    })
+    COMMON_VULN_CLASSES = frozenset(
+        {
+            "sqli",
+            "xss",
+            "ssrf",
+            "lfi",
+            "rfi",
+            "rce",
+            "idor",
+            "auth_bypass",
+            "injection",
+            "xxe",
+            "ssti",
+            "csrf",
+            "open_redirect",
+            "path_traversal",
+            "info_disclosure",
+        }
+    )
 
     def __init__(self) -> None:
         self._lock = threading.RLock()
@@ -244,20 +260,25 @@ class CoverageTracker:
             elif surface_id in self._discovered:
                 # Surface was discovered but never fully tested: record failure there
                 self._discovered[surface_id].notes = (
-                    getattr(self._discovered[surface_id], 'notes', None) or []
+                    getattr(self._discovered[surface_id], "notes", None) or []
                 )
                 self._discovered[surface_id].notes.append(f"FAILURE: {failure_reason}")
                 return surface_id
             else:
                 # Pure failure entry: use a lightweight failure-only store
-                if not hasattr(self, '_failure_only'):
+                if not hasattr(self, "_failure_only"):
                     self._failure_only: dict[str, dict] = {}
-                entry = self._failure_only.setdefault(surface_id, {
-                    "surface": surface,
-                    "surface_type": surface_type,
-                    "failure_reasons": [],
-                })
-                reason_with_class = f"[{vuln_class}] {failure_reason}" if vuln_class else failure_reason
+                entry = self._failure_only.setdefault(
+                    surface_id,
+                    {
+                        "surface": surface,
+                        "surface_type": surface_type,
+                        "failure_reasons": [],
+                    },
+                )
+                reason_with_class = (
+                    f"[{vuln_class}] {failure_reason}" if vuln_class else failure_reason
+                )
                 if reason_with_class not in entry["failure_reasons"]:
                     entry["failure_reasons"].append(reason_with_class)
                 return surface_id
@@ -275,7 +296,7 @@ class CoverageTracker:
     def get_blocked_surfaces(self) -> list[dict[str, Any]]:
         """
         FEAT-002: Return surfaces that have blocking failures (WAF, rate limit, etc.)
-        
+
         This helps the agent avoid wasting iterations on surfaces that are protected.
         Returns FACTS about what's blocked and why.
         """
@@ -283,12 +304,26 @@ class CoverageTracker:
             blocked = []
             for item in self._tested.values():
                 if item.failure_reasons:
-                    blocked.append({
-                        "surface": item.surface,
-                        "surface_type": item.surface_type,
-                        "failure_reasons": item.failure_reasons,
-                        "test_count": item.test_count,
-                    })
+                    blocked.append(
+                        {
+                            "surface": item.surface,
+                            "surface_type": item.surface_type,
+                            "failure_reasons": item.failure_reasons,
+                            "test_count": item.test_count,
+                        }
+                    )
+            # FIX: Include _failure_only surfaces (pure failures, never tested).
+            # Previously these were invisible to the LLM, causing wasted retries.
+            failure_only = getattr(self, "_failure_only", {})
+            for item in failure_only.values():
+                blocked.append(
+                    {
+                        "surface": item["surface"],
+                        "surface_type": item["surface_type"],
+                        "failure_reasons": item["failure_reasons"],
+                        "test_count": 0,
+                    }
+                )
             return blocked
 
     # ΓöÇΓöÇ Coverage Queries (return FACTS, not commands) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
@@ -406,13 +441,18 @@ class CoverageTracker:
         """Check if a surface has been tested (optionally for a specific vuln class).
 
         FIX B13: vuln_class lookup is lowercased to match the normalised storage.
+        FIX: Also check _failure_only so the agent knows blocked surfaces were
+        attempted and should not be retried blindly.
         """
         with self._lock:
             surface_key = f"{surface_type}:{surface}"
             surface_id = f"S-{hashlib.md5(surface_key.encode()).hexdigest()[:8].upper()}"
 
             if surface_id not in self._tested:
-                return False
+                # FIX: A blocked surface in _failure_only was attempted and failed;
+                # return True so the agent doesn't waste retries.
+                failure_only = getattr(self, "_failure_only", {})
+                return surface_id in failure_only
 
             if vuln_class is None:
                 return True
@@ -437,33 +477,51 @@ class CoverageTracker:
 
         lines = ["[COVERAGE TRACKER ΓÇö attack surface coverage state]"]
 
+        # FIX: Include blocked surfaces in summary so LLM knows what failed.
+        failure_only = getattr(self, "_failure_only", {})
+        blocked_count = len(failure_only)
+
         # Summary stats
-        total_surfaces = len(tested_list) + len(discovered_list)
-        lines.append(f"  Surfaces: {total_surfaces} total, {len(tested_list)} tested, {len(discovered_list)} untested")
+        total_surfaces = len(tested_list) + len(discovered_list) + blocked_count
+        lines.append(
+            f"  Surfaces: {total_surfaces} total, {len(tested_list)} tested, {len(discovered_list)} untested, {blocked_count} blocked"
+        )
 
         # Count unique vuln classes tested
         all_vuln_classes: set[str] = set()
         for item in tested_list:
             all_vuln_classes.update(item.vuln_classes_tested)
-        lines.append(f"  Vuln classes tested: {len(all_vuln_classes)} ({', '.join(sorted(all_vuln_classes)[:5])}{'...' if len(all_vuln_classes) > 5 else ''})")
+        lines.append(
+            f"  Vuln classes tested: {len(all_vuln_classes)} ({', '.join(sorted(all_vuln_classes)[:5])}{'...' if len(all_vuln_classes) > 5 else ''})"
+        )
 
         # Recently tested (most recent first)
         if tested_list:
             lines.append("  Recently tested:")
-            sorted_tested = sorted(tested_list, key=lambda x: x.last_tested, reverse=True)[:max_items // 2]
+            sorted_tested = sorted(tested_list, key=lambda x: x.last_tested, reverse=True)[
+                : max_items // 2
+            ]
             for item in sorted_tested:
                 vc_str = ",".join(item.vuln_classes_tested[:3])
                 if len(item.vuln_classes_tested) > 3:
                     vc_str += f"+{len(item.vuln_classes_tested) - 3}"
-                lines.append(f"    {item.surface[:40]:40s} | {item.surface_type:12s} | tests={item.test_count} | {vc_str}")
+                lines.append(
+                    f"    {item.surface[:40]:40s} | {item.surface_type:12s} | tests={item.test_count} | {vc_str}"
+                )
 
         # Untested surfaces
         if discovered_list:
             lines.append("  Untested surfaces:")
-            sorted_discovered = sorted(discovered_list, key=lambda x: x.discovered_at, reverse=True)[:max_items // 2]
+            sorted_discovered = sorted(
+                discovered_list, key=lambda x: x.discovered_at, reverse=True
+            )[: max_items // 2]
             for item in sorted_discovered:
-                hints_str = f" hints=[{','.join(item.priority_hints[:2])}]" if item.priority_hints else ""
-                lines.append(f"    {item.surface[:40]:40s} | {item.surface_type:12s} | src={item.source}{hints_str}")
+                hints_str = (
+                    f" hints=[{','.join(item.priority_hints[:2])}]" if item.priority_hints else ""
+                )
+                lines.append(
+                    f"    {item.surface[:40]:40s} | {item.surface_type:12s} | src={item.source}{hints_str}"
+                )
 
         lines.append("[END COVERAGE]")
         return "\n".join(lines)
@@ -473,11 +531,14 @@ class CoverageTracker:
     def to_dict(self) -> dict[str, Any]:
         """Serialize for checkpointing/persistence."""
         with self._lock:
-            return {
+            result = {
                 "counter": self._counter,
                 "tested": {k: v.to_dict() for k, v in self._tested.items()},
                 "discovered": {k: v.to_dict() for k, v in self._discovered.items()},
             }
+            if hasattr(self, "_failure_only") and self._failure_only:
+                result["failure_only"] = dict(self._failure_only)
+            return result
 
     @classmethod
     def from_dict(cls, d: dict[str, Any]) -> "CoverageTracker":
@@ -488,6 +549,9 @@ class CoverageTracker:
             tracker._tested[k] = TestedItem.from_dict(v)
         for k, v in d.get("discovered", {}).items():
             tracker._discovered[k] = DiscoveredSurface.from_dict(v)
+        failure_data = d.get("failure_only", {})
+        if failure_data:
+            tracker._failure_only = dict(failure_data)
         return tracker
 
     def __len__(self) -> int:
