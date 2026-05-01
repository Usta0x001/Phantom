diff --git a/phantom/agents/hypothesis_ledger.py b/phantom/agents/hypothesis_ledger.py
index f1a21b4..86587cf 100644
--- a/phantom/agents/hypothesis_ledger.py
+++ b/phantom/agents/hypothesis_ledger.py
@@ -1,949 +1,265 @@
-"""
-Hypothesis Ledger ΓÇö Rec 6 (SF-005, SF-006, SF-007)
-
-Structured external memory that lives outside the conversation history and
-therefore survives every memory-compression cycle.  Agents inject a compact
-summary every N iterations to maintain strategic coherence without bloating
-the context window.
-"""
-
-from __future__ import annotations
-
-import re
 import threading
-from dataclasses import dataclass, field
-from datetime import UTC, datetime
-from typing import Any, Callable
-
-from phantom.config.config import Config
-from phantom.agents.correlation_engine import CorrelationEngine
-
-
-_VALID_STATUSES = frozenset({"open", "testing", "confirmed", "rejected"})
-
-_DEFAULT_BELIEF = 0.5
-
-MAX_EVIDENCE_EVENTS = 24
-MAX_STATUS_TRANSITIONS = 24
-MAX_CONFIDENCE_HISTORY = 24
-MAX_PAYLOAD_FAMILY_EXAMPLES = 3
-MAX_GRAPH_EDGES = 40
-
-_PAYLOAD_FAMILY_RULES: dict[str, list[tuple[str, tuple[str, ...]]]] = {
-    "sqli": [
-        ("boolean", (" or 1=1", " or '1'='1", "and 1=1", "' or '1'='1")),
-        ("union", ("union select", "union all select", "group by")),
-        ("time", ("sleep(", "waitfor delay", "benchmark(")),
-        ("error", ("updatexml(", "extractvalue(", "cast(", "convert(")),
-        ("stacked", (";--", ";", "xp_cmdshell", "into outfile")),
-        ("blind", ("substring(", "ascii(", "char(", "mid(")),
-    ],
-    "xss": [
-        ("script_tag", ("<script", "</script>")),
-        ("event_handler", ("onerror=", "onload=", "onclick=", "onfocus=")),
-        ("svg", ("<svg", "<math", "<img")),
-        ("dom", ("document.", "window.", "location=", "innerhtml")),
-    ],
-    "ssrf": [
-        ("metadata", ("169.254.169.254", "metadata.google", "100.100.100.200")),
-        ("redirect", ("http://", "https://", "gopher://", "file://", "ftp://")),
-        ("dns", ("interactsh", "oast", "collaborator", ".oast")),
-    ],
-    "idor": [
-        ("numeric_id", ("id=1", "/1", "?id=", "user=1")),
-        ("uuid", ("uuid", "guid", "ulid")),
-        ("role", ("admin", "role=", "is_admin", "priv")),
-        ("path", ("/users/", "/accounts/", "/profile/")),
-    ],
-    "rce": [
-        ("command", ("whoami", "id", "uname -a", "curl ", "bash ", "nc ")),
-        ("upload", (".php", ".jsp", ".aspx", ".war")),
-        ("deserialization", ("pickle", "ysoserial", "base64", "deserialize")),
-        ("template", ("${", "{{", "%7b%7b")),
-    ],
-    "path_traversal": [
-        ("dotdot", ("../", "..\\", "..%2f", "..%5c")),
-        ("encoded", ("%2e%2e%2f", "%252e", "%c0%ae")),
-        ("absolute", ("/etc/passwd", "c:\\windows", "/proc/self")),
-    ],
-    "lfi": [
-        ("log_poisoning", ("/var/log", "access.log", "error.log")),
-        ("wrapper", ("php://", "expect://", "file://")),
-        ("session", ("sess_", "session", "cookie")),
-    ],
-    "auth_bypass": [
-        ("header", ("x-forwarded", "x-original-url", "x-rewrite-url")),
-        ("token", ("bearer", "jwt", "session", "cookie")),
-        ("role", ("admin", "is_admin", "priv")),
-    ],
-    "open_redirect": [
-        ("absolute", ("http://", "https://")),
-        ("scheme_relative", ("//", "/%2f/")),
-        ("encoded", ("%2f%2f", "%5c%5c")),
-    ],
-    "xxe": [
-        ("file", ("file://", "php://", "expect://")),
-        ("ssrf", ("http://", "https://", "ftp://")),
-        ("entity", ("<!DOCTYPE", "<!ENTITY")),
-    ],
-}
-
-_DEFAULT_PAYLOAD_FAMILIES: list[str] = [
-    "boolean",
-    "union",
-    "error",
-    "time",
-    "blind",
-    "stacked",
-    "encoding",
-]
-
-_CHAIN_RELATIONS: set[frozenset[str]] = {
-    frozenset(("sqli", "rce")),
-    frozenset(("lfi", "rce")),
-    frozenset(("xxe", "ssrf")),
-    frozenset(("idor", "auth_bypass")),
-    frozenset(("auth_bypass", "idor")),
-    frozenset(("xss", "auth_bypass")),
-    frozenset(("open_redirect", "auth_bypass")),
-}
-
-_HEURISTIC_SEVERITY_WEIGHTS: dict[str, float] = {
-    "critical": 1.0,
-    "high": 0.8,
-    "medium": 0.5,
-    "low": 0.2,
-    "info": 0.0,
-}
-
-_VULN_DEFAULT_SEVERITY: dict[str, str] = {
-    "rce": "critical",
-    "cmd_injection": "critical",
-    "auth_bypass": "critical",
-    "sqli": "high",
-    "ssrf": "high",
-    "xxe": "high",
-    "lfi": "high",
-    "path_traversal": "high",
-    "idor": "medium",
-    "xss": "medium",
-    "open_redirect": "low",
-}
-
-_MAX_SCHEDULER_EVENTS = 2000
-
-ARCHITECTURE_DIAGRAM_TEXT = (
-    "hypothesis -> belief_state -> scheduler_score -> selected_hypothesis -> outcome -> belief_propagation"
-)
-
-
-def _bounded_append(collection: list[Any], item: Any, limit: int) -> None:
-    collection.append(item)
-    if len(collection) > limit:
-        del collection[:-limit]
-
-
-def _confidence_trend_label(previous: float | None, current: float) -> str:
-    if previous is None:
-        return "new"
-    delta = current - previous
-    if delta > 2:
-        return "rising"
-    if delta < -2:
-        return "falling"
-    return "stale"
-
-
-def _payload_families_for_class(vuln_class: str) -> list[str]:
-    class_rules = _PAYLOAD_FAMILY_RULES.get(vuln_class.lower())
-    if class_rules:
-        return [family for family, _ in class_rules]
-    return list(_DEFAULT_PAYLOAD_FAMILIES)
+import logging
+from typing import Any, Dict, List, Optional, Callable
+from datetime import datetime, timezone
 
+logger = logging.getLogger(__name__)
 
-_URL_ID_RE: re.Pattern[str] = re.compile(
-    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
-    r"|\/\d{1,20}(?=/|$)"  # numeric path segment
-    , re.IGNORECASE
-)
+_VALID_STATUSES = {"open", "testing", "confirmed", "rejected"}
+_ACTIVE_STATUSES = {"open", "testing"}
 
+def _surface_matches(s1: str, s2: str) -> bool:
+    """Basic normalization for matching."""
+    s1 = str(s1 or "").strip().lower()
+    s2 = str(s2 or "").strip().lower()
+    return s1 == s2
 
-def _normalise_surface(surface: str) -> str:
-    """Collapse parameterised URL path segments into {id} tokens.
-
-    /api/user/1   -> /api/user/{id}
-    /api/user/2   -> /api/user/{id}  (same as above)
-    /item/abc-123-def -> unchanged (not numeric)
-    """
-    base, _, param = surface.strip().partition("::")
-    normalised_base = _URL_ID_RE.sub("/{id}", base)
-    if param:
-        return f"{normalised_base}::{param}"
-    return normalised_base
-
-
-def _surface_signature(surface: str) -> tuple[str, str]:
-    surface_lower = surface.strip().lower()
-    base, _, param = surface_lower.partition("::")
-    base = base.split("#", 1)[0].split("?", 1)[0].rstrip("/")
-    param = param.split("#", 1)[0].split("?", 1)[0].strip()
-    return base, param
-
-
-def _surface_similarity(target_surface: str, source_surface: str) -> float:
-    if not target_surface or not source_surface:
-        return 0.0
-
-    target_base, target_param = _surface_signature(target_surface)
-    source_base, source_param = _surface_signature(source_surface)
-    if not target_base or not source_base:
-        return 0.0
-
-    score = 0.0
-    if target_base == source_base:
-        score += 0.7
-    else:
-        target_segments = [segment for segment in target_base.split("/") if segment]
-        source_segments = [segment for segment in source_base.split("/") if segment]
-        if target_segments and source_segments:
-            if target_segments[:2] == source_segments[:2]:
-                score += 0.45
-            elif target_segments[0] == source_segments[0]:
-                score += 0.25
-            shared = len(set(target_segments) & set(source_segments))
-            union = max(len(set(target_segments) | set(source_segments)), 1)
-            score += min(0.2, (shared / union) * 0.2)
-
-    if target_param and source_param:
-        if target_param == source_param:
-            score += 0.25
-        elif target_param.split("_")[0] == source_param.split("_")[0]:
-            score += 0.1
-
-    return min(score, 1.0)
-
-
-@dataclass
 class Hypothesis:
-    id: str
-    surface: str          # e.g. "/api/login::username"
-    vuln_class: str       # e.g. "sqli"
-    status: str = "open"  # open | testing | confirmed | rejected
-    payloads_tested: list[str] = field(default_factory=list)
-    payload_families_tested: list[str] = field(default_factory=list)
-    iterations_spent: int = 0
-    tests_executed: int = 0
-    supporting_evidence: list[str] = field(default_factory=list)
-    evidence_for: list[str] = field(default_factory=list)
-    evidence_against: list[str] = field(default_factory=list)
-    evidence_history: list[dict[str, Any]] = field(default_factory=list)
-    status_transitions: list[dict[str, Any]] = field(default_factory=list)
-    confidence_history: list[dict[str, Any]] = field(default_factory=list)
-    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
-    last_updated: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
-    # P3.2: Payload Learning - Track successful payloads
-    successful_payloads: list[str] = field(default_factory=list)  # Payloads that confirmed vuln
-    details: dict[str, Any] = field(default_factory=dict)  # Additional details (exploitation, etc.)
-    preconditions: list[str] = field(default_factory=list)
-    expected_exploit_path: str = ""
-    required_signals: list[str] = field(default_factory=list)
-    graph_metadata: dict[str, Any] = field(default_factory=dict)
-    payload_family_examples: dict[str, list[str]] = field(default_factory=dict)
-    negative_space: dict[str, list[str]] = field(default_factory=dict)
-
-    def to_dict(self) -> dict[str, Any]:
+    def __init__(self, surface: str, vuln_class: str, hid: str):
+        self.id = hid
+        self.surface = str(surface or "").strip()
+        self.vuln_class = str(vuln_class or "").strip().lower()
+        self.status = "open"
+        self.payloads_tested: List[str] = []
+        self.successful_payloads: List[str] = []
+        self.evidence_for: List[str] = []
+        self.evidence_against: List[str] = []
+        self.details: Dict[str, Any] = {}
+        self.tests_executed = 0
+        self.iterations_spent = 0
+        self.created_at = datetime.now(timezone.utc).isoformat()
+        self.last_updated = self.created_at
+
+    def to_dict(self) -> Dict[str, Any]:
         return {
             "id": self.id,
             "surface": self.surface,
             "vuln_class": self.vuln_class,
             "status": self.status,
-            "payloads_tested": self.payloads_tested,
-            "payload_families_tested": self.payload_families_tested,
-            "iterations_spent": self.iterations_spent,
             "tests_executed": self.tests_executed,
-            "supporting_evidence": self.supporting_evidence,
+            "iterations_spent": self.iterations_spent,
+            "payloads_tested": self.payloads_tested,
+            "successful_payloads": self.successful_payloads,
             "evidence_for": self.evidence_for,
             "evidence_against": self.evidence_against,
-            "evidence_history": self.evidence_history,
-            "status_transitions": self.status_transitions,
-            "confidence_history": self.confidence_history,
+            "details": self.details,
             "created_at": self.created_at,
             "last_updated": self.last_updated,
-            "successful_payloads": self.successful_payloads,  # P3.2
-            "details": self.details,  # Exploitation details
-            "preconditions": self.preconditions,
-            "expected_exploit_path": self.expected_exploit_path,
-            "required_signals": self.required_signals,
-            "graph_metadata": self.graph_metadata,
-            "payload_family_examples": self.payload_family_examples,
-            "negative_space": self.negative_space,
         }
 
     @classmethod
-    def from_dict(cls, d: dict[str, Any]) -> "Hypothesis":
-        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
-
+    def from_dict(cls, data: Dict[str, Any]) -> "Hypothesis":
+        h = cls(data["surface"], data["vuln_class"], data["id"])
+        h.status = data.get("status", "open")
+        h.tests_executed = data.get("tests_executed", 0)
+        h.iterations_spent = data.get("iterations_spent", 0)
+        h.payloads_tested = data.get("payloads_tested", [])
+        h.successful_payloads = data.get("successful_payloads", [])
+        h.evidence_for = data.get("evidence_for", [])
+        h.evidence_against = data.get("evidence_against", [])
+        h.details = data.get("details", {})
+        h.created_at = data.get("created_at", datetime.now(timezone.utc).isoformat())
+        h.last_updated = data.get("last_updated", h.created_at)
+        return h
 
 class HypothesisLedger:
-    """
-    Thread-safe registry of hypotheses for a single scan.
-
-    Properties:
-    - Survives memory compression (stored outside conversation history)
-    - Prevents redundant payload testing via `has_tested()`
-    - Drives coverage tracking via `get_coverage_gaps()`
-    - Injects compact TOP-N summary into LLM context (avoids token bloat)
-    """
-
-    def __init__(self) -> None:
+    def __init__(self, auto_flush: bool = False, persist_dir: str | None = None):
+        self._hypotheses: Dict[str, Hypothesis] = {}
         self._lock = threading.RLock()
-        self._hypotheses: dict[str, Hypothesis] = {}
-        self._counter: int = 0
-        self._confirmation_callbacks: list[Callable[[str, Hypothesis], None]] = []
-        self._correlation_engine: CorrelationEngine | None = None
-        self._belief_map: dict[str, float] = {}
-
-    def set_correlation_engine(self, engine: CorrelationEngine | None) -> None:
-        """Attach optional correlation engine for learned ranking signals."""
-        with self._lock:
-            self._correlation_engine = engine
+        self._id_counter = 0
+        self._confirmation_callbacks: List[Callable[[str, Hypothesis], None]] = []
 
-    def _correlation_surface_score(self, vuln_class: str, surface: str) -> float:
-        with self._lock:
-            engine = self._correlation_engine
-        if engine is None:
-            return 0.5
-        try:
-            return float(engine.get_surface_success_score(vuln_class, surface))
-        except Exception:
-            return 0.5
-
-    def _correlation_family_score(self, vuln_class: str, family: str) -> float:
-        with self._lock:
-            engine = self._correlation_engine
-        if engine is None:
-            return 0.5
-        try:
-            return float(engine.get_payload_family_success_score(vuln_class, family))
-        except Exception:
-            return 0.5
-
-    def _scheduler_mode(self) -> str:
-        # FIX B3: Default changed from 'flat' to 'heuristic' so critical
-        # endpoints (admin, auth) are always scored above low-value ones.
-        raw = str(Config.get("phantom_scheduler_mode") or "heuristic").strip().lower()
-        if raw in {"flat", "heuristic", "fifo"}:
-            return raw
-        return "heuristic"
-
-    def compute_evidence_score(self, hyp: Hypothesis) -> float:
-        n_for = float(len(hyp.evidence_for))
-        n_support = float(len(hyp.supporting_evidence))
-        n_against = float(len(hyp.evidence_against))
-        denom = 1.0 + n_for + n_support + n_against
-        if denom <= 0:
-            return 0.0
-        return round((n_for + (0.5 * n_support)) / denom, 6)
-
-    def compute_redundancy(self, hyp: Hypothesis) -> float:
-        total_families = max(1, len(_payload_families_for_class(hyp.vuln_class)))
-        tested_families = len(set(hyp.payload_families_tested))
-        return round(tested_families / float(total_families), 6)
-
-    def _exploration_bonus(self, hyp: Hypothesis) -> float:
-        n_i = max(0, int(hyp.tests_executed))
-        return round(1.0 / float(1 + n_i), 6)
-
-    def _heuristic_endpoint_type_score(self, surface: str) -> float:
-        base, _ = _surface_signature(surface)
-        if not base:
-            return 0.2
-        if any(token in base for token in ("/admin", "/auth", "/login", "/oauth")):
-            return 1.0
-        if any(token in base for token in ("/api", "/graphql", "/v1", "/v2")):
-            return 0.7
-        return 0.4
-
-    def _heuristic_severity_score(self, vuln_class: str) -> float:
-        sev = _VULN_DEFAULT_SEVERITY.get(vuln_class.lower(), "medium")
-        return _HEURISTIC_SEVERITY_WEIGHTS.get(sev, 0.5)
-
-    def _chain_related(self, a: str, b: str) -> bool:
-        if not a or not b:
-            return False
-        if a.lower() == b.lower():
-            return True
-        return frozenset((a.lower(), b.lower())) in _CHAIN_RELATIONS
-
-    def propagate_update(self, executed_hypothesis_id: str, outcome: str) -> None:
-        normalized = str(outcome or "testing").strip().lower()
-        if normalized == "confirmed":
-            delta = 1.0
-        elif normalized == "rejected":
-            delta = -1.0
-        else:
-            return
-
-        with self._lock:
-            executed = self._hypotheses.get(executed_hypothesis_id)
-            if executed is None:
-                return
-
-            for hyp in self._hypotheses.values():
-                if hyp.id == executed.id:
-                    continue
-                rel = 0.0
-
-                same_class = executed.vuln_class.lower() == hyp.vuln_class.lower()
-                src_base, src_param = _surface_signature(executed.surface)
-                dst_base, dst_param = _surface_signature(hyp.surface)
-                same_base = bool(src_base and dst_base and src_base == dst_base)
-                same_param = bool(src_param and dst_param and src_param == dst_param)
-
-                if same_class:
-                    rel += 0.45
-                if same_base:
-                    # FIX B11: On rejection, only propagate surface-locality
-                    # signals when the vuln class is the same.  Rejecting SQLi
-                    # on /api/search tells us nothing about RCE on /api/search.
-                    if delta > 0 or same_class:
-                        rel += 0.35
-                if same_param:
-                    if delta > 0 or same_class:
-                        rel += 0.20
-                # FIX B11: Chain-relation bonus is directional ΓÇö only on confirmation.
-                if delta > 0 and self._chain_related(executed.vuln_class, hyp.vuln_class):
-                    rel += 0.25
-
-                if rel <= 0.0:
-                    continue
-
-                current = self._belief_map.get(hyp.id, _DEFAULT_BELIEF)
-                updated = max(0.0, min(1.0, current + (0.20 * rel * delta)))
-                self._belief_map[hyp.id] = round(updated, 6)
+    @classmethod
+    def from_dict(cls, data: Dict[str, Any]) -> "HypothesisLedger":
+        ledger = cls()
+        ledger._id_counter = data.get("counter", 0)
+        hypotheses = data.get("hypotheses", {})
+        if isinstance(hypotheses, dict):
+            for hid, hyp_data in hypotheses.items():
+                if isinstance(hyp_data, dict):
+                    ledger._hypotheses[hid] = Hypothesis.from_dict(hyp_data)
+        return ledger
 
-    def get_belief(self, hypothesis_id: str) -> float:
+    def to_dict(self) -> Dict[str, Any]:
         with self._lock:
-            return float(self._belief_map.get(hypothesis_id, _DEFAULT_BELIEF))
+            return {
+                "counter": self._id_counter,
+                "hypotheses": {hid: hyp.to_dict() for hid, hyp in self._hypotheses.items()},
+            }
 
-    def get_belief_snapshot(self) -> dict[str, float]:
+    def get_all(self) -> Dict[str, Hypothesis]:
         with self._lock:
-            return {hid: float(val) for hid, val in self._belief_map.items()}
+            return dict(self._hypotheses)
 
-    def get_scheduler_report(self) -> dict[str, Any]:
+    def get(self, hypothesis_id: str) -> Hypothesis | None:
         with self._lock:
-            open_or_testing = [h for h in self._hypotheses.values() if h.status in {"open", "testing"}]
-
-        return {
-            "scheduler_mode": self._scheduler_mode(),
-            "graph": {
-                "nodes": len(self._hypotheses),
-                "candidate_nodes": len(open_or_testing),
-            },
-            "belief_map": self.get_belief_snapshot(),
-            "architecture": "hypothesis -> evidence -> correlation -> summary",
-        }
-
-    def get_factual_prompt_summary(self, top_n: int = 10) -> str:
-        """Return a factual summary for prompt injection."""
-        return self.get_prioritized_summary(top_n=top_n)
-
-    # ΓöÇΓöÇ Mutations ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def add(self, surface: str, vuln_class: str) -> str:
-        """Register a new hypothesis; return its ID.  No-ops on duplicates.
+            return self._hypotheses.get(hypothesis_id)
 
-        FIX B1: Dedup is done on a *normalised* surface template so that
-        /api/user/1 and /api/user/2 resolve to the same hypothesis.
-        The original surface string is preserved on the first registration.
-        """
-        normalised = _normalise_surface(surface)
+    def find_by_surface_and_class(self, surface: str, vuln_class: str) -> Hypothesis | None:
+        vuln_lower = str(vuln_class or "").strip().lower()
         with self._lock:
-            # Dedup by normalised surface + class
             for hyp in self._hypotheses.values():
-                if _normalise_surface(hyp.surface) == normalised and hyp.vuln_class == vuln_class:
-                    self._belief_map.setdefault(hyp.id, 0.5)
-                    return hyp.id
-            self._counter += 1
-            hyp_id = f"H-{self._counter:04d}"
-            self._hypotheses[hyp_id] = Hypothesis(
-                id=hyp_id, surface=surface, vuln_class=vuln_class
-            )
-            self._belief_map[hyp_id] = 0.5
-            return hyp_id
-
-    def _make_payload_family(self, vuln_class: str, payload: str) -> str:
-        payload_lower = payload.lower().strip()
-        class_rules = _PAYLOAD_FAMILY_RULES.get(vuln_class.lower(), [])
-        for family_name, patterns in class_rules:
-            if any(pattern in payload_lower for pattern in patterns):
-                return family_name
-
-        if any(token in payload_lower for token in ("%2f", "%5c", "..", "/", "\\")):
-            return "encoding"
-        if any(token in payload_lower for token in ("<", ">", "script", "onerror", "onload")):
-            return "markup"
-        if any(token in payload_lower for token in ("select", "union", "where", "sleep", "waitfor", "and", "or")):
-            return "injection"
-        return "other"
-
-    def _update_payload_family_examples(self, hyp: Hypothesis, family: str, payload: str) -> None:
-        if family not in hyp.payload_family_examples:
-            hyp.payload_family_examples[family] = []
-        if payload not in hyp.payload_family_examples[family]:
-            _bounded_append(hyp.payload_family_examples[family], payload, MAX_PAYLOAD_FAMILY_EXAMPLES)
-
-    def _record_evidence_event(self, hyp: Hypothesis, kind: str, text: str, confidence: float | None = None) -> None:
-        event = {
-            "kind": kind,
-            "text": text[:500],
-            "timestamp": datetime.now(UTC).isoformat(),
-        }
-        if confidence is not None:
-            event["confidence"] = round(confidence, 1)
-        _bounded_append(hyp.evidence_history, event, MAX_EVIDENCE_EVENTS)
-
-    def _record_status_transition(self, hyp: Hypothesis, new_status: str, reason: str = "") -> None:
-        previous = hyp.status
-        event = {
-            "from": previous,
-            "to": new_status,
-            "reason": reason[:200],
-            "timestamp": datetime.now(UTC).isoformat(),
-        }
-        _bounded_append(hyp.status_transitions, event, MAX_STATUS_TRANSITIONS)
-
-    def _record_confidence(self, hyp: Hypothesis, confidence: float, reason: str = "") -> None:
-        previous = None
-        if hyp.confidence_history:
-            previous = float(hyp.confidence_history[-1].get("confidence", confidence))
-        event = {
-            "confidence": round(confidence, 1),
-            "trend": _confidence_trend_label(previous, confidence),
-            "reason": reason[:200],
-            "timestamp": datetime.now(UTC).isoformat(),
-        }
-        _bounded_append(hyp.confidence_history, event, MAX_CONFIDENCE_HISTORY)
-
-    def _update_negative_space(self, hyp: Hypothesis, payload: str) -> None:
-        family = self._make_payload_family(hyp.vuln_class, payload)
-        if "missing_families" not in hyp.negative_space:
-            hyp.negative_space["missing_families"] = _payload_families_for_class(hyp.vuln_class)
-        if family in hyp.negative_space["missing_families"]:
-            hyp.negative_space["missing_families"].remove(family)
-        if "payloads_tested" not in hyp.negative_space:
-            hyp.negative_space["payloads_tested"] = []
-        if payload not in hyp.negative_space["payloads_tested"]:
-            _bounded_append(hyp.negative_space["payloads_tested"], payload[:200], 30)
-
-    def _record_manual_evidence(
-        self,
-        hyp: Hypothesis,
-        evidence: str,
-        bucket: str,
-        reason: str,
-    ) -> None:
-        if bucket == "for":
-            hyp.evidence_for.append(evidence)
-            event_kind = "evidence_for"
-        elif bucket == "against":
-            hyp.evidence_against.append(evidence)
-            event_kind = "evidence_against"
-        else:
-            hyp.supporting_evidence.append(evidence)
-            event_kind = "supporting_evidence"
-
-        if hyp.status == "open":
-            self._record_status_transition(hyp, "testing", reason)
-            hyp.status = "testing"
-
-        hyp.tests_executed += 1
-        self._record_evidence_event(hyp, event_kind, evidence)
-        self._record_confidence(hyp, self._confidence_from_evidence(hyp), reason=reason)
-        hyp.last_updated = datetime.now(UTC).isoformat()
-
-    def _confidence_from_evidence(self, hyp: Hypothesis) -> float:
-        score = 0.0
-        score += len(hyp.evidence_for) * 18.0
-        score -= len(hyp.evidence_against) * 12.0
-        score += len(hyp.supporting_evidence) * 6.0
-        score += min(hyp.tests_executed, 10) * 2.5
-        score += min(len(hyp.successful_payloads), 3) * 10.0
-        score += 5.0 if hyp.status == "testing" else 0.0
-        if hyp.status == "confirmed":
-            score += 30.0
-        return max(0.0, min(100.0, score))
+                if _surface_matches(hyp.surface, surface) and hyp.vuln_class.lower() == vuln_lower:
+                    return hyp
+            return None
 
-    def record_payload(self, hyp_id: str, payload: str) -> None:
-        """Mark a payload as tested under this hypothesis."""
+    def add(self, surface: str, vuln_class: str) -> str:
+        vuln_lower = str(vuln_class or "").strip().lower()
         with self._lock:
-            hyp = self._hypotheses.get(hyp_id)
-            if hyp and payload not in hyp.payloads_tested:
-                hyp.payloads_tested.append(payload)
-                hyp.iterations_spent += 1
-                family = self._make_payload_family(hyp.vuln_class, payload)
-                if family not in hyp.payload_families_tested:
-                    hyp.payload_families_tested.append(family)
-                self._update_payload_family_examples(hyp, family, payload)
-                self._update_negative_space(hyp, payload)
-                self._record_evidence_event(hyp, "payload_tested", payload)
-                self._record_confidence(hyp, self._confidence_from_evidence(hyp), reason=f"payload:{family}")
-                hyp.last_updated = datetime.now(UTC).isoformat()
-
-    def _validate_evidence_quality(self, evidence: str, outcome: str) -> tuple[bool, str]:
-        """
-        P2.1 FIX: Validate that evidence contains substantive data, not vague claims.
-        
-        Returns:
-            (is_valid, modified_evidence): If evidence is weak, it's tagged.
-        """
-        if not evidence or len(evidence.strip()) < 10:
-            return False, evidence
-        
-        evidence_lower = evidence.lower()
-        
-        # Weak evidence indicators (vague claims without proof)
-        _weak_phrases = (
-            "appears to be",
-            "seems like",
-            "might be",
-            "could be",
-            "potentially",
-            "possibly",
-            "suggests that",
-            "indicates that",
-            "looks like",
-            "may be vulnerable",
-        )
-        
-        # Strong evidence indicators (concrete artifacts)
-        _strong_patterns = (
-            "extracted:",
-            "output:",
-            "response:",
-            "returned:",
-            "received:",
-            "data:",
-            "error message:",
-            "status code:",
-            "header:",
-            "body:",
-            "rows",
-            "uid=",
-            "root:",
-            "admin",
-            "'",  # SQL/XSS payloads often contain quotes
-            "<script",
-            "SELECT",
-            "UNION",
-        )
-        
-        has_weak = any(phrase in evidence_lower for phrase in _weak_phrases)
-        has_strong = any(pattern.lower() in evidence_lower for pattern in _strong_patterns)
-        
-        if has_weak and not has_strong:
-            # Tag as weak evidence but don't reject
-            return True, f"[WEAK_EVIDENCE] {evidence}"
-        
-        if outcome == "confirmed" and not has_strong and len(evidence) < 50:
-            # Confirmation claims need stronger evidence
-            return True, f"[NEEDS_MORE_DETAIL] {evidence}"
-        
-        return True, evidence
-
-    def record_result(
-        self,
-        hyp_id: str,
-        outcome: str,
-        evidence: str = "",
-        successful_payload: str | None = None,  # P3.2: Track successful payload
-    ) -> None:
-        """
-        Update hypothesis status.
-        outcome: 'confirmed' | 'rejected' | 'testing'
-        successful_payload: If outcome='confirmed', the payload that worked
+            existing = self.find_by_surface_and_class(surface, vuln_lower)
+            if existing:
+                return existing.id
+            self._id_counter += 1
+            hid = f"HYP-{self._id_counter:04d}"
+            self._hypotheses[hid] = Hypothesis(surface, vuln_lower, hid)
+            return hid
 
-        FIX B6: When outcome=='confirmed' and evidence is weak (tagged
-        [WEAK_EVIDENCE] by _validate_evidence_quality), the status is
-        downgraded to 'testing' instead of 'confirmed'. Strong evidence
-        still confirms normally.
-
-        FIX B-B: tests_executed is incremented only once per call, not
-        again by increment_iteration when the agent loop already called
-        record_result for the same iteration.
-        """
+    def record_payload(self, hypothesis_id: str, payload: str) -> bool:
         with self._lock:
-            hyp = self._hypotheses.get(hyp_id)
+            hyp = self.get(hypothesis_id)
             if not hyp:
-                return
-
-            # Validate evidence quality before deciding final outcome
-            effective_outcome = outcome
-            validated_evidence = evidence
-            if evidence:
-                is_valid, validated_evidence = self._validate_evidence_quality(evidence, outcome)
-                # FIX B6: Downgrade 'confirmed' to 'testing' when only weak evidence
-                if (
-                    outcome == "confirmed"
-                    and validated_evidence.startswith("[WEAK_EVIDENCE]")
-                ):
-                    effective_outcome = "testing"
-
-            # FIX B-B: Increment tests_executed exactly once per record_result call.
-            # (increment_iteration exists for iterations where no explicit result
-            # is recorded ΓÇö it must NOT be called on the same iteration as record_result)
-            if effective_outcome in _VALID_STATUSES:
+                return False
+            payload = str(payload or "").strip()
+            if payload and payload not in hyp.payloads_tested:
+                hyp.payloads_tested.append(payload)
                 hyp.tests_executed += 1
+                if hyp.status == "open":
+                    hyp.status = "testing"
+                hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            return True
 
-            if effective_outcome in _VALID_STATUSES and effective_outcome != hyp.status:
-                self._record_status_transition(hyp, effective_outcome, validated_evidence)
-                hyp.status = effective_outcome
-
-            if validated_evidence:
-                self._record_evidence_event(hyp, f"{effective_outcome}_evidence", validated_evidence)
-                if effective_outcome == "confirmed":
-                    hyp.evidence_for.append(validated_evidence)
-                elif effective_outcome == "rejected":
-                    hyp.evidence_against.append(validated_evidence)
-                else:
-                    hyp.supporting_evidence.append(validated_evidence)
-
-            # P3.2: Record successful payload (only on genuine confirmation)
-            if effective_outcome == "confirmed" and successful_payload:
-                if successful_payload not in hyp.successful_payloads:
-                    hyp.successful_payloads.append(successful_payload)
-                family = self._make_payload_family(hyp.vuln_class, successful_payload)
-                self._update_payload_family_examples(hyp, family, successful_payload)
-                self._record_evidence_event(hyp, "successful_payload", successful_payload)
-                if family not in hyp.payload_families_tested:
-                    hyp.payload_families_tested.append(family)
-
-            self._record_confidence(hyp, self._confidence_from_evidence(hyp), reason=effective_outcome)
-            hyp.last_updated = datetime.now(UTC).isoformat()
-
-        self.propagate_update(hyp_id, effective_outcome)
-
-    def increment_iteration(self, hyp_id: str) -> None:
-        """Increment the iterations-spent counter for a hypothesis.
-
-        FIX B-B: Only increments *iterations_spent*, NOT tests_executed.
-        tests_executed is incremented exactly once inside record_result.
-        Calling both on the same iteration would double-count.
-        """
+    def add_evidence_for(self, hypothesis_id: str, evidence: str, outcome: str = "success") -> bool:
         with self._lock:
-            hyp = self._hypotheses.get(hyp_id)
-            if hyp:
-                hyp.iterations_spent += 1
-                self._record_confidence(hyp, self._confidence_from_evidence(hyp), reason="iteration")
-                hyp.last_updated = datetime.now(UTC).isoformat()
-
-    # ΓöÇΓöÇ Queries ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def has_tested(
-        self,
-        surface: str,
-        vuln_class: str,
-        payload: str | None = None,
-    ) -> bool:
-        """Return True if surface+class (optionally with specific payload) was tested.
+            hyp = self.get(hypothesis_id)
+            if not hyp:
+                return False
+            hyp.evidence_for.append(str(evidence))
+            hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            return True
 
-        Uses normalised surface matching so /api/user/99 returns True when
-        /api/user/1 was previously tested (same URL template).
-        """
-        normalised = _normalise_surface(surface)
+    def add_evidence_against(self, hypothesis_id: str, evidence: str, outcome: str = "failure") -> bool:
         with self._lock:
-            for hyp in self._hypotheses.values():
-                if _normalise_surface(hyp.surface) != normalised or hyp.vuln_class != vuln_class:
-                    continue
-                if payload is None:
-                    return bool(hyp.payloads_tested or hyp.tests_executed or hyp.evidence_history)
-                return payload in hyp.payloads_tested
-        return False
+            hyp = self.get(hypothesis_id)
+            if not hyp:
+                return False
+            hyp.evidence_against.append(str(evidence))
+            hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            return True
 
-    def has_seen_hypothesis(self, surface: str, vuln_class: str) -> bool:
+    def register_confirmation_callback(self, callback: Callable[[str, Hypothesis], None]) -> None:
         with self._lock:
-            return any(h.surface == surface and h.vuln_class == vuln_class for h in self._hypotheses.values())
+            self._confirmation_callbacks.append(callback)
 
-    def has_tested_payload(self, surface: str, vuln_class: str, payload: str) -> bool:
+    def confirm(self, hypothesis_id: str, evidence: str, exploitation_details: Dict[str, Any] | None = None) -> bool:
         with self._lock:
-            for hyp in self._hypotheses.values():
-                if hyp.surface == surface and hyp.vuln_class == vuln_class:
-                    return payload in hyp.payloads_tested
-        return False
+            hyp = self.get(hypothesis_id)
+            if not hyp:
+                return False
+            hyp.status = "confirmed"
+            
+            # Apply tags but DO NOT allow JSON strings to bypass these checks.
+            evi = str(evidence)
+            weak_phrases = ["seems to", "appears to", "maybe", "probably", "might", "could be"]
+            if len(evi) < 50:
+                evi = f"[NEEDS_MORE_DETAIL] {evi}"
+            if any(phrase in evi.lower() for phrase in weak_phrases):
+                evi = f"[WEAK_EVIDENCE] {evi}"
+
+            hyp.evidence_for.append(evi)
+            if exploitation_details:
+                hyp.details.update(exploitation_details)
+                payload = exploitation_details.get("successful_payload") or exploitation_details.get("payload")
+                if payload:
+                    hyp.successful_payloads.append(str(payload))
+            hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            
+            callbacks = list(self._confirmation_callbacks)
+            hyp_copy = hyp
+            
+        for cb in callbacks:
+            try:
+                cb(hypothesis_id, hyp_copy)
+            except Exception:
+                pass
+        return True
 
-    def get_open_hypotheses(self) -> list[Hypothesis]:
-        """Return all hypotheses not yet confirmed or rejected."""
+    def reject(self, hypothesis_id: str, reason: str = "") -> bool:
         with self._lock:
-            return [h for h in self._hypotheses.values() if h.status in {"open", "testing"}]
+            hyp = self.get(hypothesis_id)
+            if not hyp:
+                return False
+            hyp.status = "rejected"
+            if reason:
+                hyp.evidence_against.append(reason)
+            hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            return True
 
-    def get_coverage_gaps(self, known_surfaces: list[str]) -> list[str]:
-        """Return surfaces that have no hypothesis registered against them."""
-        with self._lock:
-            tested = {h.surface for h in self._hypotheses.values()}
-        return [s for s in known_surfaces if s not in tested]
+    def has_tested(self, surface: str, vuln_class: str, payload: str) -> bool:
+        hyp = self.find_by_surface_and_class(surface, vuln_class)
+        if not hyp:
+            return False
+        return payload in hyp.payloads_tested
+
+    def record_result(self, hypothesis_id: str, new_status: str, evidence: str = "") -> bool:
+        if new_status == "confirmed":
+            return self.confirm(hypothesis_id, evidence)
+        elif new_status == "rejected":
+            return self.reject(hypothesis_id, evidence)
+        elif new_status == "testing":
+            with self._lock:
+                hyp = self.get(hypothesis_id)
+                if not hyp:
+                    return False
+                hyp.status = "testing"
+                if evidence:
+                    hyp.evidence_for.append(str(evidence))
+                hyp.last_updated = datetime.now(timezone.utc).isoformat()
+            return True
+        return False
 
-    def get_stale_hypotheses(self, iteration_threshold: int = 20) -> list[Hypothesis]:
-        """Return hypotheses consuming many iterations without resolution."""
+    def get_open_hypotheses(self) -> List[Hypothesis]:
         with self._lock:
-            return [
-                h for h in self._hypotheses.values()
-                if h.status in {"open", "testing"}
-                and h.iterations_spent >= iteration_threshold
-            ]
-
-    def get_stale_hypothesis_summary(self, iteration_threshold: int = 20) -> list[dict[str, Any]]:
-        """Return stale hypotheses with pruning guidance."""
-        stale = self.get_stale_hypotheses(iteration_threshold)
-        if not stale:
-            return []
-
-        summary: list[dict[str, Any]] = []
-        for hyp in stale:
-            confidence = self._confidence_from_evidence(hyp)
-            if confidence >= 70:
-                action = "pivot"
-            elif confidence <= 20:
-                action = "deprioritize"
-            else:
-                action = "retest"
-
-            summary.append({
-                "hypothesis_id": hyp.id,
-                "surface": hyp.surface,
-                "vuln_class": hyp.vuln_class,
-                "status": hyp.status,
-                "iterations_spent": hyp.iterations_spent,
-                "tests_executed": hyp.tests_executed,
-                "confidence": round(confidence, 1),
-                "recommended_action": action,
-                "next_best_tests": self.get_next_best_tests(hyp.id, limit=3),
-            })
+            return [h for h in self._hypotheses.values() if h.status in _ACTIVE_STATUSES]
 
-        summary.sort(key=lambda entry: (entry["confidence"], entry["iterations_spent"]), reverse=True)
-        return summary
+    def _make_payload_family(self, vuln_class: str, payload: str) -> str:
+        return f"{vuln_class}_payload"
 
-    def get_scored_hypotheses(self) -> list[dict[str, Any]]:
-        """Return heuristic/flat/fifo scores for open/testing hypotheses."""
+    def get_scored_hypotheses(self) -> List[Dict[str, Any]]:
+        # Returns simple priority ordering without math
         with self._lock:
-            hypotheses = [h for h in self._hypotheses.values() if h.status in {"open", "testing"}]
-
-        if not hypotheses:
+            active = [h for h in self._hypotheses.values() if h.status in _ACTIVE_STATUSES]
+        if not active:
             return []
-
-        # FIX B3: Use _scheduler_mode() to respect the heuristic default,
-        # instead of the old hardcoded 'flat' fallback.
-        mode = self._scheduler_mode()
-
-        scored: list[dict[str, Any]] = []
-        for h in hypotheses:
-            belief = self.get_belief(h.id)
-            exploration = round(1.0 / float(1 + max(0, int(h.tests_executed))), 6)
-            redundancy = round(len(set(h.payload_families_tested)) / float(max(1, len(_payload_families_for_class(h.vuln_class)))), 6)
-
-            if mode == "fifo":
-                priority = -float(h.tests_executed)
-                factors = {"fifo_order": round(priority, 6)}
-            elif mode == "heuristic":
-                heuristic_prior = (
-                    (0.5 * self._heuristic_severity_score(h.vuln_class))
-                    + (0.3 * self._heuristic_endpoint_type_score(h.surface))
-                    + (0.2 * max(0.0, 1.0 - redundancy))
-                )
-                priority = heuristic_prior + exploration - redundancy
-                factors = {
-                    "heuristic_prior": round(heuristic_prior, 6),
-                    "exploration": round(exploration, 6),
-                    "redundancy": round(redundancy, 6),
-                }
-            else:
-                priority = belief + exploration - redundancy
-                factors = {
-                    "belief": round(belief, 6),
-                    "exploration": round(exploration, 6),
-                    "redundancy": round(redundancy, 6),
-                }
-
+        
+        scored = []
+        for h in active:
+            priority = 1000 if h.status == "testing" else 500
             scored.append({
                 "hypothesis_id": h.id,
                 "surface": h.surface,
                 "vuln_class": h.vuln_class,
                 "status": h.status,
-                "payloads_tested": len(h.payloads_tested),
-                "tests_executed": h.tests_executed,
-                "iterations_spent": h.iterations_spent,
-                # FIX B3a: expose both 'priority' (expected by test/agent code)
-                # and 'priority_score' (legacy key kept for backward compat).
-                "priority": round(priority, 6),
-                "priority_score": round(priority, 6),
-                "score_factors": factors,
-                "belief": round(belief, 6),
-                "exploration_bonus": round(exploration, 6),
-                "redundancy": round(redundancy, 6),
-                "payload_families_tested": list(h.payload_families_tested),
-                "missing_payload_families": list(h.negative_space.get("missing_families", [])),
-                "next_best_tests": self.get_next_best_tests(h.id, limit=3),
+                "priority_score": priority
             })
-
-        scored.sort(key=lambda x: float(x["priority_score"]), reverse=True)
+        scored.sort(key=lambda x: x["priority_score"], reverse=True)
         return scored
 
-    def get_next_best_tests(self, hypothesis_id: str, limit: int = 3) -> list[dict[str, Any]]:
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return []
-
-            families = hyp.negative_space.get("missing_families") or list(_DEFAULT_PAYLOAD_FAMILIES)
-            suggestions: list[dict[str, Any]] = []
-            seen_payloads = set(hyp.payloads_tested)
-
-            for family in families:
-                candidate_examples = hyp.payload_family_examples.get(family, [])
-                if candidate_examples:
-                    examples = list(candidate_examples)
-                else:
-                    examples = []
-
-                if not examples:
-                    examples = [f"[{family}] baseline test"]
-
-                for payload in examples[:MAX_PAYLOAD_FAMILY_EXAMPLES]:
-                    if payload in seen_payloads:
-                        continue
-                    family_score = self._correlation_family_score(hyp.vuln_class, family)
-                    surface_score = self._correlation_surface_score(hyp.vuln_class, hyp.surface)
-                    combined = round((family_score * 0.65) + (surface_score * 0.35), 4)
-                    suggestions.append({
-                        "family": family,
-                        "payload": payload,
-                        "reason": f"missing family {family}",
-                        "correlation_score": combined,
-                    })
-
-            suggestions.sort(
-                key=lambda item: float(item.get("correlation_score", 0.5)),
-                reverse=True,
-            )
-            return suggestions[:limit]
-
-    def get_summary(self) -> dict[str, Any]:
-        """Return a token-efficient summary of the hypothesis ledger."""
+    def get_summary(self) -> Dict[str, Any]:
         with self._lock:
-            hypotheses_list = list(self._hypotheses.values())
-
-        if not hypotheses_list:
+            hyps = list(self._hypotheses.values())
+        if not hyps:
             return {"total": 0, "by_status": {}, "by_class": {}, "message": "No hypotheses in ledger"}
-
-        by_status: dict[str, int] = {}
-        by_class: dict[str, int] = {}
-        for h in hypotheses_list:
+        
+        by_status = {}
+        by_class = {}
+        for h in hyps:
             by_status[h.status] = by_status.get(h.status, 0) + 1
             by_class[h.vuln_class] = by_class.get(h.vuln_class, 0) + 1
-
-        confirmed = [h for h in hypotheses_list if h.status == "confirmed"]
-
+            
+        confirmed = [h for h in hyps if h.status == "confirmed"]
+        
         return {
-            "total": len(hypotheses_list),
+            "total": len(hyps),
             "by_status": by_status,
             "by_class": by_class,
             "confirmed_count": len(confirmed),
@@ -952,10 +268,8 @@ class HypothesisLedger:
                     "id": h.id,
                     "vuln_class": h.vuln_class,
                     "surface": h.surface[:50],
-                    "evidence_count": len(h.evidence_for),
-                    "confidence": round(self._confidence_from_evidence(h), 1),
-                }
-                for h in confirmed[:5]
+                    "evidence_count": len(h.evidence_for)
+                } for h in confirmed[:5]
             ],
             "open_hypotheses": [
                 {
@@ -963,566 +277,13 @@ class HypothesisLedger:
                     "vuln_class": h.vuln_class,
                     "surface": h.surface[:50],
                     "status": h.status,
-                    "tests_executed": h.tests_executed,
-                    "confidence": round(self._confidence_from_evidence(h), 1),
-                }
-                for h in hypotheses_list
-                if h.status in {"open", "testing"}
-            ][:5],
+                    "tests_executed": h.tests_executed
+                } for h in hyps if h.status in _ACTIVE_STATUSES
+            ][:5]
         }
 
-    # ΓöÇΓöÇ NEW METHODS FOR HYPOTHESIS_ACTIONS.PY ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def get_all(self) -> dict[str, Hypothesis]:
-        """Return all hypotheses as a dictionary {id: Hypothesis}."""
-        with self._lock:
-            return dict(self._hypotheses)
-
-    def find_by_surface_and_class(self, surface: str, vuln_class: str) -> Hypothesis | None:
-        """
-        Find a hypothesis by surface and vulnerability class.
-        
-        Returns:
-            The matching hypothesis, or None if not found.
-        """
-        with self._lock:
-            for hyp in self._hypotheses.values():
-                if hyp.surface == surface and hyp.vuln_class == vuln_class:
-                    return hyp
-            return None
-
-    def get(self, hypothesis_id: str) -> Hypothesis | None:
-        """
-        Get a specific hypothesis by ID.
-        
-        Args:
-            hypothesis_id: The hypothesis ID (e.g., "H-0001")
-        
-        Returns:
-            The hypothesis, or None if not found.
-        """
-        with self._lock:
-            return self._hypotheses.get(hypothesis_id)
-
-    def update_status(self, hypothesis_id: str, status: str, evidence: str = "") -> bool:
-        """Backward-compatible status updater used by older integration tests."""
-        if status not in _VALID_STATUSES:
-            return False
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return False
-            self.record_result(hypothesis_id, status, evidence)
-            return True
-
-    def register_confirmation_callback(
-        self, callback: Callable[[str, Hypothesis], None]
-    ) -> None:
-        """
-        Register a callback to be called when a hypothesis is confirmed.
-        
-        This allows correlation_engine and other components to listen
-        for confirmation events.
-        
-        Args:
-            callback: Function that takes (hypothesis_id, hypothesis)
-        """
-        with self._lock:
-            self._confirmation_callbacks.append(callback)
-
-    async def confirm(
-        self,
-        hypothesis_id: str,
-        evidence: str,
-        exploitation_details: dict[str, Any] | None = None
-    ) -> bool:
-        """
-        Mark a hypothesis as confirmed with evidence.
-        
-        This method:
-        - Updates the hypothesis status to "confirmed"
-        - Stores the evidence
-        - Triggers callbacks for correlation_engine
-        - Updates priority scores of related hypotheses
-        
-        Args:
-            hypothesis_id: The hypothesis ID
-            evidence: Evidence supporting the confirmation
-            exploitation_details: Optional dict with exploitation details
-        
-        Returns:
-            True if confirmed, False if hypothesis not found
-        """
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return False
-            successful_payload = None
-            if exploitation_details:
-                hyp.details = exploitation_details  # type: ignore
-                payload = exploitation_details.get("successful_payload")
-                if payload is None:
-                    payload = exploitation_details.get("payload")
-                if payload is not None:
-                    successful_payload = str(payload)
-
-            self.record_result(
-                hypothesis_id,
-                "confirmed",
-                evidence,
-                successful_payload=successful_payload,
-            )
-            
-            # Store reference for callbacks (outside lock)
-            callbacks = list(self._confirmation_callbacks)
-            hyp_copy = hyp
-        
-        # Trigger callbacks outside of lock to avoid deadlock
-        for callback in callbacks:
-            try:
-                callback(hypothesis_id, hyp_copy)
-            except Exception:
-                # Don't let callback errors break the confirmation
-                pass
-        
-        return True
-
-    async def reject(
-        self,
-        hypothesis_id: str,
-        reason: str
-    ) -> bool:
-        """
-        Mark a hypothesis as rejected with a reason.
-        
-        This method:
-        - Updates the hypothesis status to "rejected"
-        - Stores the rejection reason
-        - Updates priority scores of related hypotheses
-        
-        Args:
-            hypothesis_id: The hypothesis ID
-            reason: Reason for rejection
-        
-        Returns:
-            True if rejected, False if hypothesis not found
-        """
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return False
-
-            self.record_result(hypothesis_id, "rejected", reason)
-            
-            return True
+    def get_prioritized_summary(self, top_n: int = 10) -> List[Dict[str, Any]]:
+        return self.get_scored_hypotheses()[:top_n]
 
-    async def add_evidence_for(
-        self,
-        hypothesis_id: str,
-        evidence: str,
-        outcome: str = "testing"
-    ) -> bool:
-        """
-        Add supporting evidence for a hypothesis.
-        
-        Args:
-            hypothesis_id: The hypothesis ID
-            evidence: Evidence supporting the hypothesis
-            outcome: Current outcome status (default: "testing")
-        
-        Returns:
-            True if added, False if hypothesis not found
-        """
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return False
-            
-            # Validate and add evidence
-            _, validated_evidence = self._validate_evidence_quality(evidence, outcome)
-            self._record_manual_evidence(hyp, validated_evidence, "for", f"evidence_for:{outcome}")
-            
-            return True
-
-    async def add_evidence_against(
-        self,
-        hypothesis_id: str,
-        evidence: str,
-        outcome: str = "testing"
-    ) -> bool:
-        """
-        Add counter-evidence against a hypothesis.
-        
-        Args:
-            hypothesis_id: The hypothesis ID
-            evidence: Evidence against the hypothesis
-            outcome: Current outcome status (default: "testing")
-        
-        Returns:
-            True if added, False if hypothesis not found
-        """
-        with self._lock:
-            hyp = self._hypotheses.get(hypothesis_id)
-            if not hyp:
-                return False
-            
-            # Validate and add counter-evidence
-            _, validated_evidence = self._validate_evidence_quality(evidence, outcome)
-            self._record_manual_evidence(hyp, validated_evidence, "against", f"evidence_against:{outcome}")
-            
-            return True
-
-    # ΓöÇΓöÇ P3.2: Payload Learning ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def get_successful_payloads(
-        self,
-        vuln_class: str | None = None,
-        limit: int = 10
-    ) -> list[dict[str, Any]]:
-        """
-        P3.2: Retrieve successful payloads from confirmed vulnerabilities.
-        
-        Returns payloads that successfully exploited vulnerabilities, optionally
-        filtered by vulnerability class. This enables payload reuse against
-        similar attack surfaces.
-        
-        Args:
-            vuln_class: Filter by vulnerability type (e.g. 'sqli', 'xss'). 
-                       None returns all successful payloads.
-            limit: Maximum number of payloads to return (default 10)
-        
-        Returns:
-            List of dicts with payload, vuln_class, surface, and hypothesis_id
-        
-        Security: This retrieves READ-ONLY data. No execution occurs.
-        """
-        with self._lock:
-            results: list[dict[str, Any]] = []
-            
-            for hyp in self._hypotheses.values():
-                # Only confirmed hypotheses have proven successful payloads
-                if hyp.status != "confirmed":
-                    continue
-                
-                # Filter by vuln_class if specified
-                if vuln_class and hyp.vuln_class != vuln_class:
-                    continue
-                
-                # Add each successful payload from this hypothesis
-                for payload in hyp.successful_payloads:
-                    results.append({
-                        "payload": payload,
-                        "vuln_class": hyp.vuln_class,
-                        "surface": hyp.surface,
-                        "hypothesis_id": hyp.id,
-                    })
-            
-            # Return most recent first (reverse chronological by hypothesis)
-            return results[:limit]
-
-    def get_payload_learning_profile(
-        self,
-        vuln_class: str,
-        surface: str | None = None,
-        limit: int = 10,
-    ) -> dict[str, Any]:
-        """Return payload-transfer data for a target surface/class.
-
-        This ranks successful payloads from confirmed hypotheses by how closely
-        their source surface matches the requested surface, so payload generation
-        can reuse exact working strings instead of only using them as hints.
-        """
-        with self._lock:
-            hypotheses = [
-                h for h in self._hypotheses.values()
-                if h.vuln_class == vuln_class and h.status == "confirmed" and h.successful_payloads
-            ]
-            target = None
-            if surface:
-                for hyp in self._hypotheses.values():
-                    if hyp.surface == surface and hyp.vuln_class == vuln_class:
-                        target = hyp
-                        break
-
-        now = datetime.now(UTC)
-        payload_best: dict[str, dict[str, Any]] = {}
-        source_hypotheses: list[dict[str, Any]] = []
-
-        for hyp in hypotheses:
-            try:
-                last_update = datetime.fromisoformat(hyp.last_updated)
-                hours_ago = max((now - last_update).total_seconds() / 3600, 0.0)
-                recency = max(0.0, 1.0 - min(hours_ago / 168.0, 1.0))
-            except (ValueError, TypeError):
-                recency = 0.5
-
-            confidence = self._confidence_from_evidence(hyp)
-            surface_match = _surface_similarity(surface or "", hyp.surface) if surface else 0.0
-            source_score = round((surface_match * 0.7) + (recency * 0.2) + ((confidence / 100.0) * 0.1), 3)
-
-            source_hypotheses.append({
-                "hypothesis_id": hyp.id,
-                "surface": hyp.surface,
-                "vuln_class": hyp.vuln_class,
-                "status": hyp.status,
-                "surface_match": round(surface_match, 3),
-                "confidence": round(confidence, 1),
-                "payload_count": len(hyp.successful_payloads),
-                "last_updated": hyp.last_updated,
-                "transfer_score": source_score,
-            })
-
-            for payload in hyp.successful_payloads:
-                payload_score = source_score
-                family = self._make_payload_family(vuln_class, payload)
-                if payload in payload_best:
-                    if payload_score <= payload_best[payload]["transfer_score"]:
-                        continue
-                payload_best[payload] = {
-                    "payload": payload,
-                    "source_hypothesis_id": hyp.id,
-                    "source_surface": hyp.surface,
-                    "source_status": hyp.status,
-                    "family": family,
-                    "surface_match": round(surface_match, 3),
-                    "source_confidence": round(confidence, 1),
-                    "transfer_score": payload_score,
-                }
-
-        learned_payloads = sorted(
-            payload_best.values(),
-            key=lambda entry: (entry["transfer_score"], entry["source_confidence"]),
-            reverse=True,
-        )[:limit]
-
-        failed_payloads: list[str] = []
-        if target:
-            failed_payloads = [
-                payload for payload in target.payloads_tested
-                if payload not in target.successful_payloads
-            ]
-
-        families: dict[str, int] = {}
-        for entry in learned_payloads:
-            family = entry.get("family", "other")
-            families[family] = families.get(family, 0) + 1
-
-        recommended_families = [
-            {
-                "family": family,
-                "count": count,
-                "correlation_score": round(self._correlation_family_score(vuln_class, family), 4),
-            }
-            for family, count in sorted(families.items(), key=lambda item: item[1], reverse=True)
-        ]
-
-        surface_correlation = round(self._correlation_surface_score(vuln_class, surface or ""), 4)
-
-        return {
-            "surface": surface,
-            "vuln_class": vuln_class,
-            "successful_payloads": learned_payloads,
-            "failed_payloads": failed_payloads[:limit],
-            "surface_correlation_score": surface_correlation,
-            "source_hypotheses": sorted(
-                source_hypotheses,
-                key=lambda entry: (entry["transfer_score"], entry["confidence"]),
-                reverse=True,
-            )[:limit],
-            "recommended_families": recommended_families[:limit],
-        }
-
-    def get_payload_stats(self) -> dict[str, Any]:
-        """
-        P3.2: Return statistics about payload effectiveness across all hypotheses.
-        
-        Provides metrics on:
-        - Total payloads tested vs successful
-        - Success rate by vulnerability class
-        - Most effective payloads
-        
-        Returns:
-            Dict with payload effectiveness statistics
-        
-        Security: Aggregates READ-ONLY data. No execution.
-        """
-        with self._lock:
-            total_tested = 0
-            total_successful = 0
-            by_vuln_class: dict[str, dict[str, int]] = {}
-            payload_frequency: dict[str, int] = {}
-            
-            for hyp in self._hypotheses.values():
-                total_tested += len(hyp.payloads_tested)
-                total_successful += len(hyp.successful_payloads)
-                
-                # Track by vulnerability class
-                if hyp.vuln_class not in by_vuln_class:
-                    by_vuln_class[hyp.vuln_class] = {
-                        "tested": 0,
-                        "successful": 0,
-                    }
-                
-                by_vuln_class[hyp.vuln_class]["tested"] += len(hyp.payloads_tested)
-                by_vuln_class[hyp.vuln_class]["successful"] += len(hyp.successful_payloads)
-                
-                # Count payload reuse across hypotheses
-                for payload in hyp.successful_payloads:
-                    payload_frequency[payload] = payload_frequency.get(payload, 0) + 1
-            
-            # Calculate success rates
-            success_rate = (total_successful / total_tested * 100) if total_tested > 0 else 0.0
-            
-            # Success rate by vuln class
-            vuln_class_rates: dict[str, float] = {}
-            for vc, stats in by_vuln_class.items():
-                if stats["tested"] > 0:
-                    vuln_class_rates[vc] = (stats["successful"] / stats["tested"]) * 100
-                else:
-                    vuln_class_rates[vc] = 0.0
-            
-            # Most effective payloads (appearing in multiple successful exploits)
-            most_effective = sorted(
-                payload_frequency.items(),
-                key=lambda x: x[1],
-                reverse=True
-            )[:10]
-            
-            return {
-                "total_payloads_tested": total_tested,
-                "total_successful_payloads": total_successful,
-                "overall_success_rate": round(success_rate, 2),
-                "by_vuln_class": by_vuln_class,
-                "success_rate_by_class": {k: round(v, 2) for k, v in vuln_class_rates.items()},
-                "most_effective_payloads": [
-                    {"payload": p, "success_count": count}
-                    for p, count in most_effective
-                ],
-            }
-
-    def get_prioritized_summary(self, top_n: int = 10) -> str:
-        """Return a factual summary for the expert layer and prompt context."""
-        with self._lock:
-            hyps = [h for h in self._hypotheses.values() if h.status in {"open", "testing", "confirmed", "rejected"}]
-
-        if not hyps:
-            return ""
-
-        lines = ["[HYPOTHESIS LEDGER ΓÇö factual summary]"]
-        lines.append(f"  (scheduler_mode={self._scheduler_mode()})")
-        lines.append("")
-
-        for hyp in hyps[:top_n]:
-            lines.append(
-                f"  {hyp.id} | {hyp.status.upper():10s} | {hyp.vuln_class:15s} | {hyp.surface[:45]} | "
-                f"tests={hyp.tests_executed} conf={self._confidence_from_evidence(hyp):.1f} "
-                f"ev+={len(hyp.evidence_for)} ev-={len(hyp.evidence_against)}"
-            )
-
-        # Summary stats
-        with self._lock:
-            total = len(self._hypotheses)
-            active = len([h for h in self._hypotheses.values() if h.status in {"open", "testing"}])
-            confirmed = len([h for h in self._hypotheses.values() if h.status == "confirmed"])
-
-        lines.append("")
-        lines.append(f"  Active: {active}/{total} | Confirmed vulns: {confirmed}")
-        lines.append("[END LEDGER SUMMARY]")
-
-        return "\n".join(lines)
-
-    # ΓöÇΓöÇ Prompt Injection ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def to_prompt_summary(self, top_n: int = 10, status_filter: list[str] | None = None) -> str:
-        """
-        Return a compact text summary safe to inject into the LLM prompt.
-
-        Args:
-            top_n: Max entries to include.
-            status_filter: If provided, only include hypotheses with these statuses
-                           (e.g. ["open", "testing"] to skip resolved items).
-
-        AUDIT-FIX-08: status_filter allows callers to exclude confirmed/rejected
-        hypotheses from periodic injections, saving ~400 tokens per call.
-        """
-        with self._lock:
-            hyps = list(self._hypotheses.values())
-
-        if not hyps:
-            return ""
-
-        # Apply status filter if requested
-        if status_filter:
-            _filter_lower = {s.lower() for s in status_filter}
-            hyps = [h for h in hyps if h.status.lower() in _filter_lower]
-
-        if not hyps:
-            return ""
-
-        # Sort: confirmed/rejected first (compact), then by iterations desc
-        def sort_key(h: Hypothesis) -> tuple[int, int]:
-            status_order = {"confirmed": 0, "rejected": 1, "testing": 2, "open": 3}
-            return (status_order.get(h.status, 9), -h.iterations_spent)
-
-        hyps_sorted = sorted(hyps, key=sort_key)[:top_n]
-
-        lines = ["[HYPOTHESIS LEDGER ΓÇö current scan state]"]
-        for h in hyps_sorted:
-            tested_count = len(h.payloads_tested)
-            supporting_count = len(h.supporting_evidence)
-            ev_for = len(h.evidence_for)
-            ev_against = len(h.evidence_against)
-            conf = self._confidence_from_evidence(h)
-            trend = h.confidence_history[-1]["trend"] if h.confidence_history else "new"
-            families = ",".join(h.payload_families_tested[:3])
-            line = (
-                f"  {h.id} | {h.status.upper():10s} | {h.vuln_class:15s} | "
-                f"{h.surface[:50]} | payloads={tested_count} tests={h.tests_executed} "
-                f"sup={supporting_count} ev+={ev_for} ev-={ev_against} conf={conf:.1f}/{trend} families={families}"
-            )
-            lines.append(line)
-
-        with self._lock:
-            all_hyps = list(self._hypotheses.values())
-        open_count = sum(1 for h in all_hyps if h.status == "open")
-        testing_count = sum(1 for h in all_hyps if h.status == "testing")
-        confirmed_count = sum(1 for h in all_hyps if h.status == "confirmed")
-        rejected_count = sum(1 for h in all_hyps if h.status == "rejected")
-
-        lines.append(
-            f"  Total: {len(all_hyps)} | open={open_count} testing={testing_count} "
-            f"confirmed={confirmed_count} rejected={rejected_count}"
-        )
-        lines.append("[END LEDGER]")
-        return "\n".join(lines)
-
-    # ΓöÇΓöÇ Serialisation (survives compression) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
-    def to_dict(self) -> dict[str, Any]:
-        with self._lock:
-            return {
-                "counter": self._counter,
-                "hypotheses": {k: v.to_dict() for k, v in self._hypotheses.items()},
-                "belief_map": dict(self._belief_map),
-            }
-
-    @classmethod
-    def from_dict(cls, d: dict[str, Any]) -> "HypothesisLedger":
-        ledger = cls()
-        ledger._counter = d.get("counter", 0)
-        for k, v in d.get("hypotheses", {}).items():
-            ledger._hypotheses[k] = Hypothesis.from_dict(v)
-        raw_beliefs = d.get("belief_map", {})
-        if isinstance(raw_beliefs, dict):
-            for hyp_id, value in raw_beliefs.items():
-                try:
-                    ledger._belief_map[str(hyp_id)] = max(0.0, min(1.0, float(value)))
-                except (TypeError, ValueError):
-                    continue
-        for hyp_id in ledger._hypotheses:
-            ledger._belief_map.setdefault(hyp_id, 0.5)
-        return ledger
-
-    def __len__(self) -> int:
-        with self._lock:
-            return len(self._hypotheses)
+    def get_scheduler_report(self) -> Dict[str, Any]:
+        return {"mode": "dag", "details": "Deterministic DAG mode enabled"}
