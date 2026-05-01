diff --git a/phantom/core/attack_graph.py b/phantom/core/attack_graph.py
index 8ef5d1c..d537775 100644
--- a/phantom/core/attack_graph.py
+++ b/phantom/core/attack_graph.py
@@ -28,6 +28,7 @@ except ImportError:
 
 class AttackNodeType(str, Enum):
     """Types of nodes in the attack graph."""
+
     VULNERABILITY = "vulnerability"
     ASSET = "asset"
     OBJECTIVE = "objective"
@@ -36,6 +37,7 @@ class AttackNodeType(str, Enum):
 
 class AttackEdgeType(str, Enum):
     """Types of edges (relationships) in the attack graph."""
+
     ENABLES = "enables"  # Vuln A enables exploiting Vuln B
     AFFECTS = "affects"  # Vuln affects an asset
     ACHIEVES = "achieves"  # Attack chain achieves objective
@@ -45,6 +47,7 @@ class AttackEdgeType(str, Enum):
 @dataclass
 class AttackNode:
     """A node in the attack graph."""
+
     id: str
     type: AttackNodeType
     label: str
@@ -72,6 +75,7 @@ class AttackNode:
 @dataclass
 class AttackEdge:
     """An edge (relationship) in the attack graph."""
+
     source: str
     target: str
     type: AttackEdgeType
@@ -94,10 +98,46 @@ class AttackEdge:
         return cls(**d)
 
 
+@dataclass
+class AttackPlan:
+    """A probabilistically ranked attack path toward a goal."""
+
+    path: list[str]
+    probability: float
+    cost: float
+    score: float
+    rationale: str
+
+    def to_dict(self) -> dict[str, Any]:
+        return {
+            "path": self.path,
+            "probability": round(self.probability, 6),
+            "cost": round(self.cost, 6),
+            "score": round(self.score, 6),
+            "rationale": self.rationale,
+        }
+
+
+# Deterministic node-status priority (lower = higher priority to exploit)
+# Replaces the hallucination-prone floating-point probability matrices.
+_STATUS_PRIORITY: dict[str, int] = {
+    "confirmed": 1,
+    "testing": 2,
+    "partial": 2,
+    "open": 3,
+    "suspected": 3,
+    "inconclusive": 4,
+    "underdetermined": 4,
+    "rejected": 9,  # Effectively deprioritized
+}
+
+_MAX_PLANNER_TRACES = 20
+
+
 class AttackGraph:
     """
     Directed graph representing attack paths and vulnerability chains.
-    
+
     Features:
     - Add vulnerabilities, assets, objectives, techniques
     - Define relationships between nodes
@@ -117,8 +157,22 @@ class AttackGraph:
         self.metadata: dict[str, Any] = {
             "created_at": datetime.now(UTC).isoformat(),
             "updated_at": datetime.now(UTC).isoformat(),
+            "planner_traces": [],
         }
 
+    def _record_planner_trace(self, trace: dict[str, Any]) -> None:
+        traces = self.metadata.get("planner_traces")
+        if not isinstance(traces, list):
+            traces = []
+            self.metadata["planner_traces"] = traces
+
+        traces.append(trace)
+        if len(traces) > _MAX_PLANNER_TRACES:
+            del traces[:-_MAX_PLANNER_TRACES]
+
+        self.metadata["last_planner_trace"] = trace
+        self.metadata["updated_at"] = datetime.now(UTC).isoformat()
+
     # ΓöÇΓöÇ Node Management ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
     def add_node(
@@ -219,7 +273,15 @@ class AttackGraph:
             weight=weight,
             metadata=metadata or {},
         )
-        self._edges.append(edge)
+        # Keep the exported edge list aligned with the NetworkX graph.
+        for index, existing in enumerate(self._edges):
+            if existing.source == source and existing.target == target:
+                self._edges[index] = edge
+                break
+        else:
+            self._edges.append(edge)
+        if self._graph.has_edge(source, target):
+            self._graph.remove_edge(source, target)
         self._graph.add_edge(
             source,
             target,
@@ -250,34 +312,245 @@ class AttackGraph:
         except nx.NetworkXNoPath:
             return []
 
+    @staticmethod
+    def _normalize_weight(weight: Any) -> float:
+        try:
+            parsed = float(weight)
+        except (TypeError, ValueError):
+            return 1.0
+        # FIX: _clamp was undefined. Inline the clamp logic.
+        return max(0.05, min(1.5, parsed))
+
+    @staticmethod
+    def _coerce_probability(value: Any) -> float | None:
+        try:
+            parsed = float(value)
+        except (TypeError, ValueError):
+            return None
+        # FIX: _clamp was undefined. Inline the clamp logic.
+        return max(0.01, min(0.99, parsed))
+
+    @staticmethod
+    def _coerce_positive(value: Any) -> float | None:
+        try:
+            parsed = float(value)
+        except (TypeError, ValueError):
+            return None
+        if parsed <= 0:
+            return None
+        return parsed
+
+    def _node_priority(self, node_id: str) -> int:
+        """Return lower-is-better integer priority from confirmed node status."""
+        node = self._nodes.get(node_id)
+        if node is None:
+            return 5
+        status = str(node.status or "open").strip().lower()
+        return _STATUS_PRIORITY.get(status, 5)
+
+    def plan_attack_paths(
+        self,
+        source: str,
+        target: str,
+        cutoff: int | None = None,
+        max_plans: int = 5,
+    ) -> list[AttackPlan]:
+        """Rank attack paths by deterministic node-priority score (lower = better)."""
+        if max_plans <= 0:
+            self._record_planner_trace(
+                {
+                    "timestamp": datetime.now(UTC).isoformat(),
+                    "mode": "direct",
+                    "source": source,
+                    "target": target,
+                    "cutoff": cutoff,
+                    "max_plans": max_plans,
+                    "candidate_paths": 0,
+                    "returned_plans": 0,
+                    "top_plan": None,
+                    "top_plans": [],
+                }
+            )
+            return []
+
+        candidate_paths = self.find_paths(source, target, cutoff=cutoff)
+        plans: list[AttackPlan] = []
+        for path in candidate_paths:
+            if len(path) < 2:
+                continue
+
+            # Score = sum of node priorities along path (lower is better).
+            # Confirmed nodes score 1, open nodes score 3, rejected score 9.
+            priority_sum = sum(self._node_priority(node_id) for node_id in path[1:])
+            hop_count = len(path) - 1
+
+            plans.append(
+                AttackPlan(
+                    path=list(path),
+                    # Store priority_sum as probability field for API compat (inverted: lower = better)
+                    probability=float(priority_sum),
+                    cost=float(hop_count),
+                    score=float(priority_sum + hop_count),
+                    rationale=(
+                        f"{hop_count} hops, priority={priority_sum}; {path[0]} -> {path[-1]}"
+                    ),
+                )
+            )
+
+        # Sort: lower score is better (fewer hops through high-priority confirmed nodes)
+        plans.sort(
+            key=lambda p: (
+                p.score,
+                len(p.path),
+                "->".join(p.path),
+            )
+        )
+        selected = plans[:max_plans]
+        self._record_planner_trace(
+            {
+                "timestamp": datetime.now(UTC).isoformat(),
+                "mode": "direct",
+                "source": source,
+                "target": target,
+                "cutoff": cutoff,
+                "max_plans": max_plans,
+                "candidate_paths": len(candidate_paths),
+                "returned_plans": len(selected),
+                "top_plan": selected[0].to_dict() if selected else None,
+                "top_plans": [plan.to_dict() for plan in selected[:3]],
+            }
+        )
+        return selected
+
+    def get_ranked_attack_plans(
+        self,
+        max_plans: int = 5,
+        cutoff: int = 4,
+    ) -> list[AttackPlan]:
+        """Return top plans across vulnerability->asset/objective pairs."""
+        if max_plans <= 0:
+            self._record_planner_trace(
+                {
+                    "timestamp": datetime.now(UTC).isoformat(),
+                    "mode": "aggregate",
+                    "source_count": 0,
+                    "target_count": 0,
+                    "pairs_evaluated": 0,
+                    "candidate_paths": 0,
+                    "returned_plans": 0,
+                    "cutoff": cutoff,
+                    "max_plans": max_plans,
+                    "top_plan": None,
+                    "top_plans": [],
+                }
+            )
+            return []
+
+        sources = [
+            node.id
+            for node in self._nodes.values()
+            if node.type == AttackNodeType.VULNERABILITY
+            and str(node.status or "").strip().lower() != "rejected"
+        ]
+        targets = [
+            node.id
+            for node in self._nodes.values()
+            if node.type in {AttackNodeType.ASSET, AttackNodeType.OBJECTIVE}
+        ]
+        if not sources or not targets:
+            self._record_planner_trace(
+                {
+                    "timestamp": datetime.now(UTC).isoformat(),
+                    "mode": "aggregate",
+                    "source_count": len(sources),
+                    "target_count": len(targets),
+                    "pairs_evaluated": 0,
+                    "candidate_paths": 0,
+                    "returned_plans": 0,
+                    "cutoff": cutoff,
+                    "max_plans": max_plans,
+                    "top_plan": None,
+                    "top_plans": [],
+                }
+            )
+            return []
+
+        plans: list[AttackPlan] = []
+        seen_paths: set[tuple[str, ...]] = set()
+
+        pair_budget = max(16, max_plans * 8)
+        pairs_evaluated = 0
+        for source in sources:
+            for target in targets:
+                if source == target:
+                    continue
+                pairs_evaluated += 1
+                ranked = self.plan_attack_paths(source, target, cutoff=cutoff, max_plans=1)
+                for plan in ranked:
+                    key = tuple(plan.path)
+                    if key in seen_paths:
+                        continue
+                    seen_paths.add(key)
+                    plans.append(plan)
+                if pairs_evaluated >= pair_budget:
+                    break
+            if pairs_evaluated >= pair_budget:
+                break
+
+        plans.sort(
+            key=lambda p: (
+                p.score,
+                len(p.path),
+                "->".join(p.path),
+            )
+        )
+        selected = plans[:max_plans]
+        self._record_planner_trace(
+            {
+                "timestamp": datetime.now(UTC).isoformat(),
+                "mode": "aggregate",
+                "source_count": len(sources),
+                "target_count": len(targets),
+                "pairs_evaluated": pairs_evaluated,
+                "candidate_paths": len(plans),
+                "returned_plans": len(selected),
+                "cutoff": cutoff,
+                "max_plans": max_plans,
+                "top_plan": selected[0].to_dict() if selected else None,
+                "top_plans": [plan.to_dict() for plan in selected[:3]],
+            }
+        )
+        return selected
+
     def get_critical_vulnerabilities(self, top_n: int = 10) -> list[tuple[str, float]]:
         """
         Identify critical vulnerabilities using betweenness centrality.
-        
+
         Returns list of (vuln_id, centrality_score) tuples, sorted by score.
         High centrality means the vulnerability appears in many attack paths.
         """
         if not self._graph.nodes():
             return []
-        
+
         centrality = nx.betweenness_centrality(self._graph, weight="weight")
-        
+
         # Filter to only vulnerabilities
         vuln_centrality = [
             (node_id, score)
             for node_id, score in centrality.items()
-            if self._nodes.get(node_id) and self._nodes[node_id].type == AttackNodeType.VULNERABILITY
+            if self._nodes.get(node_id)
+            and self._nodes[node_id].type == AttackNodeType.VULNERABILITY
         ]
-        
+
         # Sort by centrality (descending)
         vuln_centrality.sort(key=lambda x: x[1], reverse=True)
-        
+
         return vuln_centrality[:top_n]
 
     def get_attack_surface(self) -> dict[str, Any]:
         """
         Calculate attack surface metrics.
-        
+
         Returns:
             - total_vulnerabilities: Count of vulnerability nodes
             - total_assets: Count of asset nodes
@@ -289,7 +562,7 @@ class AttackGraph:
         vuln_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.VULNERABILITY)
         asset_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.ASSET)
         objective_count = sum(1 for n in self._nodes.values() if n.type == AttackNodeType.OBJECTIVE)
-        
+
         metrics = {
             "total_vulnerabilities": vuln_count,
             "total_assets": asset_count,
@@ -299,7 +572,7 @@ class AttackGraph:
             "connected_components": nx.number_weakly_connected_components(self._graph),
             "density": nx.density(self._graph),
         }
-        
+
         # Calculate average path length safely for directed graphs.
         # networkx.average_shortest_path_length on a DiGraph requires strong
         # connectivity; weak connectivity is not sufficient and raises.
@@ -320,31 +593,32 @@ class AttackGraph:
     def get_vulnerability_chains(self, min_length: int = 2) -> list[list[str]]:
         """
         Find all chains of vulnerabilities (multi-step attack paths).
-        
+
         Args:
             min_length: Minimum chain length to return
-            
+
         Returns:
             List of vulnerability chains (each chain is a list of vuln IDs)
         """
         chains = []
         vuln_nodes = [n for n in self._nodes.values() if n.type == AttackNodeType.VULNERABILITY]
-        
+
         # Find paths between all pairs of vulnerabilities
         for source in vuln_nodes:
             for target in vuln_nodes:
-                if source.id != target.id:
-                    paths = self.find_paths(source.id, target.id)
-                    for path in paths:
-                        # Filter path to only vulnerability nodes
-                        vuln_path = [
-                            node_id for node_id in path
-                            if self._nodes.get(node_id) and
-                            self._nodes[node_id].type == AttackNodeType.VULNERABILITY
-                        ]
-                        if len(vuln_path) >= min_length and vuln_path not in chains:
-                            chains.append(vuln_path)
-        
+                # CF-06 FIX: Bound graph path search to depth 5 to avoid exponential runaway
+                paths = self.find_paths(source.id, target.id, cutoff=5)
+                for path in paths:
+                    # Filter path to only vulnerability nodes
+                    vuln_path = [
+                        node_id
+                        for node_id in path
+                        if self._nodes.get(node_id)
+                        and self._nodes[node_id].type == AttackNodeType.VULNERABILITY
+                    ]
+                    if len(vuln_path) >= min_length and vuln_path not in chains:
+                        chains.append(vuln_path)
+
         return chains
 
     # ΓöÇΓöÇ Export ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
@@ -361,10 +635,10 @@ class AttackGraph:
         """Export graph to JSON format."""
         data = self.to_dict()
         json_str = json.dumps(data, indent=indent)
-        
+
         if filepath:
             Path(filepath).write_text(json_str, encoding="utf-8")
-        
+
         return json_str
 
     def to_networkx(self) -> nx.DiGraph:
@@ -378,22 +652,21 @@ class AttackGraph:
     def to_dot(self, filepath: str | Path | None = None) -> str:
         """
         Export graph to DOT format (Graphviz).
-        
+
         Returns DOT string. If filepath provided, also writes to file.
         """
         try:
             from networkx.drawing.nx_pydot import to_pydot
+
             pydot_graph = to_pydot(self._graph)
             dot_str = pydot_graph.to_string()
-            
+
             if filepath:
                 Path(filepath).write_text(dot_str, encoding="utf-8")
-            
+
             return dot_str
         except ImportError:
-            raise ImportError(
-                "pydot is required for DOT export. Install with: pip install pydot"
-            )
+            raise ImportError("pydot is required for DOT export. Install with: pip install pydot")
 
     # ΓöÇΓöÇ Import ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
@@ -402,7 +675,7 @@ class AttackGraph:
         """Load graph from dictionary format."""
         graph = cls()
         graph.metadata = data.get("metadata", {})
-        
+
         # Add nodes
         for node_data in data.get("nodes", []):
             node = AttackNode.from_dict(node_data)
@@ -415,19 +688,14 @@ class AttackGraph:
                 status=node.status,
                 **node.metadata,
             )
-        
+
         # Add edges
         for edge_data in data.get("edges", []):
             edge = AttackEdge.from_dict(edge_data)
-            graph._edges.append(edge)
-            graph._graph.add_edge(
-                edge.source,
-                edge.target,
-                type=edge.type.value,
-                weight=edge.weight,
-                **edge.metadata,
+            graph.add_edge(
+                edge.source, edge.target, edge.type, weight=edge.weight, metadata=edge.metadata
             )
-        
+
         return graph
 
     @classmethod
@@ -441,7 +709,7 @@ class AttackGraph:
     def generate_summary_report(self) -> str:
         """Generate a text summary of the attack graph."""
         lines = ["=== Attack Graph Summary ===\n"]
-        
+
         surface = self.get_attack_surface()
         lines.append(f"Nodes: {surface['total_nodes']}")
         lines.append(f"  - Vulnerabilities: {surface['total_vulnerabilities']}")
@@ -450,17 +718,17 @@ class AttackGraph:
         lines.append(f"Edges: {surface['total_edges']}")
         lines.append(f"Density: {surface['density']:.3f}")
         lines.append(f"Connected Components: {surface['connected_components']}")
-        
-        if surface['avg_path_length'] is not None:
+
+        if surface["avg_path_length"] is not None:
             lines.append(f"Avg Path Length: {surface['avg_path_length']:.2f}")
-        
+
         lines.append("\n=== Critical Vulnerabilities (by Centrality) ===\n")
         critical = self.get_critical_vulnerabilities(top_n=5)
         for vuln_id, score in critical:
             node = self._nodes.get(vuln_id)
             if node:
                 lines.append(f"  {vuln_id}: {node.label} (centrality={score:.4f})")
-        
+
         lines.append("\n=== Vulnerability Chains (Multi-step Attacks) ===\n")
         chains = self.get_vulnerability_chains(min_length=2)
         if chains:
@@ -473,7 +741,7 @@ class AttackGraph:
                 lines.append(f"  Chain {i}: {' -> '.join(chain_labels)}")
         else:
             lines.append("  No multi-step attack chains detected.")
-        
+
         return "\n".join(lines)
 
 
@@ -483,43 +751,29 @@ def build_attack_graph_from_vulnerabilities(
 ) -> AttackGraph:
     """
     Build an attack graph from a list of vulnerability objects.
-    
+
     Args:
         vulnerabilities: List of Vulnerability objects
         hypothesis_ledger: Optional HypothesisLedger to extract relationships
-        
+
     Returns:
         AttackGraph instance
     """
     graph = AttackGraph()
-    
+
     # Add vulnerability nodes
     for vuln in vulnerabilities:
         graph.add_vulnerability(
             vuln_id=vuln.id,
             title=vuln.title,
-            severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
-            status=vuln.status.value if hasattr(vuln.status, 'value') else str(vuln.status),
+            severity=vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity),
+            status=vuln.status.value if hasattr(vuln.status, "value") else str(vuln.status),
             metadata={
-                "description": getattr(vuln, 'description', None),
-                "evidence": getattr(vuln, 'evidence', []),
-                "remediation": getattr(vuln, 'remediation', None),
-                "discovered_at": getattr(vuln, 'discovered_at', None),
+                "description": getattr(vuln, "description", None),
+                "evidence": getattr(vuln, "evidence", []),
+                "remediation": getattr(vuln, "remediation", None),
+                "discovered_at": getattr(vuln, "discovered_at", None),
             },
         )
 
-    if hypothesis_ledger is not None:
-        try:
-            hyps = hypothesis_ledger.get_all()
-            for src in hyps.values():
-                for dst in hyps.values():
-                    if src.id == dst.id:
-                        continue
-                    if src.vuln_class.lower() == dst.vuln_class.lower() or src.surface.split("::", 1)[0] == dst.surface.split("::", 1)[0]:
-                        if src.id in graph._nodes and dst.id in graph._nodes:
-                            # FIX B-E: method is add_edge(), not add_relationship()
-                            graph.add_edge(src.id, dst.id, AttackEdgeType.ENABLES, weight=0.5)
-        except Exception:
-            pass
-    
     return graph
