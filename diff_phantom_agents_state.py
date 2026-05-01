diff --git a/phantom/agents/state.py b/phantom/agents/state.py
index ce2fe0e..9b608b5 100644
--- a/phantom/agents/state.py
+++ b/phantom/agents/state.py
@@ -8,7 +8,10 @@ from pydantic import BaseModel, Field, PrivateAttr
 
 
 def _generate_agent_id() -> str:
-    return f"agent_{uuid.uuid4().hex[:8]}"
+    # FIX: Use full UUID instead of 8 hex chars (32 bits) to avoid collisions
+    # at scale. Birthday-boundary collision probability with 32 bits becomes
+    # non-negligible at 100+ agents per scan.
+    return f"agent_{uuid.uuid4().hex}"
 
 
 class AgentState(BaseModel):
@@ -67,7 +70,7 @@ class AgentState(BaseModel):
     # Maximum anchors to store (matches injection limit in llm.py)
     MAX_FINDING_ANCHORS: int = 15
     MAX_ARCHIVED_MESSAGES: int = 200
-    
+
     # PLAN FIX: Message expiration
     MAX_MESSAGES_BEFORE_CLEANUP: int = 50  # Keep last 50 messages, archive rest
 
@@ -85,10 +88,10 @@ class AgentState(BaseModel):
             if isinstance(content, str):
                 digest_input = f"{role}\x1f{content}"
                 self._message_hashes.add(hashlib.sha256(digest_input.encode("utf-8")).hexdigest())
-    
+
     def cleanup_old_messages(self) -> int:
         """PLAN FIX: Remove old messages beyond MAX_MESSAGES_BEFORE_CLEANUP.
-        
+
         Keeps recent messages for context, archives older ones.
         Returns number of messages removed.
         """
@@ -97,13 +100,13 @@ class AgentState(BaseModel):
 
         removed_count = len(self.messages) - self.MAX_MESSAGES_BEFORE_CLEANUP
         # Keep recent messages and preserve older context in the bounded archive.
-        older_messages = deepcopy(self.messages[:-self.MAX_MESSAGES_BEFORE_CLEANUP])
+        older_messages = deepcopy(self.messages[: -self.MAX_MESSAGES_BEFORE_CLEANUP])
         if older_messages:
             self.archived_messages.extend(older_messages)
             if len(self.archived_messages) > self.MAX_ARCHIVED_MESSAGES:
-                self.archived_messages = self.archived_messages[-self.MAX_ARCHIVED_MESSAGES:]
+                self.archived_messages = self.archived_messages[-self.MAX_ARCHIVED_MESSAGES :]
 
-        self.messages = self.messages[-self.MAX_MESSAGES_BEFORE_CLEANUP:]
+        self.messages = self.messages[-self.MAX_MESSAGES_BEFORE_CLEANUP :]
         self.last_updated = datetime.now(UTC).isoformat()
         return removed_count
 
@@ -116,7 +119,7 @@ class AgentState(BaseModel):
             self.archived_messages = []
             self.last_updated = datetime.now(UTC).isoformat()
         return removed
-    
+
     def add_finding_anchor(self, anchor: dict[str, Any]) -> None:
         """Store a high-signal finding so it survives memory compression."""
         # FIX BUG 1: Validate anchor text is not empty, None, or whitespace
@@ -126,13 +129,37 @@ class AgentState(BaseModel):
         anchor_text = anchor_text.strip()
         if not anchor_text:
             return  # Reject empty or whitespace-only anchors
-        
+
+        anchor_lower = anchor_text.lower()
+        # Drop obvious prompt-injection / role-manipulation text before it can
+        # be pinned and re-injected into later prompts.
+        blocked_patterns = (
+            "ignore previous instructions",
+            "forget previous instructions",
+            "system prompt",
+            "<system",
+            "</system>",
+            "<function=",
+            "</function>",
+            "[system",
+            "[[system]]",
+        )
+        if any(pattern in anchor_lower for pattern in blocked_patterns):
+            return
+
+        if anchor.get("confidence") == "low" and anchor.get("source") == "compressor":
+            # Low-confidence compressor anchors are useful for state, but they
+            # should not be re-injected as durable prompts.
+            anchor.setdefault("status", "transient")
+
         # Deduplicate by key if present
         key = anchor.get("key") or anchor_text[:80]
         new_score = float(anchor.get("evidence_score", anchor.get("confidence_score", 0.0)) or 0.0)
         for existing in self.finding_anchors:
             if (existing.get("key") or existing.get("text", "")[:80]) == key:
-                existing_score = float(existing.get("evidence_score", existing.get("confidence_score", 0.0)) or 0.0)
+                existing_score = float(
+                    existing.get("evidence_score", existing.get("confidence_score", 0.0)) or 0.0
+                )
                 if new_score > existing_score:
                     existing.update(anchor)
                     existing["text"] = anchor_text
@@ -141,7 +168,9 @@ class AgentState(BaseModel):
                         existing["status"] = "active"
                     self.finding_anchors.sort(
                         key=lambda item: (
-                            float(item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0),
+                            float(
+                                item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0
+                            ),
                             item.get("key", ""),
                         ),
                         reverse=True,
@@ -154,18 +183,23 @@ class AgentState(BaseModel):
             weakest_index = min(
                 range(len(self.finding_anchors)),
                 key=lambda i: float(
-                    self.finding_anchors[i].get("evidence_score", self.finding_anchors[i].get("confidence_score", 0.0))
+                    self.finding_anchors[i].get(
+                        "evidence_score", self.finding_anchors[i].get("confidence_score", 0.0)
+                    )
                     or 0.0
                 ),
             )
             weakest_score = float(
-                self.finding_anchors[weakest_index].get("evidence_score", self.finding_anchors[weakest_index].get("confidence_score", 0.0))
+                self.finding_anchors[weakest_index].get(
+                    "evidence_score",
+                    self.finding_anchors[weakest_index].get("confidence_score", 0.0),
+                )
                 or 0.0
             )
             if new_score <= weakest_score:
                 return
             self.finding_anchors.pop(weakest_index)
-        
+
         # Store the anchor with cleaned text and validity status
         anchor["text"] = anchor_text
         if "status" not in anchor:
@@ -197,26 +231,28 @@ class AgentState(BaseModel):
         self.last_updated = datetime.now(UTC).isoformat()
 
     def add_message(
-        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None
+        self,
+        role: str,
+        content: Any,
+        thinking_blocks: list[dict[str, Any]] | None = None,
+        force: bool = False,
     ) -> None:
-        # SECURITY FIX: Hash-based deduplication to prevent context poisoning
-        # Uses SHA-256 hash to efficiently detect duplicate messages
-        if isinstance(content, str):
-            content_hash = hashlib.sha256(f"{role}\x1f{content}".encode("utf-8")).hexdigest()
-            if content_hash in self._message_hashes:
-                return  # Duplicate message - skip to prevent flooding
-            self._message_hashes.add(content_hash)
-        
-        # AUDIT-QW-05: Also keep window-based dedup as secondary defense
-        # to prevent error message flooding from circuit breakers / validation.
-        if isinstance(content, str) and self.messages:
+        if isinstance(content, str) and self.messages and not force:
             _window = self.messages[-5:]
             for m in reversed(_window):
                 if m.get("role") == role and m.get("content") == content:
-                    return  # already present in recent window
+                    return
+
+        if isinstance(content, str) and not force:
+            content_hash = hashlib.sha256(f"{role}\x1f{content}".encode("utf-8")).hexdigest()
+            if content_hash in self._message_hashes:
+                return
+            self._message_hashes.add(content_hash)
+            # FIX H1: cap hash set to prevent unbounded memory growth
+            if len(self._message_hashes) > 500:
+                self._message_hashes.clear()
+
         message = {"role": role, "content": content}
-        # Do NOT store thinking_blocks in history ΓÇö they bloat context invisibly
-        # to the memory compressor and get re-sent on every subsequent call.
         self.messages.append(message)
         self.last_updated = datetime.now(UTC).isoformat()
 
@@ -297,11 +333,7 @@ class AgentState(BaseModel):
         if not self.waiting_for_input or not self.waiting_start_time:
             return False
 
-        if (
-            self.stop_requested
-            or self.llm_failed
-            or self.has_reached_max_iterations()
-        ):
+        if self.stop_requested or self.llm_failed or self.has_reached_max_iterations():
             return False
 
         elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
