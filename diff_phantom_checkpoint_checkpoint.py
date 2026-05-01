diff --git a/phantom/checkpoint/checkpoint.py b/phantom/checkpoint/checkpoint.py
index a2eef20..3f15ef5 100644
--- a/phantom/checkpoint/checkpoint.py
+++ b/phantom/checkpoint/checkpoint.py
@@ -32,8 +32,8 @@ CHECKPOINT_FILE = "checkpoint.json"
 CHECKPOINT_HMAC_FILE = "checkpoint.json.hmac"
 CHECKPOINT_INTERVAL = 5   # persist every N agent iterations
 
-# FIX 1: Max checkpoint size (10 MB)
-MAX_CHECKPOINT_SIZE_BYTES = 10 * 1024 * 1024
+# FIX 1: Max checkpoint size (50 MB) ΓÇö 10 MB was too small for long scans
+MAX_CHECKPOINT_SIZE_BYTES = 50 * 1024 * 1024
 
 # Current version for validation
 CURRENT_VERSION = "1"
@@ -192,20 +192,37 @@ class CheckpointManager:
         try:
             f = Fernet(key)
             return f.encrypt(data)
-        except Exception:
-            logger.warning("Encryption failed, saving plaintext", exc_info=True)
-            return data
+        except Exception as _enc_err:
+            # QUICK WIN: fail-closed ΓÇö if encryption fails, we MUST NOT silently
+            # write plaintext. The user needs to know their checkpoint is exposed.
+            logger.error("Checkpoint encryption failed: %s", _enc_err, exc_info=True)
+            raise RuntimeError(
+                f"Checkpoint encryption failed for {self.run_dir.name}. "
+                "Check PHANTOM_CHECKPOINT_ENCRYPTION_KEY and disk space."
+            ) from _enc_err
 
     def _decrypt_data(self, data: bytes) -> bytes:
         """FIX 4: Decrypt data using Fernet if key is available"""
         key = _get_encryption_key()
         if not key or not CRYPTO_AVAILABLE:
             return data
+        # If data is clearly plaintext JSON, skip decryption attempt.
+        _trimmed = data.lstrip()
+        if _trimmed.startswith(b"{") or _trimmed.startswith(b"["):
+            return data
         try:
             f = Fernet(key)
             return f.decrypt(data)
-        except Exception:
-            return data  # Not encrypted or wrong key, return as-is
+        except Exception as _dec_err:
+            # FIX: fail-closed for real ciphertext, but allow plaintext through.
+            # If the data is very short or clearly not Fernet ciphertext,
+            # it was probably never encrypted (e.g., test data, legacy).
+            if len(data) < 50:
+                return data
+            raise RuntimeError(
+                "Checkpoint decryption failed: wrong key or corrupted data. "
+                "Check PHANTOM_CHECKPOINT_ENCRYPTION_KEY."
+            ) from _dec_err
 
     def save(self, data: CheckpointData) -> None:
         """Atomically persist checkpoint data to disk with HMAC integrity."""
@@ -339,7 +356,6 @@ class CheckpointManager:
         interruption_reason: str | None = None,
         hypothesis_ledger: Any = None,  # P4: Add hypothesis ledger parameter
         coverage_tracker: Any = None,   # P4: Add coverage tracker parameter
-        correlation_engine: Any = None,  # P4: Add correlation engine parameter
         attack_graph: Any = None,  # FIX 5: Add attack graph parameter
         active_sub_agents: dict[str, Any] | None = None,  # FIX ISSUE#6: Sub-agent states
     ) -> CheckpointData:
@@ -384,11 +400,10 @@ class CheckpointManager:
         import datetime
         _saved_at = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
         
-        # P4: Serialize hypothesis ledger, coverage tracker, and correlation engine state
+        # P4: Serialize hypothesis ledger and coverage tracker state
         hypothesis_ledger_state: dict[str, dict[str, Any]] = {}
         coverage_tracker_state: dict[str, Any] = {}
-        correlation_engine_state: dict[str, Any] = {}
-        
+
         if hypothesis_ledger:
             # Hypothesis ledger has get_all() returning dict[str, Hypothesis]
             # Each Hypothesis has a to_dict() method
@@ -406,13 +421,6 @@ class CheckpointManager:
                 coverage_tracker_state = coverage_tracker.to_dict() if hasattr(coverage_tracker, 'to_dict') else {}
             except Exception:
                 logger.debug("Failed to serialize coverage tracker state", exc_info=True)
-        
-        if correlation_engine is not None:
-            # Correlation engine should have a method to export state
-            try:
-                correlation_engine_state = correlation_engine.to_dict() if hasattr(correlation_engine, 'to_dict') else {}
-            except Exception:
-                logger.debug("Failed to serialize correlation engine state", exc_info=True)
 
         # FIX 5: Serialize attack graph state for vulnerability chain visualization
         attack_graph_state: dict[str, Any] = {}
@@ -464,10 +472,9 @@ class CheckpointManager:
             error_calls=error_calls,
             conversation_summary=_conv_summary,
             saved_at=_saved_at,
-            # P4: Include hypothesis ledger, coverage tracker, and correlation engine state
+            # P4: Include hypothesis ledger and coverage tracker state
             hypothesis_ledger_state=hypothesis_ledger_state,
             coverage_tracker_state=coverage_tracker_state,
-            correlation_engine_state=correlation_engine_state,
             # FIX 5: Include attack graph state for vulnerability chain analysis
             attack_graph_state=attack_graph_state,
             # FIX ISSUE#6: Include sub-agent states to avoid losing work on resume
