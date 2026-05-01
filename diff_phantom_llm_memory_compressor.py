diff --git a/phantom/llm/memory_compressor.py b/phantom/llm/memory_compressor.py
index 6f23ca3..4226ec9 100644
--- a/phantom/llm/memory_compressor.py
+++ b/phantom/llm/memory_compressor.py
@@ -22,11 +22,14 @@ MAX_TOTAL_TOKENS = 128_000
 # FIX BUG-2: Increased from 10 to 15 - findings in messages 11-20 were getting
 # summarized and losing exact payload details. Now more recent context preserved.
 MIN_RECENT_MESSAGES = 15
+
+
 # Hard ceiling on compression threshold regardless of model context window size.
 # Prevents runaway context growth on models with very large windows (e.g. 200k+).
 # FIX #2: Now configurable via PHANTOM_MAX_CONTEXT_CEILING environment variable
 def _get_max_context_ceiling() -> int:
     from phantom.config.config import Config
+
     ceiling_str = Config.get("phantom_max_context_ceiling")
     if ceiling_str:
         try:
@@ -35,6 +38,7 @@ def _get_max_context_ceiling() -> int:
             pass
     return 80_000
 
+
 MAX_CONTEXT_CEILING = _get_max_context_ceiling()
 
 # Max tokens for the compressor's own summarization call (cheap, non-thinking)
@@ -55,105 +59,285 @@ def _get_context_fill_ratio(context_window: int) -> float:
     else:
         return 0.40  # Small models -> conservative compression
 
+
 # Keywords that indicate a message contains a confirmed finding worth anchoring.
 # ENHANCED: Added credentials, network info, and attack progression keywords
 # to prevent context loss during memory compression.
 _ANCHOR_KEYWORDS = (
     # Core vulnerability indicators
-    "vulnerability", "vulnerabilit", "exploit", "sqli", "xss", "rce",
-    "injection", "bypass", "authentication", "unauthorized", "open port",
-    "open ports", "found:", "discovered", "confirmed", "critical", "high",
-    "medium", "cve-", "owasp", "payload", "proof of concept", "poc",
+    "vulnerability",
+    "vulnerabilit",
+    "exploit",
+    "sqli",
+    "xss",
+    "rce",
+    "injection",
+    "bypass",
+    "authentication",
+    "unauthorized",
+    "open port",
+    "open ports",
+    "found:",
+    "discovered",
+    "confirmed",
+    "critical",
+    "high",
+    "medium",
+    "cve-",
+    "owasp",
+    "payload",
+    "proof of concept",
+    "poc",
     "create_vulnerability_report",
     # Vulnerability types
-    "idor", "idor vulnerability", "idor allows",
-    "csrf", "xsrf", "csrf vulnerability", "csrf allows",
-    "ssrf", "xxe", "ssti", "template injection",
-    "lfi", "rfi", "path traversal", "directory traversal",
-    "weak password", "default credential", "hardcoded", "api key exposed",
-    "jwt", "token", "jwt vulnerability", "broken access", "broken auth",
-    "misconfiguration", "misconfigured",
-    "sensitive data", "data exposure", "information disclosure",
-    "race condition", "deserialization", "deserializ",
-    "buffer overflow", "heap overflow", "stack overflow",
-    "command injection", "os command", "remote code",
-    "upload vulnerability", "file upload",
-    "open redirect", "redirect vulnerability",
-    "host header", "host header injection",
-    "idor allows accessing", "idor allows viewing",
+    "idor",
+    "idor vulnerability",
+    "idor allows",
+    "csrf",
+    "xsrf",
+    "csrf vulnerability",
+    "csrf allows",
+    "ssrf",
+    "xxe",
+    "ssti",
+    "template injection",
+    "lfi",
+    "rfi",
+    "path traversal",
+    "directory traversal",
+    "weak password",
+    "default credential",
+    "hardcoded",
+    "api key exposed",
+    "jwt",
+    "token",
+    "jwt vulnerability",
+    "broken access",
+    "broken auth",
+    "misconfiguration",
+    "misconfigured",
+    "sensitive data",
+    "data exposure",
+    "information disclosure",
+    "race condition",
+    "deserialization",
+    "deserializ",
+    "buffer overflow",
+    "heap overflow",
+    "stack overflow",
+    "command injection",
+    "os command",
+    "remote code",
+    "upload vulnerability",
+    "file upload",
+    "open redirect",
+    "redirect vulnerability",
+    "host header",
+    "host header injection",
+    "idor allows accessing",
+    "idor allows viewing",
     "idor vulnerability allows",
     # ADDED: Credentials and secrets (prevent losing discovered credentials)
-    "password", "passwd", "credential", "secret", "api_key", "apikey",
-    "api-key", "bearer", "authorization", "auth_token", "access_token",
-    "refresh_token", "private_key", "public_key", "ssh_key",
+    "password",
+    "passwd",
+    "credential",
+    "secret",
+    "api_key",
+    "apikey",
+    "api-key",
+    "bearer",
+    "authorization",
+    "auth_token",
+    "access_token",
+    "refresh_token",
+    "private_key",
+    "public_key",
+    "ssh_key",
     # ADDED: Session and authentication tokens
-    "session", "cookie", "session_id", "sessionid", "phpsessid",
-    "jsessionid", "asp.net_sessionid", "csrf_token", "xsrf_token",
+    "session",
+    "cookie",
+    "session_id",
+    "sessionid",
+    "phpsessid",
+    "jsessionid",
+    "asp.net_sessionid",
+    "csrf_token",
+    "xsrf_token",
     # ADDED: Network and infrastructure (internal IPs, cloud metadata)
-    "internal", "private", "localhost", "127.0.0.1", "0.0.0.0",
-    "10.0.", "10.1.", "10.2.", "172.16.", "172.17.", "172.18.",
-    "192.168.", "169.254.", "metadata.google", "169.254.169.254",
-    "metadata", "aws", "gcp", "azure", "ec2", "iam", "s3 bucket",
+    "internal",
+    "private",
+    "localhost",
+    "127.0.0.1",
+    "0.0.0.0",
+    "10.0.",
+    "10.1.",
+    "10.2.",
+    "172.16.",
+    "172.17.",
+    "172.18.",
+    "192.168.",
+    "169.254.",
+    "metadata.google",
+    "169.254.169.254",
+    "metadata",
+    "aws",
+    "gcp",
+    "azure",
+    "ec2",
+    "iam",
+    "s3 bucket",
     # ADDED: System and execution (prevent losing shell/command info)
-    "shell", "command", "exec", "system", "eval", "subprocess",
-    "admin", "root", "sudo", "privilege", "escalat", "elevated",
+    "shell",
+    "command",
+    "exec",
+    "system",
+    "eval",
+    "subprocess",
+    "admin",
+    "root",
+    "sudo",
+    "privilege",
+    "escalat",
+    "elevated",
     # ADDED: Files and paths (prevent losing file discovery info)
-    "upload", "download", "file", "/etc/", "/var/", "/tmp/",
-    "config", "backup", ".env", ".git", "web.config", "wp-config",
-    ".htaccess", "robots.txt", "sitemap", "swagger", "openapi",
+    "upload",
+    "download",
+    "file",
+    "/etc/",
+    "/var/",
+    "/tmp/",
+    "config",
+    "backup",
+    ".env",
+    ".git",
+    "web.config",
+    "wp-config",
+    ".htaccess",
+    "robots.txt",
+    "sitemap",
+    "swagger",
+    "openapi",
     # ADDED: Testing context (preserve what was tested and findings)
-    "endpoint", "parameter", "header", "query", "body", "form",
-    "response", "status", "error", "exception", "stack trace",
-    "500 internal", "403 forbidden", "401 unauthorized", "400 bad",
+    "endpoint",
+    "parameter",
+    "header",
+    "query",
+    "body",
+    "form",
+    "response",
+    "status",
+    "error",
+    "exception",
+    "stack trace",
+    "500 internal",
+    "403 forbidden",
+    "401 unauthorized",
+    "400 bad",
     # ADDED: Attack progression (preserve chaining information)
-    "chain", "pivot", "escalat", "exfiltrat", "lateral", "post-exploit",
-    "foothold", "persistence", "c2", "callback", "reverse shell",
-    "bind shell", "webshell", "backdoor",
+    "chain",
+    "pivot",
+    "escalat",
+    "exfiltrat",
+    "lateral",
+    "post-exploit",
+    "foothold",
+    "persistence",
+    "c2",
+    "callback",
+    "reverse shell",
+    "bind shell",
+    "webshell",
+    "backdoor",
     # ADDED: WAF and bypass indicators
-    "waf", "firewall", "blocked", "filtered", "sanitized", "encoded",
-    "bypass", "evasion", "obfuscat",
+    "waf",
+    "firewall",
+    "blocked",
+    "filtered",
+    "sanitized",
+    "encoded",
+    "bypass",
+    "evasion",
+    "obfuscat",
     # ADDED: Out-of-band indicators
-    "oast", "out-of-band", "dns callback", "http callback", "blind",
-    "time-based", "sleep", "delay", "waitfor",
-    
+    "oast",
+    "out-of-band",
+    "dns callback",
+    "http callback",
+    "blind",
+    "time-based",
+    "sleep",
+    "delay",
+    "waitfor",
     # PLAN FIX: Add uncertain/possible findings (new keywords)
-    "appears vulnerable", "might be", "potential", "possible issue",
-    "suspect", "uncertain", "needs verification", "needs more testing",
-    "σê¥µ¡ÑσÅæτÄ░", "σÅ»Φâ╜σ¡ÿσ£¿", "σ╛àτí«Φ«ñ",  # Chinese: initial finding, may exist, pending confirmation
+    "appears vulnerable",
+    "might be",
+    "potential",
+    "possible issue",
+    "suspect",
+    "uncertain",
+    "needs verification",
+    "needs more testing",
+    "σê¥µ¡ÑσÅæτÄ░",
+    "σÅ»Φâ╜σ¡ÿσ£¿",
+    "σ╛àτí«Φ«ñ",  # Chinese: initial finding, may exist, pending confirmation
 )
 
 # PLAN FIX: Add keywords for uncertain/potential findings
 _ANCHOR_UNCERTAIN_KEYWORDS = (
-    "appears vulnerable", "might be", "potential issue", "possible issue",
-    "suspect", "needs verification", "needs more testing", "σê¥µ¡ÑσÅæτÄ░",
-    "σÅ»Φâ╜σ¡ÿσ£¿", "σ╛àτí«Φ«ñ",
+    "appears vulnerable",
+    "might be",
+    "potential issue",
+    "possible issue",
+    "suspect",
+    "needs verification",
+    "needs more testing",
+    "σê¥µ¡ÑσÅæτÄ░",
+    "σÅ»Φâ╜σ¡ÿσ£¿",
+    "σ╛àτí«Φ«ñ",
 )
 _ANCHOR_UNCERTAIN_PATTERN = re.compile(
-    "|".join(re.escape(kw) for kw in _ANCHOR_UNCERTAIN_KEYWORDS),
-    re.IGNORECASE
+    "|".join(re.escape(kw) for kw in _ANCHOR_UNCERTAIN_KEYWORDS), re.IGNORECASE
 )
 
 # HIGH-1 FIX: Precompiled regex for case-insensitive keyword matching.
 # Uses re.IGNORECASE which avoids allocating a lowercased string copy.
 # The regex approach also simplifies the code and handles edge cases better.
 _ANCHOR_KEYWORDS_PATTERN = re.compile(
-    "|".join(re.escape(kw) for kw in _ANCHOR_KEYWORDS),
-    re.IGNORECASE
+    "|".join(re.escape(kw) for kw in _ANCHOR_KEYWORDS), re.IGNORECASE
 )
 
 
 # FIX BUG-1: Anchor keywords that indicate CONFIRMED findings (not just testing context)
 # Require at least one of these to consider message a "finding"
 _ANCHOR_CONFIRM_KEYWORDS = (
-    "found:", "confirmed", "critical", "vulnerability confirmed",
-    "exploit successful", "poc", "proof of concept",
-    "sqli confirmed", "xss confirmed", "rce confirmed",
-    "authentication bypassed", "access gained", "shell obtained",
-    "database exposed", "credentials captured", "command executed",
+    "found:",
+    "confirmed",
+    "critical",
+    "vulnerability confirmed",
+    "exploit successful",
+    "poc",
+    "proof of concept",
+    "sqli confirmed",
+    "xss confirmed",
+    "rce confirmed",
+    "authentication bypassed",
+    "access gained",
+    "shell obtained",
+    "database exposed",
+    "credentials captured",
+    "command executed",
+    '"vulnerable": true',
+    '"vulnerability_found": true',
+    '"success": true',
+    '"status": "confirmed"',
+    "<finding_status>CONFIRMED</finding_status>",
+    '"payload":',
+    'subaction"',
+    'toolName"',
+    '"args":',
 )
 _ANCHOR_CONFIRM_PATTERN = re.compile(
-    "|".join(re.escape(kw) for kw in _ANCHOR_CONFIRM_KEYWORDS),
-    re.IGNORECASE
+    "|".join(re.escape(kw) for kw in _ANCHOR_CONFIRM_KEYWORDS), re.IGNORECASE
 )
 
 # Additional concrete-evidence markers so anchors prefer actionable findings
@@ -181,13 +365,22 @@ _ANCHOR_EVIDENCE_PATTERN = re.compile(
 
 # FIX BUG-1: Keywords that indicate just "testing" (not findings) - require confirm keyword too
 _ANCHOR_TESTING_KEYWORDS = (
-    "testing", "trying", "attempting", "checking", "enumerating",
-    "scanning", "probing", "searching", "looking for",
-    "error:", "error -", "failed", "exception",
+    "testing",
+    "trying",
+    "attempting",
+    "checking",
+    "enumerating",
+    "scanning",
+    "probing",
+    "searching",
+    "looking for",
+    "error:",
+    "error -",
+    "failed",
+    "exception",
 )
 _ANCHOR_TESTING_PATTERN = re.compile(
-    "|".join(re.escape(kw) for kw in _ANCHOR_TESTING_KEYWORDS),
-    re.IGNORECASE
+    "|".join(re.escape(kw) for kw in _ANCHOR_TESTING_KEYWORDS), re.IGNORECASE
 )
 
 
@@ -226,7 +419,7 @@ def _extract_anchors_from_chunk(
         has_testing_language = _ANCHOR_TESTING_PATTERN.search(text) is not None
         has_uncertain = _ANCHOR_UNCERTAIN_PATTERN.search(text) is not None
         has_concrete_evidence = _ANCHOR_EVIDENCE_PATTERN.search(text) is not None
-        
+
         # FIX BUG-1: Skip only if it's pure error without any vulnerability context
         if has_testing_language and not has_general_vuln and not has_confirm:
             continue
@@ -250,12 +443,14 @@ def _extract_anchors_from_chunk(
         if not snippet:
             continue
 
-        anchors.append({
-            "key": snippet[:80],
-            "text": snippet,
-            "source": "compressor",
-            "confidence": confidence,
-        })
+        anchors.append(
+            {
+                "key": snippet[:80],
+                "text": snippet,
+                "source": "compressor",
+                "confidence": confidence,
+            }
+        )
 
     return anchors
 
@@ -264,6 +459,7 @@ def _get_model_context_window(model: str) -> int:
     """Return the model's context window size, or MAX_TOTAL_TOKENS if unknown."""
     # First check for explicit Ollama context length config
     from phantom.config.config import Config
+
     ollama_ctx = Config.get("phantom_ollama_context_length")
     if ollama_ctx:
         try:
@@ -272,7 +468,7 @@ def _get_model_context_window(model: str) -> int:
                 return ctx
         except ValueError:
             pass
-    
+
     # Try to get from litellm
     try:
         info = litellm.get_model_info(model)
@@ -284,6 +480,7 @@ def _get_model_context_window(model: str) -> int:
         pass
     return MAX_TOTAL_TOKENS
 
+
 SUMMARY_PROMPT_TEMPLATE = """You are a context compression agent for a penetration testing system.
 Compress the scan data below while preserving ALL operationally critical information.
 
@@ -409,25 +606,18 @@ def _message_evidence_score(msg: dict[str, Any]) -> float:
 
 
 def _get_phase_retention(agent_state: Any | None) -> tuple[str, int, int]:
-    phase = "recon"
+    """Return uniform retention settings.
+
+    REMOVED: No phase-based branching (RECON/TESTING/WRAP_UP). Pentesting
+    is opportunistic ΓÇö context needs are uniform regardless of iteration.
+    """
     scan_mode = "deep"
     if agent_state is not None:
         scan_mode = str(getattr(agent_state, "scan_mode", scan_mode)).lower()
-        current_phase = getattr(agent_state, "current_phase", None)
-        if current_phase is not None and hasattr(current_phase, "value"):
-            phase = str(current_phase.value).lower()
-        else:
-            phase = str(getattr(agent_state, "phase", phase)).lower()
-
-    if phase == "recon":
-        return phase, 18, 12
-    if phase == "testing":
-        return phase, 20, 15
-    if phase == "wrap_up":
-        return phase, 24, 15
+
     if scan_mode == "stealth":
-        return phase, 22, 10
-    return phase, MIN_RECENT_MESSAGES, 15
+        return "active", 22, 10
+    return "active", 20, 15
 
 
 def _build_structured_summary(
@@ -450,11 +640,34 @@ def _build_structured_summary(
 
 _FACT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
     ("url", re.compile(r"https?://[^\s'\"]+|/[^\s'\"]+")),
-    ("payload", re.compile(r"(?:'\s*or\s*'1'='1|union\s+select|<script[^>]*>|onerror=|onload=|sleep\(|waitfor\s+delay|../|\.\.\\|\$\{[^}]+\}|{{[^}]+}})", re.IGNORECASE)),
-    ("status_code", re.compile(r"\b(?:status\s*code[:=]\s*)?(?:200|201|204|301|302|400|401|403|404|500)\b", re.IGNORECASE)),
-    ("token", re.compile(r"\b(?:bearer|session_id|sessionid|csrf_token|auth_token|api[_-]?key|password|secret)\b", re.IGNORECASE)),
+    (
+        "payload",
+        re.compile(
+            r"(?:'\s*or\s*'1'='1|union\s+select|<script[^>]*>|onerror=|onload=|sleep\(|waitfor\s+delay|../|\.\.\\|\$\{[^}]+\}|{{[^}]+}})",
+            re.IGNORECASE,
+        ),
+    ),
+    (
+        "status_code",
+        re.compile(
+            r"\b(?:status\s*code[:=]\s*)?(?:200|201|204|301|302|400|401|403|404|500)\b",
+            re.IGNORECASE,
+        ),
+    ),
+    (
+        "token",
+        re.compile(
+            r"\b(?:bearer|session_id|sessionid|csrf_token|auth_token|api[_-]?key|password|secret)\b",
+            re.IGNORECASE,
+        ),
+    ),
     ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
-    ("chain", re.compile(r"\b(?:ssrf\s*->\s*metadata|sqli\s*->\s*rce|pivot|chain|lateral)\b", re.IGNORECASE)),
+    (
+        "chain",
+        re.compile(
+            r"\b(?:ssrf\s*->\s*metadata|sqli\s*->\s*rce|pivot|chain|lateral)\b", re.IGNORECASE
+        ),
+    ),
 )
 
 
@@ -477,12 +690,14 @@ def _extract_structured_facts(messages: list[dict[str, Any]]) -> list[dict[str,
                 if key in seen:
                     continue
                 seen.add(key)
-                facts.append({
-                    "type": fact_type,
-                    "value": value[:500],
-                    "role": role,
-                    "source": msg.get("role", "unknown"),
-                })
+                facts.append(
+                    {
+                        "type": fact_type,
+                        "value": value[:500],
+                        "role": role,
+                        "source": msg.get("role", "unknown"),
+                    }
+                )
 
     return facts
 
@@ -573,13 +788,14 @@ def _summarize_messages(
 # Previously: Sequential summarization of N chunks took N * 3-5s = 12-20s
 # Now: Parallel summarization takes 3-5s total (4x speedup)
 
+
 async def _async_summarize_messages(
     messages: list[dict[str, Any]],
     model: str,
     timeout: int = 30,
 ) -> dict[str, Any]:
     """Async version of _summarize_messages for parallel chunk processing.
-    
+
     Uses litellm.acompletion for async LLM calls.
     """
     if not messages:
@@ -659,30 +875,30 @@ async def _parallel_summarize_chunks(
     max_concurrency: int = 4,
 ) -> list[dict[str, Any]]:
     """Summarize multiple chunks in parallel with bounded concurrency.
-    
+
     Args:
         chunks: List of message chunks to summarize
         model: LLM model to use
         timeout: Timeout per summarization call
         max_concurrency: Maximum parallel LLM calls (default 4 to avoid rate limits)
-    
+
     Returns:
         List of summary messages in order
     """
     if not chunks:
         return []
-    
+
     # Use semaphore to limit concurrency and avoid rate limits
     semaphore = asyncio.Semaphore(max_concurrency)
-    
+
     async def _bounded_summarize(chunk: list[dict[str, Any]]) -> dict[str, Any]:
         async with semaphore:
             return await _async_summarize_messages(chunk, model, timeout)
-    
+
     # Run all summarizations in parallel
     tasks = [_bounded_summarize(chunk) for chunk in chunks]
     results = await asyncio.gather(*tasks, return_exceptions=True)
-    
+
     # Handle any exceptions - replace with fallback summaries
     summaries = []
     for i, result in enumerate(results):
@@ -697,17 +913,19 @@ async def _parallel_summarize_chunks(
                 if text:
                     lines.append(f"[{role}] {text[:500]}")
             fallback_text = "\n".join(lines) if lines else "no content"
-            summaries.append({
-                "role": "user",
-                "content": (
-                    f"<context_summary message_count='{len(chunk)}' compressed='fallback'>"
-                    f"{fallback_text[:4000]}"
-                    f"</context_summary>"
-                ),
-            })
+            summaries.append(
+                {
+                    "role": "user",
+                    "content": (
+                        f"<context_summary message_count='{len(chunk)}' compressed='fallback'>"
+                        f"{fallback_text[:4000]}"
+                        f"</context_summary>"
+                    ),
+                }
+            )
         else:
             summaries.append(result)
-    
+
     return summaries
 
 
@@ -732,7 +950,10 @@ def _handle_images(
                     else:
                         url = str(image_url)
                     image_bytes = len(url.encode("utf-8", errors="ignore"))
-                    if image_count >= max_images or (kept_image_bytes + image_bytes) > max_total_image_bytes:
+                    if (
+                        image_count >= max_images
+                        or (kept_image_bytes + image_bytes) > max_total_image_bytes
+                    ):
                         copied_content[index] = {
                             "type": "text",
                             "text": "[Previously attached image removed to preserve context]",
@@ -759,7 +980,7 @@ class MemoryCompressor:
             Config.get("phantom_max_total_image_bytes") or str(max_total_image_bytes)
         )
         self.model_name = model_name or Config.get("phantom_llm")
-        # R-04 regression fix: Old versions used 30s timeout which was too short 
+        # R-04 regression fix: Old versions used 30s timeout which was too short
         # for local models (Ollama). Increased to 180s to accommodate slower local inference.
         self.timeout = timeout or int(Config.get("phantom_memory_compressor_timeout") or "180")
 
@@ -815,13 +1036,15 @@ class MemoryCompressor:
         - Critical security context in summaries
         - Recent images for visual context
         - Technical details and findings
-        
+
         EFFICIENCY FIX MEM-P1.1: Now uses parallel chunk summarization for 4x speedup.
         """
         if not messages:
             return messages
 
-        runtime_llm = getattr(agent_state, "_runtime_llm", None) if agent_state is not None else None
+        runtime_llm = (
+            getattr(agent_state, "_runtime_llm", None) if agent_state is not None else None
+        )
         if runtime_llm is not None:
             routed_model = getattr(runtime_llm.config, "litellm_model", None)
             if routed_model and routed_model != self.model_name:
@@ -885,7 +1108,15 @@ class MemoryCompressor:
 
         last_digest = set(compression_state.get("last_digest", []))
         current_digest = [_message_digest(msg) for msg in old_msgs]
-        delta_messages = [msg for msg, digest in zip(old_msgs, current_digest) if digest not in last_digest]
+        delta_messages = [
+            msg for msg, digest in zip(old_msgs, current_digest) if digest not in last_digest
+        ]
+
+        # FIX: Also compute digests for recent_msgs so they are tracked.
+        # Previously only old_msgs digests were stored; after the window slides,
+        # messages that were in recent_msgs become old_msgs in the next cycle,
+        # but their digests were never in last_digest, causing re-summarization.
+        recent_digests = [_message_digest(msg) for msg in recent_msgs]
         structured_facts = _extract_structured_facts(regular_msgs)
         delta_facts = _extract_structured_facts(delta_messages)
 
@@ -908,7 +1139,9 @@ class MemoryCompressor:
         ):
             if agent_state is not None and hasattr(agent_state, "compression_state"):
                 try:
-                    compression_state["last_digest"] = [_message_digest(msg) for msg in recent_msgs]
+                    # FIX: Store digests of BOTH old and recent messages to prevent
+                    # re-summarization when the window slides in the next cycle.
+                    compression_state["last_digest"] = current_digest + recent_digests
                     compression_state["last_phase"] = phase
                     compression_state["last_keep_recent"] = keep_recent
                     agent_state.compression_state = compression_state
@@ -922,7 +1155,9 @@ class MemoryCompressor:
         # Configurable chunk size ΓÇö larger chunks = fewer compression LLM calls = less latency.
         # PHANTOM_COMPRESSOR_CHUNK_SIZE default is phase-aware.
         try:
-            chunk_size = int(Config.get("phantom_compressor_chunk_size") or str(keep_recent // 2 or 1))
+            chunk_size = int(
+                Config.get("phantom_compressor_chunk_size") or str(keep_recent // 2 or 1)
+            )
         except ValueError:
             chunk_size = max(1, keep_recent // 2 or 1)
         chunk_size = max(1, chunk_size)
@@ -944,13 +1179,20 @@ class MemoryCompressor:
                 chunk = old_msgs[i : i + chunk_size]
                 for anchor in _extract_anchors_from_chunk(chunk):
                     if isinstance(anchor, dict):
-                        anchor["evidence_score"] = max(float(anchor.get("evidence_score", 0.0)), _message_evidence_score({"content": anchor.get("text", "")}))
-                        anchor["confidence_score"] = max(float(anchor.get("confidence_score", 0.0)), anchor["evidence_score"])
+                        anchor["evidence_score"] = max(
+                            float(anchor.get("evidence_score", 0.0)),
+                            _message_evidence_score({"content": anchor.get("text", "")}),
+                        )
+                        anchor["confidence_score"] = max(
+                            float(anchor.get("confidence_score", 0.0)), anchor["evidence_score"]
+                        )
                     agent_state.add_finding_anchor(anchor)
 
         if agent_state is not None and hasattr(agent_state, "compression_state"):
             try:
-                compression_state["last_digest"] = current_digest[-keep_recent:]
+                # FIX: Store digests of ALL old messages (not just the last keep_recent)
+                # plus recent messages, so nothing gets re-summarized after window slide.
+                compression_state["last_digest"] = current_digest + recent_digests
                 compression_state["last_phase"] = phase
                 compression_state["last_keep_recent"] = keep_recent
                 compression_state["structured_facts"] = structured_facts[-50:]
@@ -959,7 +1201,7 @@ class MemoryCompressor:
                 agent_state.compression_state = compression_state
             except Exception:
                 pass
-        
+
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
         # EFFICIENCY FIX MEM-P1.1: Parallel Chunk Summarization
         # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
@@ -967,10 +1209,14 @@ class MemoryCompressor:
         chunks = []
         for i in range(0, len(old_msgs), chunk_size):
             chunks.append(old_msgs[i : i + chunk_size])
-        
+
         # Check if we're in an async context or need to run synchronously
-        parallel_enabled = (Config.get("phantom_compressor_parallel") or "true").lower() in ("true", "1", "yes")
-        
+        parallel_enabled = (Config.get("phantom_compressor_parallel") or "true").lower() in (
+            "true",
+            "1",
+            "yes",
+        )
+
         if parallel_enabled and len(chunks) > 1:
             # Use parallel compression when no loop is active. If called from
             # an active event loop context, fall back to deterministic sequential
@@ -1000,7 +1246,9 @@ class MemoryCompressor:
         # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
         if structured_facts:
-            qa_text = _build_structured_summary(old_msgs, phase, structured_facts[-20:], delta_facts[-10:])
+            qa_text = _build_structured_summary(
+                old_msgs, phase, structured_facts[-20:], delta_facts[-10:]
+            )
             qa_summary = {
                 "role": "user",
                 "content": f"<context_summary message_count='{len(old_msgs)}' phase='{phase}' format='structured'>{qa_text}</context_summary>",
@@ -1019,7 +1267,9 @@ class MemoryCompressor:
                 if len(anchors) > anchor_cap:
                     anchors.sort(
                         key=lambda item: (
-                            float(item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0),
+                            float(
+                                item.get("evidence_score", item.get("confidence_score", 0.0)) or 0.0
+                            ),
                             item.get("key", ""),
                         ),
                         reverse=True,
@@ -1031,17 +1281,16 @@ class MemoryCompressor:
                 pass
 
         result = system_msgs + compressed + recent_msgs
-        
+
         # Calculate compression metrics
-        tokens_after = sum(
-            _get_message_tokens(msg, model_name) for msg in result
-        )
+        tokens_after = sum(_get_message_tokens(msg, model_name) for msg in result)
         compression_ratio = 1.0 - (tokens_after / total_tokens) if total_tokens > 0 else 0.0
         duration_ms = (__import__("time").monotonic() - _t0) * 1000
 
         # Emit an audit event so the watch layer can track compression overhead.
         try:
             from phantom.logging.audit import get_audit_logger as _get_audit
+
             _audit = _get_audit()
             if _audit:
                 if evicted_images > 0 or image_payload_before > self.max_total_image_bytes:
