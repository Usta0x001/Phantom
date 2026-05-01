diff --git a/phantom/config/config.py b/phantom/config/config.py
index b697cb3..0f8f480 100644
--- a/phantom/config/config.py
+++ b/phantom/config/config.py
@@ -18,17 +18,20 @@ logger = logging.getLogger(__name__)
 # Import secure secrets manager - lazy to avoid circular imports
 _secrets_manager = None
 
+
 def _get_secrets_manager():
     """Lazy-load the secrets manager to avoid circular imports."""
     global _secrets_manager
     if _secrets_manager is None:
         try:
             from phantom.config.secrets import get_secrets_manager
+
             _secrets_manager = get_secrets_manager()
         except ImportError:
             _secrets_manager = None
     return _secrets_manager
 
+
 class Config:
     """Configuration Manager for Phantom."""
 
@@ -47,71 +50,75 @@ class Config:
     phantom_per_request_ceiling = None
     phantom_tool_truncation_overrides = None
     phantom_max_input_tokens = None
-    phantom_ollama_context_length = None  # PHANTOM_OLLAMA_CONTEXT_LENGTH ΓÇö set context window for local Ollama models
+    phantom_ollama_context_length = (
+        None  # PHANTOM_OLLAMA_CONTEXT_LENGTH ΓÇö set context window for local Ollama models
+    )
     # Cost rates for Azure/custom endpoints that don't return billing metadata
-    phantom_cost_per_1m_input = None   # PHANTOM_COST_PER_1M_INPUT (USD per 1M input tokens)
+    phantom_cost_per_1m_input = None  # PHANTOM_COST_PER_1M_INPUT (USD per 1M input tokens)
     phantom_cost_per_1m_output = None  # PHANTOM_COST_PER_1M_OUTPUT (USD per 1M output tokens)
     # Memory compressor configuration
-    phantom_compressor_llm = "DeepSeek-V3.2"          # PHANTOM_COMPRESSOR_LLM ΓÇö cheaper model for summarization
-    phantom_compressor_chunk_size = None   # PHANTOM_COMPRESSOR_CHUNK_SIZE ΓÇö msgs per compression call
-    phantom_max_context_ceiling = "131072"     # PHANTOM_MAX_CONTEXT_CEILING ΓÇö hard limit on context tokens (DeepSeek v3.2)
+    phantom_compressor_llm = (
+        "DeepSeek-V3.2"  # PHANTOM_COMPRESSOR_LLM ΓÇö cheaper model for summarization
+    )
+    phantom_compressor_chunk_size = (
+        None  # PHANTOM_COMPRESSOR_CHUNK_SIZE ΓÇö msgs per compression call
+    )
+    phantom_max_context_ceiling = (
+        "131072"  # PHANTOM_MAX_CONTEXT_CEILING ΓÇö hard limit on context tokens (DeepSeek v3.2)
+    )
     # Resume / checkpoint feature
-    phantom_checkpoint_interval = "5"      # save checkpoint every N agent iterations
+    phantom_checkpoint_interval = "5"  # save checkpoint every N agent iterations
     # LLM fallback on persistent failure
-    phantom_fallback_llm = None            # PHANTOM_FALLBACK_LLM ΓÇö secondary litellm model string
+    phantom_fallback_llm = None  # PHANTOM_FALLBACK_LLM ΓÇö secondary litellm model string
     # Extra retry budget specifically for 429 rate-limit errors (separate from max_retries)
     phantom_llm_ratelimit_max_retries = None  # PHANTOM_LLM_RATELIMIT_MAX_RETRIES (default: 10)
     # Hard cap on consecutive rate-limit hits in the agent loop before aborting
     phantom_llm_ratelimit_max_agent_retries = "10"  # PHANTOM_LLM_RATELIMIT_MAX_AGENT_RETRIES
     # Adaptive scan mode (auto-downgrade deepΓåÆstandardΓåÆquick when budget is near)
-    phantom_adaptive_scan = "true"         # PHANTOM_ADAPTIVE_SCAN=true to enable
+    phantom_adaptive_scan = "true"  # PHANTOM_ADAPTIVE_SCAN=true to enable
     phantom_adaptive_scan_threshold = "0.8"  # fraction of PHANTOM_MAX_COST that triggers downgrade
     # Multi-model routing (use different models for reasoning vs tool-heavy iterations)
-    phantom_routing_enabled = "true"       # PHANTOM_ROUTING_ENABLED=true to enable
-    phantom_routing_reasoning_model = None # PHANTOM_ROUTING_REASONING_MODEL
-    phantom_routing_tool_model = None      # PHANTOM_ROUTING_TOOL_MODEL
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # EFFICIENCY FIX CRIT-04: Tool Result Caching Configuration
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # Cache idempotent tool results to eliminate 21% redundant calls
-    phantom_tool_cache_enabled = "true"    # PHANTOM_TOOL_CACHE_ENABLED ΓÇö enable/disable caching
-    phantom_tool_cache_max_size = "500"    # PHANTOM_TOOL_CACHE_MAX_SIZE ΓÇö max cached entries
-    phantom_tool_cache_ttl = "300"         # PHANTOM_TOOL_CACHE_TTL ΓÇö cache TTL in seconds (5 min)
+    phantom_routing_enabled = "true"  # PHANTOM_ROUTING_ENABLED=true to enable
+    phantom_routing_reasoning_model = None  # PHANTOM_ROUTING_REASONING_MODEL
+    phantom_routing_tool_model = None  # PHANTOM_ROUTING_TOOL_MODEL
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # EFFICIENCY FIX MEM-P1.1: Parallel Compression Configuration
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # Enable parallel chunk compression for 4x speedup (12s ΓåÆ 3s)
-    phantom_compressor_parallel = "true"   # PHANTOM_COMPRESSOR_PARALLEL ΓÇö enable parallel compression
+    phantom_compressor_parallel = (
+        "true"  # PHANTOM_COMPRESSOR_PARALLEL ΓÇö enable parallel compression
+    )
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # RELIABILITY REC MED-5: Circuit Breaker Configuration
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # Circuit breaker prevents cascading LLM failures after repeated errors
-    phantom_circuit_breaker_enabled = "true"      # PHANTOM_CIRCUIT_BREAKER_ENABLED
-    phantom_circuit_breaker_threshold = "5"         # Consecutive failures before opening
-    phantom_circuit_breaker_timeout = "60"         # Seconds to wait before testing recovery
+    phantom_circuit_breaker_enabled = "true"  # PHANTOM_CIRCUIT_BREAKER_ENABLED
+    phantom_circuit_breaker_threshold = "5"  # Consecutive failures before opening
+    phantom_circuit_breaker_timeout = "60"  # Seconds to wait before testing recovery
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # SECURITY REC LOW-7: RBAC Configuration
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    phantom_security_mode = "research"              # PHANTOM_SECURITY_MODE - research | hardened
-    phantom_proxy_direct_fallback = "false"         # PHANTOM_PROXY_DIRECT_FALLBACK - explicit proxy->direct fallback gate
-    phantom_scheduler_mode = "dabs"                 # PHANTOM_SCHEDULER_MODE - dabs | heuristic | fifo
-    phantom_strict_dabs_execution = "true"          # PHANTOM_STRICT_DABS_EXECUTION - enforce DABS-selected execution path
-    phantom_dabs_lambda = "0.20"                    # PHANTOM_DABS_LAMBDA - propagation strength [0,1]
-    phantom_scheduler_export_json = None             # PHANTOM_SCHEDULER_EXPORT_JSON - optional scheduler trace path
-    # Tool-level role-based access control
-    phantom_rbac_enabled = "true"                 # PHANTOM_RBAC_ENABLED - on by default
-    phantom_rbac_default_role = "senior_pentester" # PHANTOM_RBAC_DEFAULT_ROLE
+    phantom_security_mode = "research"  # PHANTOM_SECURITY_MODE - research | hardened
+    phantom_proxy_direct_fallback = (
+        "false"  # PHANTOM_PROXY_DIRECT_FALLBACK - explicit proxy->direct fallback gate
+    )
+    phantom_scheduler_mode = "dabs"  # PHANTOM_SCHEDULER_MODE - dabs | heuristic | fifo
+    phantom_strict_dabs_execution = (
+        "true"  # PHANTOM_STRICT_DABS_EXECUTION - enforce DABS-selected execution path
+    )
+    phantom_dabs_lambda = "0.20"  # PHANTOM_DABS_LAMBDA - propagation strength [0,1]
+
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # OSINT & Vulnerability Intelligence API Keys (Phase 1 Enhancements)
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # All keys are OPTIONAL - tools degrade gracefully without them
     # NOTE: Use placeholder "NOT_SET" to show in config output. Tools check for None/unset.
-    phantom_shodan_api_key = "NOT_SET"      # PHANTOM_SHODAN_API_KEY ΓÇö for shodan_search tool
-    phantom_github_token = "NOT_SET"        # PHANTOM_GITHUB_TOKEN ΓÇö for github_dork tool (rate limits)
-    phantom_vulners_api_key = "NOT_SET"     # PHANTOM_VULNERS_API_KEY ΓÇö for exploit_search tool
-    phantom_whoisxml_api_key = "NOT_SET"    # PHANTOM_WHOISXML_API_KEY ΓÇö for whois_lookup tool
-    phantom_api_ninjas_key = "NOT_SET"      # PHANTOM_API_NINJAS_KEY ΓÇö fallback for whois_lookup
-    phantom_nvd_api_key = "NOT_SET"         # PHANTOM_NVD_API_KEY ΓÇö for cve_search (higher rate limits)
+    phantom_shodan_api_key = "NOT_SET"  # PHANTOM_SHODAN_API_KEY ΓÇö for shodan_search tool
+    phantom_github_token = "NOT_SET"  # PHANTOM_GITHUB_TOKEN ΓÇö for github_dork tool (rate limits)
+    phantom_vulners_api_key = "NOT_SET"  # PHANTOM_VULNERS_API_KEY ΓÇö for exploit_search tool
+    phantom_whoisxml_api_key = "NOT_SET"  # PHANTOM_WHOISXML_API_KEY ΓÇö for whois_lookup tool
+    phantom_api_ninjas_key = "NOT_SET"  # PHANTOM_API_NINJAS_KEY ΓÇö fallback for whois_lookup
+    phantom_nvd_api_key = "NOT_SET"  # PHANTOM_NVD_API_KEY ΓÇö for cve_search (higher rate limits)
 
     @classmethod
     def _is_api_key_set(cls, key: str) -> bool:
@@ -122,7 +129,9 @@ class Config:
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # SEC-003: Checkpoint HMAC key for team environments
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    phantom_checkpoint_key = "NOT_SET"       # PHANTOM_CHECKPOINT_KEY ΓÇö shared HMAC secret for checkpoint integrity
+    phantom_checkpoint_key = (
+        "NOT_SET"  # PHANTOM_CHECKPOINT_KEY ΓÇö shared HMAC secret for checkpoint integrity
+    )
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     _LLM_CANONICAL_NAMES = (
         "phantom_llm",
@@ -147,16 +156,23 @@ class Config:
     # Tool & Feature Configuration
     perplexity_api_key = None
     phantom_disable_browser = "false"
-    phantom_tool_subset = "full"  # full | core | core-fast | minimal ΓÇö filters tools in system prompt to reduce tokens
+    phantom_tool_subset = "core"  # core | full | core-fast | minimal ΓÇö filters tools in system prompt to reduce tokens (default: core for token efficiency)
     phantom_attach_browser_images = "false"
-    phantom_browser_image_mode = "off"          # off | thumb | full
+    phantom_browser_image_mode = "off"  # off | thumb | full
     phantom_browser_image_thumb_max_bytes = "80000"
     phantom_browser_image_thumb_max_dim = "768"
     phantom_browser_image_full_max_bytes = "250000"
     phantom_browser_image_max_per_turn = "1"
     phantom_adaptive_truncation = "true"
-    phantom_browser_truncation_burst_limit = "32000"  # FIX #5: Increased from 16K to 32K to match terminal
-    phantom_terminal_truncation_burst_limit = "100000"  # Terminal default is 100K (higher due to tool output volume)
+    phantom_browser_truncation_burst_limit = (
+        "64000"  # FIX: Increased from 32K to 64K. Modern SPAs and JSON APIs
+        # often exceed 32KB. 64KB captures verbose error pages,
+        # stack traces, and reflected XSS evidence without blowing
+        # context limits.
+    )
+    phantom_terminal_truncation_burst_limit = (
+        "100000"  # Terminal default is 100K (higher due to tool output volume)
+    )
     phantom_footer_brand = "phantom-agent"
     phantom_footer_discord = "phantom-agent"
     phantom_max_total_image_bytes = "300000"
@@ -171,21 +187,23 @@ class Config:
     phantom_sandbox_execution_timeout = "600"
     phantom_sandbox_connect_timeout = "10"
     # Rec 3 (SF-003): Docker container resource limits
-    phantom_container_mem_limit = "4g"       # PHANTOM_CONTAINER_MEM_LIMIT
-    phantom_container_cpu_quota = "200000"   # PHANTOM_CONTAINER_CPU_QUOTA (100000 = 1 CPU)
-    phantom_container_pids_limit = "512"     # PHANTOM_CONTAINER_PIDS_LIMIT
+    phantom_container_mem_limit = "4g"  # PHANTOM_CONTAINER_MEM_LIMIT
+    phantom_container_cpu_quota = "200000"  # PHANTOM_CONTAINER_CPU_QUOTA (100000 = 1 CPU)
+    phantom_container_pids_limit = "512"  # PHANTOM_CONTAINER_PIDS_LIMIT
     # Rec 7 (AI-SEC-008): Network-level scope enforcement ΓÇö set to hostname or IP/CIDR of target
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
     # SECURITY REC HIGH-1: Scope enforcement enabled by default for safety
     # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    phantom_scope_enforcement = "true"       # PHANTOM_SCOPE_ENFORCEMENT ΓÇö iptables-based network isolation
+    phantom_scope_enforcement = (
+        "true"  # PHANTOM_SCOPE_ENFORCEMENT ΓÇö iptables-based network isolation
+    )
     # Rec 9 (SF-004): Agent concurrency and tree depth limits
-    phantom_max_concurrent_agents = "20"     # PHANTOM_MAX_CONCURRENT_AGENTS
-    phantom_max_total_agents = "100"         # PHANTOM_MAX_TOTAL_AGENTS
-    phantom_max_agent_depth = "5"            # PHANTOM_MAX_AGENT_DEPTH
+    phantom_max_concurrent_agents = "20"  # PHANTOM_MAX_CONCURRENT_AGENTS
+    phantom_max_total_agents = "100"  # PHANTOM_MAX_TOTAL_AGENTS
+    phantom_max_agent_depth = "5"  # PHANTOM_MAX_AGENT_DEPTH
     # Rec 2 (SF-001): Cost circuit breaker ΓÇö phantom_max_cost already exists, this
     # controls whether hitting the limit aborts the scan (hard) or just warns (soft)
-    phantom_cost_abort_on_limit = "true"     # PHANTOM_COST_ABORT_ON_LIMIT
+    phantom_cost_abort_on_limit = "true"  # PHANTOM_COST_ABORT_ON_LIMIT
 
     # Telemetry
     phantom_telemetry = "1"
@@ -227,12 +245,12 @@ class Config:
     @classmethod
     def get(cls, name: str) -> str | None:
         env_name = name.upper()
-        
+
         # First check environment variable (always takes priority)
         env_value = os.getenv(env_name)
         if env_value is not None:
             return env_value
-        
+
         # Fall back to class default
         default = getattr(cls, name, None)
         return default
@@ -258,8 +276,7 @@ class Config:
                 file_mode = path.stat().st_mode
                 if file_mode & (stat.S_IRGRP | stat.S_IROTH):
                     logger.warning(
-                        "Config file %s is readable by group/others (mode %o). "
-                        "Run: chmod 600 %s",
+                        "Config file %s is readable by group/others (mode %o). Run: chmod 600 %s",
                         path,
                         file_mode & 0o777,
                         path,
@@ -289,20 +306,20 @@ class Config:
     @classmethod
     def reset_var(cls, var_name: str | None = None) -> bool:
         """Reset specific config variable or all if var_name is None.
-        
+
         Args:
             var_name: Optional specific variable name to reset.
                      If None, resets all saved configuration.
-        
+
         Returns:
             True if reset successful, False otherwise.
         """
         current_config = cls.load()
         env_vars = current_config.get("env", {})
-        
+
         if not isinstance(env_vars, dict):
             env_vars = {}
-        
+
         if var_name is None:
             # Reset all - clear entire env section
             env_vars = {}
@@ -310,13 +327,13 @@ class Config:
             # Reset specific variable
             var_upper = var_name.upper()
             tracked = cls.tracked_vars()
-            
+
             if var_upper not in tracked:
                 logger.warning(f"Variable {var_upper} is not a tracked config variable")
                 return False
-            
+
             env_vars.pop(var_upper, None)
-        
+
         cls.save({"env": env_vars})
         return True
 
