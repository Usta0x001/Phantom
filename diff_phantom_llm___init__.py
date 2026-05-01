diff --git a/phantom/llm/__init__.py b/phantom/llm/__init__.py
index ea8e558..3ce3c3c 100644
--- a/phantom/llm/__init__.py
+++ b/phantom/llm/__init__.py
@@ -23,6 +23,7 @@ def __getattr__(name: str) -> Any:
         return LLMRequestFailedError
     raise AttributeError(name)
 
+
 # FIX #4: Suppress LiteLLM warnings and provider list messages
 litellm._logging._disable_debugging()
 litellm.suppress_debug_info = True
@@ -38,8 +39,8 @@ _PHANTOM_EXTRA_MODELS: dict[str, dict] = {
         "max_tokens": 131072,
         "max_input_tokens": 131072,
         "max_output_tokens": 16384,
-        "input_cost_per_token": 0.00000015,   # $0.15 / 1M input
-        "output_cost_per_token": 0.0000006,   # $0.60 / 1M output
+        "input_cost_per_token": 0.00000015,  # $0.15 / 1M input
+        "output_cost_per_token": 0.0000006,  # $0.60 / 1M output
         "litellm_provider": "openai",
         "mode": "chat",
         "supports_function_calling": True,
@@ -63,8 +64,8 @@ _PHANTOM_EXTRA_MODELS: dict[str, dict] = {
         "max_tokens": 131072,
         "max_input_tokens": 131072,
         "max_output_tokens": 16384,
-        "input_cost_per_token": 0.00000058,   # $0.58 / 1M input  (azure_ai/deepseek-v3.2)
-        "output_cost_per_token": 0.0000016800, # $1.68 / 1M output (azure_ai/deepseek-v3.2)
+        "input_cost_per_token": 0.00000058,  # $0.58 / 1M input  (azure_ai/deepseek-v3.2)
+        "output_cost_per_token": 0.0000016800,  # $1.68 / 1M output (azure_ai/deepseek-v3.2)
         "litellm_provider": "openai",
         "mode": "chat",
         "supports_function_calling": True,
@@ -81,6 +82,30 @@ _PHANTOM_EXTRA_MODELS: dict[str, dict] = {
         "supports_function_calling": True,
         "supports_vision": False,
     },
+    # glm-5.1 ΓÇö context: 128K, served via agentrouter.org/v1
+    # Pricing estimates: adjust when provider publishes official rates
+    "openai/glm-5.1": {
+        "max_tokens": 131072,
+        "max_input_tokens": 131072,
+        "max_output_tokens": 16384,
+        "input_cost_per_token": 0.00000055,  # $0.55 / 1M input  (estimated)
+        "output_cost_per_token": 0.00000150,  # $1.50 / 1M output (estimated)
+        "litellm_provider": "openai",
+        "mode": "chat",
+        "supports_function_calling": True,
+        "supports_vision": False,
+    },
+    "glm-5.1": {
+        "max_tokens": 131072,
+        "max_input_tokens": 131072,
+        "max_output_tokens": 16384,
+        "input_cost_per_token": 0.00000055,
+        "output_cost_per_token": 0.00000150,
+        "litellm_provider": "openai",
+        "mode": "chat",
+        "supports_function_calling": True,
+        "supports_vision": False,
+    },
 }
 for _model_name, _model_info in _PHANTOM_EXTRA_MODELS.items():
     if _model_name not in litellm.model_cost:
