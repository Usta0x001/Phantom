import logging
import warnings

import litellm

from .config import LLMConfig
from .llm import LLM, LLMRequestFailedError


__all__ = [
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
]

litellm._logging._disable_debugging()

# ── Register models not in litellm's built-in registry ─────────────────────
# Without this, litellm.get_model_info() throws an exception for these models,
# causing memory_compressor.py to fall back to MAX_TOTAL_TOKENS (128K default)
# and litellm.completion_cost() to return 0.0 (breaking budget checks).
_PHANTOM_EXTRA_MODELS: dict[str, dict] = {
    # Kimi-K2.5 — MoE 1T, 128K context, served via Azure AI Foundry
    "openai/Kimi-K2.5": {
        "max_tokens": 131072,
        "max_input_tokens": 131072,
        "max_output_tokens": 16384,
        "input_cost_per_token": 0.00000015,   # $0.15 / 1M input
        "output_cost_per_token": 0.0000006,   # $0.60 / 1M output
        "litellm_provider": "openai",
        "mode": "chat",
        "supports_function_calling": True,
        "supports_vision": False,
    },
    # Same model referenced without the openai/ prefix (e.g. bare model calls)
    "Kimi-K2.5": {
        "max_tokens": 131072,
        "max_input_tokens": 131072,
        "max_output_tokens": 16384,
        "input_cost_per_token": 0.00000015,
        "output_cost_per_token": 0.0000006,
        "litellm_provider": "openai",
        "mode": "chat",
        "supports_function_calling": True,
        "supports_vision": False,
    },
    # DeepSeek-V3.2 — served via Azure AI Foundry same endpoint
    # Rates match azure_ai/deepseek-v3.2 from litellm registry ($0.58/$1.68 per 1M)
    "openai/DeepSeek-V3.2": {
        "max_tokens": 131072,
        "max_input_tokens": 131072,
        "max_output_tokens": 16384,
        "input_cost_per_token": 0.00000058,   # $0.58 / 1M input  (azure_ai/deepseek-v3.2)
        "output_cost_per_token": 0.0000016800, # $1.68 / 1M output (azure_ai/deepseek-v3.2)
        "litellm_provider": "openai",
        "mode": "chat",
        "supports_function_calling": True,
        "supports_vision": False,
    },
    "DeepSeek-V3.2": {
        "max_tokens": 131072,
        "max_input_tokens": 131072,
        "max_output_tokens": 16384,
        "input_cost_per_token": 0.00000058,
        "output_cost_per_token": 0.0000016800,
        "litellm_provider": "openai",
        "mode": "chat",
        "supports_function_calling": True,
        "supports_vision": False,
    },
}
for _model_name, _model_info in _PHANTOM_EXTRA_MODELS.items():
    if _model_name not in litellm.model_cost:
        litellm.model_cost[_model_name] = _model_info
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").propagate = False
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
