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
litellm.verbose = False
litellm.set_verbose = False
litellm.suppress_debug_info = True
# Silence "Provider List:" and other litellm stdout noise
logging.getLogger("LiteLLM").setLevel(logging.CRITICAL)
logging.getLogger("LiteLLM Router").setLevel(logging.CRITICAL)
logging.getLogger("LiteLLM Proxy").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").propagate = False
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
