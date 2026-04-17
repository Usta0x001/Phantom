import os

import pytest


@pytest.fixture(autouse=True)
def isolate_env_vars() -> None:
    """Isolate env vars between tests to prevent cross-test config leakage."""
    tracked_prefixes = ("PHANTOM_", "LLM_", "OPENAI_", "LITELLM_", "OLLAMA_", "PERPLEXITY_")
    preserved = {
        key: value
        for key, value in os.environ.items()
        if key.startswith(tracked_prefixes)
    }

    yield

    for key in list(os.environ.keys()):
        if key.startswith(tracked_prefixes):
            os.environ.pop(key, None)
    os.environ.update(preserved)
