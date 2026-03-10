import contextlib
import json
import os
from pathlib import Path
from typing import Any


PHANTOM_API_BASE = "https://models.phantom.ai/api/v1"


class Config:
    """Configuration Manager for Phantom."""

    # LLM Configuration
    phantom_llm = None
    llm_api_key = None
    llm_api_base = None
    openai_api_base = None
    litellm_base_url = None
    ollama_api_base = None
    phantom_reasoning_effort = "medium"
    phantom_memory_compressor_timeout = "30"
    llm_timeout = "300"
    llm_max_tokens = None
    phantom_max_cost = None
    phantom_per_request_ceiling = None
    phantom_tool_truncation_overrides = None
    _LLM_CANONICAL_NAMES = (
        "phantom_llm",
        "llm_api_key",
        "llm_api_base",
        "openai_api_base",
        "litellm_base_url",
        "ollama_api_base",
        "phantom_reasoning_effort",
        "phantom_llm_max_retries",
        "phantom_memory_compressor_timeout",
        "llm_timeout",
        "llm_max_tokens",
        "phantom_max_cost",
        "phantom_per_request_ceiling",
    )

    # Tool & Feature Configuration
    perplexity_api_key = None
    phantom_disable_browser = "false"

    # Runtime Configuration
    phantom_image = "ghcr.io/usta0x001/phantom-sandbox:latest"
    phantom_runtime_backend = "docker"
    phantom_sandbox_execution_timeout = "120"
    phantom_sandbox_connect_timeout = "10"

    # Telemetry
    phantom_telemetry = "1"
    phantom_otel_telemetry = None
    phantom_posthog_telemetry = None
    traceloop_base_url = None
    traceloop_api_key = None
    traceloop_headers = None

    # Config file override (set via --config CLI arg)
    _config_file_override: Path | None = None

    @classmethod
    def _tracked_names(cls) -> list[str]:
        return [
            k
            for k, v in vars(cls).items()
            if not k.startswith("_") and k[0].islower() and (v is None or isinstance(v, str))
        ]

    @classmethod
    def tracked_vars(cls) -> list[str]:
        return [name.upper() for name in cls._tracked_names()]

    @classmethod
    def _llm_env_vars(cls) -> set[str]:
        return {name.upper() for name in cls._LLM_CANONICAL_NAMES}

    @classmethod
    def _llm_env_changed(cls, saved_env: dict[str, Any]) -> bool:
        for var_name in cls._llm_env_vars():
            current = os.getenv(var_name)
            if current is None:
                continue
            if saved_env.get(var_name) != current:
                return True
        return False

    @classmethod
    def get(cls, name: str) -> str | None:
        env_name = name.upper()
        default = getattr(cls, name, None)
        return os.getenv(env_name, default)

    @classmethod
    def config_dir(cls) -> Path:
        return Path.home() / ".phantom"

    @classmethod
    def config_file(cls) -> Path:
        if cls._config_file_override is not None:
            return cls._config_file_override
        return cls.config_dir() / "cli-config.json"

    @classmethod
    def load(cls) -> dict[str, Any]:
        path = cls.config_file()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (json.JSONDecodeError, OSError):
            return {}

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        try:
            cls.config_dir().mkdir(parents=True, exist_ok=True)
            config_path = cls.config_dir() / "cli-config.json"
            with config_path.open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except OSError:
            return False
        with contextlib.suppress(OSError):
            config_path.chmod(0o600)  # may fail on Windows
        return True

    @classmethod
    def apply_saved(cls, force: bool = False) -> dict[str, str]:
        saved = cls.load()
        env_vars = saved.get("env", {})
        if not isinstance(env_vars, dict):
            env_vars = {}
        cleared_vars = {
            var_name
            for var_name in cls.tracked_vars()
            if var_name in os.environ and os.environ.get(var_name) == ""
        }
        if cleared_vars:
            for var_name in cleared_vars:
                env_vars.pop(var_name, None)
            if cls._config_file_override is None:
                cls.save({"env": env_vars})
        if cls._llm_env_changed(env_vars):
            for var_name in cls._llm_env_vars():
                env_vars.pop(var_name, None)
            if cls._config_file_override is None:
                cls.save({"env": env_vars})
        applied = {}

        for var_name, var_value in env_vars.items():
            if var_name in cls.tracked_vars() and (force or var_name not in os.environ):
                os.environ[var_name] = var_value
                applied[var_name] = var_value

        return applied

    @classmethod
    def capture_current(cls) -> dict[str, Any]:
        env_vars = {}
        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value:
                env_vars[var_name] = value
        return {"env": env_vars}

    @classmethod
    def save_current(cls) -> bool:
        existing = cls.load().get("env", {})
        merged = dict(existing)

        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value is None:
                pass
            elif value == "":
                merged.pop(var_name, None)
            else:
                merged[var_name] = value

        return cls.save({"env": merged})


def apply_saved_config(force: bool = False) -> dict[str, str]:
    return Config.apply_saved(force=force)


def save_current_config() -> bool:
    return Config.save_current()


def resolve_llm_config() -> tuple[str | None, str | None, str | None]:
    """Resolve LLM model, api_key, and api_base based on PHANTOM_LLM prefix.

    Returns:
        tuple: (model_name, api_key, api_base)
        - model_name: Original model name (phantom/ prefix preserved for display)
        - api_key: LLM API key
        - api_base: API base URL (auto-set to PHANTOM_API_BASE for phantom/ models)
    """
    model = Config.get("phantom_llm")
    if not model:
        return None, None, None

    api_key = Config.get("llm_api_key")

    if model.startswith("phantom/"):
        api_base: str | None = PHANTOM_API_BASE
    else:
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

    return model, api_key, api_base
