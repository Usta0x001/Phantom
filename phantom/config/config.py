import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

# IMPL-004 FIX: Credential keys that should use OS keyring when available
_SENSITIVE_KEYS = frozenset({
    "LLM_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "PERPLEXITY_API_KEY",
    "OPENROUTER_API_KEY",
})


def _get_keyring() -> Any:
    """Try to import and return the keyring module. Returns None if unavailable."""
    try:
        import keyring as _kr  # type: ignore[import-untyped]
        # Verify it's functional (not a null backend)
        backend = _kr.get_keyring()
        if "fail" in type(backend).__name__.lower() or "null" in type(backend).__name__.lower():
            return None
        return _kr
    except Exception:  # noqa: BLE001
        return None


def _store_secret(key: str, value: str) -> bool:
    """Store a secret in OS keyring. Returns True on success.
    
    P1-003 FIX: Verify readback after write to detect silent keyring failures.
    """
    kr = _get_keyring()
    if kr is None:
        return False
    try:
        kr.set_password("phantom", key, value)
        # Verify the write succeeded by reading back
        stored = kr.get_password("phantom", key)
        if stored != value:
            _logger.warning("Keyring write verification failed for %s — readback mismatch", key)
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_secret(key: str) -> str | None:
    """Load a secret from OS keyring. Returns None if unavailable."""
    kr = _get_keyring()
    if kr is None:
        return None
    try:
        return kr.get_password("phantom", key)
    except Exception:  # noqa: BLE001
        return None


def _delete_secret(key: str) -> None:
    """Delete a secret from OS keyring (best-effort)."""
    kr = _get_keyring()
    if kr is None:
        return
    with contextlib.suppress(Exception):
        kr.delete_password("phantom", key)


class Config:
    """Configuration Manager for phantom."""

    # LLM Configuration
    phantom_llm = None
    phantom_llm_fallback = None
    llm_api_key = None
    llm_api_base = None
    groq_api_key = None
    openai_api_key = None
    openai_api_base = None
    litellm_base_url = None
    ollama_api_base = None
    phantom_reasoning_effort = "high"
    phantom_llm_max_retries = "5"
    phantom_memory_compressor_timeout = "30"
    llm_timeout = "300"
    _LLM_CANONICAL_NAMES = (
        "phantom_llm",
        "phantom_llm_fallback",
        "llm_api_key",
        "llm_api_base",
        "groq_api_key",
        "openai_api_key",
        "openai_api_base",
        "litellm_base_url",
        "ollama_api_base",
        "phantom_reasoning_effort",
        "phantom_llm_max_retries",
        "phantom_memory_compressor_timeout",
        "llm_timeout",
    )

    # Tool & Feature Configuration
    perplexity_api_key = None
    phantom_disable_browser = "false"

    # Runtime Configuration
    phantom_image = "ghcr.io/usta0x001/phantom-sandbox:latest"
    phantom_runtime_backend = "docker"
    phantom_sandbox_execution_timeout = "600"
    phantom_sandbox_connect_timeout = "10"

    # Config file override (set via --config CLI arg)
    _config_file_override: Path | None = None

    # Variables that are tracked (readable) but NOT automatically persisted on
    # every scan run.  They must be set explicitly via `phantom config set`.
    _NON_PERSISTENT: frozenset[str] = frozenset({"PHANTOM_IMAGE", "PHANTOM_RUNTIME_BACKEND"})

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
    def get_redacted(cls, name: str) -> str | None:
        """Return config value with sensitive data redacted for display."""
        value = cls.get(name)
        if value is None:
            return None
        # Check if the config key holds a sensitive value (API key, token, secret)
        sensitive_keywords = ("api_key", "token", "secret", "password", "credential")
        is_sensitive = any(kw in name.lower() for kw in sensitive_keywords)
        if is_sensitive:
            if len(value) <= 8:
                return "***"
            return value[:4] + "..." + value[-4:]
        return value

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
            with path.open("r", encoding="utf-8-sig") as f:
                data: dict[str, Any] = json.load(f)

                # IMPL-004 FIX: Restore sensitive values from OS keyring
                env_vars = data.get("env", {})
                if isinstance(env_vars, dict):
                    for key, value in list(env_vars.items()):
                        if value == "__KEYRING__":
                            secret = _load_secret(key)
                            if secret:
                                env_vars[key] = secret
                            else:
                                # Keyring unavailable — remove sentinel
                                env_vars.pop(key, None)

                return data
        except (json.JSONDecodeError, OSError):
            return {}

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        try:
            cls.config_dir().mkdir(parents=True, exist_ok=True)
            config_path = cls.config_file()

            # IMPL-004 FIX: Move sensitive values to OS keyring when available
            env_vars = config.get("env", {})
            if isinstance(env_vars, dict):
                keys_moved_to_keyring: list[str] = []
                for key in list(env_vars.keys()):
                    if key.upper() in _SENSITIVE_KEYS and env_vars[key]:
                        if _store_secret(key, env_vars[key]):
                            keys_moved_to_keyring.append(key)
                            # Replace with sentinel so load() knows to check keyring
                            env_vars[key] = "__KEYRING__"
                if keys_moved_to_keyring:
                    _logger.debug("Stored %d secrets in OS keyring", len(keys_moved_to_keyring))

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
            if var_name in cls._NON_PERSISTENT:
                # Never auto-persist these; they require an explicit `phantom config set`.
                continue
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
