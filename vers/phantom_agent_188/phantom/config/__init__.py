from phantom.config.config import (
    Config,
    apply_saved_config,
    save_current_config,
)

# P1.1: Secure secrets management
try:
    from phantom.config.secrets import (
        SecureSecretsManager,
        get_secrets_manager,
        store_secret,
        get_secret,
        is_sensitive_key,
        migrate_existing_config,
        SENSITIVE_KEYS,
    )
    _HAS_SECRETS = True
except ImportError:
    _HAS_SECRETS = False


__all__ = [
    "Config",
    "apply_saved_config",
    "save_current_config",
    # Secrets (conditionally available)
    "get_secret",
    "store_secret",
    "is_sensitive_key",
    "migrate_existing_config",
]
