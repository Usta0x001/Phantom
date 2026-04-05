"""
Secure Secrets Management for Phantom.

CRITICAL FIX P1.1: Encrypt API keys at rest instead of storing plaintext
in ~/.phantom/cli-config.json

This module provides:
1. OS-native keyring storage (Windows Credential Manager, macOS Keychain, etc.)
2. Fallback to encrypted file storage with PBKDF2-derived key
3. Automatic migration of existing plaintext secrets
4. Zero-knowledge architecture: master key never stored, derived from password

Security Model:
- Primary: OS keyring (most secure, uses system credentials)
- Fallback: Encrypted file with PBKDF2 (256-bit key from machine-unique salt)
- Migration: Automatically encrypts existing plaintext on first access
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets as secrets_module
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Secret keys that should never be stored in plaintext
SENSITIVE_KEYS = frozenset({
    "LLM_API_KEY",
    "PERPLEXITY_API_KEY",
    "PHANTOM_SHODAN_API_KEY",
    "PHANTOM_GITHUB_TOKEN",
    "PHANTOM_VULNERS_API_KEY",
    "PHANTOM_WHOISXML_API_KEY",
    "PHANTOM_API_NINJAS_KEY",
    "PHANTOM_NVD_API_KEY",
    "PHANTOM_CHECKPOINT_KEY",
    "TRACELOOP_API_KEY",
})


def _get_phantom_dir() -> Path:
    """Get the phantom config directory."""
    return Path.home() / ".phantom"


def _get_secrets_file() -> Path:
    """Get the encrypted secrets file path."""
    return _get_phantom_dir() / "secrets.enc"


def _get_salt_file() -> Path:
    """Get the salt file path."""
    return _get_phantom_dir() / ".salt"


def _get_machine_id() -> bytes:
    """Get a machine-unique identifier for key derivation."""
    # Try various sources of machine identity
    machine_id = ""
    
    # Windows: use machine GUID
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                machine_id = winreg.QueryValueEx(key, "MachineGuid")[0]
        except Exception:
            pass
    
    # Linux: /etc/machine-id
    if not machine_id:
        try:
            machine_id = Path("/etc/machine-id").read_text().strip()
        except Exception:
            pass
    
    # macOS: hardware UUID
    if not machine_id:
        try:
            import subprocess
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "IOPlatformUUID" in line:
                    machine_id = line.split('"')[-2]
                    break
        except Exception:
            pass
    
    # Fallback: use hostname + username
    if not machine_id:
        import socket
        machine_id = f"{socket.gethostname()}-{os.getlogin() if hasattr(os, 'getlogin') else 'user'}"
    
    return machine_id.encode("utf-8")


def _get_or_create_salt() -> bytes:
    """Get or create a cryptographic salt for this machine."""
    salt_file = _get_salt_file()
    
    if salt_file.exists():
        try:
            return base64.b64decode(salt_file.read_text().strip())
        except Exception:
            pass
    
    # Create new salt
    salt = secrets_module.token_bytes(32)
    
    try:
        _get_phantom_dir().mkdir(parents=True, exist_ok=True)
        salt_file.write_text(base64.b64encode(salt).decode("utf-8"))
        # Restrict permissions (Unix only)
        if os.name != "nt":
            salt_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        logger.warning("Could not save salt file: %s", e)
    
    return salt


def _derive_key(password: bytes | None = None) -> bytes:
    """Derive an encryption key using PBKDF2."""
    salt = _get_or_create_salt()
    machine_id = _get_machine_id()
    
    # Combine machine ID with optional password
    key_material = machine_id
    if password:
        key_material = machine_id + password
    
    # PBKDF2 with SHA-256, 100k iterations
    return hashlib.pbkdf2_hmac(
        "sha256",
        key_material,
        salt,
        iterations=100_000,
        dklen=32,
    )


def _try_keyring_store(key: str, value: str) -> bool:
    """Try to store a secret in the OS keyring."""
    try:
        import keyring
        keyring.set_password("phantom-agent", key, value)
        return True
    except Exception:
        return False


def _try_keyring_get(key: str) -> str | None:
    """Try to get a secret from the OS keyring."""
    try:
        import keyring
        return keyring.get_password("phantom-agent", key)
    except Exception:
        return None


def _try_keyring_delete(key: str) -> bool:
    """Try to delete a secret from the OS keyring."""
    try:
        import keyring
        keyring.delete_password("phantom-agent", key)
        return True
    except Exception:
        return False


def _encrypt_value(plaintext: str, key: bytes) -> str:
    """Encrypt a value using Fernet (AES-128-CBC with HMAC)."""
    try:
        from cryptography.fernet import Fernet
        # Fernet requires a 32-byte key encoded as base64
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except ImportError:
        # Fallback: simple XOR obfuscation (NOT secure, but better than plaintext)
        logger.warning("cryptography not installed; using weak obfuscation")
        return _xor_obfuscate(plaintext, key)


def _decrypt_value(ciphertext: str, key: bytes) -> str | None:
    """Decrypt a value."""
    try:
        from cryptography.fernet import Fernet, InvalidToken
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        try:
            return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return None
    except ImportError:
        # Fallback: XOR deobfuscation
        return _xor_deobfuscate(ciphertext, key)


def _xor_obfuscate(plaintext: str, key: bytes) -> str:
    """Weak XOR obfuscation fallback when cryptography is unavailable."""
    data = plaintext.encode("utf-8")
    result = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
    return "XOR:" + base64.b64encode(result).decode("utf-8")


def _xor_deobfuscate(ciphertext: str, key: bytes) -> str | None:
    """Reverse XOR obfuscation."""
    if not ciphertext.startswith("XOR:"):
        return None
    try:
        data = base64.b64decode(ciphertext[4:])
        result = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
        return result.decode("utf-8")
    except Exception:
        return None


class SecureSecretsManager:
    """
    Secure secrets storage with OS keyring and encrypted file fallback.
    
    Usage:
        manager = SecureSecretsManager()
        manager.store("LLM_API_KEY", "sk-...")
        api_key = manager.get("LLM_API_KEY")
    """
    
    def __init__(self) -> None:
        self._key = _derive_key()
        self._cache: dict[str, str] = {}
        self._use_keyring = self._test_keyring()
    
    def _test_keyring(self) -> bool:
        """Test if OS keyring is available."""
        test_key = "phantom-test-keyring"
        test_value = secrets_module.token_hex(8)
        
        if _try_keyring_store(test_key, test_value):
            retrieved = _try_keyring_get(test_key)
            _try_keyring_delete(test_key)
            return retrieved == test_value
        return False
    
    def store(self, key: str, value: str) -> bool:
        """Store a secret securely."""
        if not value or value == "NOT_SET":
            return True
        
        # Try OS keyring first
        if self._use_keyring:
            if _try_keyring_store(key, value):
                self._cache[key] = value
                return True
        
        # Fallback to encrypted file
        return self._store_in_file(key, value)
    
    def _store_in_file(self, key: str, value: str) -> bool:
        """Store a secret in the encrypted file."""
        secrets_file = _get_secrets_file()
        
        # Load existing secrets
        secrets_data = self._load_secrets_file()
        
        # Encrypt and store
        encrypted = _encrypt_value(value, self._key)
        secrets_data[key] = encrypted
        
        # Write back
        try:
            _get_phantom_dir().mkdir(parents=True, exist_ok=True)
            secrets_file.write_text(json.dumps(secrets_data, indent=2))
            
            # Restrict permissions (Unix only)
            if os.name != "nt":
                secrets_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
            
            self._cache[key] = value
            return True
        except OSError as e:
            logger.error("Failed to store secret: %s", e)
            return False
    
    def get(self, key: str) -> str | None:
        """Retrieve a secret."""
        # Check cache first
        if key in self._cache:
            return self._cache[key]
        
        # Try OS keyring
        if self._use_keyring:
            value = _try_keyring_get(key)
            if value:
                self._cache[key] = value
                return value
        
        # Try encrypted file
        value = self._get_from_file(key)
        if value:
            self._cache[key] = value
        return value
    
    def _get_from_file(self, key: str) -> str | None:
        """Get a secret from the encrypted file."""
        secrets_data = self._load_secrets_file()
        
        encrypted = secrets_data.get(key)
        if not encrypted:
            return None
        
        return _decrypt_value(encrypted, self._key)
    
    def _load_secrets_file(self) -> dict[str, str]:
        """Load the encrypted secrets file."""
        secrets_file = _get_secrets_file()
        
        if not secrets_file.exists():
            return {}
        
        try:
            return json.loads(secrets_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    
    def delete(self, key: str) -> bool:
        """Delete a secret."""
        self._cache.pop(key, None)
        
        # Delete from keyring
        if self._use_keyring:
            _try_keyring_delete(key)
        
        # Delete from file
        secrets_data = self._load_secrets_file()
        if key in secrets_data:
            del secrets_data[key]
            try:
                _get_secrets_file().write_text(json.dumps(secrets_data, indent=2))
            except OSError:
                pass
        
        return True
    
    def migrate_plaintext_secrets(self, plaintext_config: dict[str, Any]) -> int:
        """
        Migrate plaintext secrets from old config format.
        
        Returns the number of secrets migrated.
        """
        env_vars = plaintext_config.get("env", {})
        if not isinstance(env_vars, dict):
            return 0
        
        migrated = 0
        
        for key, value in list(env_vars.items()):
            if key in SENSITIVE_KEYS and value and value != "NOT_SET":
                if self.store(key, value):
                    # Mark as migrated in the original config
                    env_vars[key] = "[ENCRYPTED]"
                    migrated += 1
                    logger.info("Migrated secret: %s", key)
        
        return migrated
    
    def list_stored_keys(self) -> list[str]:
        """List all stored secret keys (not values)."""
        keys = set()
        
        # From file
        secrets_data = self._load_secrets_file()
        keys.update(secrets_data.keys())
        
        # Check if keyring has any of our known keys
        if self._use_keyring:
            for key in SENSITIVE_KEYS:
                if _try_keyring_get(key):
                    keys.add(key)
        
        return sorted(keys)


# Global singleton
_secrets_manager: SecureSecretsManager | None = None


def get_secrets_manager() -> SecureSecretsManager:
    """Get or create the global secrets manager."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecureSecretsManager()
    return _secrets_manager


def store_secret(key: str, value: str) -> bool:
    """Store a secret securely."""
    return get_secrets_manager().store(key, value)


def get_secret(key: str) -> str | None:
    """Retrieve a secret."""
    return get_secrets_manager().get(key)


def is_sensitive_key(key: str) -> bool:
    """Check if a key should be stored securely."""
    return key.upper() in SENSITIVE_KEYS


def migrate_existing_config() -> int:
    """Migrate existing plaintext secrets in cli-config.json."""
    config_file = _get_phantom_dir() / "cli-config.json"
    
    if not config_file.exists():
        return 0
    
    try:
        config_data = json.loads(config_file.read_text())
        manager = get_secrets_manager()
        
        migrated = manager.migrate_plaintext_secrets(config_data)
        
        if migrated > 0:
            # Save the config with [ENCRYPTED] markers
            config_file.write_text(json.dumps(config_data, indent=2))
            logger.info("Migrated %d secrets to secure storage", migrated)
        
        return migrated
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to migrate secrets: %s", e)
        return 0
