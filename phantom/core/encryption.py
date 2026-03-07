"""
Data-at-Rest Encryption Module (FIX-P0-002)

Provides symmetric encryption for checkpoints, reports, and audit logs.
Uses Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption.

Key Management:
- Primary: PHANTOM_ENCRYPTION_KEY environment variable (base64-encoded 32 bytes)
- Fallback: KMS provider integration (future)
- Emergency: Per-session ephemeral key (data lost on restart)
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

# Try to import cryptography; fall back to basic encoding if unavailable
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    InvalidToken = Exception  # type: ignore


class EncryptionError(Exception):
    """Encryption or decryption operation failed."""
    pass


class KeyDerivationError(EncryptionError):
    """Key derivation from password/passphrase failed."""
    pass


class DataEncryptor:
    """
    Symmetric encryption for sensitive data at rest.
    
    Supports:
    - Direct Fernet key (32 bytes base64-encoded)
    - Password-based key derivation (PBKDF2-HMAC-SHA256)
    - Ephemeral keys for testing/development
    """
    
    # Salt for password-based key derivation (stored with encrypted data)
    _SALT_SIZE = 16
    # PBKDF2 iterations (OWASP 2024 recommendation for SHA-256)
    _PBKDF2_ITERATIONS = 600_000
    
    def __init__(
        self,
        key: bytes | None = None,
        password: str | None = None,
        allow_ephemeral: bool = True,
    ) -> None:
        """
        Initialize the encryptor with a key or password.
        
        Args:
            key: Pre-derived Fernet key (32 bytes, base64-encoded)
            password: Password to derive key from (will use PBKDF2)
            allow_ephemeral: If True and no key/password, generate ephemeral key
        
        Raises:
            EncryptionError: If no key source and ephemeral not allowed
        """
        self._fernet: Any = None
        self._key_source: str = "none"
        self._salt: bytes | None = None
        
        if not CRYPTOGRAPHY_AVAILABLE:
            _logger.warning(
                "cryptography package not available — encryption disabled. "
                "Install with: pip install cryptography"
            )
            return
        
        if key:
            self._init_from_key(key)
        elif password:
            self._init_from_password(password)
        elif allow_ephemeral:
            self._init_ephemeral()
        else:
            raise EncryptionError(
                "No encryption key provided. Set PHANTOM_ENCRYPTION_KEY environment "
                "variable or provide key/password parameter."
            )
    
    def _init_from_key(self, key: bytes) -> None:
        """Initialize from a pre-existing Fernet key."""
        try:
            self._fernet = Fernet(key)
            self._key_source = "provided"
            _logger.debug("Encryption initialized with provided key")
        except Exception as e:
            raise EncryptionError(f"Invalid encryption key: {e}") from e
    
    def _init_from_password(self, password: str) -> None:
        """Derive key from password using PBKDF2."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        
        self._salt = secrets.token_bytes(self._SALT_SIZE)
        key = self._derive_key(password, self._salt)
        self._fernet = Fernet(key)
        self._key_source = "password"
        _logger.debug("Encryption initialized with password-derived key")
    
    def _init_ephemeral(self) -> None:
        """Generate ephemeral session key (lost on restart)."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        
        key = Fernet.generate_key()
        self._fernet = Fernet(key)
        self._key_source = "ephemeral"
        _logger.warning(
            "Generated EPHEMERAL encryption key — data will be unrecoverable after "
            "restart. Set PHANTOM_ENCRYPTION_KEY for persistent encryption."
        )
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive Fernet key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        key_bytes = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(key_bytes)
    
    @property
    def is_available(self) -> bool:
        """Check if encryption is available."""
        return self._fernet is not None
    
    @property
    def key_source(self) -> str:
        """Return key source type: 'provided', 'password', 'ephemeral', 'none'."""
        return self._key_source
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with authenticated encryption.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted ciphertext (Fernet token format)
            
        Raises:
            EncryptionError: If encryption fails
        """
        if not self._fernet:
            # Encryption not available — return plaintext (with warning marker)
            _logger.warning("Encryption unavailable — data stored in plaintext")
            return b"UNENCRYPTED:" + plaintext
        
        try:
            return self._fernet.encrypt(plaintext)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt authenticated ciphertext.
        
        Args:
            ciphertext: Fernet token or unencrypted data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            EncryptionError: If decryption fails or tampering detected
        """
        # CRIT-06 FIX: Reject UNENCRYPTED prefix when encryption is active
        if ciphertext.startswith(b"UNENCRYPTED:"):
            if self._fernet:
                raise EncryptionError(
                    "Encrypted data expected but received unencrypted marker — "
                    "possible integrity bypass attempt"
                )
            _logger.warning("Loading unencrypted data — consider re-encrypting")
            return ciphertext[12:]
        
        if not self._fernet:
            raise EncryptionError(
                "Cannot decrypt — encryption not available but data is encrypted"
            )
        
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as e:
            raise EncryptionError(
                "Decryption failed — data may be tampered or key mismatch"
            ) from e
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e
    
    def encrypt_json(self, data: dict) -> bytes:
        """Encrypt a JSON-serializable dictionary."""
        import json
        plaintext = json.dumps(data, ensure_ascii=True, default=str).encode("utf-8")
        return self.encrypt(plaintext)
    
    def decrypt_json(self, ciphertext: bytes) -> dict:
        """Decrypt back to a dictionary."""
        import json
        plaintext = self.decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    
    @classmethod
    def from_env(cls, env_var: str = "PHANTOM_ENCRYPTION_KEY") -> "DataEncryptor":
        """
        Create encryptor from environment variable.
        
        The env var should contain a base64-encoded 32-byte Fernet key.
        Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        """
        key_str = os.getenv(env_var)
        if key_str:
            try:
                key_bytes = key_str.encode("utf-8")
                return cls(key=key_bytes)
            except Exception as e:
                _logger.warning("Invalid key in %s: %s — falling back to ephemeral", env_var, e)
        
        return cls(allow_ephemeral=True)


def get_default_encryptor() -> DataEncryptor:
    """Get the default encryptor instance (singleton pattern)."""
    global _default_encryptor
    if "_default_encryptor" not in globals() or _default_encryptor is None:
        _default_encryptor = DataEncryptor.from_env()
    return _default_encryptor


_default_encryptor: DataEncryptor | None = None


# Convenience functions for common operations
def encrypt_file(input_path: Path, output_path: Path | None = None) -> Path:
    """Encrypt a file in place or to a new location."""
    encryptor = get_default_encryptor()
    plaintext = input_path.read_bytes()
    ciphertext = encryptor.encrypt(plaintext)
    
    out = output_path or input_path.with_suffix(input_path.suffix + ".enc")
    out.write_bytes(ciphertext)
    return out


def decrypt_file(input_path: Path, output_path: Path | None = None) -> Path:
    """Decrypt a file to original or new location."""
    encryptor = get_default_encryptor()
    ciphertext = input_path.read_bytes()
    plaintext = encryptor.decrypt(ciphertext)
    
    out = output_path or input_path.with_suffix("")
    out.write_bytes(plaintext)
    return out
