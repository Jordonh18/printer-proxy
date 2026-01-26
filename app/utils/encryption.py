"""
Encryption utilities for Continuum.

Provides Fernet-based encryption for sensitive data like SNMP community strings.
Uses the application's SECRET_KEY as the basis for the encryption key.
"""

import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _derive_key(secret_key: str) -> bytes:
    """
    Derive a Fernet-compatible key from the application secret key.
    Uses SHA-256 to create a 32-byte key, then base64 encodes it.
    """
    # Hash the secret key to get exactly 32 bytes
    key_bytes = hashlib.sha256(secret_key.encode('utf-8')).digest()
    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet() -> Fernet:
    """Get a Fernet instance using the application secret key."""
    from config.config import SECRET_KEY
    key = _derive_key(SECRET_KEY)
    return Fernet(key)


def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt a credential string.
    
    Args:
        plaintext: The credential to encrypt (e.g., SNMP community string)
        
    Returns:
        Base64-encoded encrypted string, safe for database storage
    """
    if not plaintext:
        return ''
    
    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(plaintext.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt credential: {e}")
        raise ValueError("Encryption failed") from e


def decrypt_credential(encrypted: str) -> str:
    """
    Decrypt a credential string.
    
    Args:
        encrypted: The base64-encoded encrypted credential
        
    Returns:
        The decrypted plaintext credential
        
    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, etc.)
    """
    if not encrypted:
        return ''
    
    try:
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        logger.error("Failed to decrypt credential: invalid token (key may have changed)")
        raise ValueError("Decryption failed: invalid token")
    except Exception as e:
        logger.error(f"Failed to decrypt credential: {e}")
        raise ValueError("Decryption failed") from e


def is_encrypted(value: str) -> bool:
    """
    Check if a value appears to be encrypted.
    Fernet tokens start with 'gAAAAA' (base64 of version byte + timestamp).
    """
    if not value:
        return False
    return value.startswith('gAAAAA')


def encrypt_if_needed(value: str) -> str:
    """
    Encrypt a value only if it's not already encrypted.
    Useful for idempotent operations.
    """
    if not value or is_encrypted(value):
        return value
    return encrypt_credential(value)


def safe_decrypt(encrypted: str, default: str = '') -> str:
    """
    Decrypt a credential, returning a default value on failure.
    Useful when you don't want to raise exceptions.
    """
    if not encrypted:
        return default
    
    try:
        return decrypt_credential(encrypted)
    except ValueError:
        return default
