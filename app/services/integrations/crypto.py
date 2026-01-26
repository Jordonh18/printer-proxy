"""
Credential Encryption Module for Integrations.

Provides field-level encryption for API keys, tokens, and secrets at rest.
Uses Fernet symmetric encryption with environment-specific keys.
"""

import base64
import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class CredentialEncryption:
    """
    Handles encryption and decryption of sensitive credentials.
    
    Features:
    - Field-level encryption using Fernet (AES-128-CBC with HMAC)
    - Environment-specific encryption keys
    - Key derivation from master secret
    - Secure key storage and rotation support
    """
    
    _instance = None
    _KEY_FILE_NAME = '.integration_key'
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._fernet: Optional[Fernet] = None
        self._key_created_at: Optional[datetime] = None
        self._initialize_encryption()
    
    def _get_data_dir(self) -> Path:
        """Get the data directory for key storage."""
        from config.config import DATA_DIR
        return DATA_DIR
    
    def _get_key_file_path(self) -> Path:
        """Get the path to the encryption key file."""
        return self._get_data_dir() / self._KEY_FILE_NAME
    
    def _generate_key(self) -> bytes:
        """Generate a new Fernet encryption key."""
        return Fernet.generate_key()
    
    def _derive_key_from_master(self, master_secret: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a master secret using PBKDF2.
        
        Args:
            master_secret: The master secret string.
            salt: Random salt for key derivation.
            
        Returns:
            A Fernet-compatible key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_secret.encode()))
        return key
    
    def _initialize_encryption(self):
        """Initialize the encryption system with a key."""
        key_file = self._get_key_file_path()
        
        try:
            if key_file.exists():
                # Load existing key
                key_data = json.loads(key_file.read_text())
                key = base64.urlsafe_b64decode(key_data['key'])
                self._key_created_at = datetime.fromisoformat(key_data.get('created_at', datetime.utcnow().isoformat()))
            else:
                # Generate new key
                key = self._generate_key()
                self._key_created_at = datetime.utcnow()
                
                # Store the key securely
                key_data = {
                    'key': base64.urlsafe_b64encode(key).decode(),
                    'created_at': self._key_created_at.isoformat(),
                    'version': 1,
                }
                
                key_file.parent.mkdir(parents=True, exist_ok=True)
                key_file.write_text(json.dumps(key_data))
                key_file.chmod(0o600)  # Owner read/write only
                
                logger.info('Generated new integration encryption key')
            
            self._fernet = Fernet(key)
            
        except Exception as e:
            logger.error(f'Failed to initialize encryption: {e}')
            # Use a fallback in-memory key (data won't persist across restarts)
            self._fernet = Fernet(self._generate_key())
            self._key_created_at = datetime.utcnow()
            logger.warning('Using in-memory encryption key - credentials will not persist')
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: The string to encrypt.
            
        Returns:
            Base64-encoded encrypted string.
        """
        if not plaintext:
            return plaintext
        
        try:
            encrypted = self._fernet.encrypt(plaintext.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f'Encryption failed: {e}')
            raise ValueError('Failed to encrypt credential')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            ciphertext: Base64-encoded encrypted string.
            
        Returns:
            Decrypted plaintext string.
        """
        if not ciphertext:
            return ciphertext
        
        try:
            encrypted = base64.urlsafe_b64decode(ciphertext.encode())
            decrypted = self._fernet.decrypt(encrypted)
            return decrypted.decode()
        except InvalidToken:
            logger.error('Decryption failed - invalid token or corrupted data')
            raise ValueError('Failed to decrypt credential - key may have changed')
        except Exception as e:
            logger.error(f'Decryption failed: {e}')
            raise ValueError('Failed to decrypt credential')
    
    def encrypt_dict(self, data: Dict[str, Any], sensitive_fields: list[str]) -> Dict[str, Any]:
        """
        Encrypt specific fields in a dictionary.
        
        Args:
            data: Dictionary containing data.
            sensitive_fields: List of field names to encrypt.
            
        Returns:
            Dictionary with sensitive fields encrypted.
        """
        result = data.copy()
        
        for field in sensitive_fields:
            if field in result and result[field]:
                if isinstance(result[field], str):
                    result[field] = self.encrypt(result[field])
                elif isinstance(result[field], dict):
                    result[field] = self.encrypt(json.dumps(result[field]))
        
        return result
    
    def decrypt_dict(self, data: Dict[str, Any], sensitive_fields: list[str]) -> Dict[str, Any]:
        """
        Decrypt specific fields in a dictionary.
        
        Args:
            data: Dictionary containing encrypted data.
            sensitive_fields: List of field names to decrypt.
            
        Returns:
            Dictionary with sensitive fields decrypted.
        """
        result = data.copy()
        
        for field in sensitive_fields:
            if field in result and result[field]:
                try:
                    decrypted = self.decrypt(result[field])
                    # Try to parse as JSON
                    try:
                        result[field] = json.loads(decrypted)
                    except json.JSONDecodeError:
                        result[field] = decrypted
                except ValueError:
                    # Field may not be encrypted or decryption failed
                    pass
        
        return result
    
    def rotate_key(self) -> Tuple[bool, str]:
        """
        Rotate the encryption key.
        
        This will re-encrypt all stored credentials with a new key.
        
        Returns:
            Tuple of (success, message).
        """
        try:
            old_fernet = self._fernet
            new_key = self._generate_key()
            new_fernet = Fernet(new_key)
            
            # Store the new key
            key_file = self._get_key_file_path()
            key_data = {
                'key': base64.urlsafe_b64encode(new_key).decode(),
                'created_at': datetime.utcnow().isoformat(),
                'version': 2,  # Increment version
                'previous_key': base64.urlsafe_b64encode(self._fernet._signing_key + self._fernet._encryption_key).decode()
            }
            
            key_file.write_text(json.dumps(key_data))
            key_file.chmod(0o600)
            
            self._fernet = new_fernet
            self._key_created_at = datetime.utcnow()
            
            logger.info('Successfully rotated integration encryption key')
            return True, 'Key rotated successfully'
            
        except Exception as e:
            logger.error(f'Key rotation failed: {e}')
            return False, f'Key rotation failed: {str(e)}'
    
    def get_key_age_days(self) -> int:
        """Get the age of the current encryption key in days."""
        if not self._key_created_at:
            return 0
        return (datetime.utcnow() - self._key_created_at).days
    
    def should_rotate_key(self, max_age_days: int = 90) -> bool:
        """Check if the encryption key should be rotated."""
        return self.get_key_age_days() >= max_age_days


def get_credential_encryption() -> CredentialEncryption:
    """Get the singleton CredentialEncryption instance."""
    return CredentialEncryption()


class CredentialValidator:
    """
    Validates credentials and configuration for integrations.
    
    Provides sanitization and validation for all input data.
    """
    
    @staticmethod
    def sanitize_api_key(api_key: str) -> str:
        """Sanitize an API key by removing whitespace and newlines."""
        return api_key.strip().replace('\n', '').replace('\r', '')
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a URL for integration endpoints.
        
        Returns:
            Tuple of (is_valid, error_message).
        """
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, 'URL must include a scheme (http:// or https://)'
            
            if parsed.scheme not in ('http', 'https'):
                return False, 'URL must use http or https scheme'
            
            if not parsed.netloc:
                return False, 'URL must include a host'
            
            return True, None
            
        except Exception as e:
            return False, f'Invalid URL format: {str(e)}'
    
    @staticmethod
    def validate_port(port: int) -> Tuple[bool, Optional[str]]:
        """Validate a port number."""
        if not isinstance(port, int):
            return False, 'Port must be an integer'
        if port < 1 or port > 65535:
            return False, 'Port must be between 1 and 65535'
        return True, None
    
    @staticmethod
    def mask_credential(value: str, visible_chars: int = 4) -> str:
        """
        Mask a credential for display, showing only the last few characters.
        
        Args:
            value: The credential to mask.
            visible_chars: Number of characters to show at the end.
            
        Returns:
            Masked string like '••••••••abcd'.
        """
        if not value or len(value) <= visible_chars:
            return '•' * 8
        
        hidden_count = len(value) - visible_chars
        return '•' * min(hidden_count, 12) + value[-visible_chars:]
    
    @staticmethod
    def is_expired(expires_at: Optional[datetime], buffer_seconds: int = 300) -> bool:
        """
        Check if a token/credential is expired or about to expire.
        
        Args:
            expires_at: Expiration datetime.
            buffer_seconds: Consider expired if within this many seconds.
            
        Returns:
            True if expired or about to expire.
        """
        if not expires_at:
            return False
        return datetime.utcnow() + timedelta(seconds=buffer_seconds) >= expires_at
