"""
API Token management for programmatic access
"""
import secrets
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from app.models import get_db_connection


# Permission scopes by role
PERMISSION_SCOPES = {
    'viewer': [
        'printers:read',
        'redirects:read',
        'stats:read',
    ],
    'operator': [
        'printers:read',
        'printers:write',
        'redirects:read',
        'redirects:write',
        'stats:read',
    ],
    'admin': [
        'printers:read',
        'printers:write',
        'redirects:read',
        'redirects:write',
        'users:read',
        'users:write',
        'settings:read',
        'settings:write',
        'stats:read',
        'audit:read',
    ],
}


def get_available_permissions(user_role: str) -> List[str]:
    """Get list of permissions available to a user based on their role."""
    return PERMISSION_SCOPES.get(user_role, [])


def validate_permissions(user_role: str, requested_permissions: List[str]) -> bool:
    """Validate that requested permissions are available to the user's role."""
    available = set(get_available_permissions(user_role))
    requested = set(requested_permissions)
    return requested.issubset(available)


@dataclass
class APIToken:
    """API Token model."""
    id: int
    user_id: int
    name: str
    token_hash: str
    permissions: List[str]
    created_at: str
    last_used_at: Optional[str] = None
    expires_at: Optional[str] = None
    
    def to_dict(self, include_token: bool = False, token_value: Optional[str] = None) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'permissions': self.permissions,
            'created_at': self.created_at,
            'last_used_at': self.last_used_at,
            'expires_at': self.expires_at,
        }
        if include_token and token_value:
            data['token'] = token_value
        return data
    
    @staticmethod
    def generate_token() -> tuple[str, str]:
        """Generate a new token and its hash.
        
        Returns:
            tuple: (plain_token, token_hash)
        """
        # Generate 32-byte (64 hex chars) random token
        plain_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
        return plain_token, token_hash
    
    @staticmethod
    def create(user_id: int, name: str, permissions: List[str], 
               expires_at: Optional[str] = None) -> tuple['APIToken', str]:
        """Create a new API token.
        
        Returns:
            tuple: (APIToken instance, plain_token)
        """
        plain_token, token_hash = APIToken.generate_token()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO api_tokens 
               (user_id, name, token_hash, permissions, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, name, token_hash, json.dumps(permissions), expires_at)
        )
        conn.commit()
        token_id = cursor.lastrowid
        
        # Fetch the created token
        cursor.execute(
            "SELECT * FROM api_tokens WHERE id = ?",
            (token_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        token = APIToken(
            id=row['id'],
            user_id=row['user_id'],
            name=row['name'],
            token_hash=row['token_hash'],
            permissions=json.loads(row['permissions']),
            created_at=row['created_at'],
            last_used_at=row['last_used_at'],
            expires_at=row['expires_at']
        )
        
        return token, plain_token
    
    @staticmethod
    def get_by_hash(token_hash: str) -> Optional['APIToken']:
        """Get token by hash."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM api_tokens WHERE token_hash = ?",
            (token_hash,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return APIToken(
                id=row['id'],
                user_id=row['user_id'],
                name=row['name'],
                token_hash=row['token_hash'],
                permissions=json.loads(row['permissions']),
                created_at=row['created_at'],
                last_used_at=row['last_used_at'],
                expires_at=row['expires_at']
            )
        return None
    
    @staticmethod
    def get_by_user(user_id: int) -> List['APIToken']:
        """Get all tokens for a user."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [
            APIToken(
                id=row['id'],
                user_id=row['user_id'],
                name=row['name'],
                token_hash=row['token_hash'],
                permissions=json.loads(row['permissions']),
                created_at=row['created_at'],
                last_used_at=row['last_used_at'],
                expires_at=row['expires_at']
            )
            for row in rows
        ]
    
    @staticmethod
    def update_last_used(token_id: int):
        """Update the last_used_at timestamp."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (token_id,)
        )
        conn.commit()
        conn.close()
    
    @staticmethod
    def delete(token_id: int, user_id: int) -> bool:
        """Delete a token. Returns True if deleted."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM api_tokens WHERE id = ? AND user_id = ?",
            (token_id, user_id)
        )
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()
        return deleted
    
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        
        try:
            expires = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            return datetime.utcnow() > expires
        except:
            return False
    
    def has_permission(self, required_permission: str) -> bool:
        """Check if token has a specific permission."""
        return required_permission in self.permissions
