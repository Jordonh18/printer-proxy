"""
Settings management for Printer Proxy

Stores application settings in the database with JSON serialization.
Settings are persisted across updates.
"""
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from app.models import get_db_connection

logger = logging.getLogger(__name__)

# Default settings structure
DEFAULT_SETTINGS = {
    'notifications': {
        'smtp': {
            'enabled': False,
            'host': '',
            'port': 587,
            'username': '',
            'password': '',
            'from_address': '',
            'to_addresses': '',
            'use_tls': True,
            'use_ssl': False,
        },
        'teams': {
            'enabled': False,
            'webhook_url': '',
        },
        'slack': {
            'enabled': False,
            'webhook_url': '',
        },
        'discord': {
            'enabled': False,
            'webhook_url': '',
        },
    },
    # Future settings categories can be added here
    # 'general': {
    #     'site_name': 'Printer Proxy',
    #     'timezone': 'UTC',
    # },
}


def init_settings_table():
    """Initialize the settings table in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()


class SettingsManager:
    """
    Manages application settings with database persistence.
    
    Settings are stored as JSON in the database and cached in memory.
    Changes are immediately persisted to the database.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._cache: Dict[str, Any] = {}
        self._ensure_table()
        self._load_settings()
    
    def _ensure_table(self):
        """Ensure the settings table exists."""
        try:
            init_settings_table()
        except Exception as e:
            logger.error(f"Failed to initialize settings table: {e}")
    
    def _load_settings(self):
        """Load all settings from the database."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            rows = cursor.fetchall()
            conn.close()
            
            # Start with defaults
            self._cache = json.loads(json.dumps(DEFAULT_SETTINGS))
            
            # Overlay with stored values
            for row in rows:
                key = row['key']
                try:
                    value = json.loads(row['value'])
                    self._set_nested(self._cache, key, value)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON for setting {key}")
            
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            self._cache = json.loads(json.dumps(DEFAULT_SETTINGS))
    
    def _set_nested(self, data: dict, key: str, value: Any):
        """Set a nested value using dot notation key."""
        keys = key.split('.')
        current = data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    
    def _get_nested(self, data: dict, key: str, default: Any = None) -> Any:
        """Get a nested value using dot notation key."""
        keys = key.split('.')
        current = data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value by key (supports dot notation).
        
        Args:
            key: Setting key (e.g., 'notifications.smtp.host')
            default: Default value if key doesn't exist
            
        Returns:
            The setting value or default
        """
        return self._get_nested(self._cache, key, default)
    
    def get_all(self) -> Dict[str, Any]:
        """Get all settings."""
        return json.loads(json.dumps(self._cache))
    
    def set(self, key: str, value: Any) -> bool:
        """
        Set a setting value by key (supports dot notation).
        
        Args:
            key: Setting key (e.g., 'notifications.smtp.host')
            value: Value to set
            
        Returns:
            True on success, False on failure
        """
        try:
            # Update cache
            self._set_nested(self._cache, key, value)
            
            # Persist to database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, json.dumps(value), datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            logger.info(f"Setting updated: {key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save setting {key}: {e}")
            return False
    
    def set_many(self, settings: Dict[str, Any]) -> bool:
        """
        Set multiple settings at once.
        
        Args:
            settings: Dict of key-value pairs
            
        Returns:
            True if all succeeded, False if any failed
        """
        success = True
        for key, value in settings.items():
            if not self.set(key, value):
                success = False
        return success
    
    def update_section(self, section: str, values: Dict[str, Any]) -> bool:
        """
        Update all values in a settings section.
        
        Args:
            section: Section name (e.g., 'notifications.smtp')
            values: Dict of values to update
            
        Returns:
            True on success, False on failure
        """
        try:
            for key, value in values.items():
                full_key = f"{section}.{key}"
                self.set(full_key, value)
            return True
        except Exception as e:
            logger.error(f"Failed to update section {section}: {e}")
            return False
    
    def reset_to_defaults(self, section: Optional[str] = None) -> bool:
        """
        Reset settings to defaults.
        
        Args:
            section: Optional section to reset (resets all if None)
            
        Returns:
            True on success
        """
        try:
            if section:
                # Reset specific section
                default_value = self._get_nested(DEFAULT_SETTINGS, section)
                if default_value is not None:
                    self.set(section, default_value)
            else:
                # Reset all settings
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM settings")
                conn.commit()
                conn.close()
                self._cache = json.loads(json.dumps(DEFAULT_SETTINGS))
            
            return True
        except Exception as e:
            logger.error(f"Failed to reset settings: {e}")
            return False
    
    def reload(self):
        """Reload settings from database."""
        self._load_settings()


# Singleton instance
_settings_manager: Optional[SettingsManager] = None


def get_settings_manager() -> SettingsManager:
    """Get the singleton settings manager instance."""
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager
