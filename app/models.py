"""
Database models for Printer Proxy
"""
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import json

from config.config import DATABASE_PATH, DATA_DIR


def get_db_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            mfa_secret TEXT,
            mfa_enabled BOOLEAN DEFAULT 0,
            mfa_recovery_codes TEXT,
            theme TEXT DEFAULT 'system',
            language TEXT DEFAULT 'en',
            timezone TEXT DEFAULT 'UTC'
        )
    """)

    # Ensure role column exists for older installs
    cursor.execute("PRAGMA table_info(users)")
    user_columns = {row['name'] for row in cursor.fetchall()}
    if 'role' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'")
        cursor.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = ''")
    if 'email' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if 'full_name' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
    if 'mfa_secret' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    if 'mfa_enabled' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0")
    if 'mfa_recovery_codes' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT")
    if 'theme' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'system'")
    if 'language' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")
    if 'timezone' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC'")
    if 'notification_preferences' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN notification_preferences TEXT")
        # Set default preferences for existing users
        default_prefs = json.dumps({
            'health_alerts': True,
            'offline_alerts': True,
            'job_failures': True,
            'security_events': True,
            'weekly_reports': False
        })
        cursor.execute("UPDATE users SET notification_preferences = ? WHERE notification_preferences IS NULL", (default_prefs,))
    
    # Active redirects table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_redirects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_printer_id TEXT UNIQUE NOT NULL,
            source_ip TEXT NOT NULL,
            target_printer_id TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            protocol TEXT DEFAULT 'raw',
            port INTEGER DEFAULT 9100,
            enabled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            enabled_by TEXT NOT NULL
        )
    """)
    
    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            source_printer_id TEXT,
            source_ip TEXT,
            target_printer_id TEXT,
            target_ip TEXT,
            details TEXT,
            success BOOLEAN,
            error_message TEXT
        )
    """)
    
    # Login attempts table for rate limiting
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN
        )
    """)
    
    # Printers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            ip TEXT UNIQUE NOT NULL,
            protocols TEXT DEFAULT 'raw',
            location TEXT DEFAULT '',
            model TEXT DEFAULT '',
            department TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Redirect history table for statistics
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS redirect_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_printer_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            target_printer_id TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            enabled_at TIMESTAMP NOT NULL,
            enabled_by TEXT NOT NULL,
            disabled_at TIMESTAMP,
            disabled_by TEXT,
            duration_seconds INTEGER,
            reason TEXT
        )
    """)
    
    # Create index for redirect history queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_redirect_history_source 
        ON redirect_history(source_printer_id, enabled_at DESC)
    """)
    
    # Print job history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS print_job_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            printer_id TEXT NOT NULL,
            job_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            owner TEXT DEFAULT '',
            status TEXT DEFAULT 'Unknown',
            pages INTEGER DEFAULT 0,
            size_bytes INTEGER DEFAULT 0,
            submitted_at TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (printer_id) REFERENCES printers(id)
        )
    """)
    
    # Create index for job history queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_job_history_printer 
        ON print_job_history(printer_id, recorded_at DESC)
    """)
    
    # Printer error log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_error_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            printer_id TEXT NOT NULL,
            code INTEGER NOT NULL,
            severity TEXT DEFAULT 'warning',
            message TEXT NOT NULL,
            description TEXT DEFAULT '',
            occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            FOREIGN KEY (printer_id) REFERENCES printers(id)
        )
    """)
    
    # Create index for error log queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_error_log_printer 
        ON printer_error_log(printer_id, occurred_at DESC)
    """)
    
    # Settings table for application configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # User sessions table for JWT tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            jti TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # API tokens table for programmatic access
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            permissions TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Add index for token lookup
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_api_tokens_hash 
        ON api_tokens(token_hash)
    """)
    
    # Notifications table for storing all user notifications
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            link TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Add indexes for notification queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_user_created 
        ON notifications(user_id, created_at DESC)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_user_unread 
        ON notifications(user_id, is_read, created_at DESC)
    """)
    
    conn.commit()
    conn.close()


class User:
    """User model for authentication."""
    
    def __init__(self, id: int, username: str, password_hash: str, role: str = 'admin',
                 email: Optional[str] = None,
                 full_name: Optional[str] = None,
                 is_active: bool = True, last_login: Optional[datetime] = None,
                 failed_attempts: int = 0, locked_until: Optional[datetime] = None,
                 created_at: Optional[datetime] = None,
                 mfa_secret: Optional[str] = None,
                 mfa_enabled: bool = False,
                 mfa_recovery_codes: Optional[str] = None,
                 theme: str = 'system',
                 language: str = 'en',
                 timezone: str = 'UTC'):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.password_hash = password_hash
        self.role = role or 'admin'
        self.is_active = is_active
        self.last_login = last_login
        self.failed_attempts = failed_attempts
        self.locked_until = locked_until
        self.created_at = created_at
        self.mfa_secret = mfa_secret
        self.mfa_enabled = bool(mfa_enabled)
        self.mfa_recovery_codes = mfa_recovery_codes
        self.theme = theme or 'system'
        self.language = language or 'en'
        self.timezone = timezone or 'utc'
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)

    @property
    def is_admin(self) -> bool:
        return self.role == 'admin'

    @property
    def is_operator(self) -> bool:
        return self.role == 'operator'

    @property
    def is_viewer(self) -> bool:
        return self.role == 'viewer'
    
    @staticmethod
    def get_by_id(user_id: int) -> Optional['User']:
        """Get user by ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row['id'],
                username=row['username'],
                full_name=row['full_name'] if 'full_name' in row.keys() else None,
                email=row['email'] if 'email' in row.keys() else None,
                password_hash=row['password_hash'],
                role=row['role'] if 'role' in row.keys() else 'admin',
                is_active=bool(row['is_active']),
                last_login=row['last_login'],
                failed_attempts=row['failed_attempts'],
                locked_until=row['locked_until'],
                created_at=row['created_at'] if 'created_at' in row.keys() else None,
                mfa_secret=row['mfa_secret'] if 'mfa_secret' in row.keys() else None,
                mfa_enabled=bool(row['mfa_enabled']) if 'mfa_enabled' in row.keys() else False,
                mfa_recovery_codes=row['mfa_recovery_codes'] if 'mfa_recovery_codes' in row.keys() else None,
                theme=row['theme'] if 'theme' in row.keys() else 'system',
                language=row['language'] if 'language' in row.keys() else 'en',
                timezone=row['timezone'] if 'timezone' in row.keys() else 'utc'
            )
        return None
    
    @staticmethod
    def get_by_username(username: str) -> Optional['User']:
        """Get user by username."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row['id'],
                username=row['username'],
                full_name=row['full_name'] if 'full_name' in row.keys() else None,
                email=row['email'] if 'email' in row.keys() else None,
                password_hash=row['password_hash'],
                role=row['role'] if 'role' in row.keys() else 'admin',
                is_active=bool(row['is_active']),
                last_login=row['last_login'],
                failed_attempts=row['failed_attempts'],
                locked_until=row['locked_until'],
                created_at=row['created_at'] if 'created_at' in row.keys() else None,
                mfa_secret=row['mfa_secret'] if 'mfa_secret' in row.keys() else None,
                mfa_enabled=bool(row['mfa_enabled']) if 'mfa_enabled' in row.keys() else False,
                mfa_recovery_codes=row['mfa_recovery_codes'] if 'mfa_recovery_codes' in row.keys() else None,
                theme=row['theme'] if 'theme' in row.keys() else 'system',
                language=row['language'] if 'language' in row.keys() else 'en',
                timezone=row['timezone'] if 'timezone' in row.keys() else 'utc'
            )
        return None
    
    @staticmethod
    def create(username: str, password_hash: str, role: str = 'admin', is_active: bool = True,
               email: Optional[str] = None, full_name: Optional[str] = None,
               theme: str = 'system', language: str = 'en',
               timezone: str = 'UTC') -> 'User':
        """Create a new user."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, full_name, email, password_hash, role, is_active, theme, language, timezone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, full_name, email, password_hash, role, int(is_active), theme, language, timezone)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return User(
            id=user_id,
            username=username,
            full_name=full_name,
            email=email,
            password_hash=password_hash,
            role=role,
            is_active=is_active,
            theme=theme,
            language=language,
            timezone=timezone
        )

    @staticmethod
    def get_all() -> List['User']:
        """Get all users."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY username ASC")
        rows = cursor.fetchall()
        conn.close()

        return [User(
            id=row['id'],
            username=row['username'],
            full_name=row['full_name'] if 'full_name' in row.keys() else None,
            email=row['email'] if 'email' in row.keys() else None,
            password_hash=row['password_hash'],
            role=row['role'] if 'role' in row.keys() else 'admin',
            is_active=bool(row['is_active']),
            last_login=row['last_login'],
            failed_attempts=row['failed_attempts'],
            locked_until=row['locked_until'],
            created_at=row['created_at'] if 'created_at' in row.keys() else None,
            mfa_secret=row['mfa_secret'] if 'mfa_secret' in row.keys() else None,
            mfa_enabled=bool(row['mfa_enabled']) if 'mfa_enabled' in row.keys() else False,
            mfa_recovery_codes=row['mfa_recovery_codes'] if 'mfa_recovery_codes' in row.keys() else None,
            theme=row['theme'] if 'theme' in row.keys() else 'system',
            language=row['language'] if 'language' in row.keys() else 'en',
            timezone=row['timezone'] if 'timezone' in row.keys() else 'utc'
        ) for row in rows]

    @staticmethod
    def get_by_email(email: str) -> Optional['User']:
        """Get user by email."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(
                id=row['id'],
                username=row['username'],
                full_name=row['full_name'] if 'full_name' in row.keys() else None,
                email=row['email'] if 'email' in row.keys() else None,
                password_hash=row['password_hash'],
                role=row['role'] if 'role' in row.keys() else 'admin',
                is_active=bool(row['is_active']),
                last_login=row['last_login'],
                failed_attempts=row['failed_attempts'],
                locked_until=row['locked_until'],
                created_at=row['created_at'] if 'created_at' in row.keys() else None,
                mfa_secret=row['mfa_secret'] if 'mfa_secret' in row.keys() else None,
                mfa_enabled=bool(row['mfa_enabled']) if 'mfa_enabled' in row.keys() else False,
                mfa_recovery_codes=row['mfa_recovery_codes'] if 'mfa_recovery_codes' in row.keys() else None,
                theme=row['theme'] if 'theme' in row.keys() else 'system',
                language=row['language'] if 'language' in row.keys() else 'en',
                timezone=row['timezone'] if 'timezone' in row.keys() else 'utc'
            )
        return None

    def update_role(self, role: str):
        """Update user's role."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, self.id)
        )
        conn.commit()
        conn.close()
        self.role = role

    def set_active(self, is_active: bool):
        """Enable or disable user account."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (int(is_active), self.id)
        )
        conn.commit()
        conn.close()
        self.is_active = is_active
    
    def update_last_login(self):
        """Update last login timestamp."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = ?, failed_attempts = 0 WHERE id = ?",
            (datetime.now().isoformat(), self.id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def delete_by_id(user_id: int) -> bool:
        """Delete a user by ID."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return deleted > 0
        except Exception:
            return False
    
    def increment_failed_attempts(self):
        """Increment failed login attempts."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (self.id,)
        )
        conn.commit()
        conn.close()
    
    def lock_account(self, until: datetime):
        """Lock account until specified time."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET locked_until = ? WHERE id = ?",
            (until.isoformat(), self.id)
        )
        conn.commit()
        conn.close()
    
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        if isinstance(self.locked_until, str):
            locked_until = datetime.fromisoformat(self.locked_until)
        else:
            locked_until = self.locked_until
        return datetime.now() < locked_until
    
    def update_password(self, new_password_hash: str):
        """Update user's password."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, self.id)
        )
        conn.commit()
        conn.close()
        self.password_hash = new_password_hash

    def update_profile(self, username: str, email: Optional[str], full_name: Optional[str] = None):
        """Update user's profile info."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET username = ?, email = ?, full_name = ? WHERE id = ?",
            (username, email, full_name, self.id)
        )
        conn.commit()
        conn.close()
        self.username = username
        self.email = email
        self.full_name = full_name

    def update_preferences(self, theme: str, language: str, timezone: str):
        """Update user's preference settings."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET theme = ?, language = ?, timezone = ? WHERE id = ?",
            (theme, language, timezone, self.id)
        )
        conn.commit()
        conn.close()
        self.theme = theme
        self.language = language
        self.timezone = timezone

    def set_mfa_secret(self, secret: Optional[str]):
        """Set MFA secret."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET mfa_secret = ? WHERE id = ?",
            (secret, self.id)
        )
        conn.commit()
        conn.close()
        self.mfa_secret = secret

    def set_mfa_enabled(self, enabled: bool):
        """Enable/disable MFA."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET mfa_enabled = ? WHERE id = ?",
            (int(enabled), self.id)
        )
        conn.commit()
        conn.close()
        self.mfa_enabled = enabled

    def set_recovery_codes(self, codes_json: Optional[str]):
        """Store hashed recovery codes JSON."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET mfa_recovery_codes = ? WHERE id = ?",
            (codes_json, self.id)
        )
        conn.commit()
        conn.close()
        self.mfa_recovery_codes = codes_json


class ActiveRedirect:
    """Model for active printer redirects."""
    
    def __init__(self, id: int, source_printer_id: str, source_ip: str,
                 target_printer_id: str, target_ip: str, protocol: str,
                 port: int, enabled_at: datetime, enabled_by: str):
        self.id = id
        self.source_printer_id = source_printer_id
        self.source_ip = source_ip
        self.target_printer_id = target_printer_id
        self.target_ip = target_ip
        self.protocol = protocol
        self.port = port
        self.enabled_at = enabled_at
        self.enabled_by = enabled_by
    
    @staticmethod
    def get_all() -> List['ActiveRedirect']:
        """Get all active redirects."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_redirects ORDER BY enabled_at DESC")
        rows = cursor.fetchall()
        conn.close()
        
        return [ActiveRedirect(
            id=row['id'],
            source_printer_id=row['source_printer_id'],
            source_ip=row['source_ip'],
            target_printer_id=row['target_printer_id'],
            target_ip=row['target_ip'],
            protocol=row['protocol'],
            port=row['port'],
            enabled_at=row['enabled_at'],
            enabled_by=row['enabled_by']
        ) for row in rows]

    @staticmethod
    def get_by_source_printer(printer_id: str) -> Optional['ActiveRedirect']:
        """Get redirect by source printer ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM active_redirects WHERE source_printer_id = ?",
            (printer_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return ActiveRedirect(
                id=row['id'],
                source_printer_id=row['source_printer_id'],
                source_ip=row['source_ip'],
                target_printer_id=row['target_printer_id'],
                target_ip=row['target_ip'],
                protocol=row['protocol'],
                port=row['port'],
                enabled_at=row['enabled_at'],
                enabled_by=row['enabled_by']
            )
        return None

    @staticmethod
    def get_by_source_ip(ip: str) -> Optional['ActiveRedirect']:
        """Get redirect by source IP."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_redirects WHERE source_ip = ?", (ip,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return ActiveRedirect(
                id=row['id'],
                source_printer_id=row['source_printer_id'],
                source_ip=row['source_ip'],
                target_printer_id=row['target_printer_id'],
                target_ip=row['target_ip'],
                protocol=row['protocol'],
                port=row['port'],
                enabled_at=row['enabled_at'],
                enabled_by=row['enabled_by']
            )
        return None

    @staticmethod
    def is_target_in_use(printer_id: str) -> bool:
        """Check if a printer is already being used as a target."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM active_redirects WHERE target_printer_id = ?",
            (printer_id,)
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    @staticmethod
    def create(source_printer_id: str, source_ip: str, target_printer_id: str,
               target_ip: str, protocol: str, port: int, enabled_by: str) -> 'ActiveRedirect':
        """Create a new redirect."""
        conn = get_db_connection()
        cursor = conn.cursor()
        enabled_at = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO active_redirects 
            (source_printer_id, source_ip, target_printer_id, target_ip, 
             protocol, port, enabled_by, enabled_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (source_printer_id, source_ip, target_printer_id, target_ip,
              protocol, port, enabled_by, enabled_at))
        conn.commit()
        redirect_id = cursor.lastrowid
        conn.close()

        return ActiveRedirect(
            id=redirect_id,
            source_printer_id=source_printer_id,
            source_ip=source_ip,
            target_printer_id=target_printer_id,
            target_ip=target_ip,
            protocol=protocol,
            port=port,
            enabled_at=enabled_at,
            enabled_by=enabled_by
        )

    def delete(self, disabled_by: str = None, reason: str = None):
        """Delete this redirect and record in history."""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Calculate duration
        if isinstance(self.enabled_at, str):
            enabled_dt = datetime.fromisoformat(self.enabled_at)
        else:
            enabled_dt = self.enabled_at
        duration = int((datetime.now() - enabled_dt).total_seconds())

        # Record in history
        cursor.execute("""
            INSERT INTO redirect_history 
            (source_printer_id, source_ip, target_printer_id, target_ip,
             enabled_at, enabled_by, disabled_at, disabled_by, duration_seconds, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.source_printer_id, self.source_ip,
            self.target_printer_id, self.target_ip,
            self.enabled_at, self.enabled_by,
            datetime.now().isoformat(), disabled_by or 'system',
            duration, reason
        ))

        # Delete active redirect
        cursor.execute("DELETE FROM active_redirects WHERE id = ?", (self.id,))
        conn.commit()
        conn.close()


class UserSession:
    """Model for JWT sessions."""

    def __init__(self, id: int, user_id: int, jti: str, created_at: str,
                 last_used: str, revoked_at: Optional[str], ip_address: Optional[str],
                 user_agent: Optional[str]):
        self.id = id
        self.user_id = user_id
        self.jti = jti
        self.created_at = created_at
        self.last_used = last_used
        self.revoked_at = revoked_at
        self.ip_address = ip_address
        self.user_agent = user_agent

    @staticmethod
    def create(user_id: int, jti: str, ip_address: Optional[str], user_agent: Optional[str]) -> 'UserSession':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO user_sessions (user_id, jti, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, jti, ip_address, user_agent)
        )
        conn.commit()
        session_id = cursor.lastrowid
        cursor.execute("SELECT * FROM user_sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        conn.close()
        return UserSession(
            id=row['id'],
            user_id=row['user_id'],
            jti=row['jti'],
            created_at=row['created_at'],
            last_used=row['last_used'],
            revoked_at=row['revoked_at'],
            ip_address=row['ip_address'],
            user_agent=row['user_agent']
        )

    @staticmethod
    def get_by_jti(jti: str) -> Optional['UserSession']:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_sessions WHERE jti = ?", (jti,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return UserSession(
                id=row['id'],
                user_id=row['user_id'],
                jti=row['jti'],
                created_at=row['created_at'],
                last_used=row['last_used'],
                revoked_at=row['revoked_at'],
                ip_address=row['ip_address'],
                user_agent=row['user_agent']
            )
        return None

    @staticmethod
    def get_by_user(user_id: int) -> List['UserSession']:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_used DESC",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [UserSession(
            id=row['id'],
            user_id=row['user_id'],
            jti=row['jti'],
            created_at=row['created_at'],
            last_used=row['last_used'],
            revoked_at=row['revoked_at'],
            ip_address=row['ip_address'],
            user_agent=row['user_agent']
        ) for row in rows]

    @staticmethod
    def revoke(session_id: int):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET revoked_at = ? WHERE id = ?",
            (datetime.now().isoformat(), session_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def revoke_by_jti(jti: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET revoked_at = ? WHERE jti = ?",
            (datetime.now().isoformat(), jti)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def touch(jti: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET last_used = ? WHERE jti = ?",
            (datetime.now().isoformat(), jti)
        )
        conn.commit()
        conn.close()


class AuditLog:
    """Audit logging for all actions."""
    
    @staticmethod
    def log(username: str, action: str, source_printer_id: str = None,
            source_ip: str = None, target_printer_id: str = None,
            target_ip: str = None, details: str = None,
            success: bool = True, error_message: str = None):
        """Log an action."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log 
            (username, action, source_printer_id, source_ip, 
             target_printer_id, target_ip, details, success, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, action, source_printer_id, source_ip,
              target_printer_id, target_ip, details, success, error_message))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_recent(limit: int = 100, offset: int = 0,
                   action: Optional[str] = None,
                   username: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent audit log entries with optional filtering."""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM audit_log"
        params: List[Any] = []
        filters = []

        if action:
            filters.append("action = ?")
            params.append(action)
        if username:
            filters.append("username = ?")
            params.append(username)

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_printer(printer_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audit log entries for a specific printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM audit_log 
            WHERE source_printer_id = ? OR target_printer_id = ?
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (printer_id, printer_id, limit))
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]


class RedirectHistory:
    """Model for redirect history and statistics."""
    
    @staticmethod
    def get_by_printer(printer_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get redirect history for a printer (as source or target)."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM redirect_history 
            WHERE source_printer_id = ? OR target_printer_id = ?
            ORDER BY enabled_at DESC 
            LIMIT ?
        """, (printer_id, printer_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_all(limit: int = 100) -> List[Dict[str, Any]]:
        """Get all redirect history."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM redirect_history 
            ORDER BY enabled_at DESC 
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_statistics() -> Dict[str, Any]:
        """Get overall redirect statistics."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total redirects ever
        cursor.execute("SELECT COUNT(*) FROM redirect_history")
        total_redirects = cursor.fetchone()[0]
        
        # Currently active
        cursor.execute("SELECT COUNT(*) FROM active_redirects")
        active_redirects = cursor.fetchone()[0]
        
        # Total duration (in hours)
        cursor.execute("SELECT SUM(duration_seconds) FROM redirect_history")
        total_seconds = cursor.fetchone()[0] or 0
        total_hours = round(total_seconds / 3600, 1)
        
        # Average duration
        cursor.execute("SELECT AVG(duration_seconds) FROM redirect_history")
        avg_seconds = cursor.fetchone()[0] or 0
        avg_duration = round(avg_seconds / 60, 1)  # in minutes
        
        # Most redirected printer
        cursor.execute("""
            SELECT source_printer_id, COUNT(*) as cnt 
            FROM redirect_history 
            GROUP BY source_printer_id 
            ORDER BY cnt DESC 
            LIMIT 1
        """)
        row = cursor.fetchone()
        most_redirected = row['source_printer_id'] if row else None
        
        # Redirects this month
        cursor.execute("""
            SELECT COUNT(*) FROM redirect_history 
            WHERE enabled_at >= date('now', 'start of month')
        """)
        this_month = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_redirects': total_redirects,
            'active_redirects': active_redirects,
            'total_hours': total_hours,
            'avg_duration_minutes': avg_duration,
            'most_redirected_printer': most_redirected,
            'redirects_this_month': this_month
        }


class PrintJobHistory:
    """Model for storing print job history."""
    
    def __init__(self, id: int, printer_id: str, job_id: int, name: str = "",
                 owner: str = "", status: str = "Unknown", pages: int = 0,
                 size_bytes: int = 0, submitted_at: Optional[datetime] = None,
                 started_at: Optional[datetime] = None, 
                 completed_at: Optional[datetime] = None,
                 recorded_at: Optional[datetime] = None):
        self.id = id
        self.printer_id = printer_id
        self.job_id = job_id
        self.name = name
        self.owner = owner
        self.status = status
        self.pages = pages
        self.size_bytes = size_bytes
        self.submitted_at = submitted_at
        self.started_at = started_at
        self.completed_at = completed_at
        self.recorded_at = recorded_at or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'printer_id': self.printer_id,
            'job_id': self.job_id,
            'name': self.name,
            'owner': self.owner,
            'status': self.status,
            'pages': self.pages,
            'size_bytes': self.size_bytes,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'recorded_at': self.recorded_at.isoformat() if self.recorded_at else None
        }
    
    @staticmethod
    def create(printer_id: str, job_id: int, name: str = "", owner: str = "",
               status: str = "Unknown", pages: int = 0, size_bytes: int = 0,
               submitted_at: Optional[datetime] = None,
               started_at: Optional[datetime] = None,
               completed_at: Optional[datetime] = None) -> 'PrintJobHistory':
        """Create a new job history entry."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO print_job_history 
            (printer_id, job_id, name, owner, status, pages, size_bytes,
             submitted_at, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (printer_id, job_id, name, owner, status, pages, size_bytes,
              submitted_at, started_at, completed_at))
        job_history_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return PrintJobHistory(
            id=job_history_id, printer_id=printer_id, job_id=job_id,
            name=name, owner=owner, status=status, pages=pages,
            size_bytes=size_bytes, submitted_at=submitted_at,
            started_at=started_at, completed_at=completed_at
        )
    
    @staticmethod
    def get_for_printer(printer_id: str, limit: int = 50) -> List['PrintJobHistory']:
        """Get job history for a specific printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM print_job_history 
            WHERE printer_id = ?
            ORDER BY recorded_at DESC 
            LIMIT ?
        """, (printer_id, limit))
        rows = cursor.fetchall()
        conn.close()
        
        return [PrintJobHistory(
            id=row['id'],
            printer_id=row['printer_id'],
            job_id=row['job_id'],
            name=row['name'],
            owner=row['owner'],
            status=row['status'],
            pages=row['pages'],
            size_bytes=row['size_bytes'],
            submitted_at=row['submitted_at'],
            started_at=row['started_at'],
            completed_at=row['completed_at'],
            recorded_at=row['recorded_at']
        ) for row in rows]
    
    @staticmethod
    def record_job(printer_id, job_id: int, document_name: str = "", 
                   username: str = "", status: str = "completed", 
                   pages: int = 0, copies: int = 1, size_bytes: int = 0) -> Optional['PrintJobHistory']:
        """Record a detected print job.
        
        This is a convenience method for the job monitor to record jobs.
        """
        now = datetime.now()
        return PrintJobHistory.create(
            printer_id=str(printer_id),
            job_id=job_id,
            name=document_name,
            owner=username,
            status=status.title(),  # Capitalize first letter
            pages=pages,
            size_bytes=size_bytes,
            submitted_at=now,
            started_at=now,
            completed_at=now if status == 'completed' else None
        )
    
    @staticmethod
    def get_statistics(printer_id: str) -> Dict[str, Any]:
        """Get job statistics for a printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total jobs
        cursor.execute("""
            SELECT COUNT(*) FROM print_job_history WHERE printer_id = ?
        """, (printer_id,))
        total_jobs = cursor.fetchone()[0]
        
        # Total pages
        cursor.execute("""
            SELECT SUM(pages) FROM print_job_history WHERE printer_id = ?
        """, (printer_id,))
        total_pages = cursor.fetchone()[0] or 0
        
        # Jobs today
        cursor.execute("""
            SELECT COUNT(*) FROM print_job_history 
            WHERE printer_id = ? AND date(recorded_at) = date('now')
        """, (printer_id,))
        jobs_today = cursor.fetchone()[0]
        
        # Completed jobs
        cursor.execute("""
            SELECT COUNT(*) FROM print_job_history 
            WHERE printer_id = ? AND status = 'Completed'
        """, (printer_id,))
        completed_jobs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_jobs': total_jobs,
            'total_pages': total_pages,
            'jobs_today': jobs_today,
            'completed_jobs': completed_jobs
        }


class PrinterErrorLog:
    """Model for storing printer error logs."""
    
    def __init__(self, id: int, printer_id: str, code: int, severity: str = "warning",
                 message: str = "", description: str = "",
                 occurred_at: Optional[datetime] = None,
                 resolved_at: Optional[datetime] = None):
        self.id = id
        self.printer_id = printer_id
        self.code = code
        self.severity = severity
        self.message = message
        self.description = description
        self.occurred_at = occurred_at or datetime.now()
        self.resolved_at = resolved_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'printer_id': self.printer_id,
            'code': self.code,
            'severity': self.severity,
            'message': self.message,
            'description': self.description,
            'occurred_at': self.occurred_at.isoformat() if self.occurred_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }
    
    @staticmethod
    def create(printer_id: str, code: int, severity: str = "warning",
               message: str = "", description: str = "") -> 'PrinterErrorLog':
        """Create a new error log entry."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO printer_error_log 
            (printer_id, code, severity, message, description)
            VALUES (?, ?, ?, ?, ?)
        """, (printer_id, code, severity, message, description))
        error_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return PrinterErrorLog(
            id=error_id, printer_id=printer_id, code=code,
            severity=severity, message=message, description=description
        )
    
    @staticmethod
    def resolve(error_id: int):
        """Mark an error as resolved."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE printer_error_log 
            SET resolved_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (error_id,))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_for_printer(printer_id: str, include_resolved: bool = False,
                        limit: int = 50) -> List['PrinterErrorLog']:
        """Get error log for a specific printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if include_resolved:
            cursor.execute("""
                SELECT * FROM printer_error_log 
                WHERE printer_id = ?
                ORDER BY occurred_at DESC 
                LIMIT ?
            """, (printer_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM printer_error_log 
                WHERE printer_id = ? AND resolved_at IS NULL
                ORDER BY occurred_at DESC 
                LIMIT ?
            """, (printer_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [PrinterErrorLog(
            id=row['id'],
            printer_id=row['printer_id'],
            code=row['code'],
            severity=row['severity'],
            message=row['message'],
            description=row['description'],
            occurred_at=row['occurred_at'],
            resolved_at=row['resolved_at']
        ) for row in rows]
    
    @staticmethod
    def get_active_count(printer_id: str) -> int:
        """Get count of active (unresolved) errors for a printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM printer_error_log 
            WHERE printer_id = ? AND resolved_at IS NULL
        """, (printer_id,))
        count = cursor.fetchone()[0]
        conn.close()
        return count
