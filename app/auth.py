"""
Authentication utilities
"""
import re
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Tuple

from functools import wraps
from flask import abort, jsonify, request
from flask_login import LoginManager, current_user

from config.config import (
    MIN_PASSWORD_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_SPECIAL,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES
)
from app.models import User, AuditLog


login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = None  # Disable the "Please log in" flash message
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load user by ID for Flask-Login."""
    try:
        return User.get_by_id(int(user_id))
    except (ValueError, TypeError):
        return None


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    
    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""


def authenticate_user(username: str, password: str, client_ip: str = None) -> Tuple[Optional[User], str]:
    """
    Authenticate a user.
    Returns (user, error_message).
    """
    user = User.get_by_username(username)
    
    if user is None:
        AuditLog.log(
            username=username,
            action="LOGIN_FAILED",
            details=f"Unknown username from {client_ip}",
            success=False,
            error_message="Invalid credentials"
        )
        return None, "Invalid username or password"
    
    # Check if account is locked
    if user.is_locked():
        AuditLog.log(
            username=username,
            action="LOGIN_BLOCKED",
            details=f"Account locked, attempt from {client_ip}",
            success=False,
            error_message="Account locked"
        )
        return None, "Account is temporarily locked. Please try again later."
    
    # Check if account is active
    if not user.is_active:
        AuditLog.log(
            username=username,
            action="LOGIN_FAILED",
            details=f"Inactive account from {client_ip}",
            success=False,
            error_message="Account inactive"
        )
        return None, "Account is disabled"
    
    # Verify password
    if not verify_password(password, user.password_hash):
        user.increment_failed_attempts()
        
        # Check if we should lock the account
        updated_user = User.get_by_id(user.id)
        if updated_user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
            lockout_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            updated_user.lock_account(lockout_until)
            AuditLog.log(
                username=username,
                action="ACCOUNT_LOCKED",
                details=f"Too many failed attempts from {client_ip}",
                success=False,
                error_message=f"Locked until {lockout_until}"
            )
            return None, f"Account locked due to too many failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        
        AuditLog.log(
            username=username,
            action="LOGIN_FAILED",
            details=f"Invalid password from {client_ip}",
            success=False,
            error_message="Invalid credentials"
        )
        return None, "Invalid username or password"
    
    # Success!
    user.update_last_login()
    AuditLog.log(
        username=username,
        action="LOGIN_SUCCESS",
        details=f"Login from {client_ip}",
        success=True
    )
    
    return user, ""


def create_initial_admin(username: str, password: str) -> Tuple[bool, str]:
    """Create the initial admin user if none exists."""
    # Check if any users exist
    existing = User.get_by_username(username)
    if existing:
        return False, "User already exists"
    
    # Validate password
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return False, error
    
    # Create user
    password_hash = hash_password(password)
    User.create(username, password_hash, role='admin')
    
    AuditLog.log(
        username="SYSTEM",
        action="USER_CREATED",
        details=f"Initial admin user '{username}' created",
        success=True
    )
    
    return True, "Admin user created successfully"


def role_required(*roles):
    """Require the current user to have one of the specified roles."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_role = getattr(current_user, 'role', None)
            if user_role not in roles:
                if request.path.startswith('/api'):
                    return jsonify({'error': 'Forbidden'}), 403
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator
