"""
Utility modules for Continuum

Contains authentication helpers, decorators, rate limiting, and API token utilities.
"""

from app.utils.auth import (
    role_required,
    hash_password,
    verify_password,
    validate_password_strength,
    authenticate_user,
    create_initial_admin,
    login_manager,
)

from app.utils.rate_limiting import (
    get_ip_for_ratelimit,
    handle_rate_limit_exceeded,
    RATE_LIMITS,
)

from app.utils.api_tokens import (
    APIToken,
    get_available_permissions,
    validate_permissions,
)


__all__ = [
    # Auth utilities
    'role_required',
    'hash_password',
    'verify_password',
    'validate_password_strength',
    'authenticate_user',
    'create_initial_admin',
    'login_manager',
    # Rate limiting
    'get_ip_for_ratelimit',
    'handle_rate_limit_exceeded',
    'RATE_LIMITS',
    # API tokens
    'APIToken',
    'get_available_permissions',
    'validate_permissions',
]
