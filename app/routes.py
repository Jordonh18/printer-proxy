"""
Flask API routes for React frontend
"""
from functools import wraps
from uuid import uuid4
from flask import Blueprint, request, jsonify, g, current_app
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token, jwt_required, decode_token
)
from flask_jwt_extended.exceptions import JWTExtendedException

from app.models import AuditLog, ActiveRedirect, User, UserSession, get_db_connection
from app.auth import authenticate_user, validate_password_strength, hash_password, verify_password
from app.printers import get_registry, Printer
from app.printer_stats import get_printer_stats
import time
import secrets
import json
import queue
import pyotp
import bcrypt
from app.network import get_network_manager
from app.discovery import get_discovery
from config.config import (
    DEFAULT_PORT,
    MIN_PASSWORD_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_SPECIAL,
    SUPPORTED_PROTOCOLS
)

# Import limiter for rate limiting
from app import limiter


# API Blueprint only - React handles all UI
api_bp = Blueprint('api', __name__)


def _serialize_timestamp(value):
    if not value:
        return None
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return str(value)


def _load_recovery_codes(user: User) -> list:
    if not user.mfa_recovery_codes:
        return []
    try:
        return json.loads(user.mfa_recovery_codes)
    except Exception:
        return []


def _consume_recovery_code(user: User, code: str) -> bool:
    codes = _load_recovery_codes(user)
    if not codes:
        return False
    remaining = []
    matched = False
    for hashed in codes:
        if not matched and bcrypt.checkpw(code.encode('utf-8'), hashed.encode('utf-8')):
            matched = True
            continue
        remaining.append(hashed)
    if matched:
        user.set_recovery_codes(json.dumps(remaining))
    return matched


# ============================================================================
# API Authentication Helpers
# ============================================================================

def api_auth_required(fn):
    """Decorator for API routes that require JWT or API token authentication."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Check for Bearer token first
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Check if it's an API token (shorter than JWT, no dots)
            # API tokens are ~43 chars, JWTs are much longer and have dots
            if '.' not in token:
                from app.api_tokens import APIToken
                import hashlib
                
                # Hash the token to lookup in database
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                api_token = APIToken.get_by_hash(token_hash)
                
                if api_token:
                    # Check if token is expired
                    if api_token.is_expired():
                        return jsonify({'error': 'Token expired'}), 401
                    
                    # Get the user
                    user = User.get_by_id(api_token.user_id)
                    if not user or not user.is_active:
                        return jsonify({'error': 'Invalid token'}), 401
                    
                    # Update last used timestamp
                    APIToken.update_last_used(api_token.id)
                    
                    # Set context variables
                    g.api_user = user
                    g.api_token = api_token
                    g.api_claims = {
                        'sub': user.id,
                        'role': user.role,
                        'permissions': api_token.permissions,
                        'token_type': 'api_token'
                    }
                    
                    return fn(*args, **kwargs)
        
        # Fall back to JWT authentication
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            claims = get_jwt()
            user = User.get_by_id(int(user_id)) if user_id is not None else None
            if user and user.is_active:
                jti = claims.get('jti')
                if not jti:
                    return jsonify({'error': 'Invalid token'}), 401
                session = UserSession.get_by_jti(jti)
                if not session or session.revoked_at:
                    return jsonify({'error': 'Session revoked'}), 401
                UserSession.touch(jti)
                g.api_user = user
                g.api_claims = claims
                g.api_claims['token_type'] = 'jwt'
                g.api_session = session
                return fn(*args, **kwargs)
        except JWTExtendedException as exc:
            auth_present = bool(request.headers.get('Authorization'))
            current_app.logger.warning(
                'JWT auth failed: %s (auth header present: %s)',
                str(exc),
                auth_present
            )
            status_code = getattr(exc, 'status_code', 401)
            return jsonify({'error': str(exc)}), status_code
        except Exception as exc:
            current_app.logger.warning('JWT auth error: %s', str(exc))
            return jsonify({'error': 'Authentication required'}), 401
    return wrapper


def check_api_permission(required_permission: str):
    """Check if current API token has required permission."""
    if g.api_claims.get('token_type') == 'api_token':
        token_permissions = set(g.api_claims.get('permissions', []))
        if required_permission not in token_permissions:
            return jsonify({'error': f'Token missing required permission: {required_permission}'}), 403
    return None  # Permission OK


def api_role_required(*roles):
    """Decorator to require specific roles for API routes."""
    def decorator(fn):
        @wraps(fn)
        @api_auth_required
        def wrapper(*args, **kwargs):
            user_role = g.api_claims.get('role', '')
            
            # For API tokens, check if they have the necessary permissions
            if g.api_claims.get('token_type') == 'api_token':
                # Map roles to required permissions for this endpoint
                # We'll need to check the actual permission based on the route
                token_permissions = set(g.api_claims.get('permissions', []))
                
                # Determine required permission from the request path and method
                required_perm = None
                path = request.path
                method = request.method
                
                # Map endpoints to permissions
                if '/api/printers' in path:
                    required_perm = 'printers:write' if method in ['POST', 'PUT', 'DELETE'] else 'printers:read'
                elif '/api/redirects' in path:
                    required_perm = 'redirects:write' if method in ['POST', 'PUT', 'DELETE'] else 'redirects:read'
                elif '/api/users' in path:
                    required_perm = 'users:write' if method in ['POST', 'PUT', 'DELETE'] else 'users:read'
                elif '/api/settings' in path or '/api/admin' in path:
                    required_perm = 'settings:write' if method in ['POST', 'PUT', 'DELETE'] else 'settings:read'
                elif '/api/audit-logs' in path:
                    required_perm = 'audit:read'
                elif '/api/stats' in path or '/api/dashboard' in path:
                    required_perm = 'stats:read'
                
                # Check if token has the required permission
                if required_perm and required_perm not in token_permissions:
                    return jsonify({'error': f'Token missing required permission: {required_perm}'}), 403
            
            if user_role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# JWT Authentication API Routes
# ============================================================================

@api_bp.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_auth_login():
    """Authenticate user and return JWT tokens."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email')
    full_name = data.get('full_name')
    totp_code = data.get('totp')
    recovery_code = data.get('recovery_code')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    client_ip = request.remote_addr
    user, error = authenticate_user(username, password, client_ip)
    
    if user is None:
        return jsonify({'error': error}), 401

    if user.mfa_enabled:
        if not totp_code and not recovery_code:
            return jsonify({'error': 'MFA required', 'code': 'MFA_REQUIRED'}), 401
        if recovery_code:
            if not _consume_recovery_code(user, str(recovery_code).strip()):
                return jsonify({'error': 'Invalid recovery code'}), 401
        else:
            if not user.mfa_secret:
                return jsonify({'error': 'MFA not configured'}), 400
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(str(totp_code).strip(), valid_window=1):
                return jsonify({'error': 'Invalid verification code'}), 401
    
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'username': user.username,
            'role': user.role
        }
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    decoded = decode_token(access_token)
    jti = decoded.get('jti')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    if jti:
        UserSession.create(user.id, jti, ip_address, user_agent)
    
    # Send security event notification if enabled for this user
    from app.notifications import notify_user_login
    try:
        notify_user_login(user.username, ip_address or 'Unknown', user_agent or 'Unknown', user.id)
    except Exception as e:
        # Don't fail login if notification fails
        logger.error(f"Failed to send login notification: {e}")
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'full_name': getattr(user, 'full_name', None),
            'email': getattr(user, 'email', None),
            'role': user.role,
            'mfa_enabled': bool(user.mfa_enabled),
            'theme': user.theme,
            'language': user.language,
            'timezone': user.timezone
        }
    })


@api_bp.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def api_auth_refresh():
    """Refresh access token using refresh token."""
    user_id = get_jwt_identity()
    user = User.get_by_id(int(user_id)) if user_id is not None else None
    
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 401
    
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'username': user.username,
            'role': user.role
        }
    )
    decoded = decode_token(access_token)
    jti = decoded.get('jti')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    if jti:
        UserSession.create(user.id, jti, ip_address, user_agent)

    return jsonify({'access_token': access_token})


@api_bp.route('/auth/me')
@api_auth_required
def api_auth_me():
    """Get current user info from JWT token."""
    user = g.api_user
    return jsonify({
        'id': user.id,
        'username': user.username,
        'full_name': getattr(user, 'full_name', None),
        'email': getattr(user, 'email', None),
        'role': user.role,
        'is_active': user.is_active,
        'last_login': _serialize_timestamp(user.last_login),
        'mfa_enabled': bool(user.mfa_enabled),
        'theme': user.theme,
        'language': user.language,
        'timezone': user.timezone,
        'current_session_id': g.api_session.id if getattr(g, 'api_session', None) else None
    })


@api_bp.route('/auth/me', methods=['PUT'])
@api_auth_required
def api_auth_me_update():
    """Update current user's profile."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    user = g.api_user
    new_username = data.get('username', '').strip()
    new_email = data.get('email', None)
    full_name = data.get('full_name', None)
    theme = data.get('theme', user.theme)
    language = data.get('language', user.language)
    timezone = data.get('timezone', user.timezone)

    if theme not in ['system', 'light', 'dark']:
        return jsonify({'error': 'Invalid theme'}), 400

    if language not in ['en', 'es', 'fr']:
        return jsonify({'error': 'Invalid language'}), 400

    if isinstance(new_email, str):
        new_email = new_email.strip()
    if new_email == '':
        new_email = None
    if isinstance(full_name, str):
        full_name = full_name.strip()
    if full_name == '':
        full_name = None

    if not new_username:
        return jsonify({'error': 'Username is required'}), 400

    existing = User.get_by_username(new_username)
    if existing and existing.id != user.id:
        return jsonify({'error': 'Username already exists'}), 400

    if new_email:
        existing_email = User.get_by_email(new_email)
        if existing_email and existing_email.id != user.id:
            return jsonify({'error': 'Email already in use'}), 400

    user.update_profile(new_username, new_email, full_name)
    user.update_preferences(theme, language, timezone)

    AuditLog.log(
        username=user.username,
        action='USER_PROFILE_UPDATED',
        details='Updated account settings',
        success=True
    )

    return jsonify({
        'id': user.id,
        'username': user.username,
        'full_name': getattr(user, 'full_name', None),
        'email': getattr(user, 'email', None),
        'role': user.role,
        'is_active': user.is_active,
        'last_login': _serialize_timestamp(user.last_login),
        'mfa_enabled': bool(user.mfa_enabled),
        'theme': user.theme,
        'language': user.language,
        'timezone': user.timezone
    })


@api_bp.route('/auth/me/notifications', methods=['GET'])
@api_auth_required
def api_auth_me_notifications_get():
    """Get current user's notification preferences."""
    user = g.api_user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT notification_preferences FROM users WHERE id = ?", (user.id,))
    row = cursor.fetchone()
    conn.close()
    
    if row and row['notification_preferences']:
        try:
            prefs = json.loads(row['notification_preferences'])
        except (json.JSONDecodeError, TypeError):
            prefs = {
                'health_alerts': True,
                'offline_alerts': True,
                'job_failures': True,
                'security_events': True,
                'weekly_reports': False
            }
    else:
        prefs = {
            'health_alerts': True,
            'offline_alerts': True,
            'job_failures': True,
            'security_events': True,
            'weekly_reports': False
        }
    
    return jsonify(prefs)


@api_bp.route('/auth/me/notifications', methods=['PUT'])
@api_auth_required
def api_auth_me_notifications_update():
    """Update current user's notification preferences."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    user = g.api_user
    
    # Validate preferences
    valid_prefs = {'health_alerts', 'offline_alerts', 'job_failures', 'security_events', 'weekly_reports'}
    prefs = {}
    for key in valid_prefs:
        prefs[key] = bool(data.get(key, True))
    
    # Save to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET notification_preferences = ? WHERE id = ?",
        (json.dumps(prefs), user.id)
    )
    conn.commit()
    conn.close()
    
    AuditLog.log(
        username=user.username,
        action='NOTIFICATION_PREFERENCES_UPDATED',
        details='Updated notification preferences',
        success=True
    )
    
    return jsonify({'message': 'Notification preferences updated', 'preferences': prefs})


@api_bp.route('/auth/mfa/setup', methods=['POST'])
@api_auth_required
def api_auth_mfa_setup():
    """Initialize MFA setup and return otpauth URI."""
    user = g.api_user
    secret = pyotp.random_base32()
    user.set_mfa_secret(secret)
    user.set_mfa_enabled(False)
    user.set_recovery_codes(None)
    issuer = 'Printer Proxy'
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=issuer)
    return jsonify({
        'otpauth_uri': otpauth_uri,
        'issuer': issuer,
        'account': user.username
    })


@api_bp.route('/auth/mfa/verify', methods=['POST'])
@api_auth_required
@limiter.limit("10 per minute")
def api_auth_mfa_verify():
    """Verify MFA setup and generate recovery codes."""
    user = g.api_user
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    code = str(data.get('code', '')).strip()
    if not user.mfa_secret:
        return jsonify({'error': 'MFA not initialized'}), 400
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid verification code'}), 400

    recovery_codes = [secrets.token_hex(4) for _ in range(10)]
    hashed_codes = [bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') for code in recovery_codes]
    user.set_recovery_codes(json.dumps(hashed_codes))
    user.set_mfa_enabled(True)

    AuditLog.log(
        username=user.username,
        action='MFA_ENABLED',
        details='MFA enabled with recovery codes',
        success=True
    )

    return jsonify({
        'recovery_codes': recovery_codes
    })


@api_bp.route('/auth/mfa/disable', methods=['POST'])
@api_auth_required
def api_auth_mfa_disable():
    """Disable MFA for current user (requires password or code)."""
    user = g.api_user
    data = request.get_json() or {}
    password = data.get('password')
    code = data.get('code')

    if not password and not code:
        return jsonify({'error': 'Password or code required'}), 400

    if password and not verify_password(password, user.password_hash):
        return jsonify({'error': 'Invalid password'}), 400

    if code and user.mfa_secret:
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(str(code).strip(), valid_window=1):
            return jsonify({'error': 'Invalid verification code'}), 400

    user.set_mfa_enabled(False)
    user.set_mfa_secret(None)
    user.set_recovery_codes(None)

    AuditLog.log(
        username=user.username,
        action='MFA_DISABLED',
        details='MFA disabled',
        success=True
    )

    return jsonify({'message': 'MFA disabled'})


@api_bp.route('/auth/sessions')
@api_auth_required
def api_auth_sessions():
    """List active sessions for current user."""
    user = g.api_user
    sessions = UserSession.get_by_user(user.id)
    current_jti = g.api_claims.get('jti')
    return jsonify([
        {
            'id': s.id,
            'created_at': _serialize_timestamp(s.created_at),
            'last_used': _serialize_timestamp(s.last_used),
            'revoked_at': _serialize_timestamp(s.revoked_at),
            'ip_address': s.ip_address,
            'user_agent': s.user_agent,
            'is_current': s.jti == current_jti
        }
        for s in sessions
    ])


@api_bp.route('/auth/sessions/<int:session_id>/revoke', methods=['POST'])
@api_auth_required
def api_auth_sessions_revoke(session_id: int):
    """Revoke a session by ID."""
    user = g.api_user
    sessions = UserSession.get_by_user(user.id)
    session_ids = {s.id for s in sessions}
    if session_id not in session_ids:
        return jsonify({'error': 'Session not found'}), 404
    UserSession.revoke(session_id)
    return jsonify({'message': 'Session revoked'})


@api_bp.route('/auth/logout', methods=['POST'])
@api_auth_required
def api_auth_logout():
    """Logout endpoint (revokes current session)."""
    jti = g.api_claims.get('jti')
    if jti:
        UserSession.revoke_by_jti(jti)
    return jsonify({'message': 'Successfully logged out'})


@api_bp.route('/auth/me/tokens', methods=['GET'])
@api_auth_required
def api_auth_me_tokens_list():
    """List all API tokens for current user."""
    from app.api_tokens import APIToken
    
    user = g.api_user
    tokens = APIToken.get_by_user(user.id)
    
    return jsonify({
        'tokens': [t.to_dict() for t in tokens]
    })


@api_bp.route('/auth/me/tokens', methods=['POST'])
@api_auth_required
def api_auth_me_tokens_create():
    """Create a new API token for current user."""
    from app.api_tokens import APIToken, validate_permissions, get_available_permissions
    from datetime import datetime, timedelta
    
    user = g.api_user
    data = request.get_json() or {}
    
    name = data.get('name', '').strip()
    permissions = data.get('permissions', [])
    expires_in_days = data.get('expires_in_days')
    
    if not name:
        return jsonify({'error': 'Token name is required'}), 400
    
    if not permissions:
        return jsonify({'error': 'At least one permission is required'}), 400
    
    # Validate permissions against user's role
    if not validate_permissions(user.role, permissions):
        available = get_available_permissions(user.role)
        return jsonify({
            'error': 'Invalid permissions for your role',
            'available_permissions': available
        }), 400
    
    # Calculate expiration date
    expires_at = None
    if expires_in_days:
        try:
            days = int(expires_in_days)
            if days > 0:
                expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
        except ValueError:
            return jsonify({'error': 'Invalid expiration days'}), 400
    
    # Create token
    try:
        token, plain_token = APIToken.create(
            user_id=user.id,
            name=name,
            permissions=permissions,
            expires_at=expires_at
        )
        
        AuditLog.log(
            username=user.username,
            action='API_TOKEN_CREATED',
            details=f'Created API token: {name}'
        )
        
        return jsonify({
            'token': token.to_dict(include_token=True, token_value=plain_token),
            'message': 'Token created successfully. Save this token - it will not be shown again!'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/auth/me/tokens/<int:token_id>', methods=['DELETE'])
@api_auth_required
def api_auth_me_tokens_delete(token_id: int):
    """Delete an API token."""
    from app.api_tokens import APIToken
    
    user = g.api_user
    
    if APIToken.delete(token_id, user.id):
        AuditLog.log(
            username=user.username,
            action='API_TOKEN_DELETED',
            details=f'Deleted API token ID: {token_id}'
        )
        return jsonify({'message': 'Token deleted'})
    else:
        return jsonify({'error': 'Token not found'}), 404


@api_bp.route('/auth/me/tokens/permissions', methods=['GET'])
@api_auth_required
def api_auth_me_tokens_permissions():
    """Get available permissions for current user's role."""
    from app.api_tokens import get_available_permissions, PERMISSION_SCOPES
    
    user = g.api_user
    available = get_available_permissions(user.role)
    
    # Group permissions by resource
    grouped = {}
    for perm in available:
        resource, action = perm.split(':')
        if resource not in grouped:
            grouped[resource] = []
        grouped[resource].append(action)
    
    return jsonify({
        'role': user.role,
        'permissions': available,
        'grouped': grouped,
        'all_scopes': PERMISSION_SCOPES
    })


@api_bp.route('/auth/setup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def api_auth_setup():
    """Check if setup is needed or create initial admin."""
    from app.models import get_db_connection
    from app.auth import create_initial_admin
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()
    
    if request.method == 'GET':
        return jsonify({'setup_required': user_count == 0})
    
    # POST - create initial admin
    if user_count > 0:
        return jsonify({'error': 'Setup already completed'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email')
    full_name = data.get('full_name')
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    if isinstance(email, str):
        email = email.strip()
    if email == '':
        email = None
    if isinstance(full_name, str):
        full_name = full_name.strip()
    if full_name == '':
        full_name = None
    
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    success, message = create_initial_admin(username, password, email=email, full_name=full_name)
    if success:
        return jsonify({'message': 'Admin user created successfully'})
    else:
        return jsonify({'error': message}), 400


# ============================================================================
# App Info API Routes
# ============================================================================

@api_bp.route('/info')
def api_info():
    """Get application info (version, etc.)."""
    from app.version import __version__, VERSION_STRING
    return jsonify({
        'version': __version__,
        'version_string': VERSION_STRING,
        'app_name': 'Printer Proxy'
    })


# ============================================================================
# Printers API Routes
# ============================================================================

@api_bp.route('/printers')
@api_auth_required
def api_printers():
    """Get all printers with status."""
    # Check API token permissions
    perm_check = check_api_permission('printers:read')
    if perm_check:
        return perm_check
    
    registry = get_registry()
    return jsonify(registry.get_all_statuses())


@api_bp.route('/printers/<printer_id>')
@api_auth_required
def api_printer(printer_id):
    """Get a specific printer with status."""
    # Check API token permissions
    perm_check = check_api_permission('printers:read')
    if perm_check:
        return perm_check
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    return jsonify(registry.get_printer_status(printer))


@api_bp.route('/printers', methods=['POST'])
@api_role_required('admin', 'operator')
def api_printer_create():
    """Create a new printer."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    name = data.get('name', '').strip()
    ip = data.get('ip', '').strip()
    location = data.get('location', '').strip()
    model = data.get('model', '').strip()
    department = data.get('department', '').strip()
    notes = data.get('notes', '').strip()

    protocols_raw = data.get('protocols')
    if isinstance(protocols_raw, str):
        protocols = [p.strip() for p in protocols_raw.split(',') if p.strip()]
    elif isinstance(protocols_raw, list):
        protocols = [str(p).strip() for p in protocols_raw if str(p).strip()]
    else:
        protocols = ['raw']

    allowed_protocols = set(SUPPORTED_PROTOCOLS.keys())
    protocols = [p for p in protocols if p in allowed_protocols]
    if not protocols:
        protocols = ['raw']
    
    if not name or not ip:
        return jsonify({'error': 'Name and IP are required'}), 400
    
    registry = get_registry()
    
    for p in registry.get_all():
        if p.ip == ip:
            return jsonify({'error': 'A printer with this IP already exists'}), 400
    
    try:
        printer = Printer(
            id=data.get('id') or uuid4().hex,
            name=name,
            ip=ip,
            protocols=protocols,
            location=location,
            model=model,
            department=department,
            notes=notes
        )
        success = registry.add_printer(printer)
        if not success:
            return jsonify({'error': 'Failed to create printer'}), 500
        
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_CREATED',
            source_printer_id=printer.id,
            source_ip=printer.ip,
            details=f"Created printer '{name}' ({ip})",
            success=True
        )
        
        return jsonify({
            'id': printer.id,
            'name': printer.name,
            'ip': printer.ip,
            'location': printer.location,
            'model': printer.model,
            'protocols': printer.protocols,
            'department': printer.department,
            'notes': printer.notes
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/printers/<printer_id>', methods=['PUT'])
@api_role_required('admin', 'operator')
def api_printer_update(printer_id):
    """Update a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    name = data.get('name', printer.name).strip()
    ip = data.get('ip', printer.ip).strip()
    location = data.get('location', printer.location or '').strip()
    model = data.get('model', printer.model or '').strip()
    department = data.get('department', printer.department or '').strip()
    notes = data.get('notes', printer.notes or '').strip()

    protocols_raw = data.get('protocols', printer.protocols)
    if isinstance(protocols_raw, str):
        protocols = [p.strip() for p in protocols_raw.split(',') if p.strip()]
    elif isinstance(protocols_raw, list):
        protocols = [str(p).strip() for p in protocols_raw if str(p).strip()]
    else:
        protocols = printer.protocols

    allowed_protocols = set(SUPPORTED_PROTOCOLS.keys())
    protocols = [p for p in protocols if p in allowed_protocols]
    if not protocols:
        protocols = ['raw']
    
    if not name or not ip:
        return jsonify({'error': 'Name and IP are required'}), 400
    
    for p in registry.get_all():
        if p.ip == ip and p.id != printer_id:
            return jsonify({'error': 'A printer with this IP already exists'}), 400
    
    try:
        printer.name = name
        printer.ip = ip
        printer.location = location
        printer.model = model
        printer.department = department
        printer.notes = notes
        printer.protocols = protocols
        success = registry.update_printer(printer)
        if not success:
            return jsonify({'error': 'Failed to update printer'}), 500
        
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_UPDATED',
            source_printer_id=printer.id,
            source_ip=printer.ip,
            details=f"Updated printer '{name}' ({ip})",
            success=True
        )
        
        return jsonify({
            'id': printer.id,
            'name': printer.name,
            'ip': printer.ip,
            'location': printer.location,
            'model': printer.model,
            'protocols': printer.protocols,
            'department': printer.department,
            'notes': printer.notes
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/printers/<printer_id>', methods=['DELETE'])
@api_role_required('admin')
def api_printer_delete(printer_id):
    """Delete a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    redirect_obj = ActiveRedirect.get_by_source_printer(printer_id)
    if redirect_obj:
        return jsonify({'error': 'Cannot delete printer with active redirect'}), 400
    
    if ActiveRedirect.is_target_in_use(printer_id):
        return jsonify({'error': 'Cannot delete printer that is a redirect target'}), 400
    
    try:
        success = registry.delete_printer(printer_id)
        if not success:
            return jsonify({'error': 'Failed to delete printer'}), 500
        
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_DELETED',
            source_printer_id=printer.id,
            source_ip=printer.ip,
            details=f"Deleted printer '{printer.name}' ({printer.ip})",
            success=True
        )
        
        return jsonify({'message': f"Printer '{printer.name}' deleted"})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/printers/<printer_id>/check')
@api_auth_required
def api_check_printer(printer_id):
    """Quick reachability check for a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    icmp = registry.check_icmp_reachability(printer.ip)
    tcp = registry.check_tcp_reachability(printer.ip)
    
    return jsonify({
        'printer_id': printer_id,
        'ip': printer.ip,
        'icmp_reachable': icmp,
        'tcp_reachable': tcp,
        'is_online': icmp or tcp
    })


@api_bp.route('/printers/<printer_id>/stats')
@api_auth_required
def api_printer_stats(printer_id):
    """Get SNMP stats for a printer."""
    from app.printer_stats import get_printer_stats, get_toner_levels
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    stats = get_printer_stats(printer.ip)
    toner = get_toner_levels(printer.ip)
    
    return jsonify({
        'stats': stats.to_dict() if stats else None,
        'toner': toner
    })


@api_bp.route('/printers/<printer_id>/health')
@api_auth_required
def api_printer_health(printer_id):
    """Get health status for a printer."""
    from app.health_check import get_printer_health, get_printer_health_history
    
    health = get_printer_health(printer_id)
    history = get_printer_health_history(printer_id, limit=24)
    
    return jsonify({
        'current': health,
        'history': history
    })


@api_bp.route('/printers/<printer_id>/refresh')
@api_role_required('admin', 'operator')
def api_printer_refresh(printer_id):
    """Force a live status check for a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    from app.health_check import HealthChecker
    checker = HealthChecker()
    result = checker.check_printer(printer_id, printer.ip)
    checker.save_result(result)
    
    return jsonify({
        'printer_id': printer_id,
        'ip': printer.ip,
        'icmp_reachable': result.icmp_ok,
        'tcp_reachable': result.tcp_9100_ok,
        'is_online': result.is_online,
        'response_time_ms': result.response_time_ms
    })


@api_bp.route('/printers/<printer_id>/queue')
@api_auth_required
def api_printer_queue(printer_id):
    """Get current print queue for a printer."""
    from app.print_queue import get_print_queue

    registry = get_registry()
    printer = registry.get_by_id(printer_id)

    if not printer:
        return jsonify({'error': 'Printer not found'}), 404

    jobs = get_print_queue(printer.ip)
    return jsonify({'jobs': [job.to_dict() for job in jobs]})


@api_bp.route('/printers/<printer_id>/jobs')
@api_auth_required
def api_printer_job_history(printer_id):
    """Get print job history for a printer."""
    from app.models import PrintJobHistory

    limit = int(request.args.get('limit', 50))
    jobs = PrintJobHistory.get_for_printer(printer_id, limit=limit)
    return jsonify({'jobs': [job.to_dict() for job in jobs]})


@api_bp.route('/printers/<printer_id>/logs')
@api_auth_required
def api_printer_logs(printer_id):
    """Get device event logs for a printer."""
    from app.event_logs import get_printer_logs

    registry = get_registry()
    printer = registry.get_by_id(printer_id)

    if not printer:
        return jsonify({'error': 'Printer not found'}), 404

    events = get_printer_logs(printer.ip)
    return jsonify({'events': [event.to_dict() for event in events]})


@api_bp.route('/printers/<printer_id>/audit')
@api_auth_required
def api_printer_audit(printer_id):
    """Get audit log entries related to a printer."""
    from app.models import AuditLog

    limit = int(request.args.get('limit', 20))
    logs = AuditLog.get_by_printer(printer_id, limit=limit)
    return jsonify({'logs': logs})


# ============================================================================
# Redirects API Routes
# ============================================================================

@api_bp.route('/redirects')
@api_role_required('admin', 'operator')
def api_redirects():
    """Get all active redirects."""
    redirects = ActiveRedirect.get_all()
    return jsonify([{
        'id': r.id,
        'source_printer_id': r.source_printer_id,
        'source_ip': r.source_ip,
        'target_printer_id': r.target_printer_id,
        'target_ip': r.target_ip,
        'protocol': r.protocol,
        'port': r.port,
        'enabled_at': str(r.enabled_at),
        'enabled_by': r.enabled_by
    } for r in redirects])


@api_bp.route('/redirects', methods=['POST'])
@api_role_required('admin', 'operator')
def api_redirect_create():
    """Create a new redirect."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    source_printer_id = data.get('source_printer_id')
    target_printer_id = data.get('target_printer_id')
    
    if not source_printer_id or not target_printer_id:
        return jsonify({'error': 'Source and target printer IDs are required'}), 400
    
    registry = get_registry()
    network = get_network_manager()
    
    source_printer = registry.get_by_id(source_printer_id)
    if not source_printer:
        return jsonify({'error': 'Source printer not found'}), 404
    
    target_printer = registry.get_by_id(target_printer_id)
    if not target_printer:
        return jsonify({'error': 'Target printer not found'}), 404
    
    if source_printer.ip == target_printer.ip:
        return jsonify({'error': 'Source and target cannot be the same'}), 400
    
    existing = ActiveRedirect.get_by_source_printer(source_printer_id)
    if existing:
        return jsonify({'error': 'This printer already has an active redirect'}), 400
    
    if ActiveRedirect.is_target_in_use(target_printer_id):
        return jsonify({'error': 'Target printer is already in use'}), 400
    
    success, message = network.enable_redirect(
        source_ip=source_printer.ip,
        target_ip=target_printer.ip,
        port=DEFAULT_PORT
    )
    
    if success:
        redirect_obj = ActiveRedirect.create(
            source_printer_id=source_printer_id,
            source_ip=source_printer.ip,
            target_printer_id=target_printer_id,
            target_ip=target_printer.ip,
            protocol='raw',
            port=DEFAULT_PORT,
            enabled_by=g.api_user.username
        )
        
        AuditLog.log(
            username=g.api_user.username,
            action="REDIRECT_ENABLED",
            source_printer_id=source_printer_id,
            source_ip=source_printer.ip,
            target_printer_id=target_printer_id,
            target_ip=target_printer.ip,
            details=f"Redirecting {source_printer.name} to {target_printer.name}",
            success=True
        )
        
        return jsonify({
            'id': redirect_obj.id,
            'source_printer_id': redirect_obj.source_printer_id,
            'target_printer_id': redirect_obj.target_printer_id,
            'message': f'Redirect enabled: {source_printer.name} → {target_printer.name}'
        }), 201
    else:
        return jsonify({'error': message}), 500


@api_bp.route('/redirects/<int:redirect_id>', methods=['DELETE'])
@api_role_required('admin', 'operator')
def api_redirect_delete(redirect_id):
    """Remove a redirect."""
    redirect_obj = ActiveRedirect.get_by_id(redirect_id)
    if not redirect_obj:
        return jsonify({'error': 'Redirect not found'}), 404
    
    network = get_network_manager()
    
    success, message = network.disable_redirect(
        source_ip=redirect_obj.source_ip,
        target_ip=redirect_obj.target_ip,
        port=redirect_obj.port
    )
    
    if success:
        ActiveRedirect.delete(redirect_obj.id)
        
        AuditLog.log(
            username=g.api_user.username,
            action="REDIRECT_DISABLED",
            source_printer_id=redirect_obj.source_printer_id,
            source_ip=redirect_obj.source_ip,
            target_printer_id=redirect_obj.target_printer_id,
            target_ip=redirect_obj.target_ip,
            details="Redirect removed",
            success=True
        )
        
        return jsonify({'message': 'Redirect removed'})
    else:
        return jsonify({'error': message}), 500


# ============================================================================
# Users API Routes
# ============================================================================

@api_bp.route('/users')
@api_role_required('admin')
def api_users():
    """Get all users."""
    users = User.get_all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'full_name': getattr(u, 'full_name', None),
        'email': getattr(u, 'email', None),
        'role': u.role,
        'is_active': u.is_active,
        'last_login': _serialize_timestamp(u.last_login),
        'created_at': _serialize_timestamp(getattr(u, 'created_at', None))
    } for u in users])


@api_bp.route('/users', methods=['POST'])
@api_role_required('admin')
def api_user_create():
    """Create a new user."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', None)
    full_name = data.get('full_name', None)
    role = data.get('role', 'viewer').strip()
    is_active = data.get('is_active', True)

    if isinstance(email, str):
        email = email.strip()
    if email == '':
        email = None
    if isinstance(full_name, str):
        full_name = full_name.strip()
    if full_name == '':
        full_name = None
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    if User.get_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    if role not in ['admin', 'operator', 'viewer']:
        return jsonify({'error': 'Invalid role'}), 400
    
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    try:
        user = User.create(username, hash_password(password), role=role, is_active=is_active, email=email, full_name=full_name)
        AuditLog.log(
            username=g.api_user.username,
            action='USER_CREATED',
            details=f"Created user '{username}' with role '{role}'",
            success=True
        )
        return jsonify({
            'id': user.id,
            'username': user.username,
            'full_name': getattr(user, 'full_name', None),
            'email': getattr(user, 'email', None),
            'role': user.role,
            'is_active': user.is_active
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users/<int:user_id>')
@api_role_required('admin')
def api_user_get(user_id: int):
    """Get a specific user."""
    user = User.get_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'full_name': getattr(user, 'full_name', None),
        'email': getattr(user, 'email', None),
        'role': user.role,
        'is_active': user.is_active,
        'last_login': _serialize_timestamp(user.last_login),
        'created_at': _serialize_timestamp(getattr(user, 'created_at', None))
    })


@api_bp.route('/users/<int:user_id>', methods=['PUT'])
@api_role_required('admin')
def api_user_update(user_id: int):
    """Update a user."""
    user = User.get_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    role = data.get('role', user.role)
    is_active = data.get('is_active', user.is_active)
    new_password = data.get('password')
    
    if role not in ['admin', 'operator', 'viewer']:
        return jsonify({'error': 'Invalid role'}), 400
    
    admins = [u for u in User.get_all() if u.role == 'admin']
    if user.role == 'admin' and role != 'admin' and len(admins) <= 1:
        return jsonify({'error': 'At least one admin is required'}), 400
    
    current_api_user_id = g.api_user.id
    if user.id == current_api_user_id and role != 'admin':
        return jsonify({'error': 'You cannot remove your own admin access'}), 400
    if user.id == current_api_user_id and not is_active:
        return jsonify({'error': 'You cannot disable your own account'}), 400
    
    if new_password:
        is_valid, error = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': error}), 400
        user.update_password(hash_password(new_password))
    
    user.update_role(role)
    user.set_active(is_active)
    
    AuditLog.log(
        username=g.api_user.username,
        action='USER_UPDATED',
        details=f"Updated user '{user.username}' (role={role}, active={is_active})",
        success=True
    )
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': getattr(user, 'email', None),
        'role': user.role,
        'is_active': user.is_active
    })


@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@api_role_required('admin')
def api_user_delete(user_id: int):
    """Delete a user."""
    user = User.get_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    current_api_user_id = g.api_user.id
    if user.id == current_api_user_id:
        return jsonify({'error': 'You cannot delete your own account'}), 400
    
    admins = [u for u in User.get_all() if u.role == 'admin']
    if user.role == 'admin' and len(admins) <= 1:
        return jsonify({'error': 'At least one admin is required'}), 400
    
    if User.delete_by_id(user.id):
        AuditLog.log(
            username=g.api_user.username,
            action='USER_DELETED',
            details=f"Deleted user '{user.username}'",
            success=True
        )
        return jsonify({'message': f"User '{user.username}' deleted"})
    else:
        return jsonify({'error': 'Failed to delete user'}), 500


# ============================================================================
# Audit Log API Routes
# ============================================================================

@api_bp.route('/audit-logs')
@api_role_required('admin')
@limiter.limit("30 per minute")
def api_audit_logs():
    """Get audit logs with optional filtering."""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    action = request.args.get('action')
    username = request.args.get('username')
    
    logs = AuditLog.get_recent(limit=limit, offset=offset, action=action, username=username)
    
    return jsonify([{
        'id': log.get('id'),
        'timestamp': _serialize_timestamp(log.get('timestamp')),
        'username': log.get('username'),
        'action': log.get('action'),
        'details': log.get('details'),
        'source_printer_id': log.get('source_printer_id'),
        'source_ip': log.get('source_ip'),
        'target_printer_id': log.get('target_printer_id'),
        'target_ip': log.get('target_ip'),
        'success': log.get('success'),
        'error_message': log.get('error_message')
    } for log in logs])


# ============================================================================
# Discovery API Routes
# ============================================================================

@api_bp.route('/discovery/scan', methods=['POST'])
@api_role_required('admin', 'operator')
@limiter.limit("5 per minute")
def api_discovery_scan():
    """Start a network scan for printers."""
    discovery = get_discovery()
    
    data = request.get_json() or {}
    subnet = data.get('subnet')
    
    try:
        if subnet:
            # If a CIDR is provided, scan the network; otherwise treat as single IP.
            if '/' in subnet:
                printers = discovery.discover_all(network_cidr=subnet)
            else:
                printers = discovery.scan_single_ip(subnet)
        else:
            printers = discovery.discover_all()
        return jsonify({
            'success': True,
            'printers': [{
                'ip': p.ip,
                'name': p.name,
                'model': p.model,
                'location': p.location,
                'discovery_method': p.discovery_method,
                'hostname': p.hostname,
                'tcp_9100_open': p.tcp_9100_open,
                'snmp_available': p.snmp_available
            } for p in printers]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Network Status API Routes
# ============================================================================

@api_bp.route('/network/status')
@api_role_required('admin')
def api_network_status():
    """Get current network status (secondary IPs and NAT rules)."""
    network = get_network_manager()
    
    success, ips = network.get_secondary_ips()
    success2, nat_rules = network.get_nat_rules()
    
    return jsonify({
        'secondary_ips': ips if success else [],
        'nat_rules': nat_rules if success2 else 'Unable to retrieve'
    })


# ============================================================================
# Dashboard API Routes
# ============================================================================

_dashboard_analytics_cache = {
    'timestamp': 0.0,
    'data': None
}

@api_bp.route('/dashboard/status')
@api_auth_required
def api_dashboard_status():
    """Get all printer statuses for dashboard."""
    registry = get_registry()
    return jsonify(registry.get_all_statuses(use_cache=True))


@api_bp.route('/dashboard/stats')
@api_auth_required
def api_dashboard_stats():
    """Get dashboard statistics."""
    registry = get_registry()
    printers = registry.get_all_statuses()
    redirects = ActiveRedirect.get_all()
    
    online_count = sum(1 for p in printers if p.get('is_online'))
    offline_count = len(printers) - online_count
    
    return jsonify({
        'total_printers': len(printers),
        'online_printers': online_count,
        'offline_printers': offline_count,
        'active_redirects': len(redirects)
    })


@api_bp.route('/dashboard/analytics')
@api_auth_required
def api_dashboard_analytics():
    """Get dashboard analytics for charts."""
    # Cache SNMP-heavy analytics for 5 minutes
    now = time.time()
    cached = _dashboard_analytics_cache.get('data')
    if cached and (now - _dashboard_analytics_cache.get('timestamp', 0)) < 300:
        return jsonify(cached)

    conn = get_db_connection()
    cursor = conn.cursor()

    registry = get_registry()
    printers = registry.get_all()

    def _parse_uptime_hours(uptime: str) -> float:
        if not uptime:
            return 0.0
        days = hours = minutes = 0
        try:
            parts = uptime.split()
            for part in parts:
                if part.endswith('d'):
                    days = int(part[:-1])
                elif part.endswith('h'):
                    hours = int(part[:-1])
                elif part.endswith('m'):
                    minutes = int(part[:-1])
        except Exception:
            return 0.0
        return (days * 24) + hours + (minutes / 60.0)

    # Top printers by SNMP total pages + uptime
    snmp_pages = []
    for printer in printers:
        stats = get_printer_stats(printer.ip)
        total_pages = stats.total_pages if stats and stats.total_pages is not None else 0
        uptime_hours = _parse_uptime_hours(stats.uptime) if stats and stats.uptime else 0.0
        snmp_pages.append({
            'printer_id': printer.id,
            'name': printer.name,
            'total_pages': total_pages,
            'uptime_hours': round(uptime_hours, 1)
        })
    top_pages = sorted(snmp_pages, key=lambda x: x['total_pages'], reverse=True)[:15]

    # Daily job volume (last 7 days)
    cursor.execute(
        """
        SELECT substr(recorded_at, 1, 10) AS day,
               COALESCE(SUM(pages), 0) AS total_pages,
               COUNT(*) AS total_jobs
        FROM print_job_history
        WHERE recorded_at >= datetime('now','-6 days')
        GROUP BY substr(recorded_at, 1, 10)
        ORDER BY substr(recorded_at, 1, 10)
        """
    )
    daily_rows = cursor.fetchall()
    conn.close()

    # Fill missing days
    from datetime import datetime, timedelta
    daily_map = {row['day']: row for row in daily_rows}
    daily = []
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).date().isoformat()
        row = daily_map.get(day)
        daily.append({
            'day': day,
            'total_pages': row['total_pages'] if row else 0,
            'total_jobs': row['total_jobs'] if row else 0
        })

    payload = {
        'top_pages': top_pages,
        'daily_volume': daily
    }

    _dashboard_analytics_cache['timestamp'] = now
    _dashboard_analytics_cache['data'] = payload

    return jsonify(payload)


# ============================================================================
# Update API Routes
# ============================================================================

@api_bp.route('/update/status')
def api_update_status():
    """Get current update status."""
    from app.updater import get_update_manager
    manager = get_update_manager()
    return jsonify(manager.get_state())


@api_bp.route('/update/check', methods=['POST'])
@api_role_required('admin')
def api_update_check():
    """Force an update check."""
    from app.updater import get_update_manager
    manager = get_update_manager()
    update_available, error = manager.check_for_updates(force=True)
    
    if error:
        return jsonify({
            'success': False,
            'error': error,
            'update_available': False
        })
    
    return jsonify({
        'success': True,
        'update_available': update_available,
        **manager.get_state()
    })


@api_bp.route('/update/start', methods=['POST'])
@api_role_required('admin')
def api_update_start():
    """Start the update process."""
    from app.updater import get_update_manager
    
    manager = get_update_manager()
    success, message = manager.start_update()
    
    if success:
        AuditLog.log(
            username=g.api_user.username,
            action='UPDATE_STARTED',
            details=f"Update to version {manager._state.available_version} initiated"
        )
    
    return jsonify({
        'success': success,
        'message': message
    })


# ============================================================================
# Settings API Routes  
# ============================================================================

@api_bp.route('/settings')
@api_role_required('admin')
def api_settings():
    """Get all settings."""
    from app.settings import get_settings_manager
    settings = get_settings_manager().get_all()
    return jsonify({'success': True, 'settings': settings})


@api_bp.route('/admin/smtp', methods=['GET', 'PUT'])
@api_role_required('admin')
def api_admin_smtp():
    """Get or update SMTP notification settings."""
    from app.settings import get_settings_manager
    manager = get_settings_manager()
    
    if request.method == 'GET':
        smtp_settings = manager.get('notifications.smtp', {})
        smtp_settings = dict(smtp_settings)
        smtp_settings['password'] = '********' if smtp_settings.get('password') else ''
        return jsonify({'success': True, 'settings': smtp_settings})
    
    # PUT request
    data = request.get_json() or {}
    
    try:
        current_smtp = manager.get('notifications.smtp', {})
        
        # Remove to_addresses if present (legacy field)
        current_smtp.pop('to_addresses', None)
        
        for field in ['enabled', 'host', 'port', 'username', 'from_address', 'use_tls', 'use_ssl']:
            if field in data:
                current_smtp[field] = data[field]
        
        if data.get('password'):
            current_smtp['password'] = data['password']
        
        manager.set('notifications.smtp', current_smtp)
        
        AuditLog.log(
            username=g.api_user.username,
            action='SETTINGS_UPDATED',
            details='SMTP server configuration updated'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/admin/smtp/test', methods=['POST'])
@api_role_required('admin')
def api_admin_smtp_test():
    """Send a test email to current user using SMTP settings."""
    from app.notifications import SMTPNotificationChannel
    from app.settings import get_settings_manager

    # Get user's email
    user_email = g.api_user.email
    if not user_email:
        return jsonify({
            'success': False,
            'error': 'Your account does not have an email address configured'
        }), 400

    data = request.get_json() or {}
    if data:
        smtp_settings = {
            'enabled': data.get('enabled', True),
            'host': data.get('host', ''),
            'port': data.get('port', 587),
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'from_address': data.get('from_address', ''),
            'use_tls': data.get('use_tls', True),
            'use_ssl': data.get('use_ssl', False),
        }
        settings = {'notifications': {'smtp': smtp_settings}}
    else:
        settings = get_settings_manager().get_all()

    channel = SMTPNotificationChannel()
    if not channel.is_configured(settings):
        return jsonify({
            'success': False,
            'error': 'SMTP is not properly configured'
        }), 400

    # Send test email to current user only
    success = channel.send(
        subject="Printer Proxy - Test Notification",
        message="This is a test notification from Printer Proxy. If you received this, your notification settings are working correctly.",
        settings=settings,
        recipient_emails=[user_email],
        html_message="""
        <html>
        <body style=\"font-family: Arial, sans-serif; padding: 20px;\">
            <h2 style=\"color: #333;\">Printer Proxy - Test Notification</h2>
            <p>This is a test notification from <strong>Printer Proxy</strong>.</p>
            <p>If you received this, your notification settings are working correctly.</p>
        </body>
        </html>
        """
    )

    if success:
        AuditLog.log(
            username=g.api_user.username,
            action='SMTP_TEST',
            details='Test email sent successfully'
        )
        return jsonify({
            'success': True,
            'message': 'Test email sent successfully'
        })
    
    return jsonify({
        'success': False,
        'error': 'Failed to send test email'
    }), 500


# ============================================================================
# Password Requirements Helper
# ============================================================================

@api_bp.route('/auth/password-requirements')
def api_password_requirements():
    """Get password requirements for the frontend."""
    requirements = [f"At least {MIN_PASSWORD_LENGTH} characters"]
    if PASSWORD_REQUIRE_UPPERCASE:
        requirements.append("At least one uppercase letter")
    if PASSWORD_REQUIRE_LOWERCASE:
        requirements.append("At least one lowercase letter")
    if PASSWORD_REQUIRE_DIGIT:
        requirements.append("At least one digit")
    if PASSWORD_REQUIRE_SPECIAL:
        requirements.append("At least one special character")
    
    return jsonify({
        'requirements': requirements,
        'min_length': MIN_PASSWORD_LENGTH,
        'require_uppercase': PASSWORD_REQUIRE_UPPERCASE,
        'require_lowercase': PASSWORD_REQUIRE_LOWERCASE,
        'require_digit': PASSWORD_REQUIRE_DIGIT,
        'require_special': PASSWORD_REQUIRE_SPECIAL
    })


# ============================================================================
# Notifications API
# ============================================================================

@api_bp.route('/notifications/stream')
@api_auth_required
def notifications_stream():
    """Server-Sent Events endpoint for real-time notifications."""
    from flask import Response, stream_with_context
    from app.notification_manager import get_notification_manager
    import time
    
    user_id = g.api_user.id
    notification_manager = get_notification_manager()
    
    # Register SSE connection
    message_queue = notification_manager.register_connection(user_id)
    
    def generate():
        try:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            
            # Send unread count on connect
            unread_count = notification_manager.get_unread_count(user_id)
            yield f"data: {json.dumps({'type': 'unread_count', 'count': unread_count})}\n\n"
            
            while True:
                try:
                    # Wait for notification with timeout
                    notification = message_queue.get(timeout=30)
                    
                    # Send notification to client
                    event_data = {
                        'type': 'notification',
                        'notification': notification.to_dict()
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
                    
                except queue.Empty:
                    # Send heartbeat to keep connection alive
                    yield f": heartbeat\n\n"
                except Exception as e:
                    logger.error(f"Error in SSE stream: {e}")
                    break
        finally:
            # Cleanup connection
            notification_manager.unregister_connection(user_id, message_queue)
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Disable nginx buffering
            'Connection': 'keep-alive'
        }
    )


@api_bp.route('/notifications', methods=['GET'])
@api_auth_required
def get_notifications():
    """Get notifications for the current user."""
    from app.notification_manager import get_notification_manager
    
    user_id = g.api_user.id
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    notification_manager = get_notification_manager()
    notifications = notification_manager.get_user_notifications(
        user_id, limit, offset, unread_only
    )
    
    return jsonify({
        'notifications': [n.to_dict() for n in notifications]
    })


@api_bp.route('/notifications/unread-count', methods=['GET'])
@api_auth_required
def get_unread_count():
    """Get unread notification count for the current user."""
    from app.notification_manager import get_notification_manager
    
    user_id = g.api_user.id
    notification_manager = get_notification_manager()
    count = notification_manager.get_unread_count(user_id)
    
    return jsonify({'count': count})


@api_bp.route('/notifications/<int:notification_id>/read', methods=['POST'])
@api_auth_required
def mark_notification_read(notification_id):
    """Mark a notification as read."""
    from app.notification_manager import get_notification_manager
    
    user_id = g.api_user.id
    notification_manager = get_notification_manager()
    
    success = notification_manager.mark_as_read(notification_id, user_id)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Notification not found'}), 404


@api_bp.route('/notifications/read-all', methods=['POST'])
@api_auth_required
def mark_all_notifications_read():
    """Mark all notifications as read for the current user."""
    from app.notification_manager import get_notification_manager
    
    user_id = g.api_user.id
    notification_manager = get_notification_manager()
    
    notification_manager.mark_all_as_read(user_id)
    
    return jsonify({'success': True})


@api_bp.route('/notifications/<int:notification_id>', methods=['DELETE'])
@api_auth_required
def delete_notification(notification_id):
    """Delete a notification."""
    from app.notification_manager import get_notification_manager
    
    user_id = g.api_user.id
    notification_manager = get_notification_manager()
    
    success = notification_manager.delete_notification(notification_id, user_id)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Notification not found'}), 404
