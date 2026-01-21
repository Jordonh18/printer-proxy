"""
Flask API routes for React frontend
"""
from functools import wraps
from uuid import uuid4
from flask import Blueprint, request, jsonify, g, current_app, Response, stream_with_context
from datetime import datetime
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token, jwt_required, decode_token
)
from flask_jwt_extended.exceptions import JWTExtendedException

import sqlite3
from app.models import AuditLog, ActiveRedirect, GroupRedirectSchedule, PrinterRedirectSchedule, PrinterGroup, User, UserSession, get_db_connection
from app.auth import authenticate_user, validate_password_strength, hash_password, verify_password
from app.api_tokens import get_available_permissions
from app.notification_manager import get_notification_manager
import queue
from app.printers import get_registry, Printer
from app.printer_stats import get_printer_stats
import time
import secrets
import json
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
    """Decorator for API routes that require JWT authentication."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
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


def api_role_required(*roles):
    """Decorator to require specific roles for API routes."""
    def decorator(fn):
        @wraps(fn)
        @api_auth_required
        def wrapper(*args, **kwargs):
            user_role = g.api_claims.get('role', '')
            if user_role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def check_api_permission(required_permission: str):
    """Check if current user role has required permission."""
    role = g.api_claims.get('role', 'viewer') if hasattr(g, 'api_claims') else 'viewer'
    if required_permission not in get_available_permissions(role):
        return jsonify({'error': 'Insufficient permissions'}), 403
    return None


# ============================================================================
# JWT Authentication API Routes
# ============================================================================

@api_bp.route('/auth/login', methods=['POST'])
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


@api_bp.route('/auth/setup', methods=['GET', 'POST'])
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
    registry = get_registry()
    return jsonify(registry.get_all_statuses())


@api_bp.route('/printers/<printer_id>')
@api_auth_required
def api_printer(printer_id):
    """Get a specific printer with status."""
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


# ============================================================================
# Printer Groups API Routes
# ============================================================================

@api_bp.route('/printer-groups', methods=['GET'])
@api_auth_required
def api_printer_groups():
    """Get all printer groups with counts."""
    perm_check = check_api_permission('printers:read')
    if perm_check:
        return perm_check

    groups = PrinterGroup.get_all()
    return jsonify({'groups': groups})


@api_bp.route('/printer-groups/<int:group_id>', methods=['GET'])
@api_auth_required
def api_printer_group(group_id: int):
    """Get a printer group with members."""
    perm_check = check_api_permission('printers:read')
    if perm_check:
        return perm_check

    group = PrinterGroup.get_by_id(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    return jsonify(group)


@api_bp.route('/printer-groups', methods=['POST'])
@api_role_required('admin', 'operator')
def api_printer_group_create():
    """Create a printer group."""
    perm_check = check_api_permission('printers:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    if not name:
        return jsonify({'error': 'Group name is required'}), 400

    try:
        group = PrinterGroup.create(name=name, description=description, owner_user_id=g.api_user.id)
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_GROUP_CREATED',
            details=f"Created printer group '{name}'",
            success=True
        )
        return jsonify(group), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Group name already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/printer-groups/<int:group_id>', methods=['PUT'])
@api_role_required('admin', 'operator')
def api_printer_group_update(group_id: int):
    """Update a printer group."""
    perm_check = check_api_permission('printers:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    if not name:
        return jsonify({'error': 'Group name is required'}), 400

    existing = PrinterGroup.get_by_id(group_id)
    if not existing:
        return jsonify({'error': 'Group not found'}), 404
    if existing.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    try:
        group = PrinterGroup.update(group_id, name=name, description=description)
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_GROUP_UPDATED',
            details=f"Updated printer group '{name}'",
            success=True
        )
        return jsonify(group)
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Group name already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/printer-groups/<int:group_id>', methods=['DELETE'])
@api_role_required('admin', 'operator')
def api_printer_group_delete(group_id: int):
    """Delete a printer group."""
    perm_check = check_api_permission('printers:write')
    if perm_check:
        return perm_check

    existing = PrinterGroup.get_by_id(group_id)
    if not existing:
        return jsonify({'error': 'Group not found'}), 404
    if existing.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    deleted = PrinterGroup.delete(group_id)
    if not deleted:
        return jsonify({'error': 'Group not found'}), 404

    AuditLog.log(
        username=g.api_user.username,
        action='PRINTER_GROUP_DELETED',
        details=f"Deleted printer group ID {group_id}",
        success=True
    )
    return jsonify({'message': 'Group deleted'})


@api_bp.route('/printer-groups/<int:group_id>/printers', methods=['PUT'])
@api_role_required('admin', 'operator')
def api_printer_group_set_printers(group_id: int):
    """Set printer memberships for a group."""
    perm_check = check_api_permission('printers:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    printer_ids = data.get('printer_ids', [])
    if not isinstance(printer_ids, list):
        return jsonify({'error': 'printer_ids must be a list'}), 400

    group = PrinterGroup.get_by_id(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    if group.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    PrinterGroup.set_printers(group_id, printer_ids)
    AuditLog.log(
        username=g.api_user.username,
        action='PRINTER_GROUP_MEMBERS_UPDATED',
        details=f"Updated printers for group '{group.get('name')}'",
        success=True
    )
    return jsonify(PrinterGroup.get_by_id(group_id))


# ============================================================================
# Group Redirect Schedules API Routes
# ============================================================================

@api_bp.route('/group-redirect-schedules', methods=['GET'])
@api_auth_required
def api_group_redirect_schedules():
    """Get redirect schedules (optionally filtered by group)."""
    perm_check = check_api_permission('redirects:read')
    if perm_check:
        return perm_check

    group_id = request.args.get('group_id', type=int)
    schedules = GroupRedirectSchedule.get_all(group_id=group_id)
    return jsonify({'schedules': schedules})


@api_bp.route('/group-redirect-schedules', methods=['POST'])
@api_role_required('admin', 'operator')
def api_group_redirect_schedule_create():
    """Create a redirect schedule for a group."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    group_id = data.get('group_id')
    target_printer_id = data.get('target_printer_id')
    start_at = data.get('start_at')
    end_at = data.get('end_at')

    if not group_id or not target_printer_id or not start_at:
        return jsonify({'error': 'group_id, target_printer_id, and start_at are required'}), 400

    group = PrinterGroup.get_by_id(int(group_id))
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    if group.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    try:
        # Validate timestamps
        datetime.fromisoformat(start_at)
        if end_at:
            datetime.fromisoformat(end_at)
    except Exception:
        return jsonify({'error': 'Invalid date format'}), 400

    schedule = GroupRedirectSchedule.create(
        group_id=int(group_id),
        target_printer_id=target_printer_id,
        start_at=start_at,
        end_at=end_at,
        created_by=g.api_user.username
    )
    return jsonify(schedule), 201


@api_bp.route('/group-redirect-schedules/<int:schedule_id>', methods=['PUT'])
@api_role_required('admin', 'operator')
def api_group_redirect_schedule_update(schedule_id: int):
    """Update a redirect schedule for a group."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    target_printer_id = data.get('target_printer_id')
    start_at = data.get('start_at')
    end_at = data.get('end_at')
    enabled = bool(data.get('enabled', True))

    if not target_printer_id or not start_at:
        return jsonify({'error': 'target_printer_id and start_at are required'}), 400

    # Verify ownership via schedule -> group
    schedules = GroupRedirectSchedule.get_all()
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    group = PrinterGroup.get_by_id(schedule['group_id'])
    if not group or group.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    try:
        datetime.fromisoformat(start_at)
        if end_at:
            datetime.fromisoformat(end_at)
    except Exception:
        return jsonify({'error': 'Invalid date format'}), 400

    updated = GroupRedirectSchedule.update(schedule_id, target_printer_id, start_at, end_at, enabled)
    return jsonify(updated)


@api_bp.route('/group-redirect-schedules/<int:schedule_id>', methods=['DELETE'])
@api_role_required('admin', 'operator')
def api_group_redirect_schedule_delete(schedule_id: int):
    """Delete a redirect schedule."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    schedules = GroupRedirectSchedule.get_all()
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    group = PrinterGroup.get_by_id(schedule['group_id'])
    if not group or group.get('owner_user_id') != g.api_user.id:
        return jsonify({'error': 'You can only manage groups you own'}), 403

    deleted = GroupRedirectSchedule.delete(schedule_id)
    if not deleted:
        return jsonify({'error': 'Schedule not found'}), 404
    return jsonify({'message': 'Schedule deleted'})


# ============================================================================
# Printer Redirect Schedules API Routes
# ============================================================================

@api_bp.route('/printer-redirect-schedules', methods=['GET'])
@api_auth_required
def api_printer_redirect_schedules():
    """Get redirect schedules (optionally filtered by source printer)."""
    perm_check = check_api_permission('redirects:read')
    if perm_check:
        return perm_check

    source_printer_id = request.args.get('source_printer_id')
    schedules = PrinterRedirectSchedule.get_all(source_printer_id=source_printer_id)
    return jsonify({'schedules': schedules})


@api_bp.route('/printer-redirect-schedules', methods=['POST'])
@api_role_required('admin', 'operator')
def api_printer_redirect_schedule_create():
    """Create a redirect schedule for a printer."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    source_printer_id = data.get('source_printer_id')
    target_printer_id = data.get('target_printer_id')
    start_at = data.get('start_at')
    end_at = data.get('end_at')

    if not source_printer_id or not target_printer_id or not start_at:
        return jsonify({'error': 'source_printer_id, target_printer_id, and start_at are required'}), 400

    if source_printer_id == target_printer_id:
        return jsonify({'error': 'source_printer_id and target_printer_id must be different'}), 400

    registry = get_registry()
    if not registry.get_by_id(source_printer_id):
        return jsonify({'error': 'Source printer not found'}), 404
    if not registry.get_by_id(target_printer_id):
        return jsonify({'error': 'Target printer not found'}), 404

    try:
        datetime.fromisoformat(start_at)
        if end_at:
            datetime.fromisoformat(end_at)
    except Exception:
        return jsonify({'error': 'Invalid date format'}), 400

    schedule = PrinterRedirectSchedule.create(
        source_printer_id=source_printer_id,
        target_printer_id=target_printer_id,
        start_at=start_at,
        end_at=end_at,
        created_by=g.api_user.username
    )
    return jsonify(schedule), 201


@api_bp.route('/printer-redirect-schedules/<int:schedule_id>', methods=['PUT'])
@api_role_required('admin', 'operator')
def api_printer_redirect_schedule_update(schedule_id: int):
    """Update a redirect schedule for a printer."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    target_printer_id = data.get('target_printer_id')
    start_at = data.get('start_at')
    end_at = data.get('end_at')
    enabled = bool(data.get('enabled', True))

    if not target_printer_id or not start_at:
        return jsonify({'error': 'target_printer_id and start_at are required'}), 400

    schedules = PrinterRedirectSchedule.get_all()
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    registry = get_registry()
    if not registry.get_by_id(schedule['source_printer_id']):
        return jsonify({'error': 'Source printer not found'}), 404
    if not registry.get_by_id(target_printer_id):
        return jsonify({'error': 'Target printer not found'}), 404

    try:
        datetime.fromisoformat(start_at)
        if end_at:
            datetime.fromisoformat(end_at)
    except Exception:
        return jsonify({'error': 'Invalid date format'}), 400

    updated = PrinterRedirectSchedule.update(schedule_id, target_printer_id, start_at, end_at, enabled)
    return jsonify(updated)


@api_bp.route('/printer-redirect-schedules/<int:schedule_id>', methods=['DELETE'])
@api_role_required('admin', 'operator')
def api_printer_redirect_schedule_delete(schedule_id: int):
    """Delete a printer redirect schedule."""
    perm_check = check_api_permission('redirects:write')
    if perm_check:
        return perm_check

    schedules = PrinterRedirectSchedule.get_all()
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule not found'}), 404

    deleted = PrinterRedirectSchedule.delete(schedule_id)
    if not deleted:
        return jsonify({'error': 'Schedule not found'}), 404
    return jsonify({'message': 'Schedule deleted'})


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


# =========================================================================
# Group Notification Subscriptions API Routes
# =========================================================================

@api_bp.route('/notifications', methods=['GET'])
@api_auth_required
def api_notifications_list():
    """Get notifications for current user."""
    limit = request.args.get('limit', type=int) or 50
    offset = request.args.get('offset', type=int) or 0
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    manager = get_notification_manager()
    notifications = manager.get_user_notifications(
        user_id=g.api_user.id,
        limit=limit,
        offset=offset,
        unread_only=unread_only
    )
    return jsonify({'notifications': [n.to_dict() for n in notifications]})


@api_bp.route('/notifications/unread-count', methods=['GET'])
@api_auth_required
def api_notifications_unread_count():
    """Get unread notification count for current user."""
    manager = get_notification_manager()
    return jsonify({'count': manager.get_unread_count(g.api_user.id)})


@api_bp.route('/notifications/<int:notification_id>/read', methods=['POST'])
@api_auth_required
def api_notifications_mark_read(notification_id: int):
    """Mark a notification as read."""
    manager = get_notification_manager()
    success = manager.mark_as_read(notification_id, g.api_user.id)
    if not success:
        return jsonify({'error': 'Notification not found'}), 404
    return jsonify({'success': True})


@api_bp.route('/notifications/read-all', methods=['POST'])
@api_auth_required
def api_notifications_mark_all_read():
    """Mark all notifications as read for current user."""
    manager = get_notification_manager()
    manager.mark_all_as_read(g.api_user.id)
    return jsonify({'success': True})


@api_bp.route('/notifications/<int:notification_id>', methods=['DELETE'])
@api_auth_required
def api_notifications_delete(notification_id: int):
    """Delete a notification."""
    manager = get_notification_manager()
    success = manager.delete_notification(notification_id, g.api_user.id)
    if not success:
        return jsonify({'error': 'Notification not found'}), 404
    return jsonify({'success': True})


@api_bp.route('/notifications/stream')
def api_notifications_stream():
    """Server-Sent Events stream for notifications."""
    token = request.args.get('access_token')
    if not token:
        return jsonify({'error': 'Access token required'}), 401

    try:
        decoded = decode_token(token)
        user_id = decoded.get('sub')
        jti = decoded.get('jti')
        user = User.get_by_id(int(user_id)) if user_id is not None else None
        session = UserSession.get_by_jti(jti) if jti else None
        if not user or not user.is_active or not session or session.revoked_at:
            return jsonify({'error': 'Authentication required'}), 401
    except Exception:
        return jsonify({'error': 'Authentication required'}), 401

    manager = get_notification_manager()
    q = manager.register_connection(user.id)

    def stream():
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    notification = q.get(timeout=20)
                    payload = {'type': 'notification', 'notification': notification.to_dict()}
                    yield f"data: {json.dumps(payload)}\n\n"
                except queue.Empty:
                    payload = {'type': 'unread_count', 'count': manager.get_unread_count(user.id)}
                    yield f"data: {json.dumps(payload)}\n\n"
        finally:
            manager.unregister_connection(user.id, q)

    return Response(stream_with_context(stream()), mimetype='text/event-stream')

@api_bp.route('/notifications/subscriptions', methods=['GET'])
@api_auth_required
def get_notification_subscriptions():
    """Get group-based notification subscriptions for current user."""
    preference_key = request.args.get('preference')
    conn = get_db_connection()
    cursor = conn.cursor()

    if preference_key:
        cursor.execute(
            "SELECT group_id FROM user_group_subscriptions WHERE user_id = ? AND preference_key = ?",
            (g.api_user.id, preference_key)
        )
        rows = cursor.fetchall()
        conn.close()
        return jsonify({'preference': preference_key, 'group_ids': [row['group_id'] for row in rows]})

    cursor.execute(
        "SELECT preference_key, group_id FROM user_group_subscriptions WHERE user_id = ?",
        (g.api_user.id,)
    )
    rows = cursor.fetchall()
    conn.close()

    grouped = {}
    for row in rows:
        grouped.setdefault(row['preference_key'], []).append(row['group_id'])

    return jsonify({'subscriptions': grouped})


@api_bp.route('/notifications/subscriptions', methods=['PUT'])
@api_auth_required
def update_notification_subscriptions():
    """Update group-based notification subscriptions for current user."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400

    preference_key = data.get('preference')
    group_ids = data.get('group_ids', [])

    if not preference_key:
        return jsonify({'error': 'preference is required'}), 400

    if not isinstance(group_ids, list):
        return jsonify({'error': 'group_ids must be a list'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM user_group_subscriptions WHERE user_id = ? AND preference_key = ?",
        (g.api_user.id, preference_key)
    )

    if group_ids:
        cursor.executemany(
            "INSERT INTO user_group_subscriptions (user_id, group_id, preference_key) VALUES (?, ?, ?)",
            [(g.api_user.id, int(group_id), preference_key) for group_id in group_ids]
        )

    conn.commit()
    conn.close()

    return jsonify({'preference': preference_key, 'group_ids': group_ids})


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


@api_bp.route('/settings/notifications/smtp', methods=['GET', 'POST'])
@api_role_required('admin')
def api_settings_smtp():
    """Get or update SMTP notification settings."""
    from app.settings import get_settings_manager
    manager = get_settings_manager()
    
    if request.method == 'GET':
        smtp_settings = manager.get('notifications.smtp', {})
        smtp_settings = dict(smtp_settings)
        smtp_settings['password'] = '********' if smtp_settings.get('password') else ''
        return jsonify({'success': True, 'settings': smtp_settings})
    
    data = request.get_json() or {}
    
    try:
        current_smtp = manager.get('notifications.smtp', {})
        
        for field in ['enabled', 'host', 'port', 'username', 'from_address', 'to_addresses', 'use_tls', 'use_ssl']:
            if field in data:
                current_smtp[field] = data[field]
        
        if data.get('password'):
            current_smtp['password'] = data['password']
        
        manager.set('notifications.smtp', current_smtp)
        
        AuditLog.log(
            username=g.api_user.username,
            action='SETTINGS_UPDATED',
            details='SMTP notification settings updated'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/notifications/smtp/test', methods=['POST'])
@api_role_required('admin')
def api_settings_smtp_test():
    """Send a test email using current SMTP settings."""
    from app.notifications import SMTPNotificationChannel
    from app.settings import get_settings_manager

    data = request.get_json() or {}
    if data:
        smtp_settings = {
            'enabled': data.get('enabled', True),
            'host': data.get('host', ''),
            'port': data.get('port', 587),
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'from_address': data.get('from_address', ''),
            'to_addresses': data.get('to_addresses', ''),
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

    success = channel.send(
        subject="Printer Proxy - Test Notification",
        message="This is a test notification from Printer Proxy. If you received this, your notification settings are working correctly.",
        settings=settings,
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

