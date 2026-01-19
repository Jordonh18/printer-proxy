"""
Flask API routes for React frontend
"""
from functools import wraps
from uuid import uuid4
from flask import Blueprint, request, jsonify, g, current_app
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token, jwt_required
)
from flask_jwt_extended.exceptions import JWTExtendedException

from app.models import AuditLog, ActiveRedirect, User
from app.auth import authenticate_user, validate_password_strength, hash_password
from app.printers import get_registry, Printer
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
            user = User.get_by_id(int(user_id)) if user_id is not None else None
            if user and user.is_active:
                g.api_user = user
                g.api_claims = get_jwt()
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
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    client_ip = request.remote_addr
    user, error = authenticate_user(username, password, client_ip)
    
    if user is None:
        return jsonify({'error': error}), 401
    
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'username': user.username,
            'role': user.role
        }
    )
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role
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
    return jsonify({'access_token': access_token})


@api_bp.route('/auth/me')
@jwt_required()
def api_auth_me():
    """Get current user info from JWT token."""
    user_id = get_jwt_identity()
    user = User.get_by_id(int(user_id)) if user_id is not None else None
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'is_active': user.is_active,
        'last_login': _serialize_timestamp(user.last_login)
    })


@api_bp.route('/auth/logout', methods=['POST'])
def api_auth_logout():
    """Logout endpoint (client should discard tokens)."""
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
    
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    success, message = create_initial_admin(username, password)
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
        registry.delete(printer_id)
        
        AuditLog.log(
            username=g.api_user.username,
            action='PRINTER_DELETED',
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
    role = data.get('role', 'viewer').strip()
    is_active = data.get('is_active', True)
    
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
        user = User.create(username, hash_password(password), role=role, is_active=is_active)
        AuditLog.log(
            username=g.api_user.username,
            action='USER_CREATED',
            details=f"Created user '{username}' with role '{role}'",
            success=True
        )
        return jsonify({
            'id': user.id,
            'username': user.username,
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
        'id': log.id,
        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
        'username': log.username,
        'action': log.action,
        'details': log.details,
        'source_printer_id': log.source_printer_id,
        'target_printer_id': log.target_printer_id,
        'success': log.success,
        'error_message': log.error_message
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
    from app.notifications import get_notification_manager
    
    manager = get_notification_manager()
    success, message = manager.test_channel('smtp')
    
    if success:
        AuditLog.log(
            username=g.api_user.username,
            action='SMTP_TEST',
            details='Test email sent successfully'
        )
    
    return jsonify({
        'success': success,
        'message': message if success else None,
        'error': message if not success else None
    })


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

