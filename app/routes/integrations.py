"""
API Routes for Integrations Marketplace.

Provides REST endpoints for:
- Listing available integrations
- Managing connection instances
- Testing connections
- Configuring event routing
- Handling webhooks
"""

import asyncio
import json
import logging
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models import get_db_connection, AuditLog

logger = logging.getLogger(__name__)

# Create blueprint
integrations_bp = Blueprint('integrations', __name__, url_prefix='/api/integrations')


def run_async(coro):
    """Run an async function synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def handle_integration_errors(fn):
    """Decorator to handle integration errors uniformly."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception(f'Integration API error: {e}')
            return jsonify({
                'error': 'INTERNAL_ERROR',
                'message': str(e),
            }), 500
    return wrapper


# =============================================================================
# Integration Catalog
# =============================================================================

@integrations_bp.route('/catalog', methods=['GET'])
@jwt_required()
@handle_integration_errors
def list_integrations():
    """
    List all available integrations from the database.
    
    Query params:
    - category: Filter by category
    - search: Search by name/description
    """
    category = request.args.get('category')
    search = request.args.get('search')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Build query based on filters
    query = "SELECT * FROM integrations WHERE enabled = 1"
    params = []
    
    if category:
        query += " AND category = ?"
        params.append(category)
    
    if search:
        query += " AND (name LIKE ? OR description LIKE ?)"
        search_pattern = f'%{search}%'
        params.extend([search_pattern, search_pattern])
    
    query += " ORDER BY display_order, name"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Convert rows to dict
    result = []
    categories_count = {}
    
    for row in rows:
        integration = {
            'id': row['id'],
            'name': row['name'],
            'description': row['description'],
            'category': row['category'],
            'auth_type': row['auth_type'],
            'capabilities': json.loads(row['capabilities']) if row['capabilities'] else [],
            'icon': row['icon'],
            'color': row['color'],
            'version': row['version'],
            'vendor': row['vendor'],
            'docs_url': row['docs_url'],
            'support_url': row['support_url'],
            'beta': bool(row['beta']),
            'deprecated': bool(row['deprecated']),
        }
        result.append(integration)
        
        # Count categories
        cat = row['category']
        categories_count[cat] = categories_count.get(cat, 0) + 1
    
    conn.close()
    
    return jsonify({
        'integrations': result,
        'categories': categories_count,
    })


@integrations_bp.route('/catalog/<integration_id>', methods=['GET'])
@jwt_required()
@handle_integration_errors
def get_integration(integration_id: str):
    """Get details of a specific integration including config schema from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM integrations WHERE id = ? AND enabled = 1", (integration_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Integration not found'}), 404
    
    # Parse JSON fields
    config_schema = json.loads(row['config_schema']) if row['config_schema'] else []
    capabilities = json.loads(row['capabilities']) if row['capabilities'] else []
    
    return jsonify({
        'id': row['id'],
        'name': row['name'],
        'description': row['description'],
        'category': row['category'],
        'auth_type': row['auth_type'],
        'capabilities': capabilities,
        'icon': row['icon'],
        'color': row['color'],
        'version': row['version'],
        'vendor': row['vendor'],
        'docs_url': row['docs_url'],
        'support_url': row['support_url'],
        'config_schema': config_schema,
        'beta': bool(row['beta']),
        'deprecated': bool(row['deprecated']),
    })


# =============================================================================
# Connection Management
# =============================================================================

@integrations_bp.route('/connections', methods=['GET'])
@jwt_required()
@handle_integration_errors
def list_connections():
    """
    List all integration connections for the current user.
    
    Query params:
    - integration_id: Filter by integration type
    - include_disabled: Include disabled connections
    """
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    integration_id = request.args.get('integration_id')
    include_disabled = request.args.get('include_disabled', '').lower() == 'true'
    
    connections = manager.list_connections(
        user_id=user_id,
        integration_id=integration_id,
        include_disabled=include_disabled,
    )
    
    # Mask sensitive fields
    for conn in connections:
        conn.pop('credentials_encrypted', None)
    
    return jsonify({'connections': connections})


@integrations_bp.route('/connections', methods=['POST'])
@jwt_required()
@handle_integration_errors
def create_connection():
    """Create a new integration connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    integration_id = data.get('integration_id')
    name = data.get('name')
    description = data.get('description', '')
    config = data.get('config', {})
    credentials = data.get('credentials', {})
    
    if not integration_id:
        return jsonify({'error': 'integration_id is required'}), 400
    
    if not name:
        return jsonify({'error': 'name is required'}), 400
    
    manager = get_integration_manager()
    connection_id, error = manager.create_connection(
        integration_id=integration_id,
        name=name,
        user_id=user_id,
        config=config,
        credentials=credentials,
        description=description,
    )
    
    if error:
        return jsonify({'error': error}), 400
    
    # Log the action
    AuditLog.create(
        username=f'user:{user_id}',
        action='integration.connection.created',
        details=json.dumps({
            'connection_id': connection_id,
            'integration_id': integration_id,
            'name': name,
        }),
        success=True,
    )
    
    return jsonify({
        'connection_id': connection_id,
        'message': 'Connection created successfully',
    }), 201


@integrations_bp.route('/connections/<connection_id>', methods=['GET'])
@jwt_required()
@handle_integration_errors
def get_connection(connection_id: str):
    """Get details of a specific connection."""
    from app.services.integrations import get_integration_manager
    from app.services.integrations.crypto import CredentialValidator
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    connection = manager.get_connection(connection_id, include_credentials=True)
    
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    # Check ownership
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Mask sensitive credentials for display
    masked_credentials = {}
    for key, value in connection.get('credentials', {}).items():
        if isinstance(value, str) and len(value) > 0:
            masked_credentials[key] = CredentialValidator.mask_credential(value)
        else:
            masked_credentials[key] = value
    
    connection['credentials'] = masked_credentials
    
    return jsonify(connection)


@integrations_bp.route('/connections/<connection_id>', methods=['PUT'])
@jwt_required()
@handle_integration_errors
def update_connection(connection_id: str):
    """Update an integration connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    success, error = manager.update_connection(
        connection_id=connection_id,
        user_id=user_id,
        name=data.get('name'),
        description=data.get('description'),
        config=data.get('config'),
        credentials=data.get('credentials'),
        enabled=data.get('enabled'),
    )
    
    if not success:
        return jsonify({'error': error}), 400
    
    # Log the action
    AuditLog.create(
        username=f'user:{user_id}',
        action='integration.connection.updated',
        details=json.dumps({
            'connection_id': connection_id,
            'fields_updated': list(data.keys()),
        }),
        success=True,
    )
    
    return jsonify({'message': 'Connection updated successfully'})


@integrations_bp.route('/connections/<connection_id>', methods=['DELETE'])
@jwt_required()
@handle_integration_errors
def delete_connection(connection_id: str):
    """Delete an integration connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    success, error = manager.delete_connection(connection_id, user_id)
    
    if not success:
        return jsonify({'error': error}), 400
    
    # Log the action
    AuditLog.create(
        username=f'user:{user_id}',
        action='integration.connection.deleted',
        details=json.dumps({
            'connection_id': connection_id,
            'integration_id': connection['integration_id'],
        }),
        success=True,
    )
    
    return jsonify({'message': 'Connection deleted successfully'})


# =============================================================================
# Connection Actions
# =============================================================================

@integrations_bp.route('/connections/<connection_id>/test', methods=['POST'])
@jwt_required()
@handle_integration_errors
def test_connection(connection_id: str):
    """Test an integration connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Run test connection
    success, health_data = run_async(manager.test_connection(connection_id))
    
    return jsonify({
        'success': success,
        'health': health_data,
    })


@integrations_bp.route('/connections/<connection_id>/connect', methods=['POST'])
@jwt_required()
@handle_integration_errors
def connect_integration(connection_id: str):
    """Activate/connect an integration."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    success, error = run_async(manager.connect(connection_id))
    
    if not success:
        return jsonify({'error': error}), 400
    
    # Log the action
    AuditLog.create(
        username=f'user:{user_id}',
        action='integration.connection.connected',
        details=json.dumps({'connection_id': connection_id}),
        success=True,
    )
    
    return jsonify({'message': 'Connection activated successfully'})


@integrations_bp.route('/connections/<connection_id>/disconnect', methods=['POST'])
@jwt_required()
@handle_integration_errors
def disconnect_integration(connection_id: str):
    """Deactivate/disconnect an integration."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    success, error = run_async(manager.disconnect(connection_id))
    
    if not success:
        return jsonify({'error': error}), 400
    
    # Log the action
    AuditLog.create(
        username=f'user:{user_id}',
        action='integration.connection.disconnected',
        details=json.dumps({'connection_id': connection_id}),
        success=True,
    )
    
    return jsonify({'message': 'Connection deactivated successfully'})


# =============================================================================
# Event Routing
# =============================================================================

@integrations_bp.route('/connections/<connection_id>/routing', methods=['GET'])
@jwt_required()
@handle_integration_errors
def get_event_routing(connection_id: str):
    """Get event routing configuration for a connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    routings = manager.get_event_routing(connection_id)
    
    return jsonify({
        'routings': [
            {
                'event_type': r.event_type,
                'enabled': r.enabled,
                'filters': r.filters,
                'transform': r.transform,
                'priority': r.priority,
            }
            for r in routings
        ]
    })


@integrations_bp.route('/connections/<connection_id>/routing', methods=['POST'])
@jwt_required()
@handle_integration_errors
def set_event_routing(connection_id: str):
    """Set event routing for a connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    event_type = data.get('event_type')
    if not event_type:
        return jsonify({'error': 'event_type is required'}), 400
    
    success, error = manager.set_event_routing(
        connection_id=connection_id,
        event_type=event_type,
        enabled=data.get('enabled', True),
        filters=data.get('filters'),
        transform=data.get('transform'),
        priority=data.get('priority', 0),
    )
    
    if not success:
        return jsonify({'error': error}), 400
    
    return jsonify({'message': 'Event routing configured successfully'})


# =============================================================================
# Available Event Types
# =============================================================================

@integrations_bp.route('/events', methods=['GET'])
@jwt_required()
@handle_integration_errors
def list_event_types():
    """List available event types for routing."""
    event_types = [
        {
            'type': 'printer.online',
            'description': 'Printer came online',
            'category': 'health',
        },
        {
            'type': 'printer.offline',
            'description': 'Printer went offline',
            'category': 'health',
        },
        {
            'type': 'printer.error',
            'description': 'Printer reported an error',
            'category': 'health',
        },
        {
            'type': 'redirect.created',
            'description': 'Print redirect was created',
            'category': 'redirect',
        },
        {
            'type': 'redirect.removed',
            'description': 'Print redirect was removed',
            'category': 'redirect',
        },
        {
            'type': 'job.completed',
            'description': 'Print job completed',
            'category': 'job',
        },
        {
            'type': 'job.failed',
            'description': 'Print job failed',
            'category': 'job',
        },
        {
            'type': 'workflow.triggered',
            'description': 'Workflow was triggered',
            'category': 'workflow',
        },
        {
            'type': 'security.login',
            'description': 'User logged in',
            'category': 'security',
        },
        {
            'type': 'security.login_failed',
            'description': 'Failed login attempt',
            'category': 'security',
        },
    ]
    
    return jsonify({'event_types': event_types})


# =============================================================================
# Webhook Endpoints
# =============================================================================

@integrations_bp.route('/webhooks/<connection_id>', methods=['POST'])
@handle_integration_errors
def handle_webhook(connection_id: str):
    """
    Handle incoming webhook from an integration.
    
    This endpoint is publicly accessible (no JWT) as it receives
    callbacks from third-party services.
    """
    import hashlib
    import hmac
    import time
    
    from app.services.integrations import get_integration_manager
    
    manager = get_integration_manager()
    
    # Get connection (don't require credentials)
    connection = manager.get_connection(connection_id, include_credentials=False)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    # Parse payload
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = {}
    
    headers = dict(request.headers)
    
    # Store webhook event for audit
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate event ID for deduplication
        event_id = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:32]
        
        # Check for replay (duplicate event_id within 24 hours)
        cursor.execute("""
            SELECT id FROM integration_webhook_events
            WHERE event_id = ? AND received_at > datetime('now', '-24 hours')
        """, (event_id,))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({'status': 'duplicate', 'message': 'Event already processed'}), 200
        
        # Store the event
        cursor.execute("""
            INSERT INTO integration_webhook_events
            (connection_id, event_id, event_type, payload, headers)
            VALUES (?, ?, ?, ?, ?)
        """, (
            connection_id,
            event_id,
            payload.get('type') or payload.get('event_type', 'unknown'),
            json.dumps(payload),
            json.dumps(headers),
        ))
        
        webhook_event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f'Failed to store webhook event: {e}')
    
    # Process the webhook asynchronously
    # For now, just acknowledge receipt
    # TODO: Queue for async processing
    
    return jsonify({
        'status': 'received',
        'message': 'Webhook received successfully',
    }), 200


# =============================================================================
# Connection History
# =============================================================================

@integrations_bp.route('/connections/<connection_id>/history', methods=['GET'])
@jwt_required()
@handle_integration_errors
def get_connection_history(connection_id: str):
    """Get history/audit log for a connection."""
    from app.services.integrations import get_integration_manager
    
    user_id = get_jwt_identity()
    manager = get_integration_manager()
    
    # Verify ownership
    connection = manager.get_connection(connection_id)
    if not connection:
        return jsonify({'error': 'Connection not found'}), 404
    
    if connection['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    limit = min(int(request.args.get('limit', 50)), 100)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM integration_connection_history
        WHERE connection_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (connection_id, limit))
    
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            'id': row['id'],
            'action': row['action'],
            'details': json.loads(row['details']) if row['details'] else None,
            'status': row['status'],
            'error_message': row['error_message'],
            'created_at': row['created_at'],
        })
    
    return jsonify({'history': history})
