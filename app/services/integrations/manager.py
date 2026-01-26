"""
Integration Manager.

Manages connection instances, event routing, and integration lifecycle.
Provides the main API for interacting with integrations.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.models import get_db_connection
from .base import (
    IntegrationBase,
    IntegrationError,
    IntegrationStatus,
    ConnectionHealth,
    EventRouting,
)
from .crypto import get_credential_encryption, CredentialValidator
from .registry import get_integration_registry

logger = logging.getLogger(__name__)


# Sensitive fields that should be encrypted
SENSITIVE_FIELDS = [
    'api_key', 'api_token', 'secret_key', 'password', 'client_secret',
    'access_token', 'refresh_token', 'private_key', 'webhook_secret',
    'hec_token', 'bearer_token', 'auth_token',
]


class IntegrationManager:
    """
    Manages integration connections and their lifecycle.
    
    Provides:
    - Connection CRUD operations
    - Connection health monitoring
    - Event routing configuration
    - Credential management
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
        self._active_connections: Dict[str, IntegrationBase] = {}
        self._health_check_task: Optional[asyncio.Task] = None
        self._crypto = get_credential_encryption()
        self._registry = get_integration_registry()
        self._ensure_tables()
    
    def _ensure_tables(self):
        """Ensure required database tables exist."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Integrations metadata table (catalog of available integrations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integrations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT NOT NULL,
                    icon TEXT,
                    color TEXT,
                    version TEXT,
                    vendor TEXT,
                    auth_type TEXT NOT NULL,
                    capabilities TEXT,
                    config_schema TEXT,
                    docs_url TEXT,
                    support_url TEXT,
                    beta INTEGER DEFAULT 0,
                    deprecated INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1,
                    display_order INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Connection instances table (user-specific configurations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integration_connections (
                    id TEXT PRIMARY KEY,
                    integration_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    config TEXT,
                    credentials_encrypted TEXT,
                    oauth_state TEXT,
                    granted_scopes TEXT,
                    status TEXT DEFAULT 'disconnected',
                    last_connected_at TIMESTAMP,
                    last_error TEXT,
                    error_count INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deleted_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Create indexes for connection queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_integration_connections_user
                ON integration_connections(user_id, deleted_at)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_integration_connections_integration
                ON integration_connections(integration_id, deleted_at)
            """)
            
            # Event routing table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integration_event_routing (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    filters TEXT,
                    transform TEXT,
                    priority INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES integration_connections(id) ON DELETE CASCADE,
                    UNIQUE(connection_id, event_type)
                )
            """)
            
            # Connection history for audit
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integration_connection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    user_id INTEGER,
                    details TEXT,
                    status TEXT,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES integration_connections(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Webhook events table for inbound webhooks
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integration_webhook_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id TEXT NOT NULL,
                    event_id TEXT UNIQUE,
                    event_type TEXT,
                    payload TEXT,
                    headers TEXT,
                    signature_valid INTEGER,
                    processed INTEGER DEFAULT 0,
                    processed_at TIMESTAMP,
                    error TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES integration_connections(id) ON DELETE CASCADE
                )
            """)
            
            # Create index for webhook event deduplication
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_webhook_events_event_id
                ON integration_webhook_events(event_id)
            """)
            
            # OAuth tokens table (separate from main credentials for security)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS integration_oauth_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id TEXT UNIQUE NOT NULL,
                    access_token_encrypted TEXT,
                    refresh_token_encrypted TEXT,
                    token_type TEXT DEFAULT 'Bearer',
                    scope TEXT,
                    expires_at TIMESTAMP,
                    refresh_expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES integration_connections(id) ON DELETE CASCADE
                )
            """)
            
            conn.commit()
            conn.close()
            
            logger.info('Integration database tables initialized')
            
        except Exception as e:
            logger.error(f'Failed to initialize integration tables: {e}')
    
    def _auto_setup_event_routing(self, connection_id: str, integration_id: str):
        """
        Auto-configure event routing based on integration category.
        
        This automatically sets up appropriate event types for the integration
        based on its category (LOGGING, MONITORING, ALERTING).
        """
        try:
            metadata = self._registry.get_metadata(integration_id)
            if not metadata:
                return
            
            category = metadata.category.value
            
            # Define default event routing by category
            event_types = {
                'LOGGING': [
                    'printer.added', 'printer.removed', 'printer.offline', 'printer.online',
                    'redirect.created', 'redirect.removed', 
                    'job.completed', 'job.failed',
                    'group.created', 'group.updated', 'group.deleted',
                    'workflow.started', 'workflow.completed', 'workflow.failed',
                    'security.login_failed', 'security.account_locked',
                    'system.info', 'system.warning', 'system.error'
                ],
                'MONITORING': [
                    'printer.offline', 'printer.online', 'printer.error',
                    'redirect.failed', 
                    'job.failed',
                    'workflow.failed',
                    'system.error', 'system.warning'
                ],
                'ALERTING': [
                    'printer.offline', 'printer.error', 
                    'redirect.failed',
                    'job.failed',
                    'workflow.failed',
                    'security.account_locked',
                    'system.error'
                ],
            }
            
            routing_events = event_types.get(category, [])
            
            if not routing_events:
                return
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            for event_type in routing_events:
                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO integration_event_routing
                        (connection_id, event_type, enabled, priority)
                        VALUES (?, ?, 1, 0)
                    """, (connection_id, event_type))
                except Exception as e:
                    logger.warning(f'Failed to add routing for {event_type}: {e}')
            
            conn.commit()
            conn.close()
            
            logger.info(f'Auto-configured {len(routing_events)} event routes for {connection_id}')
            
        except Exception as e:
            logger.error(f'Failed to auto-setup event routing: {e}')
    
    # =========================================================================
    # Connection Management
    # =========================================================================
    
    def create_connection(self, integration_id: str, name: str, user_id: int,
                         config: Dict[str, Any], credentials: Dict[str, Any],
                         description: str = '') -> Tuple[Optional[str], Optional[str]]:
        """
        Create a new integration connection.
        
        Args:
            integration_id: The integration type ID.
            name: Display name for this connection.
            user_id: ID of the user creating the connection.
            config: Configuration settings.
            credentials: Sensitive credentials (will be encrypted).
            description: Optional description.
            
        Returns:
            Tuple of (connection_id, error_message).
        """
        # Validate integration exists
        integration_metadata = self._registry.get_metadata(integration_id)
        if not integration_metadata:
            return None, f'Integration not found: {integration_id}'
        
        # Validate configuration
        integration_class = self._registry.get(integration_id)
        if integration_class:
            temp_instance = integration_class.__new__(integration_class)
            temp_instance.config = config
            errors = temp_instance.validate_config(config)
            if errors:
                return None, '; '.join(errors)
        
        try:
            connection_id = str(uuid.uuid4())
            
            # Encrypt sensitive credentials
            encrypted_credentials = self._crypto.encrypt_dict(credentials, SENSITIVE_FIELDS)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO integration_connections
                (id, integration_id, name, description, user_id, config, credentials_encrypted, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                connection_id,
                integration_id,
                name,
                description,
                user_id,
                json.dumps(config),
                json.dumps(encrypted_credentials),
                IntegrationStatus.DISCONNECTED.value,
            ))
            
            # Log the action
            cursor.execute("""
                INSERT INTO integration_connection_history
                (connection_id, action, user_id, details, status)
                VALUES (?, ?, ?, ?, ?)
            """, (
                connection_id,
                'created',
                user_id,
                json.dumps({'integration': integration_id, 'name': name}),
                IntegrationStatus.DISCONNECTED.value,
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f'Created integration connection: {connection_id} ({integration_id})')
            return connection_id, None
            
        except Exception as e:
            logger.error(f'Failed to create connection: {e}')
            return None, str(e)
    
    def get_connection(self, connection_id: str, 
                       include_credentials: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get a connection by ID.
        
        Args:
            connection_id: The connection ID.
            include_credentials: Whether to include decrypted credentials.
            
        Returns:
            Connection data or None if not found.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM integration_connections
                WHERE id = ? AND deleted_at IS NULL
            """, (connection_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            result = dict(row)
            result['config'] = json.loads(result['config'] or '{}')
            
            if include_credentials:
                encrypted = json.loads(result['credentials_encrypted'] or '{}')
                result['credentials'] = self._crypto.decrypt_dict(encrypted, SENSITIVE_FIELDS)
            else:
                result['credentials'] = {}
            
            del result['credentials_encrypted']
            
            # Get integration metadata
            metadata = self._registry.get_metadata(result['integration_id'])
            if metadata:
                result['integration'] = {
                    'id': metadata.id,
                    'name': metadata.name,
                    'category': metadata.category.value,
                    'icon': metadata.icon,
                    'color': metadata.color,
                }
            
            return result
            
        except Exception as e:
            logger.error(f'Failed to get connection: {e}')
            return None
    
    def list_connections(self, user_id: Optional[int] = None,
                        integration_id: Optional[str] = None,
                        include_disabled: bool = False) -> List[Dict[str, Any]]:
        """
        List integration connections.
        
        Args:
            user_id: Filter by user ID.
            integration_id: Filter by integration type.
            include_disabled: Include disabled connections.
            
        Returns:
            List of connection data.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            query = """
                SELECT id, integration_id, name, description, user_id,
                       config, status, last_connected_at, last_error,
                       error_count, enabled, created_at, updated_at
                FROM integration_connections
                WHERE deleted_at IS NULL
            """
            params = []
            
            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if integration_id:
                query += " AND integration_id = ?"
                params.append(integration_id)
            
            if not include_disabled:
                query += " AND enabled = 1"
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                data = dict(row)
                data['config'] = json.loads(data['config'] or '{}')
                
                # Get integration metadata
                metadata = self._registry.get_metadata(data['integration_id'])
                if metadata:
                    data['integration'] = {
                        'id': metadata.id,
                        'name': metadata.name,
                        'category': metadata.category.value,
                        'icon': metadata.icon,
                        'color': metadata.color,
                    }
                
                results.append(data)
            
            return results
            
        except Exception as e:
            logger.error(f'Failed to list connections: {e}')
            return []
    
    def update_connection(self, connection_id: str, user_id: int,
                         name: Optional[str] = None,
                         description: Optional[str] = None,
                         config: Optional[Dict[str, Any]] = None,
                         credentials: Optional[Dict[str, Any]] = None,
                         enabled: Optional[bool] = None) -> Tuple[bool, Optional[str]]:
        """
        Update an integration connection.
        
        Args:
            connection_id: The connection ID.
            user_id: ID of the user making the update.
            name: New display name.
            description: New description.
            config: New configuration.
            credentials: New credentials (will be encrypted).
            enabled: Enable/disable the connection.
            
        Returns:
            Tuple of (success, error_message).
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get existing connection
            cursor.execute("""
                SELECT * FROM integration_connections
                WHERE id = ? AND deleted_at IS NULL
            """, (connection_id,))
            
            existing = cursor.fetchone()
            if not existing:
                conn.close()
                return False, 'Connection not found'
            
            # Build update query
            updates = []
            params = []
            changes = {}
            
            if name is not None:
                updates.append("name = ?")
                params.append(name)
                changes['name'] = name
            
            if description is not None:
                updates.append("description = ?")
                params.append(description)
                changes['description'] = description
            
            if config is not None:
                # Validate new configuration
                integration_class = self._registry.get(existing['integration_id'])
                if integration_class:
                    temp_instance = integration_class.__new__(integration_class)
                    temp_instance.config = config
                    errors = temp_instance.validate_config(config)
                    if errors:
                        conn.close()
                        return False, '; '.join(errors)
                
                updates.append("config = ?")
                params.append(json.dumps(config))
                changes['config_updated'] = True
            
            if credentials is not None:
                encrypted = self._crypto.encrypt_dict(credentials, SENSITIVE_FIELDS)
                updates.append("credentials_encrypted = ?")
                params.append(json.dumps(encrypted))
                changes['credentials_updated'] = True
            
            if enabled is not None:
                updates.append("enabled = ?")
                params.append(1 if enabled else 0)
                changes['enabled'] = enabled
            
            if not updates:
                conn.close()
                return True, None
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            
            query = f"UPDATE integration_connections SET {', '.join(updates)} WHERE id = ?"
            params.append(connection_id)
            
            cursor.execute(query, params)
            
            # Log the action
            cursor.execute("""
                INSERT INTO integration_connection_history
                (connection_id, action, user_id, details)
                VALUES (?, ?, ?, ?)
            """, (
                connection_id,
                'updated',
                user_id,
                json.dumps(changes),
            ))
            
            conn.commit()
            conn.close()
            
            # If connection is active, reconnect with new settings
            if connection_id in self._active_connections:
                asyncio.create_task(self._reconnect(connection_id))
            
            logger.info(f'Updated integration connection: {connection_id}')
            return True, None
            
        except Exception as e:
            logger.error(f'Failed to update connection: {e}')
            return False, str(e)
    
    def delete_connection(self, connection_id: str, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Soft delete an integration connection.
        
        Args:
            connection_id: The connection ID.
            user_id: ID of the user deleting the connection.
            
        Returns:
            Tuple of (success, error_message).
        """
        try:
            # Disconnect if active
            if connection_id in self._active_connections:
                asyncio.create_task(self.disconnect(connection_id))
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE integration_connections
                SET deleted_at = CURRENT_TIMESTAMP, enabled = 0
                WHERE id = ? AND deleted_at IS NULL
            """, (connection_id,))
            
            if cursor.rowcount == 0:
                conn.close()
                return False, 'Connection not found'
            
            # Log the action
            cursor.execute("""
                INSERT INTO integration_connection_history
                (connection_id, action, user_id, details)
                VALUES (?, ?, ?, ?)
            """, (
                connection_id,
                'deleted',
                user_id,
                json.dumps({'soft_delete': True}),
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f'Deleted integration connection: {connection_id}')
            return True, None
            
        except Exception as e:
            logger.error(f'Failed to delete connection: {e}')
            return False, str(e)
    
    # =========================================================================
    # Connection Lifecycle
    # =========================================================================
    
    async def connect(self, connection_id: str) -> Tuple[bool, Optional[str]]:
        """
        Establish a connection.
        
        Args:
            connection_id: The connection ID.
            
        Returns:
            Tuple of (success, error_message).
        """
        connection_data = self.get_connection(connection_id, include_credentials=True)
        if not connection_data:
            return False, 'Connection not found'
        
        integration_id = connection_data['integration_id']
        instance = self._registry.create_instance(
            integration_id=integration_id,
            connection_id=connection_id,
            config=connection_data['config'],
            credentials=connection_data['credentials'],
        )
        
        if not instance:
            return False, f'Failed to create integration instance: {integration_id}'
        
        try:
            await instance.connect()
            self._active_connections[connection_id] = instance
            
            # Update status in database
            self._update_connection_status(
                connection_id,
                IntegrationStatus.CONNECTED,
            )
            
            # Auto-setup event routing based on integration category
            self._auto_setup_event_routing(connection_id, integration_id)
            
            logger.info(f'Connected: {connection_id}')
            return True, None
            
        except IntegrationError as e:
            self._update_connection_status(
                connection_id,
                IntegrationStatus.ERROR,
                error=e.message,
            )
            return False, e.message
        except Exception as e:
            self._update_connection_status(
                connection_id,
                IntegrationStatus.ERROR,
                error=str(e),
            )
            return False, str(e)
    
    async def disconnect(self, connection_id: str) -> Tuple[bool, Optional[str]]:
        """
        Disconnect a connection.
        
        Args:
            connection_id: The connection ID.
            
        Returns:
            Tuple of (success, error_message).
        """
        instance = self._active_connections.pop(connection_id, None)
        
        if instance:
            try:
                await instance.disconnect()
            except Exception as e:
                logger.warning(f'Error during disconnect: {e}')
        
        self._update_connection_status(
            connection_id,
            IntegrationStatus.DISCONNECTED,
        )
        
        logger.info(f'Disconnected: {connection_id}')
        return True, None
    
    async def test_connection(self, connection_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Test a connection.
        
        Args:
            connection_id: The connection ID.
            
        Returns:
            Tuple of (success, health_data).
        """
        connection_data = self.get_connection(connection_id, include_credentials=True)
        if not connection_data:
            return False, {'error': 'Connection not found'}
        
        integration_id = connection_data['integration_id']
        instance = self._registry.create_instance(
            integration_id=integration_id,
            connection_id=connection_id,
            config=connection_data['config'],
            credentials=connection_data['credentials'],
        )
        
        if not instance:
            return False, {'error': f'Failed to create integration instance'}
        
        try:
            health = await instance.test_connection()
            
            return health.status == IntegrationStatus.CONNECTED, {
                'status': health.status.value,
                'last_check': health.last_check.isoformat() if health.last_check else None,
                'last_success': health.last_success.isoformat() if health.last_success else None,
                'last_error': health.last_error,
                'response_time_ms': health.response_time_ms,
                'details': health.details,
            }
            
        except IntegrationError as e:
            return False, e.to_dict()
        except Exception as e:
            return False, {'error': str(e)}
    
    async def _reconnect(self, connection_id: str):
        """Reconnect an active connection with new settings."""
        await self.disconnect(connection_id)
        await self.connect(connection_id)
    
    def _update_connection_status(self, connection_id: str, status: IntegrationStatus,
                                   error: Optional[str] = None):
        """Update connection status in the database."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if status == IntegrationStatus.CONNECTED:
                cursor.execute("""
                    UPDATE integration_connections
                    SET status = ?, last_connected_at = CURRENT_TIMESTAMP,
                        last_error = NULL, error_count = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status.value, connection_id))
            else:
                if error:
                    cursor.execute("""
                        UPDATE integration_connections
                        SET status = ?, last_error = ?, error_count = error_count + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (status.value, error, connection_id))
                else:
                    cursor.execute("""
                        UPDATE integration_connections
                        SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (status.value, connection_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f'Failed to update connection status: {e}')
    
    # =========================================================================
    # Event Routing
    # =========================================================================
    
    def get_event_routing(self, connection_id: str) -> List[EventRouting]:
        """Get event routing configuration for a connection."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM integration_event_routing
                WHERE connection_id = ?
                ORDER BY priority DESC, event_type
            """, (connection_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [
                EventRouting(
                    event_type=row['event_type'],
                    enabled=bool(row['enabled']),
                    filters=json.loads(row['filters'] or '{}'),
                    transform=json.loads(row['transform']) if row['transform'] else None,
                    priority=row['priority'],
                )
                for row in rows
            ]
            
        except Exception as e:
            logger.error(f'Failed to get event routing: {e}')
            return []
    
    def set_event_routing(self, connection_id: str, event_type: str,
                         enabled: bool = True, filters: Optional[Dict] = None,
                         transform: Optional[Dict] = None,
                         priority: int = 0) -> Tuple[bool, Optional[str]]:
        """Set event routing for a connection."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO integration_event_routing
                (connection_id, event_type, enabled, filters, transform, priority)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(connection_id, event_type) DO UPDATE SET
                    enabled = excluded.enabled,
                    filters = excluded.filters,
                    transform = excluded.transform,
                    priority = excluded.priority,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                connection_id,
                event_type,
                1 if enabled else 0,
                json.dumps(filters or {}),
                json.dumps(transform) if transform else None,
                priority,
            ))
            
            conn.commit()
            conn.close()
            
            return True, None
            
        except Exception as e:
            logger.error(f'Failed to set event routing: {e}')
            return False, str(e)
    
    # =========================================================================
    # Event Sending
    # =========================================================================
    
    async def send_event(self, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send an event to all configured integrations.
        
        Args:
            event_type: The type of event (e.g., 'printer.offline', 'redirect.created').
            event_data: The event data.
            
        Returns:
            Summary of delivery results.
        """
        results = {
            'event_type': event_type,
            'sent': 0,
            'failed': 0,
            'skipped': 0,
            'details': [],
        }
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get all enabled routings for this event type
            cursor.execute("""
                SELECT r.*, c.id as connection_id, c.integration_id
                FROM integration_event_routing r
                JOIN integration_connections c ON r.connection_id = c.id
                WHERE r.event_type = ? AND r.enabled = 1 AND c.enabled = 1
                      AND c.deleted_at IS NULL
                ORDER BY r.priority DESC
            """, (event_type,))
            
            routings = cursor.fetchall()
            conn.close()
            
            for routing in routings:
                connection_id = routing['connection_id']
                
                # Check if connection is active
                if connection_id not in self._active_connections:
                    # Try to connect
                    success, _ = await self.connect(connection_id)
                    if not success:
                        results['skipped'] += 1
                        continue
                
                instance = self._active_connections.get(connection_id)
                if not instance:
                    results['skipped'] += 1
                    continue
                
                try:
                    # Apply filters
                    filters = json.loads(routing['filters'] or '{}')
                    if not self._matches_filters(event_data, filters):
                        results['skipped'] += 1
                        continue
                    
                    # Apply transform
                    transform = json.loads(routing['transform']) if routing['transform'] else None
                    log_data = self._apply_transform(event_data, transform)
                    
                    # Send log
                    await instance.send_log(log_data)
                    results['sent'] += 1
                    results['details'].append({
                        'connection_id': connection_id,
                        'status': 'sent',
                    })
                    
                except IntegrationError as e:
                    results['failed'] += 1
                    results['details'].append({
                        'connection_id': connection_id,
                        'status': 'failed',
                        'error': e.message,
                    })
                except Exception as e:
                    results['failed'] += 1
                    results['details'].append({
                        'connection_id': connection_id,
                        'status': 'failed',
                        'error': str(e),
                    })
            
        except Exception as e:
            logger.error(f'Failed to send event: {e}')
            results['error'] = str(e)
        
        return results
    
    def _matches_filters(self, data: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if event data matches the configured filters."""
        if not filters:
            return True
        
        for key, value in filters.items():
            if key not in data:
                return False
            
            if isinstance(value, list):
                if data[key] not in value:
                    return False
            elif data[key] != value:
                return False
        
        return True
    
    def _apply_transform(self, data: Dict[str, Any], 
                        transform: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply transformation to event data."""
        if not transform:
            return data
        
        result = data.copy()
        
        # Field mapping
        if 'field_map' in transform:
            for src, dst in transform['field_map'].items():
                if src in result:
                    result[dst] = result.pop(src)
        
        # Field removal
        if 'exclude_fields' in transform:
            for field in transform['exclude_fields']:
                result.pop(field, None)
        
        # Add static fields
        if 'add_fields' in transform:
            result.update(transform['add_fields'])
        
        return result


def get_integration_manager() -> IntegrationManager:
    """Get the singleton IntegrationManager instance."""
    return IntegrationManager()
