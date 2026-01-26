"""
Database models for Continuum
"""
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import json
import uuid

from config.config import DATABASE_PATH, DATA_DIR


def get_db_connection() -> sqlite3.Connection:
    """Get a database connection with row factory and optimized settings."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    # Enable WAL mode for better concurrent access
    conn.execute('PRAGMA journal_mode=WAL')
    # Optimize for concurrent reads/writes
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA temp_store=MEMORY')
    
    return conn


def _seed_example_workflows(cursor):
    """Seed database with example workflows."""
    
    # Example 1: Printer Offline Alert
    wf1_id = uuid.uuid4().hex
    wf1_webhook_id = uuid.uuid4().hex
    wf1_webhook_secret = uuid.uuid4().hex
    
    workflow1 = {
        'id': wf1_id,
        'name': 'Printer Offline Alert',
        'description': 'Send email notification when a printer goes offline',
        'enabled': 1,
        'nodes': [
            {
                'id': 'node_trigger',
                'type': 'trigger.health_change',
                'label': 'Printer Goes Offline',
                'position': {'x': 100, 'y': 100},
                'properties': {
                    'state': 'offline',
                    'printer_id': '',  # Any printer
                    'description': 'Triggers when any printer goes offline'
                }
            },
            {
                'id': 'node_email',
                'type': 'action.notify.email',
                'label': 'Send Email Alert',
                'position': {'x': 400, 'y': 100},
                'properties': {
                    'to': 'admin@example.com',
                    'subject': 'Printer {{printer_name}} is Offline',
                    'message': 'Printer {{printer_name}} ({{printer_ip}}) went offline at {{timestamp}}'
                }
            }
        ],
        'edges': [
            {
                'id': 'edge_1',
                'source': 'node_trigger',
                'target': 'node_email',
                'sourceHandle': 'out',
                'targetHandle': 'in'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 2: Auto-Redirect on Failure
    wf2_id = uuid.uuid4().hex
    
    workflow2 = {
        'id': wf2_id,
        'name': 'Auto-Redirect on Printer Failure',
        'description': 'Automatically create redirect when printer goes offline',
        'enabled': 1,
        'nodes': [
            {
                'id': 'node_trigger',
                'type': 'trigger.health_change',
                'label': 'Printer Goes Offline',
                'position': {'x': 100, 'y': 100},
                'properties': {
                    'state': 'offline',
                    'printer_id': '',
                    'description': 'Triggers when printer goes offline'
                }
            },
            {
                'id': 'node_redirect',
                'type': 'action.redirect',
                'label': 'Create Redirect',
                'position': {'x': 400, 'y': 100},
                'properties': {
                    'printer_id': '{{printer_id}}',
                    'target_printer_id': '',  # User should configure target
                    'description': 'Redirect traffic to backup printer'
                }
            },
            {
                'id': 'node_notify',
                'type': 'action.notify.inapp',
                'label': 'Send Notification',
                'position': {'x': 700, 'y': 100},
                'properties': {
                    'title': 'Redirect Created',
                    'message': 'Traffic from {{printer_name}} redirected to backup printer',
                    'type': 'info'
                }
            }
        ],
        'edges': [
            {
                'id': 'edge_1',
                'source': 'node_trigger',
                'target': 'node_redirect',
                'sourceHandle': 'out',
                'targetHandle': 'in'
            },
            {
                'id': 'edge_2',
                'source': 'node_redirect',
                'target': 'node_notify',
                'sourceHandle': 'out',
                'targetHandle': 'in'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 3: Scheduled Health Report
    wf3_id = uuid.uuid4().hex
    
    workflow3 = {
        'id': wf3_id,
        'name': 'Daily Printer Health Report',
        'description': 'Send daily email with printer status summary',
        'enabled': 0,  # Disabled by default
        'nodes': [
            {
                'id': 'node_trigger',
                'type': 'trigger.schedule',
                'label': 'Daily at 9 AM',
                'position': {'x': 100, 'y': 100},
                'properties': {
                    'schedule_type': 'cron',
                    'cron': '0 9 * * *',
                    'description': 'Runs every day at 9:00 AM'
                }
            },
            {
                'id': 'node_email',
                'type': 'action.notify.email',
                'label': 'Send Health Report',
                'position': {'x': 400, 'y': 100},
                'properties': {
                    'to': 'admin@example.com',
                    'subject': 'Daily Printer Health Report',
                    'message': 'Daily printer status report generated at {{timestamp}}'
                }
            }
        ],
        'edges': [
            {
                'id': 'edge_1',
                'source': 'node_trigger',
                'target': 'node_email',
                'sourceHandle': 'out',
                'targetHandle': 'in'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 4: Webhook Integration
    wf4_id = uuid.uuid4().hex
    wf4_webhook_id = uuid.uuid4().hex
    wf4_webhook_secret = uuid.uuid4().hex
    
    workflow4 = {
        'id': wf4_id,
        'name': 'External System Integration',
        'description': 'Receive webhook from external system and log audit event',
        'enabled': 1,
        'nodes': [
            {
                'id': 'node_trigger',
                'type': 'trigger.webhook',
                'label': 'Webhook Trigger',
                'position': {'x': 100, 'y': 100},
                'properties': {
                    'hook_id': wf4_webhook_id,
                    'hook_secret': wf4_webhook_secret,
                    'description': 'External webhook endpoint'
                }
            },
            {
                'id': 'node_audit',
                'type': 'action.audit',
                'label': 'Log Event',
                'position': {'x': 400, 'y': 100},
                'properties': {
                    'event_type': 'external_webhook',
                    'message': 'Webhook received from external system: {{payload}}'
                }
            }
        ],
        'edges': [
            {
                'id': 'edge_1',
                'source': 'node_trigger',
                'target': 'node_audit',
                'sourceHandle': 'out',
                'targetHandle': 'in'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Insert workflows
    for workflow in [workflow1, workflow2, workflow3, workflow4]:
        cursor.execute("""
            INSERT INTO workflows (id, name, description, enabled, nodes, edges, ui_state, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            workflow['id'],
            workflow['name'],
            workflow['description'],
            workflow['enabled'],
            json.dumps(workflow['nodes']),
            json.dumps(workflow['edges']),
            json.dumps(workflow['ui_state']),
            workflow['created_by'],
            workflow['created_at'],
            workflow['updated_at']
        ))


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
            syslog_enabled BOOLEAN DEFAULT 0,
            syslog_configured_at TIMESTAMP,
            snmp_write_community TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Add syslog columns for existing installs
    cursor.execute("PRAGMA table_info(printers)")
    printer_columns = {row[1] for row in cursor.fetchall()}
    if 'syslog_enabled' not in printer_columns:
        cursor.execute("ALTER TABLE printers ADD COLUMN syslog_enabled BOOLEAN DEFAULT 0")
    if 'syslog_configured_at' not in printer_columns:
        cursor.execute("ALTER TABLE printers ADD COLUMN syslog_configured_at TIMESTAMP")
    if 'snmp_write_community' not in printer_columns:
        cursor.execute("ALTER TABLE printers ADD COLUMN snmp_write_community TEXT")

    # Printer groups table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            owner_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Ensure owner_user_id exists for older installs
    cursor.execute("PRAGMA table_info(printer_groups)")
    group_columns = {row[1] for row in cursor.fetchall()}
    if 'owner_user_id' not in group_columns:
        cursor.execute("ALTER TABLE printer_groups ADD COLUMN owner_user_id INTEGER")
        cursor.execute("UPDATE printer_groups SET owner_user_id = 1 WHERE owner_user_id IS NULL")

    # Printer group members table (one group per printer enforced by UNIQUE)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_group_members (
            group_id INTEGER NOT NULL,
            printer_id TEXT NOT NULL UNIQUE,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES printer_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (printer_id) REFERENCES printers(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_printer_group_members_group
        ON printer_group_members(group_id)
    """)

    # Group redirect schedules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_redirect_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            target_printer_id TEXT NOT NULL,
            start_at TIMESTAMP NOT NULL,
            end_at TIMESTAMP,
            enabled BOOLEAN DEFAULT 1,
            is_active BOOLEAN DEFAULT 0,
            last_activated_at TIMESTAMP,
            last_deactivated_at TIMESTAMP,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES printer_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (target_printer_id) REFERENCES printers(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_group_redirect_schedules_group
        ON group_redirect_schedules(group_id)
    """)

    # Printer redirect schedules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_redirect_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_printer_id TEXT NOT NULL,
            target_printer_id TEXT NOT NULL,
            start_at TIMESTAMP NOT NULL,
            end_at TIMESTAMP,
            enabled BOOLEAN DEFAULT 1,
            is_active BOOLEAN DEFAULT 0,
            last_activated_at TIMESTAMP,
            last_deactivated_at TIMESTAMP,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_printer_id) REFERENCES printers(id) ON DELETE CASCADE,
            FOREIGN KEY (target_printer_id) REFERENCES printers(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_printer_redirect_schedules_source
        ON printer_redirect_schedules(source_printer_id)
    """)

    # Group redirect instances (track redirects created by schedules)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_redirect_instances (
            schedule_id INTEGER NOT NULL,
            redirect_id INTEGER NOT NULL,
            source_printer_id TEXT NOT NULL,
            PRIMARY KEY (schedule_id, redirect_id),
            FOREIGN KEY (schedule_id) REFERENCES group_redirect_schedules(id) ON DELETE CASCADE,
            FOREIGN KEY (redirect_id) REFERENCES active_redirects(id) ON DELETE CASCADE
        )
    """)

    # Printer redirect instances (track redirects created by schedules)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_redirect_instances (
            schedule_id INTEGER NOT NULL,
            redirect_id INTEGER NOT NULL,
            source_printer_id TEXT NOT NULL,
            PRIMARY KEY (schedule_id, redirect_id),
            FOREIGN KEY (schedule_id) REFERENCES printer_redirect_schedules(id) ON DELETE CASCADE,
            FOREIGN KEY (redirect_id) REFERENCES active_redirects(id) ON DELETE CASCADE
        )
    """)

    # Group-based notification subscriptions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_group_subscriptions (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            preference_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, group_id, preference_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES printer_groups(id) ON DELETE CASCADE
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

    # Workflow registry nodes (server-driven node catalog)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workflow_registry_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            category TEXT NOT NULL,
            color TEXT DEFAULT '#10b981',
            icon TEXT DEFAULT 'Workflow',
            inputs TEXT,
            outputs TEXT,
            config_schema TEXT,
            default_properties TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_workflow_registry_category
        ON workflow_registry_nodes(category)
    """)

    # Add output_schema column if it doesn't exist (migration)
    cursor.execute("PRAGMA table_info(workflow_registry_nodes)")
    registry_columns = {row['name'] for row in cursor.fetchall()}
    if 'output_schema' not in registry_columns:
        cursor.execute("ALTER TABLE workflow_registry_nodes ADD COLUMN output_schema TEXT")

    # Workflows table (simplified JSON schema)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workflows (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            nodes TEXT,
            edges TEXT,
            ui_state TEXT,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    # Seed or update workflow registry defaults
    cursor.execute("SELECT node_key FROM workflow_registry_nodes")
    existing_keys = {row['node_key'] for row in cursor.fetchall()}

    default_nodes = [
        {
            'node_key': 'trigger.schedule',
            'name': 'Schedule Trigger',
            'description': 'Start a workflow on a cron schedule.',
            'category': 'trigger',
            'color': '#22c55e',
            'icon': 'CalendarClock',
            'inputs': [],
            'outputs': [{'id': 'out', 'label': 'Run', 'type': 'flow'}],
            'output_schema': [
                {'key': 'scheduled_time', 'type': 'string', 'description': 'Scheduled execution time'},
                {'key': 'timestamp', 'type': 'string', 'description': 'ISO timestamp of execution'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'cron', 'label': 'Cron', 'type': 'string', 'placeholder': '0 9 * * 1-5'},
                    {'key': 'timezone', 'label': 'Timezone', 'type': 'string', 'placeholder': 'UTC'}
                ]
            },
            'default_properties': {'cron': '0 9 * * 1-5', 'timezone': 'UTC'}
        },
        {
            'node_key': 'trigger.event',
            'name': 'Event Trigger',
            'description': 'Start when a printer or system event occurs.',
            'category': 'trigger',
            'color': '#22c55e',
            'icon': 'Zap',
            'inputs': [],
            'outputs': [{'id': 'out', 'label': 'Run', 'type': 'flow'}],
            'output_schema': [
                {'key': 'event_type', 'type': 'string', 'description': 'Type of event triggered'},
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'ID of affected printer'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of affected printer'},
                {'key': 'printer_ip', 'type': 'ip_address', 'description': 'IP address of printer'},
                {'key': 'timestamp', 'type': 'timestamp', 'description': 'When the event occurred (ISO format)'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'event_type',
                        'label': 'Event Type',
                        'type': 'select',
                        'options': [
                            {'label': 'Printer Offline', 'value': 'printer_offline'},
                            {'label': 'Printer Online', 'value': 'printer_online'},
                            {'label': 'Job Failed', 'value': 'job_failed'},
                            {'label': 'Job Completed', 'value': 'job_completed'},
                            {'label': 'Redirect Activated', 'value': 'redirect_activated'}
                        ]
                    }
                ]
            },
            'default_properties': {'event_type': 'printer_offline'}
        },
        {
            'node_key': 'trigger.webhook',
            'name': 'Webhook Trigger',
            'description': 'Start when an incoming webhook is received.',
            'category': 'trigger',
            'color': '#22c55e',
            'icon': 'Webhook',
            'inputs': [],
            'outputs': [{'id': 'out', 'label': 'Run', 'type': 'flow'}],
            'output_schema': [
                {'key': 'payload', 'type': 'object', 'description': 'JSON payload from webhook request'},
                {'key': 'headers', 'type': 'object', 'description': 'HTTP headers from request'},
                {'key': 'method', 'type': 'string', 'description': 'HTTP method (GET/POST)'},
                {'key': 'timestamp', 'type': 'string', 'description': 'ISO timestamp of when webhook was received'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'path',
                        'label': 'Webhook Endpoint',
                        'type': 'string',
                        'placeholder': '/webhooks/workflows',
                        'readOnly': True,
                        'helperText': 'Generated automatically for this workflow trigger.'
                    },
                    {
                        'key': 'secret',
                        'label': 'Shared Secret',
                        'type': 'string',
                        'readOnly': True,
                        'helperText': 'Use this secret when calling the webhook.'
                    }
                ]
            },
            'default_properties': {'path': '/webhooks/printer', 'secret': ''}
        },
        {
            'node_key': 'trigger.queue_threshold',
            'name': 'Queue Threshold',
            'description': 'Start when a printer queue exceeds a threshold.',
            'category': 'trigger',
            'color': '#22c55e',
            'icon': 'ListFilter',
            'inputs': [],
            'outputs': [{'id': 'out', 'label': 'Run', 'type': 'flow'}],
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'ID of the printer'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of the printer'},
                {'key': 'queue_count', 'type': 'number', 'description': 'Current queue count'},
                {'key': 'threshold', 'type': 'number', 'description': 'Threshold value that was exceeded'},
                {'key': 'timestamp', 'type': 'timestamp', 'description': 'When threshold was exceeded'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Choose the printer to monitor.',
                        'icon': 'Printer'
                    },
                    {'key': 'min_jobs', 'label': 'Minimum Jobs', 'type': 'number'}
                ]
            },
            'default_properties': {'printer_id': '', 'min_jobs': 5}
        },
        {
            'node_key': 'trigger.health_change',
            'name': 'Health Change',
            'description': 'Trigger workflow when a printer goes online or offline.',
            'category': 'trigger',
            'color': '#22c55e',
            'icon': 'Activity',
            'inputs': [],
            'outputs': [{'id': 'out', 'label': 'Run', 'type': 'flow'}],
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'ID of the affected printer'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Display name of the printer'},
                {'key': 'printer_ip', 'type': 'ip_address', 'description': 'IP address of the printer'},
                {'key': 'old_state', 'type': 'string', 'description': 'Previous health state (online/offline)'},
                {'key': 'new_state', 'type': 'string', 'description': 'New health state (online/offline)'},
                {'key': 'timestamp', 'type': 'timestamp', 'description': 'When the state change occurred (ISO format)'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Monitor Printer',
                        'type': 'printer_id',
                        'helperText': 'Select which printer to monitor for health changes. Leave empty to monitor all printers.',
                        'placeholder': 'All printers',
                        'icon': 'Printer'
                    },
                    {
                        'key': 'state',
                        'label': 'Trigger On State',
                        'type': 'select',
                        'options': [
                            {'label': 'Goes Offline', 'value': 'offline'},
                            {'label': 'Comes Online', 'value': 'online'},
                            {'label': 'Any Change', 'value': 'any'}
                        ],
                        'helperText': 'Which state transition should trigger this workflow.',
                        'required': True,
                        'icon': 'Activity'
                    }
                ]
            },
            'default_properties': {'printer_id': '', 'state': 'offline'}
        },
        {
            'node_key': 'action.print',
            'name': 'Print Job',
            'description': 'Send a document to a printer.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'Printer',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'job_id', 'type': 'string', 'description': 'ID of the print job created'},
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'ID of the printer used'},
                {'key': 'document_path', 'type': 'string', 'description': 'Path to the printed document'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether job was submitted successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Select the destination printer.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'required': True,
                        'icon': 'Printer'
                    },
                    {
                        'key': 'document_path',
                        'label': 'Document Path',
                        'type': 'string',
                        'placeholder': '/path/to/document.pdf',
                        'helperText': 'File path to the document to print.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'icon': 'File'
                    },
                    {'key': 'copies', 'label': 'Copies', 'type': 'number'}
                ]
            },
            'default_properties': {'printer_id': '', 'document_path': '', 'copies': 1}
        },
        {
            'node_key': 'action.redirect',
            'name': 'Activate Redirect',
            'description': 'Route print traffic from one printer to another. Jobs sent to the source printer will be forwarded to the target.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'ArrowRightLeft',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'redirect_id', 'type': 'string', 'description': 'ID of the redirect created'},
                {'key': 'source_printer_id', 'type': 'printer_id', 'description': 'Source printer ID'},
                {'key': 'source_printer_name', 'type': 'string', 'description': 'Source printer name'},
                {'key': 'source_printer_ip', 'type': 'ip_address', 'description': 'Source printer IP address'},
                {'key': 'target_printer_id', 'type': 'printer_id', 'description': 'Target printer ID'},
                {'key': 'target_printer_name', 'type': 'string', 'description': 'Target printer name'},
                {'key': 'target_printer_ip', 'type': 'ip_address', 'description': 'Target printer IP address'},
                {'key': 'port', 'type': 'number', 'description': 'Port used for redirect'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether redirect was created successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'source_printer_id',
                        'label': 'Source Printer',
                        'type': 'printer_id',
                        'helperText': 'The offline or failing printer whose traffic should be redirected.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'required': True,
                        'group': 'redirect',
                        'icon': 'Printer'
                    },
                    {
                        'key': 'target_printer_id',
                        'label': 'Target Printer',
                        'type': 'printer_id',
                        'helperText': 'The working printer that will receive the redirected traffic.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'required': True,
                        'group': 'redirect',
                        'icon': 'Printer'
                    },
                    {
                        'key': 'port',
                        'label': 'Port',
                        'type': 'number',
                        'placeholder': '9100',
                        'helperText': 'Network port for print traffic (default: 9100 for RAW printing).',
                        'group': 'advanced',
                        'icon': 'Hash'
                    }
                ]
            },
            'default_properties': {'source_printer_id': '', 'target_printer_id': '', 'port': 9100}
        },
        {
            'node_key': 'action.redirect.disable',
            'name': 'Deactivate Redirect',
            'description': 'Disable an active redirect for a printer.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'ArrowRightLeft',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'source_printer_id', 'type': 'printer_id', 'description': 'Printer that was redirected'},
                {'key': 'source_printer_name', 'type': 'string', 'description': 'Name of source printer'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether redirect was disabled successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'source_printer_id',
                        'label': 'Source Printer',
                        'type': 'printer_id',
                        'helperText': 'Select the printer with an active redirect.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'icon': 'Printer'
                    }
                ]
            },
            'default_properties': {'source_printer_id': ''}
        },
        {
            'node_key': 'action.queue.pause',
            'name': 'Pause Print Queue',
            'description': 'Pause all jobs for a printer queue.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'PauseCircle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'Printer whose queue was paused'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of the printer'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether queue was paused successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Choose the queue to pause.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'icon': 'Printer'
                    }
                ]
            },
            'default_properties': {'printer_id': ''}
        },
        {
            'node_key': 'action.queue.resume',
            'name': 'Resume Print Queue',
            'description': 'Resume processing for a printer queue.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'PlayCircle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'Printer whose queue was resumed'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of the printer'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether queue was resumed successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Choose the queue to resume.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'icon': 'Printer'
                    }
                ]
            },
            'default_properties': {'printer_id': ''}
        },
        {
            'node_key': 'action.queue.clear',
            'name': 'Clear Print Queue',
            'description': 'Delete all pending jobs for a printer.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'Trash2',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'Printer whose queue was cleared'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of the printer'},
                {'key': 'jobs_cleared', 'type': 'number', 'description': 'Number of jobs removed'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether queue was cleared successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Choose the queue to clear.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'icon': 'Printer'
                    }
                ]
            },
            'default_properties': {'printer_id': ''}
        },
        {
            'node_key': 'action.notify.email',
            'name': 'Send Email',
            'description': 'Send an email notification to one or more recipients.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'Mail',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'to', 'type': 'email', 'description': 'Email recipient address'},
                {'key': 'subject', 'type': 'string', 'description': 'Email subject line'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether email was sent successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'to',
                        'label': 'Recipient Email',
                        'type': 'email',
                        'placeholder': 'user@example.com',
                        'helperText': 'Enter email address(es). Separate multiple with commas.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['email', 'string'],
                        'required': True,
                        'group': 'recipient',
                        'icon': 'AtSign'
                    },
                    {
                        'key': 'subject',
                        'label': 'Subject Line',
                        'type': 'string',
                        'placeholder': 'Printer Alert: {{printer_name}}',
                        'helperText': 'Email subject. Use {{variable}} to include dynamic data.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'required': True,
                        'group': 'content',
                        'icon': 'Type'
                    },
                    {
                        'key': 'body',
                        'label': 'Email Body',
                        'type': 'textarea',
                        'placeholder': 'Printer {{printer_name}} ({{printer_ip}}) has gone offline.',
                        'helperText': 'Email content. Supports {{variable}} syntax for dynamic values.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'required': True,
                        'group': 'content',
                        'icon': 'FileText'
                    }
                ]
            },
            'default_properties': {'to': '', 'subject': 'Workflow Alert', 'body': ''}
        },
        {
            'node_key': 'action.notify.inapp',
            'name': 'In-App Notification',
            'description': 'Create an in-app notification visible to dashboard users.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'Bell',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'notification_id', 'type': 'string', 'description': 'ID of the notification created'},
                {'key': 'title', 'type': 'string', 'description': 'Notification title'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether notification was created successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'title',
                        'label': 'Notification Title',
                        'type': 'string',
                        'placeholder': 'Printer Alert',
                        'helperText': 'Short title shown in notification banner.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'required': True,
                        'icon': 'Type'
                    },
                    {
                        'key': 'message',
                        'label': 'Message',
                        'type': 'textarea',
                        'placeholder': 'Printer {{printer_name}} requires attention.',
                        'helperText': 'Notification body content. Supports {{variable}} syntax.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'required': True,
                        'icon': 'MessageSquare'
                    },
                    {
                        'key': 'link',
                        'label': 'Action Link',
                        'type': 'url',
                        'placeholder': '/printers/{{printer_id}}',
                        'helperText': 'Optional URL to navigate when notification is clicked.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string', 'url'],
                        'icon': 'ExternalLink'
                    }
                ]
            },
            'default_properties': {'title': '', 'message': '', 'link': ''}
        },
        {
            'node_key': 'action.audit',
            'name': 'Audit Log Entry',
            'description': 'Record an action to the audit trail for compliance and tracking.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'ClipboardList',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'action', 'type': 'string', 'description': 'Action that was logged'},
                {'key': 'details', 'type': 'string', 'description': 'Details of the action'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether log entry was created'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'action',
                        'label': 'Action Type',
                        'type': 'select',
                        'options': [
                            {'label': 'Workflow Action', 'value': 'WORKFLOW_ACTION'},
                            {'label': 'Redirect Created', 'value': 'REDIRECT_CREATED'},
                            {'label': 'Redirect Removed', 'value': 'REDIRECT_REMOVED'},
                            {'label': 'Alert Triggered', 'value': 'ALERT_TRIGGERED'},
                            {'label': 'Custom', 'value': 'CUSTOM'}
                        ],
                        'helperText': 'Type of action to record in audit log.',
                        'required': True,
                        'icon': 'Tag'
                    },
                    {
                        'key': 'details',
                        'label': 'Details',
                        'type': 'textarea',
                        'placeholder': 'Printer {{printer_name}} redirect activated by workflow.',
                        'helperText': 'Detailed description of the action. Supports {{variable}} syntax.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'icon': 'FileText'
                    }
                ]
            },
            'default_properties': {'action': 'WORKFLOW_ACTION', 'details': ''}
        },
        {
            'node_key': 'action.printer.note',
            'name': 'Update Printer Notes',
            'description': 'Append a note to a printer record.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'StickyNote',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'printer_id', 'type': 'printer_id', 'description': 'Printer that was updated'},
                {'key': 'printer_name', 'type': 'string', 'description': 'Name of the printer'},
                {'key': 'note', 'type': 'string', 'description': 'Note that was added'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether note was added successfully'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'printer_id',
                        'label': 'Printer',
                        'type': 'printer_id',
                        'helperText': 'Choose the printer to update.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['printer_id', 'string'],
                        'icon': 'Printer'
                    },
                    {
                        'key': 'note',
                        'label': 'Note',
                        'type': 'textarea',
                        'placeholder': 'Add a note about printer {{printer_name}}',
                        'helperText': 'Note content to append. Supports {{variable}} syntax.',
                        'supportsDynamic': True,
                        'acceptsTypes': ['string'],
                        'icon': 'StickyNote'
                    }
                ]
            },
            'default_properties': {'printer_id': '', 'note': ''}
        },
        {
            'node_key': 'action.end',
            'name': 'End Workflow',
            'description': 'Stop processing this workflow branch.',
            'category': 'action',
            'color': '#38bdf8',
            'icon': 'StopCircle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [],
            'allow_multiple_inputs': True,
            'output_schema': [],
            'config_schema': None,
            'default_properties': {}
        },
        {
            'node_key': 'transform.filter',
            'name': 'Filter',
            'description': 'Filter items by condition.',
            'category': 'transform',
            'color': '#a855f7',
            'icon': 'Filter',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'data'}],
            'outputs': [{'id': 'out', 'label': 'Out', 'type': 'data'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'matched', 'type': 'boolean', 'description': 'Whether the filter condition matched'},
                {'key': 'data', 'type': 'object', 'description': 'Filtered data (passed through if matched)'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'expression',
                        'label': 'Filter Condition',
                        'type': 'select',
                        'options': [
                            {'label': 'Printer Offline', 'value': 'printer_offline'},
                            {'label': 'Printer Online', 'value': 'printer_online'},
                            {'label': 'Queue High', 'value': 'queue_high'},
                            {'label': 'Queue Empty', 'value': 'queue_empty'},
                            {'label': 'Redirect Active', 'value': 'redirect_active'},
                            {'label': 'Redirect Inactive', 'value': 'redirect_inactive'},
                            {'label': 'Job Failed', 'value': 'job_failed'}
                        ],
                        'helperText': 'Select a built-in condition to filter data.'
                    }
                ]
            },
            'default_properties': {'expression': 'printer_offline'}
        },
        {
            'node_key': 'transform.map_fields',
            'name': 'Map Fields',
            'description': 'Map incoming data fields to new keys.',
            'category': 'transform',
            'color': '#a855f7',
            'icon': 'Shuffle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'data'}],
            'outputs': [{'id': 'out', 'label': 'Out', 'type': 'data'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'data', 'type': 'object', 'description': 'Data with remapped field names'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'mappings', 'label': 'Mappings (JSON)', 'type': 'string', 'supportsDynamic': True}
                ]
            },
            'default_properties': {'mappings': '{"source":"target"}'}
        },
        {
            'node_key': 'transform.template',
            'name': 'Template',
            'description': 'Render a text template from data.',
            'category': 'transform',
            'color': '#a855f7',
            'icon': 'Type',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'data'}],
            'outputs': [{'id': 'out', 'label': 'Out', 'type': 'data'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'result', 'type': 'string', 'description': 'Rendered template string'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'template', 'label': 'Template', 'type': 'string', 'supportsDynamic': True},
                    {'key': 'output_key', 'label': 'Output Key', 'type': 'string', 'placeholder': 'result'}
                ]
            },
            'default_properties': {'template': 'Printer {{printer_id}} is offline.', 'output_key': 'result'}
        },
        {
            'node_key': 'logic.if',
            'name': 'If / Else',
            'description': 'Branch based on a condition.',
            'category': 'conditional',
            'color': '#f97316',
            'icon': 'Split',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [
                {'id': 'true', 'label': 'True', 'type': 'flow'},
                {'id': 'false', 'label': 'False', 'type': 'flow'}
            ],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'condition_result', 'type': 'boolean', 'description': 'Result of the condition evaluation'},
                {'key': 'branch', 'type': 'string', 'description': 'Which branch was taken (true/false)'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'expression',
                        'label': 'Condition',
                        'type': 'select',
                        'options': [
                            {'label': 'Printer Offline', 'value': 'printer_offline'},
                            {'label': 'Printer Online', 'value': 'printer_online'},
                            {'label': 'Queue High', 'value': 'queue_high'},
                            {'label': 'Queue Empty', 'value': 'queue_empty'},
                            {'label': 'Redirect Active', 'value': 'redirect_active'},
                            {'label': 'Redirect Inactive', 'value': 'redirect_inactive'},
                            {'label': 'Job Failed', 'value': 'job_failed'}
                        ],
                        'helperText': 'Select a built-in condition for this branch.'
                    }
                ]
            },
            'default_properties': {'expression': 'printer_offline'}
        },
        {
            'node_key': 'logic.switch',
            'name': 'Switch',
            'description': 'Route flow based on matching cases.',
            'category': 'conditional',
            'color': '#f97316',
            'icon': 'SwitchCamera',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [
                {'id': 'case1', 'label': 'Case 1', 'type': 'flow'},
                {'id': 'case2', 'label': 'Case 2', 'type': 'flow'},
                {'id': 'default', 'label': 'Default', 'type': 'flow'}
            ],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'matched_case', 'type': 'string', 'description': 'Which case was matched (case1/case2/default)'},
                {'key': 'switch_value', 'type': 'string', 'description': 'The value that was evaluated'}
            ],
            'config_schema': {
                'fields': [
                    {
                        'key': 'value',
                        'label': 'Switch On',
                        'type': 'select',
                        'options': [
                            {'label': 'Printer State', 'value': 'printer_state'},
                            {'label': 'Queue State', 'value': 'queue_state'},
                            {'label': 'Redirect State', 'value': 'redirect_state'}
                        ]
                    },
                    {
                        'key': 'case1',
                        'label': 'Case 1',
                        'type': 'select',
                        'options': [
                            {'label': 'Online', 'value': 'online'},
                            {'label': 'Offline', 'value': 'offline'},
                            {'label': 'High Queue', 'value': 'queue_high'},
                            {'label': 'Queue Empty', 'value': 'queue_empty'},
                            {'label': 'Redirect Active', 'value': 'redirect_active'},
                            {'label': 'Redirect Inactive', 'value': 'redirect_inactive'}
                        ]
                    },
                    {
                        'key': 'case2',
                        'label': 'Case 2',
                        'type': 'select',
                        'options': [
                            {'label': 'Online', 'value': 'online'},
                            {'label': 'Offline', 'value': 'offline'},
                            {'label': 'High Queue', 'value': 'queue_high'},
                            {'label': 'Queue Empty', 'value': 'queue_empty'},
                            {'label': 'Redirect Active', 'value': 'redirect_active'},
                            {'label': 'Redirect Inactive', 'value': 'redirect_inactive'}
                        ]
                    }
                ]
            },
            'default_properties': {'value': 'printer_state', 'case1': 'offline', 'case2': 'online'}
        },
        {
            'node_key': 'integration.api',
            'name': 'API Call',
            'description': 'Call an external API or webhook.',
            'category': 'integration',
            'color': '#0ea5e9',
            'icon': 'Globe',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'status_code', 'type': 'number', 'description': 'HTTP response status code'},
                {'key': 'response_body', 'type': 'object', 'description': 'Response body (JSON parsed if applicable)'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether request was successful (2xx status)'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'url', 'label': 'URL', 'type': 'string', 'supportsDynamic': True},
                    {
                        'key': 'method',
                        'label': 'Method',
                        'type': 'select',
                        'options': [
                            {'label': 'GET', 'value': 'GET'},
                            {'label': 'POST', 'value': 'POST'},
                            {'label': 'PUT', 'value': 'PUT'},
                            {'label': 'DELETE', 'value': 'DELETE'}
                        ]
                    },
                    {'key': 'timeout', 'label': 'Timeout (ms)', 'type': 'number'}
                ]
            },
            'default_properties': {'url': '', 'method': 'POST', 'timeout': 5000}
        },
        {
            'node_key': 'integration.slack',
            'name': 'Slack Message',
            'description': 'Send a Slack message via webhook.',
            'category': 'integration',
            'color': '#0ea5e9',
            'icon': 'MessageCircle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'status_code', 'type': 'number', 'description': 'HTTP response status code'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether message was sent successfully'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'webhook_url', 'label': 'Webhook URL', 'type': 'string'},
                    {'key': 'message', 'label': 'Message', 'type': 'string', 'supportsDynamic': True}
                ]
            },
            'default_properties': {'webhook_url': '', 'message': ''}
        },
        {
            'node_key': 'integration.teams',
            'name': 'Teams Message',
            'description': 'Send a Microsoft Teams webhook message.',
            'category': 'integration',
            'color': '#0ea5e9',
            'icon': 'MessageSquare',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'output_schema': [
                {'key': 'status_code', 'type': 'number', 'description': 'HTTP response status code'},
                {'key': 'success', 'type': 'boolean', 'description': 'Whether message was sent successfully'}
            ],
            'config_schema': {
                'fields': [
                    {'key': 'webhook_url', 'label': 'Webhook URL', 'type': 'string'},
                    {'key': 'message', 'label': 'Message', 'type': 'string', 'supportsDynamic': True}
                ]
            },
            'default_properties': {'webhook_url': '', 'message': ''}
        },
        {
            'node_key': 'integration.discord',
            'name': 'Discord Message',
            'description': 'Send a Discord webhook message.',
            'category': 'integration',
            'color': '#0ea5e9',
            'icon': 'MessageCircle',
            'inputs': [{'id': 'in', 'label': 'In', 'type': 'flow'}],
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'allow_multiple_inputs': True,
            'outputs': [{'id': 'out', 'label': 'Next', 'type': 'flow'}],
            'config_schema': {
                'fields': [
                    {'key': 'webhook_url', 'label': 'Webhook URL', 'type': 'string'},
                    {'key': 'message', 'label': 'Message', 'type': 'string'}
                ]
            },
            'default_properties': {'webhook_url': '', 'message': ''}
        }
    ]

    insert_rows = [
        (
            node['node_key'],
            node['name'],
            node['description'],
            node['category'],
            node['color'],
            node['icon'],
            json.dumps(node['inputs']),
            json.dumps(node['outputs']),
            json.dumps(node.get('output_schema')) if node.get('output_schema') is not None else None,
            json.dumps(node['config_schema']) if node.get('config_schema') is not None else None,
            json.dumps(node['default_properties'])
        )
        for node in default_nodes
        if node['node_key'] not in existing_keys
    ]

    if insert_rows:
        cursor.executemany(
            """
            INSERT INTO workflow_registry_nodes
            (node_key, name, description, category, color, icon, inputs, outputs, output_schema, config_schema, default_properties)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            insert_rows
        )

    cursor.execute("UPDATE workflow_registry_nodes SET enabled = 0 WHERE node_key = 'transform.convert'")
    
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
        default_prefs = json.dumps({
            'health_alerts': True,
            'offline_alerts': True,
            'job_failures': True,
            'security_events': True,
            'weekly_reports': False
        })
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, full_name, email, password_hash, role, is_active, theme, language, timezone, notification_preferences) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, full_name, email, password_hash, role, int(is_active), theme, language, timezone, default_prefs)
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


class PrinterGroup:
    """Model for printer groups."""

    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Get all printer groups with printer counts."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pg.id, pg.name, pg.description, pg.owner_user_id, pg.created_at, pg.updated_at,
                   u.username AS owner_username,
                   COUNT(pgm.printer_id) AS printer_count
            FROM printer_groups pg
            LEFT JOIN printer_group_members pgm ON pg.id = pgm.group_id
            LEFT JOIN users u ON u.id = pg.owner_user_id
            GROUP BY pg.id
            ORDER BY pg.name
        """)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    @staticmethod
    def get_by_id(group_id: int) -> Optional[Dict[str, Any]]:
        """Get a printer group by ID with member printer IDs."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pg.*, u.username AS owner_username
            FROM printer_groups pg
            LEFT JOIN users u ON u.id = pg.owner_user_id
            WHERE pg.id = ?
        """, (group_id,))
        group_row = cursor.fetchone()
        if not group_row:
            conn.close()
            return None

        cursor.execute(
            "SELECT printer_id FROM printer_group_members WHERE group_id = ?",
            (group_id,)
        )
        printer_rows = cursor.fetchall()
        conn.close()

        group = dict(group_row)
        group['printer_ids'] = [row['printer_id'] for row in printer_rows]
        group['printer_count'] = len(group['printer_ids'])
        return group

    @staticmethod
    def create(name: str, description: str = '', owner_user_id: Optional[int] = None) -> Dict[str, Any]:
        """Create a new printer group."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO printer_groups (name, description, owner_user_id) VALUES (?, ?, ?)",
            (name, description or '', owner_user_id)
        )
        conn.commit()
        group_id = cursor.lastrowid
        conn.close()
        return PrinterGroup.get_by_id(group_id)

    @staticmethod
    def update(group_id: int, name: str, description: str = '') -> Optional[Dict[str, Any]]:
        """Update an existing printer group."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE printer_groups SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (name, description or '', group_id)
        )
        conn.commit()
        conn.close()
        return PrinterGroup.get_by_id(group_id)

    @staticmethod
    def delete(group_id: int) -> bool:
        """Delete a printer group and its members."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM printer_group_members WHERE group_id = ?", (group_id,))
        cursor.execute("DELETE FROM printer_groups WHERE id = ?", (group_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0

    @staticmethod
    def set_printers(group_id: int, printer_ids: List[str]) -> None:
        """Set printer memberships for a group (one group per printer)."""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Clear existing members for this group
        cursor.execute("DELETE FROM printer_group_members WHERE group_id = ?", (group_id,))

        if printer_ids:
            # Remove printers from other groups to enforce 1 group per printer
            placeholders = ",".join(["?"] * len(printer_ids))
            cursor.execute(
                f"DELETE FROM printer_group_members WHERE printer_id IN ({placeholders}) AND group_id != ?",
                (*printer_ids, group_id)
            )

            cursor.executemany(
                "INSERT INTO printer_group_members (group_id, printer_id) VALUES (?, ?)",
                [(group_id, printer_id) for printer_id in printer_ids]
            )

        conn.commit()
        conn.close()


class GroupRedirectSchedule:
    """Model for group redirect schedules."""

    @staticmethod
    def get_all(group_id: Optional[int] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if group_id is None:
            cursor.execute("""
                SELECT grs.*, pg.name AS group_name, p.name AS target_printer_name
                FROM group_redirect_schedules grs
                JOIN printer_groups pg ON pg.id = grs.group_id
                JOIN printers p ON p.id = grs.target_printer_id
                ORDER BY grs.start_at DESC
            """)
        else:
            cursor.execute("""
                SELECT grs.*, pg.name AS group_name, p.name AS target_printer_name
                FROM group_redirect_schedules grs
                JOIN printer_groups pg ON pg.id = grs.group_id
                JOIN printers p ON p.id = grs.target_printer_id
                WHERE grs.group_id = ?
                ORDER BY grs.start_at DESC
            """, (group_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    @staticmethod
    def create(group_id: int, target_printer_id: str, start_at: str, end_at: Optional[str], created_by: str) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO group_redirect_schedules (group_id, target_printer_id, start_at, end_at, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (group_id, target_printer_id, start_at, end_at, created_by)
        )
        conn.commit()
        schedule_id = cursor.lastrowid
        conn.close()
        schedules = GroupRedirectSchedule.get_all()
        return next((s for s in schedules if s['id'] == schedule_id), None)

    @staticmethod
    def update(schedule_id: int, target_printer_id: str, start_at: str, end_at: Optional[str], enabled: bool) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE group_redirect_schedules
            SET target_printer_id = ?, start_at = ?, end_at = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (target_printer_id, start_at, end_at, int(enabled), schedule_id)
        )
        conn.commit()
        conn.close()
        schedules = GroupRedirectSchedule.get_all()
        return next((s for s in schedules if s['id'] == schedule_id), None)

    @staticmethod
    def delete(schedule_id: int) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM group_redirect_schedules WHERE id = ?", (schedule_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0


class PrinterRedirectSchedule:
    @staticmethod
    def get_all(source_printer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if source_printer_id:
            cursor.execute("""
                SELECT prs.*, sp.name AS source_printer_name, tp.name AS target_printer_name
                FROM printer_redirect_schedules prs
                JOIN printers sp ON sp.id = prs.source_printer_id
                JOIN printers tp ON tp.id = prs.target_printer_id
                WHERE prs.source_printer_id = ?
                ORDER BY prs.start_at DESC
            """, (source_printer_id,))
        else:
            cursor.execute("""
                SELECT prs.*, sp.name AS source_printer_name, tp.name AS target_printer_name
                FROM printer_redirect_schedules prs
                JOIN printers sp ON sp.id = prs.source_printer_id
                JOIN printers tp ON tp.id = prs.target_printer_id
                ORDER BY prs.start_at DESC
            """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    @staticmethod
    def create(source_printer_id: str, target_printer_id: str, start_at: str, end_at: Optional[str], created_by: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO printer_redirect_schedules (source_printer_id, target_printer_id, start_at, end_at, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source_printer_id, target_printer_id, start_at, end_at, created_by)
        )
        conn.commit()
        schedule_id = cursor.lastrowid
        conn.close()
        schedules = PrinterRedirectSchedule.get_all()
        return next((s for s in schedules if s['id'] == schedule_id), None)

    @staticmethod
    def update(schedule_id: int, target_printer_id: str, start_at: str, end_at: Optional[str], enabled: bool) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE printer_redirect_schedules
            SET target_printer_id = ?, start_at = ?, end_at = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (target_printer_id, start_at, end_at, int(enabled), schedule_id)
        )
        conn.commit()
        conn.close()
        schedules = PrinterRedirectSchedule.get_all()
        return next((s for s in schedules if s['id'] == schedule_id), None)

    @staticmethod
    def delete(schedule_id: int) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM printer_redirect_schedules WHERE id = ?", (schedule_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0


class WorkflowRegistryNode:
    """Model for workflow registry nodes."""
    
    _cache: Optional[Dict[str, Any]] = None
    _cache_time: Optional[float] = None
    _cache_ttl: int = 300  # 5 minutes

    @staticmethod
    def _get_cache() -> Optional[List[Dict[str, Any]]]:
        """Get cached registry nodes if still valid."""
        import time
        if WorkflowRegistryNode._cache is None or WorkflowRegistryNode._cache_time is None:
            return None
        if time.time() - WorkflowRegistryNode._cache_time > WorkflowRegistryNode._cache_ttl:
            return None
        return WorkflowRegistryNode._cache
    
    @staticmethod
    def _set_cache(nodes: List[Dict[str, Any]]):
        """Cache registry nodes."""
        import time
        WorkflowRegistryNode._cache = nodes
        WorkflowRegistryNode._cache_time = time.time()
    
    @staticmethod
    def _clear_cache():
        """Clear the cache."""
        WorkflowRegistryNode._cache = None
        WorkflowRegistryNode._cache_time = None

    @staticmethod
    def get_all(include_disabled: bool = False) -> List[Dict[str, Any]]:
        # Use cache for enabled nodes only
        if not include_disabled:
            cached = WorkflowRegistryNode._get_cache()
            if cached is not None:
                return cached
        
        conn = get_db_connection()
        cursor = conn.cursor()
        if include_disabled:
            cursor.execute("SELECT * FROM workflow_registry_nodes ORDER BY category, name")
        else:
            cursor.execute("SELECT * FROM workflow_registry_nodes WHERE enabled = 1 ORDER BY category, name")
        rows = cursor.fetchall()
        conn.close()
        nodes = []
        for row in rows:
            nodes.append({
                'id': row['id'],
                'key': row['node_key'],
                'name': row['name'],
                'description': row['description'],
                'category': row['category'],
                'color': row['color'],
                'icon': row['icon'],
                'inputs': json.loads(row['inputs']) if row['inputs'] else [],
                'outputs': json.loads(row['outputs']) if row['outputs'] else [],
                'output_schema': json.loads(row['output_schema']) if ('output_schema' in row.keys() and row['output_schema']) else None,
                'config_schema': json.loads(row['config_schema']) if row['config_schema'] else None,
                'default_properties': json.loads(row['default_properties']) if row['default_properties'] else {},
                'enabled': bool(row['enabled']),
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            })
        
        # Cache enabled nodes only
        if not include_disabled:
            WorkflowRegistryNode._set_cache(nodes)
        
        return nodes

    @staticmethod
    def get_by_key(node_key: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM workflow_registry_nodes WHERE node_key = ?", (node_key,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            'id': row['id'],
            'key': row['node_key'],
            'name': row['name'],
            'description': row['description'],
            'category': row['category'],
            'color': row['color'],
            'icon': row['icon'],
            'inputs': json.loads(row['inputs']) if row['inputs'] else [],
            'outputs': json.loads(row['outputs']) if row['outputs'] else [],
            'output_schema': json.loads(row['output_schema']) if ('output_schema' in row.keys() and row['output_schema']) else None,
            'config_schema': json.loads(row['config_schema']) if row['config_schema'] else None,
            'default_properties': json.loads(row['default_properties']) if row['default_properties'] else {},
            'enabled': bool(row['enabled']),
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }

    @staticmethod
    def create(payload: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO workflow_registry_nodes
            (node_key, name, description, category, color, icon, inputs, outputs, output_schema, config_schema, default_properties, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload['key'],
                payload['name'],
                payload.get('description', ''),
                payload['category'],
                payload.get('color', '#10b981'),
                payload.get('icon', 'Workflow'),
                json.dumps(payload.get('inputs', [])),
                json.dumps(payload.get('outputs', [])),
                json.dumps(payload.get('output_schema')) if payload.get('output_schema') is not None else None,
                json.dumps(payload.get('config_schema')) if payload.get('config_schema') is not None else None,
                json.dumps(payload.get('default_properties', {})),
                int(payload.get('enabled', True))
            )
        )
        conn.commit()
        conn.close()
        WorkflowRegistryNode._clear_cache()
        return WorkflowRegistryNode.get_by_key(payload['key'])

    @staticmethod
    def update(node_key: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE workflow_registry_nodes
            SET name = ?, description = ?, category = ?, color = ?, icon = ?,
                inputs = ?, outputs = ?, output_schema = ?, config_schema = ?, default_properties = ?, enabled = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE node_key = ?
            """,
            (
                payload['name'],
                payload.get('description', ''),
                payload['category'],
                payload.get('color', '#10b981'),
                payload.get('icon', 'Workflow'),
                json.dumps(payload.get('inputs', [])),
                json.dumps(payload.get('outputs', [])),
                json.dumps(payload.get('output_schema')) if payload.get('output_schema') is not None else None,
                json.dumps(payload.get('config_schema')) if payload.get('config_schema') is not None else None,
                json.dumps(payload.get('default_properties', {})),
                int(payload.get('enabled', True)),
                node_key
            )
        )
        conn.commit()
        conn.close()
        WorkflowRegistryNode._clear_cache()
        return WorkflowRegistryNode.get_by_key(node_key)

    @staticmethod
    def delete(node_key: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workflow_registry_nodes WHERE node_key = ?", (node_key,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        WorkflowRegistryNode._clear_cache()
        return deleted > 0


class Workflow:
    """Model for workflow graphs with simplified JSON storage."""

    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, description, enabled, created_by, created_at, updated_at
            FROM workflows
            ORDER BY updated_at DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        return [{
            'id': row['id'],
            'name': row['name'],
            'description': row['description'],
            'is_active': bool(row['enabled']),
            'created_by': row['created_by'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        } for row in rows]

    @staticmethod
    def get_by_id(workflow_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM workflows WHERE id = ?", (workflow_id,))
        workflow = cursor.fetchone()
        conn.close()
        
        if not workflow:
            return None

        return {
            'id': workflow['id'],
            'name': workflow['name'],
            'description': workflow['description'],
            'is_active': bool(workflow['enabled']),
            'created_by': workflow['created_by'] if 'created_by' in workflow.keys() else None,
            'created_at': workflow['created_at'],
            'updated_at': workflow['updated_at'],
            'ui_state': json.loads(workflow['ui_state']) if workflow['ui_state'] else None,
            'nodes': json.loads(workflow['nodes']) if workflow['nodes'] else [],
            'edges': json.loads(workflow['edges']) if workflow['edges'] else []
        }

    @staticmethod
    def create(name: str, description: str, created_by: str,
               nodes: Optional[List[Dict[str, Any]]] = None,
               edges: Optional[List[Dict[str, Any]]] = None,
               ui_state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        workflow_id = uuid.uuid4().hex
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO workflows (id, name, description, enabled, nodes, edges, ui_state, created_by, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (
                workflow_id,
                name,
                description or '',
                json.dumps(nodes or []),
                json.dumps(edges or []),
                json.dumps(ui_state) if ui_state else None,
                created_by
            )
        )
        conn.commit()
        conn.close()

        return Workflow.get_by_id(workflow_id)

    @staticmethod
    def update(workflow_id: str, name: Optional[str] = None, description: Optional[str] = None,
               is_active: Optional[bool] = None,
               nodes: Optional[List[Dict[str, Any]]] = None,
               edges: Optional[List[Dict[str, Any]]] = None,
               ui_state: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        fields = []
        values = []

        if name is not None:
            fields.append("name = ?")
            values.append(name)
        if description is not None:
            fields.append("description = ?")
            values.append(description)
        if is_active is not None:
            fields.append("enabled = ?")
            values.append(int(is_active))
        if nodes is not None:
            fields.append("nodes = ?")
            values.append(json.dumps(nodes))
        if edges is not None:
            fields.append("edges = ?")
            values.append(json.dumps(edges))
        if ui_state is not None:
            fields.append("ui_state = ?")
            values.append(json.dumps(ui_state))

        if fields:
            fields.append("updated_at = datetime('now')")
            values.append(workflow_id)
            cursor.execute(
                f"UPDATE workflows SET {', '.join(fields)} WHERE id = ?",
                values
            )
            conn.commit()
        conn.close()

        return Workflow.get_by_id(workflow_id)

    @staticmethod
    def delete(workflow_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workflows WHERE id = ?", (workflow_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0

    @staticmethod
    def save_graph(workflow_id: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
        """Save workflow graph (nodes and edges) - simplified version."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE workflows SET nodes = ?, edges = ?, updated_at = datetime('now') WHERE id = ?",
            (json.dumps(nodes), json.dumps(edges), workflow_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def validate_connection(workflow_id: str, source_node_id: str, target_node_id: str,
                            source_handle: Optional[str], target_handle: Optional[str],
                            source_node_type: Optional[str] = None,
                            target_node_type: Optional[str] = None) -> Tuple[bool, str]:
        def normalize_handle(handle: Optional[str]) -> Optional[str]:
            if not handle:
                return handle
            return handle.split(':')[0]

        if source_node_id == target_node_id:
            return False, 'Cannot connect a node to itself.'

        # Get workflow to check node types
        workflow = Workflow.get_by_id(workflow_id)
        if not workflow:
            return False, 'Workflow not found.'
        
        nodes = workflow.get('nodes', [])
        edges = workflow.get('edges', [])
        node_map = {node['id']: node['type'] for node in nodes}
        
        source_type = node_map.get(source_node_id) or source_node_type
        target_type = node_map.get(target_node_id) or target_node_type
        if not source_type or not target_type:
            return False, 'Unknown node reference.'

        source_registry = WorkflowRegistryNode.get_by_key(source_type)
        target_registry = WorkflowRegistryNode.get_by_key(target_type)
        if not source_registry or not target_registry:
            return False, 'Unknown node type.'

        source_outputs = source_registry.get('outputs', [])
        target_inputs = target_registry.get('inputs', [])

        normalized_source = normalize_handle(source_handle)
        normalized_target = normalize_handle(target_handle)

        if source_outputs:
            output = next((item for item in source_outputs if item.get('id') == normalized_source), None)
        else:
            output = None
        if target_inputs:
            target = next((item for item in target_inputs if item.get('id') == normalized_target), None)
        else:
            target = None

        if output is None:
            return False, 'Invalid source handle.'
        if target is None:
            return False, 'Invalid target handle.'

        output_type = output.get('type', 'any')
        input_type = target.get('type', 'any')
        if output_type != 'any' and input_type != 'any' and output_type != input_type:
            return False, 'Incompatible connection types.'

        # Check if target handle already has an incoming connection
        allow_multiple_inputs = target_registry.get('allow_multiple_inputs', False)
        if not allow_multiple_inputs:
            for edge in edges:
                edge_target_handle = normalize_handle(edge.get('targetHandle') or edge.get('target_handle'))
                if (edge.get('target') == target_node_id and
                    edge_target_handle == normalized_target):
                    return False, 'This input already has a connection. Node does not support multiple inputs.'

        return True, 'Connection valid.'


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
    def get_by_id(redirect_id: int) -> Optional['ActiveRedirect']:
        """Get redirect by ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_redirects WHERE id = ?", (redirect_id,))
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
