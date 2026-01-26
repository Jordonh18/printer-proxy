#!/usr/bin/env python3
"""
Database initialization script with example workflow seeding.
Run this to set up a fresh database with example workflows.
"""

import sqlite3
import json
import secrets
from datetime import datetime
from pathlib import Path

# Determine database path
BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'continuum.db'

def generate_workflow_id():
    """Generate a random workflow ID similar to webhook IDs."""
    return secrets.token_urlsafe(16)

def init_workflows_table(cursor):
    """Create workflows table with string ID."""
    cursor.execute("DROP TABLE IF EXISTS workflows")
    cursor.execute("""
        CREATE TABLE workflows (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            enabled INTEGER DEFAULT 1,
            nodes TEXT,
            edges TEXT,
            ui_state TEXT,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    print("✓ Created workflows table with string ID")

def seed_example_workflows(cursor):
    """Seed database with example workflows."""
    
    # Example 1: Printer Offline Alert
    wf1_id = generate_workflow_id()
    wf1_webhook_id = secrets.token_urlsafe(32)
    wf1_webhook_secret = secrets.token_urlsafe(32)
    
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
                'sourceHandle': 'output',
                'targetHandle': 'input'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 2: Auto-Redirect on Failure
    wf2_id = generate_workflow_id()
    
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
                'sourceHandle': 'output',
                'targetHandle': 'input'
            },
            {
                'id': 'edge_2',
                'source': 'node_redirect',
                'target': 'node_notify',
                'sourceHandle': 'output',
                'targetHandle': 'input'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 3: Scheduled Health Report
    wf3_id = generate_workflow_id()
    
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
                'sourceHandle': 'output',
                'targetHandle': 'input'
            }
        ],
        'ui_state': {},
        'created_by': 'system',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Example 4: Webhook Integration
    wf4_id = generate_workflow_id()
    wf4_webhook_id = secrets.token_urlsafe(32)
    wf4_webhook_secret = secrets.token_urlsafe(32)
    
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
                'sourceHandle': 'output',
                'targetHandle': 'input'
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
    
    print(f"✓ Seeded 4 example workflows:")
    print(f"  1. {workflow1['name']} (ID: {wf1_id})")
    print(f"  2. {workflow2['name']} (ID: {wf2_id})")
    print(f"  3. {workflow3['name']} (ID: {wf3_id}) - Disabled")
    print(f"  4. {workflow4['name']} (ID: {wf4_id})")
    print(f"\n  Webhook endpoint for workflow 4:")
    print(f"  POST /api/webhooks/workflows/{wf4_id}/{wf4_webhook_id}")
    print(f"  Secret: {wf4_webhook_secret}")

def main():
    print("="*70)
    print("DATABASE INITIALIZATION")
    print("="*70)
    
    # Ensure data directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    print(f"\nDatabase: {DB_PATH}")
    
    # Initialize workflows table
    init_workflows_table(cursor)
    
    # Seed example workflows
    print("\nSeeding example workflows...")
    seed_example_workflows(cursor)
    
    conn.commit()
    conn.close()
    
    print("\n" + "="*70)
    print("✓ Database initialization complete!")
    print("="*70)

if __name__ == '__main__':
    main()
