"""
Workflow execution engine for Printer Proxy.
Handles workflow triggers, execution, and action processing.
"""
import json
import logging
import hmac
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
import requests
from flask import current_app
from app.models import get_db_connection
from app.notification_manager import get_notification_manager
from app.network import get_network_manager

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """Executes workflows based on triggers and events."""
    
    def __init__(self):
        self.running_workflows = {}
    
    def execute_workflow(self, workflow_id: str, context: Dict[str, Any]) -> bool:
        """
        Execute a workflow with the given context.
        
        Args:
            workflow_id: ID of the workflow to execute
            context: Execution context containing trigger data
            
        Returns:
            True if execution succeeded, False otherwise
        """
        try:
            workflow = self._get_workflow(workflow_id)
            if not workflow or not workflow.get('enabled'):
                logger.warning(f"Workflow {workflow_id} not found or disabled")
                return False
            
            logger.info(f"Executing workflow: {workflow['name']}")
            
            # Find trigger node
            trigger_node = self._find_trigger_node(workflow)
            if not trigger_node:
                logger.error(f"No trigger node found in workflow {workflow_id}")
                return False
            
            # Start execution from trigger
            return self._execute_node(workflow, trigger_node['id'], context)
            
        except Exception as e:
            logger.error(f"Error executing workflow {workflow_id}: {e}", exc_info=True)
            return False
    
    def verify_webhook_signature(self, payload: str, signature: str, secret: str) -> bool:
        """Verify HMAC signature for webhook."""
        expected = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)
    
    def _get_workflow(self, workflow_id: str) -> Optional[Dict]:
        """Get workflow from database."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, description, enabled, nodes, edges FROM workflows WHERE id = ?",
            (workflow_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'id': row[0],
            'name': row[1],
            'description': row[2],
            'enabled': bool(row[3]),
            'nodes': json.loads(row[4]) if row[4] else [],
            'edges': json.loads(row[5]) if row[5] else []
        }
    
    def _find_trigger_node(self, workflow: Dict) -> Optional[Dict]:
        """Find the trigger node in a workflow."""
        for node in workflow['nodes']:
            if node['type'].startswith('trigger.'):
                return node
        return None
    
    def _execute_node(self, workflow: Dict, node_id: str, context: Dict[str, Any]) -> bool:
        """Execute a single node and follow edges."""
        node = self._get_node_by_id(workflow, node_id)
        if not node:
            return False
        
        logger.debug(f"Executing node: {node.get('label', node_id)} ({node['type']})")
        
        # Execute based on node type
        node_type = node['type']
        properties = node.get('properties', {})
        
        # Triggers (already fired, continue to next)
        if node_type.startswith('trigger.'):
            return self._execute_next_nodes(workflow, node_id, context)
        
        # Actions
        elif node_type.startswith('action.'):
            # Special handling for end node - terminates workflow
            if node_type == 'action.end':
                logger.info("Workflow terminated by End node")
                return True  # Success, but don't continue
            
            success = self._execute_action(node_type, properties, context)
            if success:
                return self._execute_next_nodes(workflow, node_id, context)
            return False
        
        # Conditionals
        elif node_type.startswith('logic.'):
            output_handle = self._evaluate_conditional(node_type, properties, context)
            if output_handle:
                return self._execute_next_nodes(workflow, node_id, context, output_handle)
            return False
        
        # Transforms
        elif node_type.startswith('transform.'):
            context = self._apply_transform(node_type, properties, context)
            return self._execute_next_nodes(workflow, node_id, context)
        
        # Integrations
        elif node_type.startswith('integration.'):
            success = self._execute_integration(node_type, properties, context)
            if success:
                return self._execute_next_nodes(workflow, node_id, context)
            return False
        
        return True
    
    def _execute_action(self, action_type: str, properties: Dict, context: Dict) -> bool:
        """Execute an action node."""
        try:
            # Redirect actions
            if action_type == 'action.redirect.create' or action_type == 'action.redirect':
                return self._action_create_redirect(properties, context)
            elif action_type == 'action.redirect.delete' or action_type == 'action.redirect.disable':
                return self._action_delete_redirect(properties, context)
            
            # Queue actions
            elif action_type == 'action.queue.pause':
                return self._action_pause_queue(properties, context)
            elif action_type == 'action.queue.resume':
                return self._action_resume_queue(properties, context)
            elif action_type == 'action.queue.clear':
                return self._action_clear_queue(properties, context)
            
            # Notification actions
            elif action_type == 'action.notify.email':
                return self._action_send_email(properties, context)
            elif action_type == 'action.notify.inapp':
                return self._action_send_inapp_notification(properties, context)
            
            # Note/printer note actions
            elif action_type == 'action.note' or action_type == 'action.printer.note':
                return self._action_add_printer_note(properties, context)
            
            # Audit action
            elif action_type == 'action.audit':
                return self._action_audit_log(properties, context)
            
            # HTTP request action
            elif action_type == 'action.http':
                return self._action_http_request(properties, context)
            
            # Print job action
            elif action_type == 'action.print':
                return self._action_print_job(properties, context)
            
            # End action (terminates the workflow)
            elif action_type == 'action.end':
                logger.info("Workflow ended via End node")
                return True  # Success but don't continue
            
            else:
                logger.warning(f"Unknown action type: {action_type}")
                return False
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {e}", exc_info=True)
            return False
    
    def _action_create_redirect(self, properties: Dict, context: Dict) -> bool:
        """Create a printer redirect."""
        printer_id = properties.get('printer_id')
        target_id = properties.get('target_printer_id')
        
        if not printer_id or not target_id:
            logger.error("Missing printer_id or target_printer_id")
            return False
        
        try:
            network = get_network_manager()
            # Get printer IPs
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ip FROM printers WHERE id = ?", (printer_id,))
            source_row = cursor.fetchone()
            cursor.execute("SELECT ip FROM printers WHERE id = ?", (target_id,))
            target_row = cursor.fetchone()
            conn.close()
            
            if not source_row or not target_row:
                return False
            
            # Create redirect in database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO redirects (printer_id, target_printer_id, active, created_at) VALUES (?, ?, 1, ?)",
                (printer_id, target_id, datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
            
            # Apply NAT rules
            success, _ = network.add_nat_rule(source_row[0], target_row[0], 9100)
            return success
            
        except Exception as e:
            logger.error(f"Error creating redirect: {e}")
            return False
    
    def _action_delete_redirect(self, properties: Dict, context: Dict) -> bool:
        """Delete a printer redirect."""
        printer_id = properties.get('printer_id')
        
        if not printer_id:
            return False
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE redirects SET active = 0 WHERE printer_id = ?", (printer_id,))
            conn.commit()
            conn.close()
            
            # Remove NAT rules
            network = get_network_manager()
            cursor = conn.cursor()
            cursor.execute("SELECT ip FROM printers WHERE id = ?", (printer_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                success, _ = network.remove_nat_rule(row[0], 9100)
                return success
            return False
            
        except Exception as e:
            logger.error(f"Error deleting redirect: {e}")
            return False
    
    def _action_pause_queue(self, properties: Dict, context: Dict) -> bool:
        """Pause printer queue."""
        # This would integrate with print queue management
        logger.info(f"Pausing queue for printer {properties.get('printer_id')}")
        return True
    
    def _action_resume_queue(self, properties: Dict, context: Dict) -> bool:
        """Resume printer queue."""
        logger.info(f"Resuming queue for printer {properties.get('printer_id')}")
        return True
    
    def _action_clear_queue(self, properties: Dict, context: Dict) -> bool:
        """Clear printer queue."""
        logger.info(f"Clearing queue for printer {properties.get('printer_id')}")
        return True
    
    def _action_send_email(self, properties: Dict, context: Dict) -> bool:
        """Send email notification."""
        try:
            notif_manager = get_notification_manager()
            message = self._render_template(properties.get('message', ''), context)
            subject = properties.get('subject', 'Printer Alert')
            to_email = properties.get('to', '')
            
            notif_manager.send_notification(
                'email',
                subject,
                message,
                {'to': to_email}
            )
            return True
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False
    
    def _action_send_inapp_notification(self, properties: Dict, context: Dict) -> bool:
        """Send in-app notification."""
        try:
            from app.notifications import create_notification
            
            message = self._render_template(properties.get('message', ''), context)
            title = properties.get('title', 'Workflow Notification')
            notification_type = properties.get('type', 'info')
            
            create_notification(
                notification_type=notification_type,
                title=title,
                message=message,
                printer_id=context.get('printer_id')
            )
            return True
        except Exception as e:
            logger.error(f"Error sending in-app notification: {e}")
            return False
    
    def _action_add_printer_note(self, properties: Dict, context: Dict) -> bool:
        """Add a note to a printer."""
        try:
            printer_id = properties.get('printer_id') or context.get('printer_id')
            note = self._render_template(properties.get('message', ''), context)
            
            if not printer_id or not note:
                logger.warning("Missing printer_id or message for printer note")
                return True  # Non-critical, don't fail workflow
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE printers SET notes = COALESCE(notes || char(10), '') || ? WHERE id = ?",
                (f"[Workflow] {note}", printer_id)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"Added note to printer {printer_id}: {note}")
            return True
        except Exception as e:
            logger.error(f"Error adding printer note: {e}")
            return False
    
    def _action_audit_log(self, properties: Dict, context: Dict) -> bool:
        """Create an audit log entry."""
        try:
            from app.models import AuditLog
            
            message = self._render_template(properties.get('message', 'Workflow action executed'), context)
            action = properties.get('action', 'workflow_action')
            
            AuditLog.log(
                username='workflow_engine',
                action=action,
                details=message,
                success=True
            )
            return True
        except Exception as e:
            logger.error(f"Error creating audit log: {e}", exc_info=True)
            return False
    
    def _action_http_request(self, properties: Dict, context: Dict) -> bool:
        """Make HTTP request."""
        try:
            url = properties.get('url', '')
            method = properties.get('method', 'POST')
            body = properties.get('body', '{}')
            
            rendered_body = self._render_template(body, context)
            
            response = requests.request(
                method,
                url,
                data=rendered_body,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            return response.status_code < 400
        except Exception as e:
            logger.error(f"Error making HTTP request: {e}")
            return False
    
    def _action_print_job(self, properties: Dict, context: Dict) -> bool:
        """Submit print job."""
        # This would integrate with print job submission
        logger.info(f"Printing to {properties.get('printer_id')}")
        return True
    
    def _evaluate_conditional(self, conditional_type: str, properties: Dict, context: Dict) -> Optional[str]:
        """Evaluate conditional and return output handle."""
        if conditional_type == 'logic.if':
            expression = properties.get('expression', '')
            result = self._evaluate_expression(expression, context)
            return 'true' if result else 'false'
        
        elif conditional_type == 'logic.switch':
            switch_on = properties.get('value', '')
            cases = properties.get('cases', [])
            
            value = context.get(switch_on)
            for i, case in enumerate(cases):
                if value == case:
                    return f'case{i+1}'
            return 'default'
        
        return None
    
    def _evaluate_expression(self, expression: str, context: Dict) -> bool:
        """Evaluate a condition expression."""
        # Map expression values to context checks
        printer_id = context.get('printer_id')
        
        if expression == 'printer_offline':
            return context.get('printer_state') == 'offline'
        elif expression == 'printer_online':
            return context.get('printer_state') == 'online'
        elif expression == 'queue_high':
            return context.get('queue_count', 0) > 10
        elif expression == 'queue_empty':
            return context.get('queue_count', 0) == 0
        elif expression == 'redirect_active':
            return context.get('redirect_active', False)
        elif expression == 'redirect_inactive':
            return not context.get('redirect_active', False)
        elif expression == 'job_failed':
            return context.get('job_status') == 'failed'
        
        return False
    
    def _apply_transform(self, transform_type: str, properties: Dict, context: Dict) -> Dict:
        """Apply data transformation."""
        try:
            if transform_type == 'transform.filter':
                # Filter: only continue if condition is met
                expression = properties.get('expression', '')
                if not self._evaluate_expression(expression, context):
                    # Filter didn't match - set a flag for downstream
                    context['_filtered'] = True
                return context
            
            elif transform_type == 'transform.map_fields':
                # Map fields: rename or restructure context fields
                field_mappings = properties.get('mappings', {})
                for source_field, target_field in field_mappings.items():
                    if source_field in context:
                        context[target_field] = context[source_field]
                return context
            
            elif transform_type == 'transform.template':
                # Template: render a template and store result
                template = properties.get('template', '')
                output_field = properties.get('output_field', 'rendered_message')
                context[output_field] = self._render_template(template, context)
                return context
            
            else:
                logger.warning(f"Unknown transform type: {transform_type}")
                return context
                
        except Exception as e:
            logger.error(f"Error applying transform {transform_type}: {e}")
            return context
    
    def _execute_integration(self, integration_type: str, properties: Dict, context: Dict) -> bool:
        """Execute integration action."""
        try:
            message = self._render_template(properties.get('message', ''), context)
            
            if integration_type == 'integration.slack':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'text': message}, timeout=10)
                return response.status_code == 200
            
            elif integration_type == 'integration.teams':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'text': message}, timeout=10)
                return response.status_code == 200
            
            elif integration_type == 'integration.discord':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'content': message}, timeout=10)
                return response.status_code in [200, 204]
            
            elif integration_type == 'integration.api':
                # Generic API call integration
                url = properties.get('url', '')
                method = properties.get('method', 'POST').upper()
                headers = properties.get('headers', {})
                body_template = properties.get('body', '{}')
                
                rendered_body = self._render_template(body_template, context)
                
                # Add default content type if not specified
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
                
                response = requests.request(
                    method,
                    url,
                    data=rendered_body,
                    headers=headers,
                    timeout=int(properties.get('timeout', 10))
                )
                
                logger.info(f"API integration {method} {url} returned {response.status_code}")
                return response.status_code < 400
            
            return False
        except Exception as e:
            logger.error(f"Error executing integration {integration_type}: {e}")
            return False
    
    def _render_template(self, template: str, context: Dict) -> str:
        """Render template with context variables."""
        result = template
        for key, value in context.items():
            result = result.replace(f'{{{{{key}}}}}', str(value))
        return result
    
    def _get_node_by_id(self, workflow: Dict, node_id: str) -> Optional[Dict]:
        """Get node by ID from workflow."""
        for node in workflow['nodes']:
            if node['id'] == node_id:
                return node
        return None
    
    def _execute_next_nodes(self, workflow: Dict, current_node_id: str, context: Dict, source_handle: Optional[str] = None) -> bool:
        """Execute all nodes connected to the current node's outputs."""
        edges = workflow['edges']
        next_edges = [
            e for e in edges 
            if e['source'] == current_node_id and (source_handle is None or e.get('sourceHandle', '').split(':')[0] == source_handle)
        ]
        
        if not next_edges:
            logger.debug("No more nodes to execute, workflow complete")
            return True
        
        success = True
        for edge in next_edges:
            if not self._execute_node(workflow, edge['target'], context):
                success = False
        
        return success


# Global engine instance
_workflow_engine = None

def get_workflow_engine() -> WorkflowEngine:
    """Get the global workflow engine instance."""
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine


def trigger_workflows_for_event(event_type: str, context: Dict[str, Any]) -> None:
    """
    Trigger all workflows that match the given event type.
    
    Args:
        event_type: Type of event (printer_offline, printer_online, job_failed, etc.)
        context: Event context data
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all enabled workflows
        cursor.execute("SELECT id, nodes FROM workflows WHERE enabled = 1")
        rows = cursor.fetchall()
        conn.close()
        
        engine = get_workflow_engine()
        
        for row in rows:
            workflow_id, nodes_json = row
            nodes = json.loads(nodes_json) if nodes_json else []
            
            # Check if workflow has matching trigger
            for node in nodes:
                should_trigger = False
                
                # Event trigger
                if node['type'] == 'trigger.event':
                    node_event = node.get('properties', {}).get('event_type', '')
                    if node_event == event_type:
                        should_trigger = True
                
                # Health change trigger
                elif node['type'] == 'trigger.health_change':
                    node_state = node.get('properties', {}).get('state', '')
                    node_printer = node.get('properties', {}).get('printer_id', '')
                    
                    # Match state (offline/online)
                    if event_type == 'printer_offline' and node_state == 'offline':
                        # If specific printer, check it matches
                        if not node_printer or node_printer == context.get('printer_id'):
                            should_trigger = True
                    elif event_type == 'printer_online' and node_state == 'online':
                        if not node_printer or node_printer == context.get('printer_id'):
                            should_trigger = True
                
                # Queue threshold trigger
                elif node['type'] == 'trigger.queue_threshold':
                    node_printer = node.get('properties', {}).get('printer_id', '')
                    threshold = int(node.get('properties', {}).get('threshold', 10))
                    direction = node.get('properties', {}).get('direction', 'above')
                    
                    if event_type == 'queue_threshold':
                        # Check if printer matches
                        if not node_printer or node_printer == context.get('printer_id'):
                            queue_count = context.get('queue_count', 0)
                            if direction == 'above' and queue_count >= threshold:
                                should_trigger = True
                            elif direction == 'below' and queue_count <= threshold:
                                should_trigger = True
                
                if should_trigger:
                    logger.info(f"Triggering workflow {workflow_id} for event {event_type}")
                    try:
                        engine.execute_workflow(workflow_id, {
                            'trigger': event_type,
                            **context,
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Error executing workflow {workflow_id}: {e}", exc_info=True)
                    break  # Only trigger once per workflow
                    
    except Exception as e:
        logger.error(f"Error triggering workflows for event {event_type}: {e}", exc_info=True)
