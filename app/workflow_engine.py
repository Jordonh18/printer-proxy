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
        """
        Execute a single node and follow edges.
        
        Context accumulates as the workflow executes - each node's outputs
        are merged into context for downstream nodes to reference via {{variable}}.
        """
        node = self._get_node_by_id(workflow, node_id)
        if not node:
            return False
        
        logger.debug(f"Executing node: {node.get('label', node_id)} ({node['type']})")
        
        # Execute based on node type
        node_type = node['type']
        raw_properties = node.get('properties', {})
        
        # Render all properties with current context (supports {{variable}} syntax)
        properties = self._render_properties(raw_properties, context)
        
        # Triggers (already fired, continue to next)
        if node_type.startswith('trigger.'):
            return self._execute_next_nodes(workflow, node_id, context)
        
        # Actions
        elif node_type.startswith('action.'):
            # Special handling for end node - terminates workflow
            if node_type == 'action.end':
                logger.info("Workflow terminated by End node")
                return True  # Success, but don't continue
            
            result = self._execute_action(node_type, properties, context)
            if isinstance(result, dict):
                # Action returned outputs - merge into context
                context.update(result)
                return self._execute_next_nodes(workflow, node_id, context)
            elif result:
                return self._execute_next_nodes(workflow, node_id, context)
            return False
        
        # Conditionals
        elif node_type.startswith('logic.'):
            output_handle, condition_result = self._evaluate_conditional(node_type, properties, context)
            # Merge conditional outputs into context
            context['condition_result'] = condition_result
            context['branch'] = output_handle
            if output_handle:
                return self._execute_next_nodes(workflow, node_id, context, output_handle)
            return False
        
        # Transforms
        elif node_type.startswith('transform.'):
            context = self._apply_transform(node_type, properties, context)
            return self._execute_next_nodes(workflow, node_id, context)
        
        # Integrations
        elif node_type.startswith('integration.'):
            result = self._execute_integration(node_type, properties, context)
            if isinstance(result, dict):
                # Integration returned outputs - merge into context
                context.update(result)
                return self._execute_next_nodes(workflow, node_id, context)
            elif result:
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
    
    def _action_create_redirect(self, properties: Dict, context: Dict) -> Dict:
        """
        Create a printer redirect.
        
        Returns dict with output variables for downstream nodes.
        """
        # Use rendered properties - may contain {{variable}} references
        source_printer_id = properties.get('source_printer_id') or properties.get('printer_id')
        target_printer_id = properties.get('target_printer_id')
        port = properties.get('port', 9100)
        
        if not source_printer_id or not target_printer_id:
            logger.error("Missing source_printer_id or target_printer_id")
            return {'success': False}
        
        try:
            network = get_network_manager()
            # Get printer details
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, ip FROM printers WHERE id = ?", (source_printer_id,))
            source_row = cursor.fetchone()
            cursor.execute("SELECT id, name, ip FROM printers WHERE id = ?", (target_printer_id,))
            target_row = cursor.fetchone()
            conn.close()
            
            if not source_row or not target_row:
                return {'success': False}
            
            source_name, source_ip = source_row[1], source_row[2]
            target_name, target_ip = target_row[1], target_row[2]
            
            # Create redirect in database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO redirects (printer_id, target_printer_id, active, created_at) VALUES (?, ?, 1, ?)",
                (source_printer_id, target_printer_id, datetime.now().isoformat())
            )
            redirect_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Apply NAT rules
            success, _ = network.add_nat_rule(source_ip, target_ip, port)
            
            # Return output variables for downstream nodes
            return {
                'redirect_id': str(redirect_id),
                'source_printer_id': source_printer_id,
                'source_printer_name': source_name,
                'source_printer_ip': source_ip,
                'target_printer_id': target_printer_id,
                'target_printer_name': target_name,
                'target_printer_ip': target_ip,
                'port': port,
                'success': success
            }
            
        except Exception as e:
            logger.error(f"Error creating redirect: {e}")
            return {'success': False}
    
    def _action_delete_redirect(self, properties: Dict, context: Dict) -> Dict:
        """Delete a printer redirect."""
        source_printer_id = properties.get('source_printer_id') or properties.get('printer_id')
        
        if not source_printer_id:
            return {'success': False}
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get printer info
            cursor.execute("SELECT name, ip FROM printers WHERE id = ?", (source_printer_id,))
            row = cursor.fetchone()
            printer_name = row[0] if row else ''
            printer_ip = row[1] if row else ''
            
            cursor.execute("UPDATE redirects SET active = 0 WHERE printer_id = ?", (source_printer_id,))
            conn.commit()
            conn.close()
            
            # Remove NAT rules
            network = get_network_manager()
            if printer_ip:
                success, _ = network.remove_nat_rule(printer_ip, 9100)
            else:
                success = False
            
            return {
                'source_printer_id': source_printer_id,
                'source_printer_name': printer_name,
                'success': success
            }
            
        except Exception as e:
            logger.error(f"Error deleting redirect: {e}")
            return {'success': False}
    
    def _action_pause_queue(self, properties: Dict, context: Dict) -> Dict:
        """Pause printer queue."""
        printer_id = properties.get('printer_id') or context.get('printer_id')
        logger.info(f"Pausing queue for printer {printer_id}")
        return {
            'printer_id': printer_id,
            'success': True
        }
    
    def _action_resume_queue(self, properties: Dict, context: Dict) -> Dict:
        """Resume printer queue."""
        printer_id = properties.get('printer_id') or context.get('printer_id')
        logger.info(f"Resuming queue for printer {printer_id}")
        return {
            'printer_id': printer_id,
            'success': True
        }
    
    def _action_clear_queue(self, properties: Dict, context: Dict) -> Dict:
        """Clear printer queue."""
        printer_id = properties.get('printer_id') or context.get('printer_id')
        logger.info(f"Clearing queue for printer {printer_id}")
        return {
            'printer_id': printer_id,
            'jobs_cleared': 0,  # Would be actual count from queue operations
            'success': True
        }
    
    def _action_send_email(self, properties: Dict, context: Dict) -> Dict:
        """Send email notification."""
        try:
            notif_manager = get_notification_manager()
            # Properties are already rendered, no need to render again
            message = properties.get('body', properties.get('message', ''))
            subject = properties.get('subject', 'Printer Alert')
            to_email = properties.get('to', '')
            
            notif_manager.send_notification(
                'email',
                subject,
                message,
                {'to': to_email}
            )
            return {
                'to': to_email,
                'subject': subject,
                'success': True
            }
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return {'success': False}
    
    def _action_send_inapp_notification(self, properties: Dict, context: Dict) -> Dict:
        """Send in-app notification."""
        try:
            from app.notifications import create_notification
            
            # Properties are already rendered
            message = properties.get('message', '')
            title = properties.get('title', 'Workflow Notification')
            notification_type = properties.get('type', 'info')
            
            notification = create_notification(
                notification_type=notification_type,
                title=title,
                message=message,
                printer_id=context.get('printer_id')
            )
            return {
                'notification_id': str(notification.get('id', '')) if isinstance(notification, dict) else '',
                'title': title,
                'success': True
            }
        except Exception as e:
            logger.error(f"Error sending in-app notification: {e}")
            return {'success': False}
    
    def _action_add_printer_note(self, properties: Dict, context: Dict) -> Dict:
        """Add a note to a printer."""
        try:
            printer_id = properties.get('printer_id') or context.get('printer_id')
            # Properties are already rendered
            note = properties.get('note', properties.get('message', ''))
            
            if not printer_id or not note:
                logger.warning("Missing printer_id or message for printer note")
                return {'success': True}  # Non-critical, don't fail workflow
            
            # Get printer name
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM printers WHERE id = ?", (printer_id,))
            row = cursor.fetchone()
            printer_name = row[0] if row else ''
            
            cursor.execute(
                "UPDATE printers SET notes = COALESCE(notes || char(10), '') || ? WHERE id = ?",
                (f"[Workflow] {note}", printer_id)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"Added note to printer {printer_id}: {note}")
            return {
                'printer_id': printer_id,
                'printer_name': printer_name,
                'note': note,
                'success': True
            }
        except Exception as e:
            logger.error(f"Error adding printer note: {e}")
            return {'success': False}
    
    def _action_audit_log(self, properties: Dict, context: Dict) -> Dict:
        """Create an audit log entry."""
        try:
            from app.models import AuditLog
            
            # Properties are already rendered
            details = properties.get('details', properties.get('message', 'Workflow action executed'))
            action = properties.get('action', 'workflow_action')
            
            AuditLog.log(
                username='workflow_engine',
                action=action,
                details=details,
                success=True
            )
            return {
                'action': action,
                'details': details,
                'success': True
            }
        except Exception as e:
            logger.error(f"Error creating audit log: {e}", exc_info=True)
            return {'success': False}
    
    def _action_http_request(self, properties: Dict, context: Dict) -> Dict:
        """Make HTTP request."""
        try:
            # Properties are already rendered
            url = properties.get('url', '')
            method = properties.get('method', 'POST')
            body = properties.get('body', '{}')
            
            response = requests.request(
                method,
                url,
                data=body,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            # Try to parse response as JSON
            try:
                response_body = response.json()
            except:
                response_body = response.text
            
            return {
                'status_code': response.status_code,
                'response_body': response_body,
                'success': response.status_code < 400
            }
        except Exception as e:
            logger.error(f"Error making HTTP request: {e}")
            return {'success': False, 'status_code': 0}
    
    def _action_print_job(self, properties: Dict, context: Dict) -> Dict:
        """Submit print job."""
        printer_id = properties.get('printer_id') or context.get('printer_id')
        document_path = properties.get('document_path', '')
        copies = properties.get('copies', 1)
        
        logger.info(f"Printing to {printer_id}: {document_path}")
        return {
            'job_id': '',  # Would be actual job ID from print system
            'printer_id': printer_id,
            'document_path': document_path,
            'success': True
        }
    
    def _evaluate_conditional(self, conditional_type: str, properties: Dict, context: Dict) -> tuple:
        """
        Evaluate conditional and return (output_handle, condition_result).
        
        Returns:
            Tuple of (output_handle: str, condition_result: bool)
        """
        if conditional_type == 'logic.if':
            expression = properties.get('expression', '')
            result = self._evaluate_expression(expression, context)
            return ('true' if result else 'false', result)
        
        elif conditional_type == 'logic.switch':
            switch_on = properties.get('value', '')
            cases = properties.get('cases', [])
            
            value = context.get(switch_on)
            for i, case in enumerate(cases):
                if value == case:
                    return (f'case{i+1}', True)
            return ('default', False)
        
        return (None, False)
    
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
        """Apply data transformation. Returns updated context."""
        try:
            if transform_type == 'transform.filter':
                # Filter: only continue if condition is met
                expression = properties.get('expression', '')
                matched = self._evaluate_expression(expression, context)
                context['matched'] = matched
                if not matched:
                    # Filter didn't match - set a flag for downstream
                    context['_filtered'] = True
                return context
            
            elif transform_type == 'transform.map_fields':
                # Map fields: rename or restructure context fields
                mappings_str = properties.get('mappings', '{}')
                # Parse mappings if it's a string (JSON)
                if isinstance(mappings_str, str):
                    try:
                        import json
                        field_mappings = json.loads(mappings_str)
                    except:
                        field_mappings = {}
                else:
                    field_mappings = mappings_str
                    
                for source_field, target_field in field_mappings.items():
                    if source_field in context:
                        context[target_field] = context[source_field]
                return context
            
            elif transform_type == 'transform.template':
                # Template: render a template and store result
                # Properties are already rendered, but template content should be rendered again
                template = properties.get('template', '')
                output_key = properties.get('output_key', 'result')
                # The template itself needs to be rendered with context
                result = self._render_template(template, context)
                context[output_key] = result
                context['result'] = result  # Also store in standard 'result' key
                return context
            
            else:
                logger.warning(f"Unknown transform type: {transform_type}")
                return context
                
        except Exception as e:
            logger.error(f"Error applying transform {transform_type}: {e}")
            return context
    
    def _execute_integration(self, integration_type: str, properties: Dict, context: Dict) -> Dict:
        """Execute integration action. Returns dict with output variables."""
        try:
            # Properties are already rendered by _execute_node
            message = properties.get('message', '')
            
            if integration_type == 'integration.slack':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'text': message}, timeout=10)
                return {
                    'status_code': response.status_code,
                    'success': response.status_code == 200
                }
            
            elif integration_type == 'integration.teams':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'text': message}, timeout=10)
                return {
                    'status_code': response.status_code,
                    'success': response.status_code == 200
                }
            
            elif integration_type == 'integration.discord':
                webhook_url = properties.get('webhook_url', '')
                response = requests.post(webhook_url, json={'content': message}, timeout=10)
                return {
                    'status_code': response.status_code,
                    'success': response.status_code in [200, 204]
                }
            
            elif integration_type == 'integration.api':
                # Generic API call integration
                url = properties.get('url', '')
                method = properties.get('method', 'POST').upper()
                headers = properties.get('headers', {})
                body = properties.get('body', '{}')
                
                # Add default content type if not specified
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
                
                response = requests.request(
                    method,
                    url,
                    data=body,
                    headers=headers,
                    timeout=int(properties.get('timeout', 10))
                )
                
                # Try to parse response as JSON
                try:
                    response_body = response.json()
                except:
                    response_body = response.text
                
                logger.info(f"API integration {method} {url} returned {response.status_code}")
                return {
                    'status_code': response.status_code,
                    'response_body': response_body,
                    'success': response.status_code < 400
                }
            
            return {'success': False}
        except Exception as e:
            logger.error(f"Error executing integration {integration_type}: {e}")
            return {'success': False}
    
    def _render_template(self, template: str, context: Dict) -> str:
        """
        Render template with context variables.
        Supports both simple {{variable}} and nested {{object.key}} syntax.
        """
        import re
        
        def get_nested_value(obj: Dict, path: str) -> Any:
            """Get a nested value from a dictionary using dot notation."""
            keys = path.split('.')
            current = obj
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            return current
        
        result = template
        # Find all {{variable}} patterns
        pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_\.]*)\}\}'
        matches = re.findall(pattern, template)
        
        for match in matches:
            value = get_nested_value(context, match)
            if value is not None:
                result = result.replace(f'{{{{{match}}}}}', str(value))
        
        return result
    
    def _render_properties(self, properties: Dict, context: Dict) -> Dict:
        """
        Render all string properties that may contain {{variable}} templates.
        Returns a new dictionary with rendered values.
        """
        rendered = {}
        for key, value in properties.items():
            if isinstance(value, str):
                rendered[key] = self._render_template(value, context)
            elif isinstance(value, dict):
                rendered[key] = self._render_properties(value, context)
            elif isinstance(value, list):
                rendered[key] = [
                    self._render_template(item, context) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                rendered[key] = value
        return rendered
    
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
