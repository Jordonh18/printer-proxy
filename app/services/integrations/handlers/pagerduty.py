"""
PagerDuty Integration Handler.

Provides integration with PagerDuty for incident management:
- Send alerts/incidents to PagerDuty
- Receive incident updates via webhook
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from ..base import (
    IntegrationBase,
    IntegrationMetadata,
    IntegrationStatus,
    IntegrationCategory,
    IntegrationCapability,
    AuthType,
    ConfigField,
    ConnectionHealth,
    IntegrationError,
    IntegrationAuthError,
    IntegrationConnectionError,
    IntegrationRateLimitError,
    IntegrationValidationError,
)

logger = logging.getLogger(__name__)


class PagerDutyIntegration(IntegrationBase):
    """
    PagerDuty Integration for incident management.
    
    Features:
    - Trigger, acknowledge, resolve incidents
    - Receive incident webhooks
    - Custom severity mapping
    - Deduplication key support
    """
    
    EVENTS_API_V2 = 'https://events.pagerduty.com/v2/enqueue'
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='pagerduty',
            name='PagerDuty',
            description='Create incidents in PagerDuty when printers fail or need attention. Trigger on-call alerts for critical print infrastructure issues.',
            category=IntegrationCategory.ALERTING,
            auth_type=AuthType.TOKEN,
            capabilities=[
                IntegrationCapability.SEND_ALERTS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon='🚨',
            color='#06AC38',
            version='1.0.0',
            vendor='PagerDuty, Inc.',
            docs_url='https://developer.pagerduty.com/docs/events-api-v2/overview/',
            support_url='https://support.pagerduty.com/',
            config_schema=[
                ConfigField(
                    name='default_severity',
                    label='Default Severity',
                    type='select',
                    required=False,
                    default='warning',
                    options=[
                        {'value': 'critical', 'label': 'Critical'},
                        {'value': 'error', 'label': 'Error'},
                        {'value': 'warning', 'label': 'Warning'},
                        {'value': 'info', 'label': 'Info'},
                    ],
                    description='Default severity for alerts',
                ),
                ConfigField(
                    name='source',
                    label='Source',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Source identifier for incidents',
                ),
                ConfigField(
                    name='component',
                    label='Component',
                    type='text',
                    required=False,
                    default='print-infrastructure',
                    description='Component name for incidents',
                ),
                ConfigField(
                    name='group',
                    label='Group',
                    type='text',
                    required=False,
                    description='Logical grouping for incidents',
                ),
                ConfigField(
                    name='class',
                    label='Class',
                    type='text',
                    required=False,
                    description='Class/type of the incident',
                ),
            ],
            webhook_config={
                'supported': True,
                'signature_header': 'X-PagerDuty-Signature',
                'signature_algorithm': 'sha256',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._pending_events: List[Dict[str, Any]] = []
    
    async def connect(self) -> bool:
        """Initialize connection to PagerDuty."""
        try:
            routing_key = self.credentials.get('routing_key')
            if not routing_key:
                raise IntegrationAuthError('Routing key (Integration Key) is required')
            
            self._session = requests.Session()
            self._session.headers.update({
                'Content-Type': 'application/json',
            })
            
            # PagerDuty doesn't have a simple health check, so we validate the routing key format
            if len(routing_key) != 32:
                raise IntegrationAuthError('Invalid routing key format')
            
            self._status = IntegrationStatus.CONNECTED
            self._last_connected = datetime.utcnow()
            logger.info(f'Connected to PagerDuty: {self.connection_id}')
            return True
                
        except Exception as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'PagerDuty connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from PagerDuty: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check PagerDuty connectivity."""
        start_time = time.time()
        
        try:
            if not self._session:
                return ConnectionHealth(
                    status='disconnected',
                    last_check=datetime.utcnow(),
                )
            
            # PagerDuty doesn't have a health endpoint, check API status page
            response = requests.get(
                'https://status.pagerduty.com/api/v2/status.json',
                timeout=10,
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                status_data = response.json()
                indicator = status_data.get('status', {}).get('indicator', 'unknown')
                return ConnectionHealth(
                    status='healthy' if indicator == 'none' else 'degraded',
                    last_check=datetime.utcnow(),
                    last_success=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={'pagerduty_status': indicator},
                )
            else:
                return ConnectionHealth(
                    status='unknown',
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                )
                
        except Exception as e:
            return ConnectionHealth(
                status='error',
                last_check=datetime.utcnow(),
                last_error=str(e),
            )
    
    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """Send an event/incident to PagerDuty."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        routing_key = self.credentials.get('routing_key')
        if not routing_key:
            raise IntegrationAuthError('Routing key not configured')
        
        # Map event type to PagerDuty action
        action = payload.get('action', 'trigger')
        if action not in ('trigger', 'acknowledge', 'resolve'):
            action = 'trigger'
        
        # Build PagerDuty event
        severity = payload.get('severity', self.config.get('default_severity', 'warning'))
        
        pagerduty_event = {
            'routing_key': routing_key,
            'event_action': action,
            'dedup_key': payload.get('dedup_key', f'continuum-{event_type}-{payload.get("id", time.time())}'),
            'payload': {
                'summary': payload.get('summary', payload.get('message', f'Continuum: {event_type}')),
                'source': self.config.get('source', 'continuum'),
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'component': self.config.get('component', 'print-infrastructure'),
                'custom_details': {
                    'event_type': event_type,
                    **{k: v for k, v in payload.items() if k not in ('summary', 'message', 'severity', 'action', 'dedup_key')},
                },
            },
        }
        
        if self.config.get('group'):
            pagerduty_event['payload']['group'] = self.config['group']
        if self.config.get('class'):
            pagerduty_event['payload']['class'] = self.config['class']
        
        try:
            response = self._session.post(
                self.EVENTS_API_V2,
                json=pagerduty_event,
                timeout=30,
            )
            
            if response.status_code in (200, 201, 202):
                result = response.json()
                logger.info(f'PagerDuty event sent: {result.get("dedup_key")}')
                return True
            elif response.status_code == 429:
                raise IntegrationRateLimitError('PagerDuty rate limit exceeded')
            else:
                logger.error(f'PagerDuty event failed: HTTP {response.status_code} - {response.text}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'PagerDuty event error: {e}')
            raise IntegrationConnectionError(f'Event failed: {e}')
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Get pending event from PagerDuty webhook."""
        if self._pending_events:
            return self._pending_events.pop(0)
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Validate PagerDuty webhook signature."""
        webhook_secret = self.credentials.get('webhook_secret')
        if not webhook_secret:
            return True
        
        # PagerDuty uses HMAC-SHA256
        expected_sig = 'v1=' + hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_sig)
    
    def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Process incoming PagerDuty webhook."""
        messages = payload.get('messages', [])
        
        for msg in messages:
            event = msg.get('event', 'unknown')
            incident = msg.get('incident', {})
            
            processed_event = {
                'source': 'pagerduty',
                'type': event,
                'incident_id': incident.get('id'),
                'incident_number': incident.get('incident_number'),
                'title': incident.get('title'),
                'status': incident.get('status'),
                'urgency': incident.get('urgency'),
                'service': incident.get('service', {}).get('name'),
                'raw': msg,
                'received_at': datetime.utcnow().isoformat(),
            }
            
            self._pending_events.append(processed_event)
        
        return {'status': 'accepted', 'events_received': len(messages)}
