"""
Opsgenie Integration Handler.

Provides integration with Opsgenie for alert management:
- Send alerts to Opsgenie
- Receive alert updates via webhook
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


class OpsgenieIntegration(IntegrationBase):
    """
    Opsgenie Integration for alert management.
    
    Features:
    - Create, acknowledge, close alerts
    - Receive alert webhooks
    - Priority and tag support
    - Team routing
    """
    
    API_ENDPOINTS = {
        'us': 'https://api.opsgenie.com',
        'eu': 'https://api.eu.opsgenie.com',
    }
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='opsgenie',
            name='Opsgenie',
            description='Send alerts to Opsgenie for on-call notification and incident management. Route printer alerts to the right teams.',
            category=IntegrationCategory.ALERTING,
            auth_type=AuthType.API_KEY,
            capabilities=[
                IntegrationCapability.SEND_ALERTS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon='🔔',
            color='#2684FF',
            version='1.0.0',
            vendor='Atlassian',
            docs_url='https://support.atlassian.com/opsgenie/docs/opsgenie-api-overview/',
            support_url='https://support.atlassian.com/opsgenie/',
            config_schema=[
                ConfigField(
                    name='region',
                    label='Region',
                    type='select',
                    required=False,
                    default='us',
                    options=[
                        {'value': 'us', 'label': 'United States'},
                        {'value': 'eu', 'label': 'Europe'},
                    ],
                    description='Opsgenie API region',
                ),
                ConfigField(
                    name='default_priority',
                    label='Default Priority',
                    type='select',
                    required=False,
                    default='P3',
                    options=[
                        {'value': 'P1', 'label': 'P1 - Critical'},
                        {'value': 'P2', 'label': 'P2 - High'},
                        {'value': 'P3', 'label': 'P3 - Moderate'},
                        {'value': 'P4', 'label': 'P4 - Low'},
                        {'value': 'P5', 'label': 'P5 - Informational'},
                    ],
                    description='Default priority for alerts',
                ),
                ConfigField(
                    name='responders',
                    label='Default Responders',
                    type='text',
                    required=False,
                    description='Comma-separated list of team or user names',
                ),
                ConfigField(
                    name='tags',
                    label='Default Tags',
                    type='text',
                    required=False,
                    default='continuum,printer',
                    description='Comma-separated list of tags',
                ),
                ConfigField(
                    name='source',
                    label='Source',
                    type='text',
                    required=False,
                    default='Continuum Print Management',
                    description='Source identifier for alerts',
                ),
            ],
            webhook_config={
                'supported': True,
                'signature_header': 'X-OpsGenie-Signature',
                'signature_algorithm': 'sha256',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._pending_events: List[Dict[str, Any]] = []
    
    def _get_api_url(self) -> str:
        region = self.config.get('region', 'us')
        return self.API_ENDPOINTS.get(region, self.API_ENDPOINTS['us'])
    
    async def connect(self) -> bool:
        """Initialize connection to Opsgenie."""
        try:
            api_key = self.credentials.get('api_key')
            if not api_key:
                raise IntegrationAuthError('API key is required')
            
            self._session = requests.Session()
            self._session.headers.update({
                'Authorization': f'GenieKey {api_key}',
                'Content-Type': 'application/json',
            })
            
            # Test connection by getting account info
            api_url = self._get_api_url()
            response = self._session.get(
                f'{api_url}/v2/account',
                timeout=10,
            )
            
            if response.status_code == 200:
                self._status = IntegrationStatus.CONNECTED
                self._last_connected = datetime.utcnow()
                logger.info(f'Connected to Opsgenie: {self.connection_id}')
                return True
            elif response.status_code == 401:
                raise IntegrationAuthError('Invalid API key')
            elif response.status_code == 403:
                raise IntegrationAuthError('API key lacks required permissions')
            else:
                raise IntegrationConnectionError(
                    f'Failed to connect: HTTP {response.status_code}'
                )
                
        except requests.exceptions.RequestException as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'Opsgenie connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from Opsgenie: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check Opsgenie health."""
        start_time = time.time()
        
        try:
            if not self._session:
                return ConnectionHealth(
                    status='disconnected',
                    last_check=datetime.utcnow(),
                )
            
            api_url = self._get_api_url()
            response = self._session.get(
                f'{api_url}/v2/heartbeats',
                timeout=10,
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code in (200, 404):  # 404 if no heartbeats configured
                return ConnectionHealth(
                    status='healthy',
                    last_check=datetime.utcnow(),
                    last_success=datetime.utcnow(),
                    response_time_ms=response_time,
                )
            else:
                return ConnectionHealth(
                    status='unhealthy',
                    last_check=datetime.utcnow(),
                    last_error=f'HTTP {response.status_code}',
                    response_time_ms=response_time,
                )
                
        except Exception as e:
            return ConnectionHealth(
                status='error',
                last_check=datetime.utcnow(),
                last_error=str(e),
            )
    
    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """Send an alert to Opsgenie."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        api_url = self._get_api_url()
        
        # Determine action
        action = payload.get('action', 'create')
        alert_id = payload.get('alert_id')
        
        if action == 'close' and alert_id:
            return await self._close_alert(alert_id)
        elif action == 'acknowledge' and alert_id:
            return await self._acknowledge_alert(alert_id)
        
        # Create new alert
        tags_str = self.config.get('tags', 'continuum,printer')
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]
        tags.append(event_type.replace('.', '-'))
        
        alert = {
            'message': payload.get('message', f'Continuum: {event_type}'),
            'priority': payload.get('priority', self.config.get('default_priority', 'P3')),
            'source': self.config.get('source', 'Continuum Print Management'),
            'tags': tags,
            'details': {
                'event_type': event_type,
                **{k: str(v) for k, v in payload.items() if k not in ('message', 'priority', 'action', 'alert_id')},
            },
        }
        
        if payload.get('description'):
            alert['description'] = payload['description']
        
        if payload.get('alias'):
            alert['alias'] = payload['alias']
        
        # Add responders
        responders_str = self.config.get('responders', '')
        if responders_str:
            responders = []
            for r in responders_str.split(','):
                r = r.strip()
                if r:
                    responders.append({'type': 'team', 'name': r})
            if responders:
                alert['responders'] = responders
        
        try:
            response = self._session.post(
                f'{api_url}/v2/alerts',
                json=alert,
                timeout=30,
            )
            
            if response.status_code in (200, 201, 202):
                result = response.json()
                logger.info(f'Opsgenie alert created: {result.get("requestId")}')
                return True
            elif response.status_code == 429:
                raise IntegrationRateLimitError('Opsgenie rate limit exceeded')
            else:
                logger.error(f'Opsgenie alert failed: HTTP {response.status_code} - {response.text}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'Opsgenie alert error: {e}')
            raise IntegrationConnectionError(f'Alert failed: {e}')
    
    async def _close_alert(self, alert_id: str) -> bool:
        """Close an alert."""
        api_url = self._get_api_url()
        try:
            response = self._session.post(
                f'{api_url}/v2/alerts/{alert_id}/close',
                json={'source': self.config.get('source', 'Continuum')},
                timeout=30,
            )
            return response.status_code in (200, 202)
        except Exception as e:
            logger.error(f'Failed to close Opsgenie alert: {e}')
            return False
    
    async def _acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        api_url = self._get_api_url()
        try:
            response = self._session.post(
                f'{api_url}/v2/alerts/{alert_id}/acknowledge',
                json={'source': self.config.get('source', 'Continuum')},
                timeout=30,
            )
            return response.status_code in (200, 202)
        except Exception as e:
            logger.error(f'Failed to acknowledge Opsgenie alert: {e}')
            return False
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Get pending event from Opsgenie webhook."""
        if self._pending_events:
            return self._pending_events.pop(0)
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Validate Opsgenie webhook signature."""
        webhook_secret = self.credentials.get('webhook_secret')
        if not webhook_secret:
            return True
        
        expected_sig = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature.lower(), expected_sig.lower())
    
    def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Process incoming Opsgenie webhook."""
        action = payload.get('action', 'unknown')
        alert = payload.get('alert', {})
        
        event = {
            'source': 'opsgenie',
            'type': action,
            'alert_id': alert.get('alertId'),
            'message': alert.get('message'),
            'priority': alert.get('priority'),
            'tags': alert.get('tags', []),
            'raw': payload,
            'received_at': datetime.utcnow().isoformat(),
        }
        
        self._pending_events.append(event)
        return {'status': 'accepted'}
