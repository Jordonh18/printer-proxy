"""
Grafana Integration Handler.

Provides integration with Grafana for alerting and annotations:
- Receive alerts from Grafana Alerting
- Send annotations to Grafana
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


class GrafanaIntegration(IntegrationBase):
    """
    Grafana Integration for alerting and annotations.
    
    Features:
    - Receive Grafana alerts via webhook
    - Push annotations to Grafana dashboards
    - Create dashboard annotations for events
    """
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='grafana',
            name='Grafana',
            description='Receive alerts from Grafana and create annotations on dashboards. Visualize printer events alongside your metrics.',
            category=IntegrationCategory.MONITORING,
            auth_type=AuthType.API_KEY,
            capabilities=[
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.SEND_LOGS,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon='📈',
            color='#F46800',
            version='1.0.0',
            vendor='Grafana Labs',
            docs_url='https://grafana.com/docs/grafana/latest/alerting/',
            support_url='https://grafana.com/support/',
            config_schema=[
                ConfigField(
                    name='grafana_url',
                    label='Grafana URL',
                    type='url',
                    required=True,
                    description='Your Grafana instance URL (e.g., https://grafana.example.com)',
                    placeholder='https://grafana.example.com',
                ),
                ConfigField(
                    name='org_id',
                    label='Organization ID',
                    type='number',
                    required=False,
                    default=1,
                    description='Grafana organization ID',
                ),
                ConfigField(
                    name='dashboard_uid',
                    label='Dashboard UID',
                    type='text',
                    required=False,
                    description='Default dashboard UID for annotations',
                ),
                ConfigField(
                    name='annotation_tags',
                    label='Annotation Tags',
                    type='text',
                    required=False,
                    default='continuum,printer',
                    description='Comma-separated tags for annotations',
                ),
            ],
            webhook_config={
                'supported': True,
                'signature_header': 'X-Grafana-Signature',
                'signature_algorithm': 'sha256',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._pending_alerts: List[Dict[str, Any]] = []
    
    async def connect(self) -> bool:
        """Initialize connection to Grafana."""
        try:
            self._session = requests.Session()
            
            api_key = self.credentials.get('api_key')
            if not api_key:
                raise IntegrationAuthError('API key is required')
            
            self._session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
            })
            
            # Test connection
            grafana_url = self.config.get('grafana_url', '').rstrip('/')
            response = self._session.get(
                f'{grafana_url}/api/org',
                timeout=10,
            )
            
            if response.status_code == 200:
                self._status = IntegrationStatus.CONNECTED
                self._last_connected = datetime.utcnow()
                logger.info(f'Connected to Grafana: {self.connection_id}')
                return True
            elif response.status_code == 401:
                raise IntegrationAuthError('Invalid API key')
            else:
                raise IntegrationConnectionError(
                    f'Failed to connect: HTTP {response.status_code}'
                )
                
        except requests.exceptions.RequestException as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'Grafana connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from Grafana: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check Grafana health."""
        start_time = time.time()
        
        try:
            if not self._session:
                return ConnectionHealth(
                    status='disconnected',
                    last_check=datetime.utcnow(),
                )
            
            grafana_url = self.config.get('grafana_url', '').rstrip('/')
            response = self._session.get(
                f'{grafana_url}/api/health',
                timeout=10,
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                health_data = response.json()
                return ConnectionHealth(
                    status='healthy',
                    last_check=datetime.utcnow(),
                    last_success=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={
                        'database': health_data.get('database', 'unknown'),
                        'version': health_data.get('version', 'unknown'),
                    },
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
        """Create an annotation in Grafana."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        grafana_url = self.config.get('grafana_url', '').rstrip('/')
        dashboard_uid = self.config.get('dashboard_uid')
        tags_str = self.config.get('annotation_tags', 'continuum,printer')
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]
        
        # Add event type as a tag
        tags.append(event_type.replace('.', '-'))
        
        annotation = {
            'time': int(time.time() * 1000),
            'tags': tags,
            'text': payload.get('message', json.dumps(payload)),
        }
        
        if dashboard_uid:
            annotation['dashboardUID'] = dashboard_uid
        
        try:
            response = self._session.post(
                f'{grafana_url}/api/annotations',
                json=annotation,
                timeout=30,
            )
            
            if response.status_code in (200, 201):
                logger.debug(f'Created Grafana annotation for {event_type}')
                return True
            else:
                logger.error(f'Grafana annotation failed: HTTP {response.status_code}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'Grafana annotation error: {e}')
            raise IntegrationConnectionError(f'Annotation failed: {e}')
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Get pending alert from Grafana webhook."""
        if self._pending_alerts:
            return self._pending_alerts.pop(0)
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Validate Grafana webhook signature."""
        webhook_secret = self.credentials.get('webhook_secret')
        if not webhook_secret:
            # If no secret configured, skip validation
            return True
        
        expected_sig = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_sig)
    
    def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Process incoming Grafana alert webhook."""
        # Grafana alert format
        alert_state = payload.get('state', 'unknown')
        alert_name = payload.get('ruleName', payload.get('title', 'Unknown Alert'))
        message = payload.get('message', '')
        
        event = {
            'source': 'grafana',
            'type': 'alert',
            'alert_name': alert_name,
            'state': alert_state,
            'message': message,
            'labels': payload.get('tags', {}),
            'raw': payload,
            'received_at': datetime.utcnow().isoformat(),
        }
        
        self._pending_alerts.append(event)
        return {'status': 'accepted', 'event_id': len(self._pending_alerts)}
