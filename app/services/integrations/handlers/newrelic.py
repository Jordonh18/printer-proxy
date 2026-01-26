"""
New Relic Integration Handler.

Provides integration with New Relic for monitoring:
- Send custom events to New Relic
- Send logs via Log API
- Receive alerts via webhook
"""

import gzip
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


class NewRelicIntegration(IntegrationBase):
    """
    New Relic Integration for observability.
    
    Features:
    - Send custom events
    - Send logs via Log API
    - Receive alert webhooks
    - Multi-region support
    """
    
    ENDPOINTS = {
        'us': {
            'events': 'https://insights-collector.newrelic.com/v1/accounts/{account_id}/events',
            'logs': 'https://log-api.newrelic.com/log/v1',
            'metrics': 'https://metric-api.newrelic.com/metric/v1',
        },
        'eu': {
            'events': 'https://insights-collector.eu01.nr-data.net/v1/accounts/{account_id}/events',
            'logs': 'https://log-api.eu.newrelic.com/log/v1',
            'metrics': 'https://metric-api.eu.newrelic.com/metric/v1',
        },
    }
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='newrelic',
            name='New Relic',
            description='Send printer events and logs to New Relic for full-stack observability. Create custom dashboards and alerts for your print infrastructure.',
            category=IntegrationCategory.MONITORING,
            auth_type=AuthType.API_KEY,
            capabilities=[
                IntegrationCapability.SEND_LOGS,
                IntegrationCapability.SEND_METRICS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon='📡',
            color='#008C99',
            version='1.0.0',
            vendor='New Relic, Inc.',
            docs_url='https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/',
            support_url='https://support.newrelic.com/',
            config_schema=[
                ConfigField(
                    name='account_id',
                    label='Account ID',
                    type='text',
                    required=True,
                    description='Your New Relic Account ID',
                    placeholder='1234567',
                ),
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
                    description='New Relic data center region',
                ),
                ConfigField(
                    name='event_type',
                    label='Custom Event Type',
                    type='text',
                    required=False,
                    default='ContinuumPrinterEvent',
                    description='Custom event type name in New Relic',
                ),
                ConfigField(
                    name='service_name',
                    label='Service Name',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Service name for logs',
                ),
                ConfigField(
                    name='compress_logs',
                    label='Compress Logs',
                    type='boolean',
                    required=False,
                    default=True,
                    description='Use gzip compression for log payloads',
                ),
            ],
            webhook_config={
                'supported': True,
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._pending_events: List[Dict[str, Any]] = []
    
    def _get_endpoints(self) -> Dict[str, str]:
        region = self.config.get('region', 'us')
        endpoints = self.ENDPOINTS.get(region, self.ENDPOINTS['us']).copy()
        account_id = self.config.get('account_id', '')
        endpoints['events'] = endpoints['events'].format(account_id=account_id)
        return endpoints
    
    async def connect(self) -> bool:
        """Initialize connection to New Relic."""
        try:
            api_key = self.credentials.get('api_key')
            if not api_key:
                raise IntegrationAuthError('API key (License Key or Ingest Key) is required')
            
            account_id = self.config.get('account_id')
            if not account_id:
                raise IntegrationValidationError('Account ID is required')
            
            self._session = requests.Session()
            self._session.headers.update({
                'Api-Key': api_key,
                'Content-Type': 'application/json',
            })
            
            # Test by sending a test event
            endpoints = self._get_endpoints()
            test_event = [{
                'eventType': 'ContinuumConnectionTest',
                'timestamp': int(time.time()),
                'test': True,
            }]
            
            response = self._session.post(
                endpoints['events'],
                json=test_event,
                timeout=10,
            )
            
            if response.status_code in (200, 202):
                self._status = IntegrationStatus.CONNECTED
                self._last_connected = datetime.utcnow()
                logger.info(f'Connected to New Relic: {self.connection_id}')
                return True
            elif response.status_code == 403:
                raise IntegrationAuthError('Invalid API key or insufficient permissions')
            else:
                raise IntegrationConnectionError(
                    f'Failed to connect: HTTP {response.status_code}'
                )
                
        except requests.exceptions.RequestException as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'New Relic connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from New Relic: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check New Relic health."""
        start_time = time.time()
        
        try:
            if not self._session:
                return ConnectionHealth(
                    status='disconnected',
                    last_check=datetime.utcnow(),
                )
            
            # Check New Relic status page
            response = requests.get(
                'https://status.newrelic.com/api/v2/status.json',
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
                    details={'newrelic_status': indicator},
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
        """Send an event to New Relic."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        endpoints = self._get_endpoints()
        custom_event_type = self.config.get('event_type', 'ContinuumPrinterEvent')
        
        # Build New Relic event
        nr_event = {
            'eventType': custom_event_type,
            'timestamp': int(time.time()),
            'continuum_event_type': event_type,
            **{k: v for k, v in payload.items() if isinstance(v, (str, int, float, bool))},
        }
        
        try:
            response = self._session.post(
                endpoints['events'],
                json=[nr_event],
                timeout=30,
            )
            
            if response.status_code in (200, 202):
                logger.debug(f'New Relic event sent: {event_type}')
                return True
            elif response.status_code == 429:
                raise IntegrationRateLimitError('New Relic rate limit exceeded')
            else:
                logger.error(f'New Relic event failed: HTTP {response.status_code}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'New Relic event error: {e}')
            raise IntegrationConnectionError(f'Event failed: {e}')
    
    async def send_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Send logs to New Relic Log API."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        endpoints = self._get_endpoints()
        service_name = self.config.get('service_name', 'continuum')
        compress = self.config.get('compress_logs', True)
        
        # Format logs for New Relic
        log_entries = []
        for log in logs:
            entry = {
                'timestamp': int(log.get('timestamp', time.time()) * 1000),
                'message': log.get('message', json.dumps(log)),
                'attributes': {
                    'service.name': service_name,
                    **{k: v for k, v in log.items() if k not in ('timestamp', 'message')},
                },
            }
            log_entries.append(entry)
        
        payload = [{'logs': log_entries}]
        
        headers = {'Content-Type': 'application/json'}
        data = json.dumps(payload).encode()
        
        if compress:
            data = gzip.compress(data)
            headers['Content-Encoding'] = 'gzip'
        
        try:
            response = self._session.post(
                endpoints['logs'],
                data=data,
                headers=headers,
                timeout=30,
            )
            
            if response.status_code in (200, 202):
                logger.debug(f'Sent {len(logs)} logs to New Relic')
                return True
            else:
                logger.error(f'New Relic logs failed: HTTP {response.status_code}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'New Relic logs error: {e}')
            raise IntegrationConnectionError(f'Log send failed: {e}')
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Get pending event from New Relic webhook."""
        if self._pending_events:
            return self._pending_events.pop(0)
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Validate New Relic webhook (no built-in signature)."""
        # New Relic doesn't sign webhooks by default
        return True
    
    def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Process incoming New Relic alert webhook."""
        # New Relic alert format varies by channel type
        condition_name = payload.get('condition_name', 'Unknown')
        current_state = payload.get('current_state', 'unknown')
        
        event = {
            'source': 'newrelic',
            'type': 'alert',
            'condition_name': condition_name,
            'state': current_state,
            'incident_id': payload.get('incident_id'),
            'account_id': payload.get('account_id'),
            'policy_name': payload.get('policy_name'),
            'details': payload.get('details'),
            'raw': payload,
            'received_at': datetime.utcnow().isoformat(),
        }
        
        self._pending_events.append(event)
        return {'status': 'accepted'}
