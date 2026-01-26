"""
Splunk Integration Handler.

Provides bidirectional integration with Splunk:
- Send logs via HTTP Event Collector (HEC)
- Receive alerts via webhook
"""

import asyncio
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


class SplunkIntegration(IntegrationBase):
    """
    Splunk Integration using HTTP Event Collector (HEC).
    
    Features:
    - Send logs to Splunk via HEC
    - Batch log sending for efficiency
    - Receive Splunk alerts via webhook
    - SSL/TLS with optional certificate verification
    """
    
    SPLUNK_ICON = '''<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L2 7l10 5 10-5-10-5z" fill="currentColor"/>
        <path d="M2 17l10 5 10-5" stroke="currentColor" stroke-width="2"/>
        <path d="M2 12l10 5 10-5" stroke="currentColor" stroke-width="2"/>
    </svg>'''
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='splunk',
            name='Splunk',
            description='Send printer events and logs to Splunk via HTTP Event Collector (HEC). Receive alerts from Splunk to trigger workflows.',
            category=IntegrationCategory.LOGGING,
            auth_type=AuthType.TOKEN,
            capabilities=[
                IntegrationCapability.SEND_LOGS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon=cls.SPLUNK_ICON,
            color='#65A637',
            version='1.0.0',
            vendor='Splunk Inc.',
            docs_url='https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
            support_url='https://www.splunk.com/en_us/support.html',
            config_schema=[
                ConfigField(
                    name='hec_url',
                    label='HEC Endpoint URL',
                    type='url',
                    required=True,
                    description='Splunk HTTP Event Collector URL (e.g., https://splunk.example.com:8088)',
                    placeholder='https://splunk.example.com:8088',
                ),
                ConfigField(
                    name='index',
                    label='Index',
                    type='text',
                    required=False,
                    default='main',
                    description='Splunk index to send events to',
                    placeholder='main',
                ),
                ConfigField(
                    name='source',
                    label='Source',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Source identifier for events',
                ),
                ConfigField(
                    name='sourcetype',
                    label='Source Type',
                    type='text',
                    required=False,
                    default='_json',
                    description='Source type for events',
                ),
                ConfigField(
                    name='verify_ssl',
                    label='Verify SSL Certificate',
                    type='boolean',
                    required=False,
                    default=True,
                    description='Verify SSL certificate for HTTPS connections',
                ),
                ConfigField(
                    name='batch_size',
                    label='Batch Size',
                    type='number',
                    required=False,
                    default=100,
                    description='Number of events to batch before sending',
                    validation={'min': 1, 'max': 1000},
                ),
                ConfigField(
                    name='timeout',
                    label='Request Timeout (seconds)',
                    type='number',
                    required=False,
                    default=30,
                    validation={'min': 5, 'max': 300},
                ),
            ],
            webhook_config={
                'supported': True,
                'signature_header': 'X-Splunk-Signature',
                'signature_algorithm': 'hmac-sha256',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._batch: List[Dict[str, Any]] = []
    
    @property
    def hec_url(self) -> str:
        """Get the HEC endpoint URL."""
        url = self.config.get('hec_url', '')
        if url and not url.endswith('/services/collector/event'):
            url = url.rstrip('/') + '/services/collector/event'
        return url
    
    @property
    def hec_token(self) -> str:
        """Get the HEC token from credentials."""
        return self._credentials.get('hec_token', '')
    
    async def connect(self) -> bool:
        """Establish connection to Splunk HEC."""
        self._update_health(IntegrationStatus.CONNECTING)
        
        if not self.hec_url:
            raise IntegrationValidationError('HEC endpoint URL is required', field='hec_url')
        
        if not self.hec_token:
            raise IntegrationAuthError('HEC token is required')
        
        # Create session with authentication
        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json',
        })
        
        # Test the connection
        health = await self.test_connection()
        
        if health.status != IntegrationStatus.CONNECTED:
            raise IntegrationConnectionError(
                health.last_error or 'Failed to connect to Splunk HEC'
            )
        
        return True
    
    async def disconnect(self) -> bool:
        """Disconnect from Splunk."""
        # Flush any remaining batched events
        if self._batch:
            await self._flush_batch()
        
        if self._session:
            self._session.close()
            self._session = None
        
        self._update_health(IntegrationStatus.DISCONNECTED)
        return True
    
    async def test_connection(self) -> ConnectionHealth:
        """Test the HEC connection."""
        start_time = time.time()
        
        try:
            if not self._session:
                self._session = requests.Session()
                self._session.headers.update({
                    'Authorization': f'Splunk {self.hec_token}',
                    'Content-Type': 'application/json',
                })
            
            # Send a test event to the health endpoint
            health_url = self.hec_url.replace('/event', '/health')
            
            response = self._session.get(
                health_url,
                verify=self.config.get('verify_ssl', True),
                timeout=self.config.get('timeout', 30),
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                self._update_health(
                    IntegrationStatus.CONNECTED,
                    response_time_ms=response_time
                )
                return self._health
            elif response.status_code == 401:
                raise IntegrationAuthError(
                    'Invalid HEC token',
                    remediation='Check that your HEC token is correct and has not been revoked.'
                )
            elif response.status_code == 403:
                raise IntegrationAuthError(
                    'HEC token does not have required permissions',
                    remediation='Ensure the HEC token has permission to write to the specified index.'
                )
            else:
                raise IntegrationConnectionError(
                    f'HEC returned status {response.status_code}: {response.text}'
                )
                
        except requests.exceptions.SSLError as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(
                'SSL certificate verification failed',
                remediation='Check the SSL certificate or disable verification if using self-signed certificates.'
            )
        except requests.exceptions.Timeout:
            self._update_health(IntegrationStatus.ERROR, error='Connection timeout')
            raise IntegrationConnectionError(
                'Connection to Splunk timed out',
                remediation='Check network connectivity and firewall rules.'
            )
        except requests.exceptions.ConnectionError as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(
                'Could not connect to Splunk HEC',
                remediation='Verify the HEC URL is correct and the service is running.'
            )
        except IntegrationError:
            raise
        except Exception as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Connection test failed: {str(e)}')
    
    async def send_log(self, log_data: Dict[str, Any]) -> bool:
        """Send a single log event to Splunk."""
        if not self._session:
            await self.connect()
        
        event = self._format_event(log_data)
        
        # Add to batch if batching is enabled
        batch_size = self.config.get('batch_size', 100)
        if batch_size > 1:
            self._batch.append(event)
            if len(self._batch) >= batch_size:
                await self._flush_batch()
            return True
        
        # Send immediately
        return await self._send_events([event])
    
    async def send_logs_batch(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send multiple logs in a batch."""
        if not self._session:
            await self.connect()
        
        events = [self._format_event(log) for log in logs]
        
        try:
            success = await self._send_events(events)
            return {
                'total': len(logs),
                'success': len(logs) if success else 0,
                'failures': [] if success else [{'error': 'Batch send failed'}],
            }
        except IntegrationError as e:
            return {
                'total': len(logs),
                'success': 0,
                'failures': [{'error': e.message}],
            }
    
    def _format_event(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format log data as a Splunk HEC event."""
        event = {
            'event': log_data,
            'time': log_data.get('timestamp', datetime.utcnow().timestamp()),
            'source': self.config.get('source', 'continuum'),
            'sourcetype': self.config.get('sourcetype', '_json'),
            'host': log_data.get('host', 'continuum'),
        }
        
        index = self.config.get('index')
        if index:
            event['index'] = index
        
        return event
    
    async def _send_events(self, events: List[Dict[str, Any]]) -> bool:
        """Send events to Splunk HEC."""
        start_time = time.time()
        
        try:
            # HEC accepts newline-delimited JSON for batch
            payload = '\n'.join(json.dumps(e) for e in events)
            
            response = self._session.post(
                self.hec_url,
                data=payload,
                verify=self.config.get('verify_ssl', True),
                timeout=self.config.get('timeout', 30),
            )
            
            duration = int((time.time() - start_time) * 1000)
            self._log_api_call('POST', self.hec_url, response.status_code, duration)
            
            if response.status_code == 200:
                self._update_health(IntegrationStatus.CONNECTED, response_time_ms=duration)
                return True
            elif response.status_code == 401:
                raise IntegrationAuthError('HEC token invalid or expired')
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                raise IntegrationRateLimitError(
                    'Rate limit exceeded',
                    retry_after=retry_after
                )
            else:
                error_body = response.json() if response.text else {}
                raise IntegrationError(
                    f'Failed to send events: {error_body.get("text", response.text)}',
                    code='SEND_FAILED'
                )
                
        except requests.exceptions.RequestException as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Request failed: {str(e)}')
    
    async def _flush_batch(self):
        """Flush batched events."""
        if not self._batch:
            return
        
        events = self._batch.copy()
        self._batch.clear()
        
        await self._send_events(events)
    
    async def handle_webhook(self, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle incoming Splunk alert webhook."""
        # Validate webhook signature if configured
        webhook_secret = self._credentials.get('webhook_secret')
        if webhook_secret:
            signature = headers.get('X-Splunk-Signature', '')
            if not self._verify_webhook_signature(payload, signature, webhook_secret):
                raise IntegrationAuthError('Invalid webhook signature')
        
        # Parse Splunk alert payload
        alert_name = payload.get('search_name', 'Unknown Alert')
        results = payload.get('result', {})
        
        self._logger.info(f'Received Splunk alert: {alert_name}')
        
        return {
            'received': True,
            'alert_name': alert_name,
            'processed': True,
        }
    
    def _verify_webhook_signature(self, payload: Dict[str, Any], 
                                  signature: str, secret: str) -> bool:
        """Verify webhook HMAC signature."""
        import hmac
        import hashlib
        
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        expected = hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected)
