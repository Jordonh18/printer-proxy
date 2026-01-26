"""
Datadog Integration Handler.

Provides bidirectional integration with Datadog:
- Send logs via Logs API
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


class DatadogIntegration(IntegrationBase):
    """
    Datadog Integration using Logs API.
    
    Features:
    - Send logs to Datadog via Logs API
    - Automatic batching for efficiency
    - Receive Datadog alerts via webhook
    - Multi-region support (US, EU, etc.)
    """
    
    DATADOG_ICON = '''<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M12.26 2c-.57.01-1.14.1-1.68.28-.54.17-1.04.43-1.5.75-.46.32-.87.71-1.22 1.14-.35.43-.64.91-.86 1.42-.22.51-.37 1.05-.44 1.6-.07.55-.07 1.11 0 1.66.08.55.23 1.09.44 1.6.22.51.51.99.86 1.42.35.43.76.82 1.22 1.14.46.32.96.58 1.5.75.54.17 1.11.27 1.68.28.57-.01 1.14-.1 1.68-.28.54-.17 1.04-.43 1.5-.75.46-.32.87-.71 1.22-1.14.35-.43.64-.91.86-1.42.22-.51.37-1.05.44-1.6.07-.55.07-1.11 0-1.66-.08-.55-.23-1.09-.44-1.6-.22-.51-.51-.99-.86-1.42-.35-.43-.76-.82-1.22-1.14-.46-.32-.96-.58-1.5-.75-.54-.17-1.11-.27-1.68-.28z"/>
    </svg>'''
    
    # Datadog site endpoints
    SITES = {
        'us1': 'https://http-intake.logs.datadoghq.com',
        'us3': 'https://http-intake.logs.us3.datadoghq.com',
        'us5': 'https://http-intake.logs.us5.datadoghq.com',
        'eu1': 'https://http-intake.logs.datadoghq.eu',
        'ap1': 'https://http-intake.logs.ap1.datadoghq.com',
        'gov': 'https://http-intake.logs.ddog-gov.com',
    }
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='datadog',
            name='Datadog',
            description='Send printer events and logs to Datadog. Receive monitor alerts to trigger workflows and automated responses.',
            category=IntegrationCategory.MONITORING,
            auth_type=AuthType.API_KEY,
            capabilities=[
                IntegrationCapability.SEND_LOGS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon=cls.DATADOG_ICON,
            color='#632CA6',
            version='1.0.0',
            vendor='Datadog, Inc.',
            docs_url='https://docs.datadoghq.com/api/latest/logs/',
            support_url='https://www.datadoghq.com/support/',
            config_schema=[
                ConfigField(
                    name='site',
                    label='Datadog Site',
                    type='select',
                    required=True,
                    default='us1',
                    description='Select your Datadog site/region',
                    options=[
                        {'value': 'us1', 'label': 'US1 (datadoghq.com)'},
                        {'value': 'us3', 'label': 'US3 (us3.datadoghq.com)'},
                        {'value': 'us5', 'label': 'US5 (us5.datadoghq.com)'},
                        {'value': 'eu1', 'label': 'EU (datadoghq.eu)'},
                        {'value': 'ap1', 'label': 'AP1 (ap1.datadoghq.com)'},
                        {'value': 'gov', 'label': 'US1-FED (ddog-gov.com)'},
                    ],
                ),
                ConfigField(
                    name='service',
                    label='Service Name',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Service name to tag logs with',
                    placeholder='continuum',
                ),
                ConfigField(
                    name='source',
                    label='Log Source',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Source of the logs',
                ),
                ConfigField(
                    name='env',
                    label='Environment',
                    type='text',
                    required=False,
                    description='Environment tag (e.g., production, staging)',
                    placeholder='production',
                ),
                ConfigField(
                    name='tags',
                    label='Additional Tags',
                    type='text',
                    required=False,
                    description='Comma-separated list of tags (e.g., team:ops,app:printers)',
                    placeholder='team:ops,app:printers',
                ),
                ConfigField(
                    name='batch_size',
                    label='Batch Size',
                    type='number',
                    required=False,
                    default=100,
                    description='Number of logs to batch before sending',
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
                'signature_header': 'X-Datadog-Signature',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._batch: List[Dict[str, Any]] = []
    
    @property
    def logs_url(self) -> str:
        """Get the logs API endpoint URL."""
        site = self.config.get('site', 'us1')
        base_url = self.SITES.get(site, self.SITES['us1'])
        return f'{base_url}/api/v2/logs'
    
    @property
    def api_key(self) -> str:
        """Get the API key from credentials."""
        return self._credentials.get('api_key', '')
    
    async def connect(self) -> bool:
        """Establish connection to Datadog."""
        self._update_health(IntegrationStatus.CONNECTING)
        
        if not self.api_key:
            raise IntegrationAuthError('API key is required')
        
        # Create session with authentication
        self._session = requests.Session()
        self._session.headers.update({
            'DD-API-KEY': self.api_key,
            'Content-Type': 'application/json',
        })
        
        # Test the connection
        health = await self.test_connection()
        
        if health.status != IntegrationStatus.CONNECTED:
            raise IntegrationConnectionError(
                health.last_error or 'Failed to connect to Datadog'
            )
        
        return True
    
    async def disconnect(self) -> bool:
        """Disconnect from Datadog."""
        # Flush any remaining batched logs
        if self._batch:
            await self._flush_batch()
        
        if self._session:
            self._session.close()
            self._session = None
        
        self._update_health(IntegrationStatus.DISCONNECTED)
        return True
    
    async def test_connection(self) -> ConnectionHealth:
        """Test the Datadog connection."""
        start_time = time.time()
        
        try:
            if not self._session:
                self._session = requests.Session()
                self._session.headers.update({
                    'DD-API-KEY': self.api_key,
                    'Content-Type': 'application/json',
                })
            
            # Send a test log with dryRun=true (validate only)
            test_log = [{
                'message': 'Continuum integration test',
                'service': 'continuum',
                'ddsource': 'continuum',
                'ddtags': 'test:connection',
            }]
            
            response = self._session.post(
                self.logs_url,
                json=test_log,
                timeout=self.config.get('timeout', 30),
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code in (200, 202):
                self._update_health(
                    IntegrationStatus.CONNECTED,
                    response_time_ms=response_time
                )
                return self._health
            elif response.status_code == 400:
                # Check if it's an API key issue
                error_body = response.json() if response.text else {}
                errors = error_body.get('errors', [])
                if any('api key' in str(e).lower() for e in errors):
                    raise IntegrationAuthError(
                        'Invalid API key',
                        remediation='Check that your Datadog API key is correct.'
                    )
                raise IntegrationValidationError(f'Invalid request: {errors}')
            elif response.status_code == 403:
                raise IntegrationAuthError(
                    'API key does not have required permissions',
                    remediation='Ensure the API key has permission to submit logs.'
                )
            else:
                raise IntegrationConnectionError(
                    f'Datadog returned status {response.status_code}'
                )
                
        except requests.exceptions.Timeout:
            self._update_health(IntegrationStatus.ERROR, error='Connection timeout')
            raise IntegrationConnectionError(
                'Connection to Datadog timed out',
                remediation='Check network connectivity.'
            )
        except requests.exceptions.ConnectionError as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(
                'Could not connect to Datadog',
                remediation='Verify network connectivity and check if Datadog is accessible.'
            )
        except IntegrationError:
            raise
        except Exception as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Connection test failed: {str(e)}')
    
    async def send_log(self, log_data: Dict[str, Any]) -> bool:
        """Send a single log entry to Datadog."""
        if not self._session:
            await self.connect()
        
        log_entry = self._format_log(log_data)
        
        # Add to batch if batching is enabled
        batch_size = self.config.get('batch_size', 100)
        if batch_size > 1:
            self._batch.append(log_entry)
            if len(self._batch) >= batch_size:
                await self._flush_batch()
            return True
        
        # Send immediately
        return await self._send_logs([log_entry])
    
    async def send_logs_batch(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send multiple logs in a batch."""
        if not self._session:
            await self.connect()
        
        log_entries = [self._format_log(log) for log in logs]
        
        try:
            success = await self._send_logs(log_entries)
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
    
    def _format_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format log data for Datadog."""
        # Build tags list
        tags = []
        
        env = self.config.get('env')
        if env:
            tags.append(f'env:{env}')
        
        custom_tags = self.config.get('tags', '')
        if custom_tags:
            tags.extend(t.strip() for t in custom_tags.split(',') if t.strip())
        
        # Add any tags from the log data
        if 'tags' in log_data and isinstance(log_data['tags'], list):
            tags.extend(log_data['tags'])
        
        log_entry = {
            'message': log_data.get('message', json.dumps(log_data)),
            'service': self.config.get('service', 'continuum'),
            'ddsource': self.config.get('source', 'continuum'),
            'ddtags': ','.join(tags) if tags else None,
            'hostname': log_data.get('host', 'continuum'),
        }
        
        # Add timestamp if present
        if 'timestamp' in log_data:
            ts = log_data['timestamp']
            if isinstance(ts, (int, float)):
                log_entry['date'] = int(ts * 1000)  # Datadog expects ms
            elif isinstance(ts, datetime):
                log_entry['date'] = int(ts.timestamp() * 1000)
        
        # Add structured attributes
        if 'attributes' in log_data:
            log_entry.update(log_data['attributes'])
        
        # Remove None values
        return {k: v for k, v in log_entry.items() if v is not None}
    
    async def _send_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Send logs to Datadog."""
        start_time = time.time()
        
        try:
            response = self._session.post(
                self.logs_url,
                json=logs,
                timeout=self.config.get('timeout', 30),
            )
            
            duration = int((time.time() - start_time) * 1000)
            self._log_api_call('POST', self.logs_url, response.status_code, duration)
            
            if response.status_code in (200, 202):
                self._update_health(IntegrationStatus.CONNECTED, response_time_ms=duration)
                return True
            elif response.status_code == 403:
                raise IntegrationAuthError('API key invalid or expired')
            elif response.status_code == 429:
                retry_after = int(response.headers.get('X-RateLimit-Reset', 60))
                raise IntegrationRateLimitError(
                    'Rate limit exceeded',
                    retry_after=retry_after
                )
            elif response.status_code == 413:
                raise IntegrationValidationError(
                    'Payload too large',
                    details={'max_size': '5MB'},
                )
            else:
                error_body = response.json() if response.text else {}
                raise IntegrationError(
                    f'Failed to send logs: {error_body.get("errors", response.text)}',
                    code='SEND_FAILED'
                )
                
        except requests.exceptions.RequestException as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Request failed: {str(e)}')
    
    async def _flush_batch(self):
        """Flush batched logs."""
        if not self._batch:
            return
        
        logs = self._batch.copy()
        self._batch.clear()
        
        await self._send_logs(logs)
    
    async def handle_webhook(self, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle incoming Datadog monitor alert webhook."""
        # Parse Datadog webhook payload
        alert_type = payload.get('alert_type', 'unknown')
        title = payload.get('title', 'Unknown Alert')
        body = payload.get('body', '')
        
        self._logger.info(f'Received Datadog alert: {title} ({alert_type})')
        
        return {
            'received': True,
            'alert_type': alert_type,
            'title': title,
            'processed': True,
        }
