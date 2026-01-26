"""
Elastic (Elasticsearch) Integration Handler.

Provides bidirectional integration with Elasticsearch/Elastic Stack:
- Send logs to Elasticsearch indices
- Receive alerts from Elastic Watcher or Kibana Alerts
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

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


class ElasticIntegration(IntegrationBase):
    """
    Elasticsearch Integration.
    
    Features:
    - Send logs to Elasticsearch indices
    - Bulk indexing for efficiency
    - Multiple authentication methods (API key, Basic auth)
    - Receive Elastic Watcher/Kibana alerts via webhook
    - Data stream support
    """
    
    ELASTIC_ICON = '''<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M13.5 2c-3.31 0-6 2.69-6 6 0 1.98.96 3.73 2.44 4.82L9 14l-6 8h12c3.31 0 6-2.69 6-6 0-1.98-.96-3.73-2.44-4.82L19.5 10l6-8H13.5z"/>
    </svg>'''
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='elastic',
            name='Elasticsearch',
            description='Send printer events and logs to Elasticsearch. Receive alerts from Elastic Watcher or Kibana Alerting.',
            category=IntegrationCategory.LOGGING,
            auth_type=AuthType.API_KEY,
            capabilities=[
                IntegrationCapability.SEND_LOGS,
                IntegrationCapability.RECEIVE_ALERTS,
                IntegrationCapability.WEBHOOK_INBOUND,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon=cls.ELASTIC_ICON,
            color='#00BFB3',
            version='1.0.0',
            vendor='Elastic N.V.',
            docs_url='https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html',
            support_url='https://www.elastic.co/support',
            config_schema=[
                ConfigField(
                    name='url',
                    label='Elasticsearch URL',
                    type='url',
                    required=True,
                    description='Elasticsearch cluster URL (e.g., https://elasticsearch.example.com:9200)',
                    placeholder='https://elasticsearch.example.com:9200',
                ),
                ConfigField(
                    name='cloud_id',
                    label='Elastic Cloud ID',
                    type='text',
                    required=False,
                    description='Elastic Cloud deployment ID (alternative to URL)',
                    placeholder='my-deployment:dXMtZWFzdC0xLmF3cy...',
                ),
                ConfigField(
                    name='auth_method',
                    label='Authentication Method',
                    type='select',
                    required=True,
                    default='api_key',
                    options=[
                        {'value': 'api_key', 'label': 'API Key'},
                        {'value': 'basic', 'label': 'Basic Auth (username/password)'},
                    ],
                ),
                ConfigField(
                    name='index_pattern',
                    label='Index Pattern',
                    type='text',
                    required=False,
                    default='continuum-logs',
                    description='Index name or pattern (use {date} for daily indices)',
                    placeholder='continuum-logs-{date}',
                ),
                ConfigField(
                    name='use_data_stream',
                    label='Use Data Streams',
                    type='boolean',
                    required=False,
                    default=False,
                    description='Use Elasticsearch data streams instead of regular indices',
                ),
                ConfigField(
                    name='pipeline',
                    label='Ingest Pipeline',
                    type='text',
                    required=False,
                    description='Name of ingest pipeline to process documents',
                    placeholder='continuum-pipeline',
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
                    label='Bulk Batch Size',
                    type='number',
                    required=False,
                    default=100,
                    description='Number of documents to batch for bulk indexing',
                    validation={'min': 1, 'max': 5000},
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
                'signature_header': 'X-Elastic-Signature',
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._batch: List[Dict[str, Any]] = []
    
    @property
    def base_url(self) -> str:
        """Get the Elasticsearch base URL."""
        url = self.config.get('url', '')
        if url:
            return url.rstrip('/')
        
        # Handle Cloud ID if provided
        cloud_id = self.config.get('cloud_id')
        if cloud_id:
            # Parse Cloud ID to extract URL
            try:
                import base64
                decoded = base64.b64decode(cloud_id.split(':')[1]).decode()
                parts = decoded.split('$')
                return f'https://{parts[1]}.{parts[0]}'
            except Exception:
                pass
        
        return ''
    
    @property
    def index_name(self) -> str:
        """Get the target index name."""
        pattern = self.config.get('index_pattern', 'continuum-logs')
        if '{date}' in pattern:
            return pattern.replace('{date}', datetime.utcnow().strftime('%Y.%m.%d'))
        return pattern
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on auth method."""
        auth_method = self.config.get('auth_method', 'api_key')
        
        if auth_method == 'api_key':
            api_key = self._credentials.get('api_key', '')
            if api_key:
                return {'Authorization': f'ApiKey {api_key}'}
        
        elif auth_method == 'basic':
            import base64
            username = self._credentials.get('username', '')
            password = self._credentials.get('password', '')
            if username and password:
                creds = base64.b64encode(f'{username}:{password}'.encode()).decode()
                return {'Authorization': f'Basic {creds}'}
        
        return {}
    
    async def connect(self) -> bool:
        """Establish connection to Elasticsearch."""
        self._update_health(IntegrationStatus.CONNECTING)
        
        if not self.base_url:
            raise IntegrationValidationError(
                'Elasticsearch URL or Cloud ID is required',
                field='url'
            )
        
        # Create session with authentication
        self._session = requests.Session()
        self._session.headers.update({
            'Content-Type': 'application/json',
            **self._get_auth_headers(),
        })
        
        # Test the connection
        health = await self.test_connection()
        
        if health.status != IntegrationStatus.CONNECTED:
            raise IntegrationConnectionError(
                health.last_error or 'Failed to connect to Elasticsearch'
            )
        
        return True
    
    async def disconnect(self) -> bool:
        """Disconnect from Elasticsearch."""
        # Flush any remaining batched documents
        if self._batch:
            await self._flush_batch()
        
        if self._session:
            self._session.close()
            self._session = None
        
        self._update_health(IntegrationStatus.DISCONNECTED)
        return True
    
    async def test_connection(self) -> ConnectionHealth:
        """Test the Elasticsearch connection."""
        start_time = time.time()
        
        try:
            if not self._session:
                self._session = requests.Session()
                self._session.headers.update({
                    'Content-Type': 'application/json',
                    **self._get_auth_headers(),
                })
            
            # Check cluster health
            response = self._session.get(
                f'{self.base_url}/_cluster/health',
                verify=self.config.get('verify_ssl', True),
                timeout=self.config.get('timeout', 30),
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                health_data = response.json()
                cluster_status = health_data.get('status', 'unknown')
                
                self._update_health(
                    IntegrationStatus.CONNECTED,
                    response_time_ms=response_time
                )
                self._health.details = {
                    'cluster_name': health_data.get('cluster_name'),
                    'cluster_status': cluster_status,
                    'number_of_nodes': health_data.get('number_of_nodes'),
                }
                return self._health
            elif response.status_code == 401:
                raise IntegrationAuthError(
                    'Invalid credentials',
                    remediation='Check your API key or username/password.'
                )
            elif response.status_code == 403:
                raise IntegrationAuthError(
                    'Credentials do not have required permissions',
                    remediation='Ensure credentials have cluster:monitor/health and index write permissions.'
                )
            else:
                raise IntegrationConnectionError(
                    f'Elasticsearch returned status {response.status_code}'
                )
                
        except requests.exceptions.SSLError as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(
                'SSL certificate verification failed',
                remediation='Check the SSL certificate or disable verification.'
            )
        except requests.exceptions.Timeout:
            self._update_health(IntegrationStatus.ERROR, error='Connection timeout')
            raise IntegrationConnectionError(
                'Connection to Elasticsearch timed out',
                remediation='Check network connectivity and cluster availability.'
            )
        except requests.exceptions.ConnectionError as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(
                'Could not connect to Elasticsearch',
                remediation='Verify the URL is correct and the cluster is running.'
            )
        except IntegrationError:
            raise
        except Exception as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Connection test failed: {str(e)}')
    
    async def send_log(self, log_data: Dict[str, Any]) -> bool:
        """Send a single document to Elasticsearch."""
        if not self._session:
            await self.connect()
        
        document = self._format_document(log_data)
        
        # Add to batch if batching is enabled
        batch_size = self.config.get('batch_size', 100)
        if batch_size > 1:
            self._batch.append(document)
            if len(self._batch) >= batch_size:
                await self._flush_batch()
            return True
        
        # Send immediately
        return await self._index_document(document)
    
    async def send_logs_batch(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send multiple documents using bulk API."""
        if not self._session:
            await self.connect()
        
        documents = [self._format_document(log) for log in logs]
        
        try:
            result = await self._bulk_index(documents)
            return result
        except IntegrationError as e:
            return {
                'total': len(logs),
                'success': 0,
                'failures': [{'error': e.message}],
            }
    
    def _format_document(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format log data as an Elasticsearch document."""
        document = log_data.copy()
        
        # Add timestamp if not present
        if '@timestamp' not in document:
            ts = log_data.get('timestamp')
            if isinstance(ts, (int, float)):
                document['@timestamp'] = datetime.utcfromtimestamp(ts).isoformat() + 'Z'
            elif isinstance(ts, datetime):
                document['@timestamp'] = ts.isoformat() + 'Z'
            else:
                document['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add source metadata
        document['_source'] = 'continuum'
        
        return document
    
    async def _index_document(self, document: Dict[str, Any]) -> bool:
        """Index a single document."""
        start_time = time.time()
        
        try:
            url = f'{self.base_url}/{self.index_name}/_doc'
            
            params = {}
            pipeline = self.config.get('pipeline')
            if pipeline:
                params['pipeline'] = pipeline
            
            response = self._session.post(
                url,
                json=document,
                params=params,
                verify=self.config.get('verify_ssl', True),
                timeout=self.config.get('timeout', 30),
            )
            
            duration = int((time.time() - start_time) * 1000)
            self._log_api_call('POST', url, response.status_code, duration)
            
            if response.status_code in (200, 201):
                self._update_health(IntegrationStatus.CONNECTED, response_time_ms=duration)
                return True
            elif response.status_code == 401:
                raise IntegrationAuthError('Credentials invalid or expired')
            elif response.status_code == 429:
                raise IntegrationRateLimitError('Rate limit exceeded', retry_after=60)
            else:
                error_body = response.json() if response.text else {}
                raise IntegrationError(
                    f'Failed to index document: {error_body.get("error", response.text)}',
                    code='INDEX_FAILED'
                )
                
        except requests.exceptions.RequestException as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Request failed: {str(e)}')
    
    async def _bulk_index(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk index multiple documents."""
        start_time = time.time()
        
        try:
            # Build bulk request body (NDJSON format)
            bulk_body = []
            for doc in documents:
                # Action line
                action = {'index': {'_index': self.index_name}}
                bulk_body.append(json.dumps(action))
                # Document line
                bulk_body.append(json.dumps(doc))
            
            body = '\n'.join(bulk_body) + '\n'
            
            url = f'{self.base_url}/_bulk'
            
            params = {}
            pipeline = self.config.get('pipeline')
            if pipeline:
                params['pipeline'] = pipeline
            
            response = self._session.post(
                url,
                data=body,
                params=params,
                headers={'Content-Type': 'application/x-ndjson'},
                verify=self.config.get('verify_ssl', True),
                timeout=self.config.get('timeout', 30),
            )
            
            duration = int((time.time() - start_time) * 1000)
            self._log_api_call('POST', url, response.status_code, duration)
            
            if response.status_code == 200:
                result = response.json()
                errors = result.get('errors', False)
                items = result.get('items', [])
                
                success_count = sum(1 for item in items 
                                   if item.get('index', {}).get('status', 0) in (200, 201))
                failures = [
                    {
                        'error': item.get('index', {}).get('error', {}).get('reason', 'Unknown error'),
                        'index': i,
                    }
                    for i, item in enumerate(items)
                    if item.get('index', {}).get('status', 0) not in (200, 201)
                ]
                
                if not errors:
                    self._update_health(IntegrationStatus.CONNECTED, response_time_ms=duration)
                
                return {
                    'total': len(documents),
                    'success': success_count,
                    'failures': failures,
                }
            elif response.status_code == 429:
                raise IntegrationRateLimitError('Rate limit exceeded', retry_after=60)
            else:
                raise IntegrationError(
                    f'Bulk index failed with status {response.status_code}',
                    code='BULK_FAILED'
                )
                
        except requests.exceptions.RequestException as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Request failed: {str(e)}')
    
    async def _flush_batch(self):
        """Flush batched documents."""
        if not self._batch:
            return
        
        documents = self._batch.copy()
        self._batch.clear()
        
        await self._bulk_index(documents)
    
    async def handle_webhook(self, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle incoming Elastic Watcher/Kibana alert webhook."""
        # Parse alert payload
        alert_id = payload.get('watch_id') or payload.get('alert_id', 'unknown')
        alert_state = payload.get('state', {}).get('status', 'unknown')
        
        self._logger.info(f'Received Elastic alert: {alert_id} ({alert_state})')
        
        return {
            'received': True,
            'alert_id': alert_id,
            'state': alert_state,
            'processed': True,
        }
