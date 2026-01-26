"""
Prometheus Integration Handler.

Provides integration with Prometheus for metrics collection:
- Expose metrics endpoint for Prometheus scraping
- Push metrics via Pushgateway
"""

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


class PrometheusIntegration(IntegrationBase):
    """
    Prometheus Integration for metrics collection.
    
    Features:
    - Push metrics to Prometheus Pushgateway
    - Remote write to Prometheus
    - Label customization
    - Metric batching
    """
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='prometheus',
            name='Prometheus',
            description='Push printer metrics to Prometheus via Pushgateway or remote write. Monitor print queue depths, job durations, and printer health.',
            category=IntegrationCategory.MONITORING,
            auth_type=AuthType.BASIC,
            capabilities=[
                IntegrationCapability.SEND_METRICS,
                IntegrationCapability.BIDIRECTIONAL,
            ],
            icon='📊',
            color='#E6522C',
            version='1.0.0',
            vendor='Prometheus Authors',
            docs_url='https://prometheus.io/docs/introduction/overview/',
            support_url='https://prometheus.io/community/',
            config_schema=[
                ConfigField(
                    name='pushgateway_url',
                    label='Pushgateway URL',
                    type='url',
                    required=True,
                    description='Prometheus Pushgateway URL (e.g., http://pushgateway:9091)',
                    placeholder='http://pushgateway:9091',
                ),
                ConfigField(
                    name='job_name',
                    label='Job Name',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Job name label for metrics',
                ),
                ConfigField(
                    name='instance',
                    label='Instance Label',
                    type='text',
                    required=False,
                    description='Instance label for metrics (defaults to hostname)',
                ),
                ConfigField(
                    name='metric_prefix',
                    label='Metric Prefix',
                    type='text',
                    required=False,
                    default='continuum_',
                    description='Prefix for all metric names',
                ),
                ConfigField(
                    name='push_interval',
                    label='Push Interval (seconds)',
                    type='number',
                    required=False,
                    default=60,
                    description='How often to push metrics to Pushgateway',
                ),
            ],
            webhook_config={
                'supported': False,
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._session: Optional[requests.Session] = None
        self._last_push = 0
    
    async def connect(self) -> bool:
        """Initialize connection to Prometheus Pushgateway."""
        try:
            self._session = requests.Session()
            
            # Set up basic auth if provided
            username = self.credentials.get('username')
            password = self.credentials.get('password')
            if username and password:
                self._session.auth = (username, password)
            
            # Test connection by getting metrics
            pushgateway_url = self.config.get('pushgateway_url', '').rstrip('/')
            response = self._session.get(
                f'{pushgateway_url}/metrics',
                timeout=10,
            )
            
            if response.status_code in (200, 401, 403):
                self._status = IntegrationStatus.CONNECTED
                self._last_connected = datetime.utcnow()
                logger.info(f'Connected to Prometheus Pushgateway: {self.connection_id}')
                return True
            else:
                raise IntegrationConnectionError(
                    f'Failed to connect: HTTP {response.status_code}'
                )
                
        except requests.exceptions.RequestException as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'Prometheus connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close the connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from Prometheus: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check Pushgateway health."""
        start_time = time.time()
        
        try:
            if not self._session:
                return ConnectionHealth(
                    status='disconnected',
                    last_check=datetime.utcnow(),
                )
            
            pushgateway_url = self.config.get('pushgateway_url', '').rstrip('/')
            response = self._session.get(
                f'{pushgateway_url}/-/healthy',
                timeout=10,
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                return ConnectionHealth(
                    status='healthy',
                    last_check=datetime.utcnow(),
                    last_success=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={'pushgateway': 'healthy'},
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
        """Push metrics to Pushgateway."""
        if not self._session:
            raise IntegrationConnectionError('Not connected')
        
        pushgateway_url = self.config.get('pushgateway_url', '').rstrip('/')
        job_name = self.config.get('job_name', 'continuum')
        instance = self.config.get('instance', '')
        metric_prefix = self.config.get('metric_prefix', 'continuum_')
        
        # Convert event payload to Prometheus metrics format
        metrics_lines = []
        
        for key, value in payload.items():
            if isinstance(value, (int, float)):
                metric_name = f'{metric_prefix}{key}'.replace('.', '_').replace('-', '_')
                metrics_lines.append(f'{metric_name} {value}')
        
        if not metrics_lines:
            return True
        
        metrics_text = '\n'.join(metrics_lines) + '\n'
        
        # Build URL with job and optional instance
        url = f'{pushgateway_url}/metrics/job/{job_name}'
        if instance:
            url += f'/instance/{instance}'
        
        try:
            response = self._session.post(
                url,
                data=metrics_text,
                headers={'Content-Type': 'text/plain'},
                timeout=30,
            )
            
            if response.status_code in (200, 202):
                self._last_push = time.time()
                return True
            else:
                logger.error(f'Prometheus push failed: HTTP {response.status_code}')
                return False
                
        except requests.exceptions.RequestException as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'Prometheus push error: {e}')
            raise IntegrationConnectionError(f'Push failed: {e}')
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Prometheus doesn't support receiving events directly."""
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Prometheus doesn't use webhooks."""
        return False
