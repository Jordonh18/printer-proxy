"""
Base classes and interfaces for the Integration Framework.

Provides a standardized interface pattern that makes new integrations easy to scaffold.
Each integration is self-contained with its own authentication provider, schema validator,
and connection handler.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Callable
import json

logger = logging.getLogger(__name__)


class IntegrationStatus(str, Enum):
    """Status of an integration connection."""
    DISCONNECTED = 'disconnected'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    ERROR = 'error'
    RATE_LIMITED = 'rate_limited'
    AUTHENTICATING = 'authenticating'
    PENDING_OAUTH = 'pending_oauth'


class AuthType(str, Enum):
    """Authentication type for an integration."""
    NONE = 'none'
    API_KEY = 'api_key'
    OAUTH2 = 'oauth2'
    BASIC = 'basic'
    TOKEN = 'token'
    WEBHOOK_SECRET = 'webhook_secret'
    CERTIFICATE = 'certificate'


class IntegrationCategory(str, Enum):
    """Category of an integration."""
    LOGGING = 'logging'
    MONITORING = 'monitoring'
    ALERTING = 'alerting'
    TICKETING = 'ticketing'
    COMMUNICATION = 'communication'
    SECURITY = 'security'
    AUTOMATION = 'automation'


class IntegrationCapability(str, Enum):
    """Capabilities an integration can support."""
    SEND_LOGS = 'send_logs'
    RECEIVE_EVENTS = 'receive_events'
    SEND_ALERTS = 'send_alerts'
    RECEIVE_ALERTS = 'receive_alerts'
    SEND_METRICS = 'send_metrics'
    BIDIRECTIONAL = 'bidirectional'
    WEBHOOK_INBOUND = 'webhook_inbound'
    WEBHOOK_OUTBOUND = 'webhook_outbound'


class IntegrationError(Exception):
    """Base exception for integration errors."""
    
    def __init__(self, message: str, code: str = 'INTEGRATION_ERROR', 
                 details: Optional[Dict[str, Any]] = None,
                 remediation: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.remediation = remediation
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'error': self.code,
            'message': self.message,
            'details': self.details,
            'remediation': self.remediation,
        }


class IntegrationAuthError(IntegrationError):
    """Authentication or authorization error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None,
                 remediation: Optional[str] = None):
        super().__init__(
            message=message,
            code='AUTH_ERROR',
            details=details,
            remediation=remediation or 'Please check your credentials and try again.'
        )


class IntegrationConnectionError(IntegrationError):
    """Connection or network error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None,
                 remediation: Optional[str] = None):
        super().__init__(
            message=message,
            code='CONNECTION_ERROR',
            details=details,
            remediation=remediation or 'Check your network connection and firewall settings.'
        )


class IntegrationRateLimitError(IntegrationError):
    """Rate limit exceeded error."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='RATE_LIMIT_ERROR',
            details={**(details or {}), 'retry_after_seconds': retry_after},
            remediation=f'Rate limit exceeded. Try again in {retry_after} seconds.' if retry_after else 'Rate limit exceeded. Please wait before retrying.'
        )
        self.retry_after = retry_after


class IntegrationValidationError(IntegrationError):
    """Validation error for configuration or data."""
    
    def __init__(self, message: str, field: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='VALIDATION_ERROR',
            details={**(details or {}), 'field': field} if field else details,
            remediation='Please check the configuration values and try again.'
        )
        self.field = field


@dataclass
class ConfigField:
    """Definition of a configuration field for an integration."""
    name: str
    label: str
    type: str  # 'text', 'password', 'url', 'number', 'select', 'multiselect', 'boolean', 'json'
    required: bool = True
    default: Any = None
    description: Optional[str] = None
    placeholder: Optional[str] = None
    sensitive: bool = False
    options: Optional[List[Dict[str, str]]] = None  # For select/multiselect
    validation: Optional[Dict[str, Any]] = None  # Validation rules
    depends_on: Optional[Dict[str, Any]] = None  # Show only if condition is met


@dataclass
class IntegrationMetadata:
    """Metadata about an integration."""
    id: str
    name: str
    description: str
    category: IntegrationCategory
    auth_type: AuthType
    capabilities: List[IntegrationCapability]
    icon: str  # SVG or icon name
    color: str  # Hex color for branding
    version: str
    vendor: str
    docs_url: Optional[str] = None
    support_url: Optional[str] = None
    config_schema: List[ConfigField] = field(default_factory=list)
    oauth_config: Optional[Dict[str, Any]] = None  # OAuth configuration if applicable
    webhook_config: Optional[Dict[str, Any]] = None  # Webhook configuration if applicable
    required_scopes: List[str] = field(default_factory=list)
    optional_scopes: List[str] = field(default_factory=list)
    beta: bool = False
    deprecated: bool = False


@dataclass
class ConnectionHealth:
    """Health status of an integration connection."""
    status: IntegrationStatus
    last_check: datetime
    last_success: Optional[datetime] = None
    last_error: Optional[str] = None
    error_count: int = 0
    response_time_ms: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EventRouting:
    """Routing configuration for events."""
    event_type: str
    enabled: bool = True
    filters: Dict[str, Any] = field(default_factory=dict)
    transform: Optional[Dict[str, Any]] = None  # Optional data transformation
    priority: int = 0


class IntegrationBase(ABC):
    """
    Base class for all integrations.
    
    Provides a standardized interface with:
    - Authentication handling
    - Connection management
    - Health monitoring
    - Error handling with retry logic
    - Rate limiting
    - Logging and observability
    """
    
    def __init__(self, connection_id: str, config: Dict[str, Any],
                 credentials: Dict[str, Any]):
        self.connection_id = connection_id
        self.config = config
        self._credentials = credentials
        self._status = IntegrationStatus.DISCONNECTED
        self._health = ConnectionHealth(
            status=IntegrationStatus.DISCONNECTED,
            last_check=datetime.utcnow()
        )
        self._retry_count = 0
        self._max_retries = 3
        self._base_retry_delay = 1.0
        self._max_retry_delay = 60.0
        self._logger = logging.getLogger(f'integration.{self.get_metadata().id}.{connection_id}')
    
    @classmethod
    @abstractmethod
    def get_metadata(cls) -> IntegrationMetadata:
        """Get the integration metadata."""
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the integration.
        
        Returns:
            True if connection was successful.
            
        Raises:
            IntegrationConnectionError: If connection fails.
            IntegrationAuthError: If authentication fails.
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """
        Disconnect from the integration.
        
        Returns:
            True if disconnection was successful.
        """
        pass
    
    @abstractmethod
    async def test_connection(self) -> ConnectionHealth:
        """
        Test the connection and return health status.
        
        Returns:
            ConnectionHealth with current status.
        """
        pass
    
    @abstractmethod
    async def send_log(self, log_data: Dict[str, Any]) -> bool:
        """
        Send log data to the integration.
        
        Args:
            log_data: The log entry to send.
            
        Returns:
            True if the log was sent successfully.
            
        Raises:
            IntegrationError: If sending fails.
        """
        pass
    
    async def send_logs_batch(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send multiple logs in a batch (if supported).
        
        Default implementation sends logs individually.
        Override for batch support.
        
        Args:
            logs: List of log entries to send.
            
        Returns:
            Result with success count and failures.
        """
        success = 0
        failures = []
        
        for log in logs:
            try:
                await self.send_log(log)
                success += 1
            except IntegrationError as e:
                failures.append({'log': log, 'error': str(e)})
        
        return {
            'total': len(logs),
            'success': success,
            'failures': failures,
        }
    
    async def handle_webhook(self, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Handle an incoming webhook from the integration.
        
        Override if the integration supports inbound webhooks.
        
        Args:
            payload: The webhook payload.
            headers: HTTP headers from the request.
            
        Returns:
            Response data to send back.
        """
        raise NotImplementedError(
            f'{self.get_metadata().name} does not support inbound webhooks.'
        )
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration against the schema.
        
        Args:
            config: Configuration to validate.
            
        Returns:
            List of validation error messages.
        """
        errors = []
        metadata = self.get_metadata()
        
        for field in metadata.config_schema:
            value = config.get(field.name)
            
            # Check required fields
            if field.required and (value is None or value == ''):
                errors.append(f'{field.label} is required.')
                continue
            
            if value is None:
                continue
            
            # Type validation
            if field.type == 'url':
                if not isinstance(value, str) or not value.startswith(('http://', 'https://')):
                    errors.append(f'{field.label} must be a valid URL.')
            
            elif field.type == 'number':
                if not isinstance(value, (int, float)):
                    errors.append(f'{field.label} must be a number.')
                elif field.validation:
                    if 'min' in field.validation and value < field.validation['min']:
                        errors.append(f'{field.label} must be at least {field.validation["min"]}.')
                    if 'max' in field.validation and value > field.validation['max']:
                        errors.append(f'{field.label} must be at most {field.validation["max"]}.')
            
            elif field.type == 'select' and field.options:
                valid_values = [opt['value'] for opt in field.options]
                if value not in valid_values:
                    errors.append(f'{field.label} must be one of: {", ".join(valid_values)}.')
        
        return errors
    
    def get_health(self) -> ConnectionHealth:
        """Get current health status."""
        return self._health
    
    def get_status(self) -> IntegrationStatus:
        """Get current connection status."""
        return self._status
    
    def _update_health(self, status: IntegrationStatus, 
                       error: Optional[str] = None,
                       response_time_ms: Optional[int] = None):
        """Update health status."""
        now = datetime.utcnow()
        
        if status == IntegrationStatus.CONNECTED:
            self._health.last_success = now
            self._health.error_count = 0
            self._retry_count = 0
        elif status == IntegrationStatus.ERROR:
            self._health.last_error = error
            self._health.error_count += 1
        
        self._health.status = status
        self._health.last_check = now
        self._health.response_time_ms = response_time_ms
        self._status = status
    
    def _calculate_retry_delay(self) -> float:
        """Calculate exponential backoff delay."""
        delay = self._base_retry_delay * (2 ** self._retry_count)
        return min(delay, self._max_retry_delay)
    
    async def _with_retry(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Execute an operation with retry logic.
        
        Args:
            operation: Async function to execute.
            *args: Positional arguments for the operation.
            **kwargs: Keyword arguments for the operation.
            
        Returns:
            Result of the operation.
            
        Raises:
            IntegrationError: If all retries fail.
        """
        import asyncio
        
        last_error = None
        
        for attempt in range(self._max_retries + 1):
            try:
                return await operation(*args, **kwargs)
            except IntegrationRateLimitError as e:
                last_error = e
                if e.retry_after:
                    await asyncio.sleep(e.retry_after)
                else:
                    await asyncio.sleep(self._calculate_retry_delay())
                self._retry_count += 1
            except IntegrationConnectionError as e:
                last_error = e
                if attempt < self._max_retries:
                    await asyncio.sleep(self._calculate_retry_delay())
                    self._retry_count += 1
            except IntegrationAuthError:
                # Don't retry auth errors
                raise
            except IntegrationError:
                # Don't retry other errors by default
                raise
        
        raise last_error or IntegrationError('Operation failed after retries.')
    
    def _log_api_call(self, method: str, endpoint: str, 
                      status_code: Optional[int] = None,
                      duration_ms: Optional[int] = None,
                      error: Optional[str] = None):
        """Log an API call for observability."""
        log_data = {
            'integration': self.get_metadata().id,
            'connection_id': self.connection_id,
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'duration_ms': duration_ms,
        }
        
        if error:
            log_data['error'] = error
            self._logger.warning('Integration API call failed', extra=log_data)
        else:
            self._logger.debug('Integration API call', extra=log_data)
