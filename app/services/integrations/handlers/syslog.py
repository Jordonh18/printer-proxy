"""
Generic Syslog Integration Handler.

Provides syslog integration for sending logs to any syslog server:
- RFC 5424 (structured data) and RFC 3164 (BSD) format support
- UDP and TCP transport
- TLS encryption support
"""

import asyncio
import json
import logging
import socket
import ssl
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

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
    IntegrationConnectionError,
    IntegrationValidationError,
)

logger = logging.getLogger(__name__)


class SyslogIntegration(IntegrationBase):
    """
    Generic Syslog Integration.
    
    Features:
    - RFC 5424 and RFC 3164 format support
    - UDP, TCP, and TLS transport
    - Facility and severity configuration
    - Structured data support (RFC 5424)
    """
    
    SYSLOG_ICON = '''<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M3 3h18v18H3V3zm2 2v14h14V5H5zm2 2h10v2H7V7zm0 4h10v2H7v-2zm0 4h6v2H7v-2z"/>
    </svg>'''
    
    # Syslog facilities
    FACILITIES = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
    }
    
    # Syslog severities
    SEVERITIES = {
        'emergency': 0, 'alert': 1, 'critical': 2, 'error': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7,
    }
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='syslog',
            name='Syslog',
            description='Send printer events and logs to any syslog server. Supports RFC 5424 and RFC 3164 formats with UDP, TCP, and TLS transport.',
            category=IntegrationCategory.LOGGING,
            auth_type=AuthType.NONE,
            capabilities=[
                IntegrationCapability.SEND_LOGS,
            ],
            icon=cls.SYSLOG_ICON,
            color='#6B7280',
            version='1.0.0',
            vendor='Generic',
            docs_url='https://datatracker.ietf.org/doc/html/rfc5424',
            config_schema=[
                ConfigField(
                    name='host',
                    label='Syslog Server Host',
                    type='text',
                    required=True,
                    description='Hostname or IP address of the syslog server',
                    placeholder='syslog.example.com',
                ),
                ConfigField(
                    name='port',
                    label='Port',
                    type='number',
                    required=True,
                    default=514,
                    description='Syslog server port',
                    validation={'min': 1, 'max': 65535},
                ),
                ConfigField(
                    name='protocol',
                    label='Protocol',
                    type='select',
                    required=True,
                    default='udp',
                    description='Transport protocol',
                    options=[
                        {'value': 'udp', 'label': 'UDP'},
                        {'value': 'tcp', 'label': 'TCP'},
                        {'value': 'tls', 'label': 'TCP with TLS'},
                    ],
                ),
                ConfigField(
                    name='format',
                    label='Syslog Format',
                    type='select',
                    required=True,
                    default='rfc5424',
                    description='Syslog message format',
                    options=[
                        {'value': 'rfc5424', 'label': 'RFC 5424 (Structured)'},
                        {'value': 'rfc3164', 'label': 'RFC 3164 (BSD)'},
                    ],
                ),
                ConfigField(
                    name='facility',
                    label='Facility',
                    type='select',
                    required=False,
                    default='local0',
                    description='Syslog facility',
                    options=[
                        {'value': 'user', 'label': 'User'},
                        {'value': 'daemon', 'label': 'Daemon'},
                        {'value': 'local0', 'label': 'Local0'},
                        {'value': 'local1', 'label': 'Local1'},
                        {'value': 'local2', 'label': 'Local2'},
                        {'value': 'local3', 'label': 'Local3'},
                        {'value': 'local4', 'label': 'Local4'},
                        {'value': 'local5', 'label': 'Local5'},
                        {'value': 'local6', 'label': 'Local6'},
                        {'value': 'local7', 'label': 'Local7'},
                    ],
                ),
                ConfigField(
                    name='app_name',
                    label='Application Name',
                    type='text',
                    required=False,
                    default='continuum',
                    description='Application name for syslog messages',
                ),
                ConfigField(
                    name='hostname',
                    label='Hostname Override',
                    type='text',
                    required=False,
                    description='Override hostname in syslog messages (default: auto-detect)',
                ),
                ConfigField(
                    name='verify_ssl',
                    label='Verify SSL Certificate',
                    type='boolean',
                    required=False,
                    default=True,
                    description='Verify SSL certificate for TLS connections',
                    depends_on={'protocol': 'tls'},
                ),
                ConfigField(
                    name='timeout',
                    label='Connection Timeout (seconds)',
                    type='number',
                    required=False,
                    default=10,
                    validation={'min': 1, 'max': 60},
                ),
            ],
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(connection_id, config, credentials)
        self._socket: Optional[socket.socket] = None
        self._hostname = None
    
    @property
    def syslog_host(self) -> str:
        """Get the syslog server host."""
        return self.config.get('host', '')
    
    @property
    def syslog_port(self) -> int:
        """Get the syslog server port."""
        return self.config.get('port', 514)
    
    @property
    def protocol(self) -> str:
        """Get the transport protocol."""
        return self.config.get('protocol', 'udp')
    
    def _get_hostname(self) -> str:
        """Get the hostname for syslog messages."""
        if self._hostname:
            return self._hostname
        
        self._hostname = self.config.get('hostname') or socket.gethostname()
        return self._hostname
    
    def _get_priority(self, severity: str = 'info') -> int:
        """Calculate syslog priority from facility and severity."""
        facility = self.FACILITIES.get(self.config.get('facility', 'local0'), 16)
        sev = self.SEVERITIES.get(severity.lower(), 6)
        return (facility * 8) + sev
    
    async def connect(self) -> bool:
        """Establish connection to syslog server."""
        self._update_health(IntegrationStatus.CONNECTING)
        
        if not self.syslog_host:
            raise IntegrationValidationError('Syslog server host is required', field='host')
        
        try:
            if self.protocol == 'udp':
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.config.get('timeout', 10))
                
                if self.protocol == 'tls':
                    context = ssl.create_default_context()
                    if not self.config.get('verify_ssl', True):
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self._socket = context.wrap_socket(
                        self._socket,
                        server_hostname=self.syslog_host
                    )
                
                self._socket.connect((self.syslog_host, self.syslog_port))
            
            # Test the connection
            health = await self.test_connection()
            
            if health.status != IntegrationStatus.CONNECTED:
                raise IntegrationConnectionError(
                    health.last_error or 'Failed to connect to syslog server'
                )
            
            return True
            
        except socket.timeout:
            raise IntegrationConnectionError(
                'Connection to syslog server timed out',
                remediation='Check network connectivity and firewall rules.'
            )
        except socket.gaierror as e:
            raise IntegrationConnectionError(
                f'Could not resolve hostname: {self.syslog_host}',
                remediation='Verify the hostname is correct.'
            )
        except ssl.SSLError as e:
            raise IntegrationConnectionError(
                f'SSL error: {str(e)}',
                remediation='Check SSL certificate or disable verification.'
            )
        except Exception as e:
            raise IntegrationConnectionError(f'Connection failed: {str(e)}')
    
    async def disconnect(self) -> bool:
        """Disconnect from syslog server."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        
        self._update_health(IntegrationStatus.DISCONNECTED)
        return True
    
    async def test_connection(self) -> ConnectionHealth:
        """Test the syslog connection."""
        start_time = time.time()
        
        try:
            # For UDP, we can't really test the connection, just the socket creation
            if self.protocol == 'udp':
                if self._socket is None:
                    self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Try to resolve the hostname
                socket.gethostbyname(self.syslog_host)
                
                response_time = int((time.time() - start_time) * 1000)
                self._update_health(
                    IntegrationStatus.CONNECTED,
                    response_time_ms=response_time
                )
                self._health.details = {'note': 'UDP connection verified (host resolved)'}
                return self._health
            
            # For TCP/TLS, try to connect if not already connected
            if self._socket is None:
                await self.connect()
            
            # Send a test message
            test_msg = self._format_message({
                'message': 'Continuum syslog connection test',
                'severity': 'debug',
            })
            
            if self.protocol == 'udp':
                self._socket.sendto(
                    test_msg.encode(),
                    (self.syslog_host, self.syslog_port)
                )
            else:
                self._socket.send(test_msg.encode())
            
            response_time = int((time.time() - start_time) * 1000)
            self._update_health(
                IntegrationStatus.CONNECTED,
                response_time_ms=response_time
            )
            return self._health
            
        except Exception as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            raise IntegrationConnectionError(f'Connection test failed: {str(e)}')
    
    async def send_log(self, log_data: Dict[str, Any]) -> bool:
        """Send a log message to syslog."""
        if self._socket is None:
            await self.connect()
        
        message = self._format_message(log_data)
        
        try:
            if self.protocol == 'udp':
                self._socket.sendto(
                    message.encode(),
                    (self.syslog_host, self.syslog_port)
                )
            else:
                self._socket.send(message.encode())
            
            self._update_health(IntegrationStatus.CONNECTED)
            return True
            
        except socket.error as e:
            self._update_health(IntegrationStatus.ERROR, error=str(e))
            
            # Try to reconnect for TCP/TLS
            if self.protocol != 'udp':
                await self.disconnect()
                await self.connect()
                
                # Retry once
                if self.protocol == 'udp':
                    self._socket.sendto(
                        message.encode(),
                        (self.syslog_host, self.syslog_port)
                    )
                else:
                    self._socket.send(message.encode())
                
                return True
            
            raise IntegrationConnectionError(f'Failed to send syslog message: {str(e)}')
    
    def _format_message(self, log_data: Dict[str, Any]) -> str:
        """Format log data as a syslog message."""
        syslog_format = self.config.get('format', 'rfc5424')
        
        if syslog_format == 'rfc5424':
            return self._format_rfc5424(log_data)
        else:
            return self._format_rfc3164(log_data)
    
    def _format_rfc5424(self, log_data: Dict[str, Any]) -> str:
        """Format message according to RFC 5424."""
        severity = log_data.get('severity', 'info')
        priority = self._get_priority(severity)
        
        # Timestamp in RFC 5424 format
        ts = log_data.get('timestamp')
        if isinstance(ts, (int, float)):
            timestamp = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        elif isinstance(ts, datetime):
            timestamp = ts.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        else:
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        hostname = self._get_hostname()
        app_name = self.config.get('app_name', 'continuum')
        proc_id = log_data.get('process_id', '-')
        msg_id = log_data.get('message_id', '-')
        
        # Structured data
        structured_data = '-'
        if 'structured_data' in log_data:
            sd_parts = []
            for sd_id, params in log_data['structured_data'].items():
                param_str = ' '.join(
                    f'{k}="{v}"' for k, v in params.items()
                )
                sd_parts.append(f'[{sd_id} {param_str}]')
            if sd_parts:
                structured_data = ''.join(sd_parts)
        
        message = log_data.get('message', json.dumps(log_data))
        
        # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        return f'<{priority}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {structured_data} {message}\n'
    
    def _format_rfc3164(self, log_data: Dict[str, Any]) -> str:
        """Format message according to RFC 3164 (BSD syslog)."""
        severity = log_data.get('severity', 'info')
        priority = self._get_priority(severity)
        
        # Timestamp in BSD format (Mmm dd hh:mm:ss)
        ts = log_data.get('timestamp')
        if isinstance(ts, (int, float)):
            timestamp = datetime.utcfromtimestamp(ts).strftime('%b %d %H:%M:%S')
        elif isinstance(ts, datetime):
            timestamp = ts.strftime('%b %d %H:%M:%S')
        else:
            timestamp = datetime.utcnow().strftime('%b %d %H:%M:%S')
        
        hostname = self._get_hostname()
        app_name = self.config.get('app_name', 'continuum')
        message = log_data.get('message', json.dumps(log_data))
        
        # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
        return f'<{priority}>{timestamp} {hostname} {app_name}: {message}\n'
