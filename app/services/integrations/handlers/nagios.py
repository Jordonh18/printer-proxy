"""
Nagios Integration Handler.

Provides integration with Nagios for monitoring:
- Submit passive check results via NSCA
- Receive alerts (external commands)
"""

import logging
import socket
import struct
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
    IntegrationAuthError,
    IntegrationConnectionError,
    IntegrationRateLimitError,
    IntegrationValidationError,
)

logger = logging.getLogger(__name__)


class NagiosIntegration(IntegrationBase):
    """
    Nagios Integration for monitoring.
    
    Features:
    - Submit passive check results
    - NSCA protocol support
    - Custom check configurations
    """
    
    # NSCA constants
    NSCA_VERSION = 3
    NSCA_PACKET_SIZE = 720
    
    # Nagios return codes
    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3
    
    @classmethod
    def get_metadata(cls) -> IntegrationMetadata:
        return IntegrationMetadata(
            id='nagios',
            name='Nagios',
            description='Submit passive check results to Nagios for monitoring. Report printer status and health to your Nagios infrastructure.',
            category=IntegrationCategory.MONITORING,
            auth_type=AuthType.TOKEN,
            capabilities=[
                IntegrationCapability.SEND_METRICS,
            ],
            icon='👁️',
            color='#2B2B2B',
            version='1.0.0',
            vendor='Nagios Enterprises',
            docs_url='https://www.nagios.org/documentation/',
            support_url='https://support.nagios.com/',
            config_schema=[
                ConfigField(
                    name='nsca_host',
                    label='NSCA Host',
                    type='text',
                    required=True,
                    description='Nagios NSCA server hostname or IP',
                    placeholder='nagios.example.com',
                ),
                ConfigField(
                    name='nsca_port',
                    label='NSCA Port',
                    type='number',
                    required=False,
                    default=5667,
                    description='NSCA server port',
                ),
                ConfigField(
                    name='nagios_host',
                    label='Nagios Host Name',
                    type='text',
                    required=True,
                    description='Host name as configured in Nagios',
                    placeholder='printer-server',
                ),
                ConfigField(
                    name='service_description',
                    label='Service Description',
                    type='text',
                    required=False,
                    default='Continuum Print Service',
                    description='Service description in Nagios',
                ),
                ConfigField(
                    name='timeout',
                    label='Connection Timeout',
                    type='number',
                    required=False,
                    default=10,
                    description='Timeout in seconds for NSCA connection',
                ),
            ],
            webhook_config={
                'supported': False,
            },
        )
    
    def __init__(self, connection_id: str, config: Dict[str, Any], credentials: Dict[str, str]):
        super().__init__(connection_id, config, credentials)
        self._socket: Optional[socket.socket] = None
    
    async def connect(self) -> bool:
        """Verify NSCA server is reachable."""
        try:
            nsca_host = self.config.get('nsca_host')
            nsca_port = self.config.get('nsca_port', 5667)
            timeout = self.config.get('timeout', 10)
            
            if not nsca_host:
                raise IntegrationValidationError('NSCA host is required')
            
            # Test connection
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(timeout)
            
            try:
                test_socket.connect((nsca_host, nsca_port))
                # Read initial packet (timestamp + IV)
                init_packet = test_socket.recv(132)
                if len(init_packet) >= 128:
                    self._status = IntegrationStatus.CONNECTED
                    self._last_connected = datetime.utcnow()
                    logger.info(f'Connected to Nagios NSCA: {self.connection_id}')
                    return True
                else:
                    raise IntegrationConnectionError('Invalid NSCA handshake')
            finally:
                test_socket.close()
                
        except socket.timeout:
            self._status = IntegrationStatus.ERROR
            self._last_error = 'Connection timeout'
            self._error_count += 1
            raise IntegrationConnectionError('NSCA connection timeout')
        except socket.error as e:
            self._status = IntegrationStatus.ERROR
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f'Nagios connection failed: {e}')
            raise IntegrationConnectionError(f'Connection failed: {e}')
    
    async def disconnect(self) -> bool:
        """Close any open connections."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._status = IntegrationStatus.DISCONNECTED
        logger.info(f'Disconnected from Nagios: {self.connection_id}')
        return True
    
    async def health_check(self) -> ConnectionHealth:
        """Check NSCA server health."""
        start_time = time.time()
        
        try:
            nsca_host = self.config.get('nsca_host')
            nsca_port = self.config.get('nsca_port', 5667)
            timeout = self.config.get('timeout', 10)
            
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(timeout)
            
            try:
                test_socket.connect((nsca_host, nsca_port))
                init_packet = test_socket.recv(132)
                
                response_time = int((time.time() - start_time) * 1000)
                
                if len(init_packet) >= 128:
                    return ConnectionHealth(
                        status='healthy',
                        last_check=datetime.utcnow(),
                        last_success=datetime.utcnow(),
                        response_time_ms=response_time,
                        details={'nsca_version': 'v3'},
                    )
                else:
                    return ConnectionHealth(
                        status='unhealthy',
                        last_check=datetime.utcnow(),
                        last_error='Invalid NSCA response',
                        response_time_ms=response_time,
                    )
            finally:
                test_socket.close()
                
        except Exception as e:
            return ConnectionHealth(
                status='error',
                last_check=datetime.utcnow(),
                last_error=str(e),
            )
    
    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """Send passive check result to Nagios."""
        nsca_host = self.config.get('nsca_host')
        nsca_port = self.config.get('nsca_port', 5667)
        timeout = self.config.get('timeout', 10)
        nagios_host = self.config.get('nagios_host')
        service_desc = self.config.get('service_description', 'Continuum Print Service')
        encryption_key = self.credentials.get('encryption_key', '')
        
        if not nsca_host or not nagios_host:
            raise IntegrationValidationError('NSCA host and Nagios host are required')
        
        # Map event to Nagios state
        state = self._map_state(payload.get('state', 'ok'))
        message = payload.get('message', f'Event: {event_type}')
        
        # Truncate message to fit NSCA packet
        if len(message) > 512:
            message = message[:509] + '...'
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((nsca_host, nsca_port))
                
                # Read initialization packet
                init_packet = sock.recv(132)
                if len(init_packet) < 128:
                    raise IntegrationConnectionError('Invalid NSCA init packet')
                
                # Extract timestamp and IV
                timestamp = struct.unpack('!I', init_packet[:4])[0]
                iv = init_packet[4:132]
                
                # Build service check result packet
                packet = self._build_packet(
                    nagios_host,
                    service_desc,
                    state,
                    message,
                    timestamp,
                    iv,
                    encryption_key,
                )
                
                # Send packet
                sock.send(packet)
                
                logger.debug(f'Sent Nagios check result: {service_desc} = {state}')
                return True
                
            finally:
                sock.close()
                
        except socket.error as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f'Nagios send error: {e}')
            raise IntegrationConnectionError(f'Send failed: {e}')
    
    def _map_state(self, state: str) -> int:
        """Map state string to Nagios return code."""
        state_lower = state.lower()
        if state_lower in ('ok', 'success', 'healthy', 'up'):
            return self.STATE_OK
        elif state_lower in ('warning', 'warn', 'degraded'):
            return self.STATE_WARNING
        elif state_lower in ('critical', 'error', 'down', 'failed'):
            return self.STATE_CRITICAL
        else:
            return self.STATE_UNKNOWN
    
    def _build_packet(
        self,
        host: str,
        service: str,
        state: int,
        message: str,
        timestamp: int,
        iv: bytes,
        encryption_key: str,
    ) -> bytes:
        """Build NSCA packet."""
        # Simple XOR encryption (for compatibility)
        # Production should use proper encryption
        
        # Pack data: version(2), padding(2), crc(4), timestamp(4), 
        # return_code(2), host(64), service(128), output(512)
        packet = struct.pack(
            '!hhIIh',
            self.NSCA_VERSION,
            0,  # padding
            0,  # CRC placeholder
            timestamp,
            state,
        )
        
        # Add host (null-padded to 64 bytes)
        host_bytes = host.encode()[:63] + b'\x00' * (64 - min(len(host), 63))
        packet += host_bytes
        
        # Add service (null-padded to 128 bytes)
        service_bytes = service.encode()[:127] + b'\x00' * (128 - min(len(service), 127))
        packet += service_bytes
        
        # Add output (null-padded to 512 bytes)
        output_bytes = message.encode()[:511] + b'\x00' * (512 - min(len(message), 511))
        packet += output_bytes
        
        # Calculate CRC32
        import binascii
        crc = binascii.crc32(packet) & 0xffffffff
        
        # Rebuild with actual CRC
        packet = struct.pack(
            '!hhIIh',
            self.NSCA_VERSION,
            0,
            crc,
            timestamp,
            state,
        ) + host_bytes + service_bytes + output_bytes
        
        # XOR with IV if encryption key provided
        if encryption_key:
            key_bytes = (encryption_key * ((len(packet) // len(encryption_key)) + 1)).encode()
            packet = bytes(a ^ b for a, b in zip(packet, key_bytes[:len(packet)]))
        
        return packet
    
    async def receive_event(self) -> Optional[Dict[str, Any]]:
        """Nagios doesn't support receiving events via NSCA."""
        return None
    
    def validate_webhook_signature(self, payload: bytes, signature: str, headers: Dict[str, str]) -> bool:
        """Nagios doesn't use webhooks for this integration."""
        return False
