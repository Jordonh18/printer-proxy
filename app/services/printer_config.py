"""
Printer Configuration Service for Continuum.

Provides remote configuration capabilities for printers via SNMP.
Currently supports HP printers for syslog configuration.
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class PrinterConfigError(Exception):
    """Exception raised when printer configuration fails."""
    pass


# HP-specific SNMP OIDs for syslog configuration
# These are from the HP MIB (hp-laserjet.mib)
# HP-specific SNMP OIDs for syslog configuration
# NOTE: These OIDs work on older HP LaserJet models (e.g., LaserJet 4xxx series)
# Many newer HP printers (e.g., M477fdw, M479fdw) do NOT support syslog via SNMP
# and require manual configuration via the Embedded Web Server (EWS) instead.
#
# For manual configuration on unsupported models:
# 1. Access printer's web interface (http://printer-ip)
# 2. Navigate to: Networking tab > Syslog Settings
# 3. Enable syslog and configure server IP/port
#
# HP JetDirect SNMP OIDs for syslog configuration
# These work on HP printers with JetDirect network cards (most modern HP printers including M477fdw)
HP_SYSLOG_OIDS = {
    # Syslog server IP address
    'syslog_server': '1.3.6.1.4.1.11.2.4.3.5.5',
    # Syslog facility identifier (0-23, typically 6 for printer/lpr)
    'syslog_facility': '1.3.6.1.4.1.11.2.4.3.5.6',
    # Enable/disable syslog (0=disabled, 1=enabled)
    'syslog_enable': '1.3.6.1.4.1.11.2.4.3.7.26',
    # Maximum syslog packets per minute (0=disabled, recommend 100+)
    'syslog_max_rate': '1.3.6.1.4.1.11.2.4.3.6.11',
    # Priority threshold (0-7 for syslog levels, 8=disabled)
    'syslog_priority': '1.3.6.1.4.1.11.2.4.3.6.12',
}


def configure_hp_syslog(
    printer_ip: str,
    syslog_server: str,
    syslog_port: int = 514,
    write_community: str = 'public',
    facility: int = 6,  # Local printer
    severity: int = 6,  # Info and above
    timeout: int = 5
) -> Dict[str, Any]:
    """
    Configure an HP JetDirect printer to send syslog messages to the Continuum server.
    
    Uses SNMP SET commands with HP JetDirect MIB OIDs to configure syslog.
    Works on most modern HP printers with JetDirect network cards (e.g., M477fdw, M479fdw).
    
    Note: HP JetDirect printers use fixed UDP port 514 for syslog regardless of syslog_port parameter.
    
    Args:
        printer_ip: IP address of the HP printer
        syslog_server: IP address of the syslog server (Continuum)
        syslog_port: UDP port for syslog (default 514 for standard syslog/JetDirect)
        write_community: SNMP write community string (default 'public')
        facility: Syslog facility code (default 6 = lpr/printer)
        severity: Maximum severity to log (default 6 = info)
        timeout: SNMP timeout in seconds
        
    Returns:
        Dict with configuration results
        
    Raises:
        PrinterConfigError: If configuration fails
    """
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            set_cmd,
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )
        from pysnmp.proto.rfc1902 import OctetString, Integer
    except ImportError as e:
        raise PrinterConfigError(f"pysnmp library not available or incompatible: {e}")
    
    logger.info(f"Configuring HP JetDirect printer {printer_ip} to send syslog to {syslog_server}:{syslog_port}")
    
    # Note: HP JetDirect uses fixed port 514 for syslog, port parameter is ignored
    if syslog_port != 514:
        logger.warning(f"HP JetDirect printers use fixed syslog port 514, requested port {syslog_port} will be ignored")
    
    results = {}
    errors = []
    
    # Prepare the SNMP SET commands for HP JetDirect
    # Note: No port OID - JetDirect always uses port 514
    set_operations = [
        ('syslog_server', HP_SYSLOG_OIDS['syslog_server'], OctetString(syslog_server)),
        ('syslog_facility', HP_SYSLOG_OIDS['syslog_facility'], Integer(facility)),
        ('syslog_max_rate', HP_SYSLOG_OIDS['syslog_max_rate'], Integer(100)),  # 100 packets/min
        ('syslog_priority', HP_SYSLOG_OIDS['syslog_priority'], Integer(severity)),
        ('syslog_enable', HP_SYSLOG_OIDS['syslog_enable'], Integer(1)),  # Enable last
    ]
    
    import asyncio
    
    # Define async helper function for SNMP SET operations
    async def _set_snmp_value(name, oid, value):
        """Helper to perform async SNMP SET operation."""
        target = await UdpTransportTarget.create((printer_ip, 161), timeout=timeout, retries=1)
        error_indication, error_status, error_index, var_binds = await set_cmd(
            SnmpEngine(),
            CommunityData(write_community, mpModel=1),  # SNMPv2c
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid), value)
        )
        return error_indication, error_status, error_index, var_binds
    
    for name, oid, value in set_operations:
        try:
            # Create event loop for async SNMP operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                error_indication, error_status, error_index, var_binds = loop.run_until_complete(
                    _set_snmp_value(name, oid, value)
                )
            finally:
                loop.close()
            
            if error_indication:
                errors.append(f"{name}: {error_indication}")
                results[name] = {'success': False, 'error': str(error_indication)}
            elif error_status:
                error_msg = f"{error_status.prettyPrint()} at {error_index}"
                # Check for noSuchName error - indicates OID doesn't exist on this printer
                if 'noSuchName' in error_msg:
                    error_msg = "OID not supported on this printer model"
                errors.append(f"{name}: {error_msg}")
                results[name] = {'success': False, 'error': error_msg}
            else:
                results[name] = {'success': True}
                logger.debug(f"Successfully set {name} on {printer_ip}")
                
        except Exception as e:
            errors.append(f"{name}: {str(e)}")
            results[name] = {'success': False, 'error': str(e)}
    
    if errors:
        # Check if all errors are "OID not supported" - this means the printer model doesn't support SNMP syslog
        all_unsupported = all('OID not supported' in str(results.get(k, {}).get('error', '')) for k in results)
        
        if all_unsupported:
            error_msg = (
                f"This printer model does not support syslog configuration via SNMP. "
                f"Please configure syslog manually via the printer's web interface at http://{printer_ip} "
                f"(Networking > Syslog Settings). Set server to {syslog_server}:{syslog_port}"
            )
            logger.warning(f"HP printer {printer_ip} does not support SNMP syslog configuration")
            raise PrinterConfigError(error_msg)
        
        # Check if any critical settings failed
        critical_failed = any(
            not results.get(k, {}).get('success', False) 
            for k in ['syslog_server', 'syslog_enable']
        )
        
        if critical_failed:
            error_msg = "; ".join(errors)
            logger.error(f"Failed to configure HP printer {printer_ip}: {error_msg}")
            raise PrinterConfigError(f"SNMP configuration failed: {error_msg}")
        else:
            # Some non-critical settings failed, but core config worked
            logger.warning(f"Partial configuration success for {printer_ip}: {errors}")
    
    logger.info(f"Successfully configured HP printer {printer_ip} for syslog")
    
    return {
        'printer_ip': printer_ip,
        'syslog_server': syslog_server,
        'syslog_port': syslog_port,
        'operations': results
    }


def verify_hp_syslog_config(
    printer_ip: str,
    read_community: str = 'public',
    timeout: int = 5
) -> Optional[Dict[str, Any]]:
    """
    Verify the current syslog configuration on an HP printer.
    
    Args:
        printer_ip: IP address of the HP printer
        read_community: SNMP read community string
        timeout: SNMP timeout in seconds
        
    Returns:
        Dict with current syslog configuration, or None if read fails
    """
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            get_cmd,
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )
    except ImportError:
        return None
    
    config = {}
    
    import asyncio
    
    # Define async helper function for SNMP GET operations
    async def _get_snmp_value(oid):
        """Helper to perform async SNMP GET operation."""
        target = await UdpTransportTarget.create((printer_ip, 161), timeout=timeout, retries=1)
        error_indication, error_status, error_index, var_binds = await get_cmd(
            SnmpEngine(),
            CommunityData(read_community),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return error_indication, error_status, error_index, var_binds
    
    for name, oid in HP_SYSLOG_OIDS.items():
        try:
            # Create event loop for async SNMP operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                error_indication, error_status, error_index, var_binds = loop.run_until_complete(
                    _get_snmp_value(oid)
                )
            finally:
                loop.close()
            
            if not error_indication and not error_status:
                for oid, val in var_binds:
                    config[name] = str(val)
                    
        except Exception as e:
            logger.debug(f"Failed to read {name} from {printer_ip}: {e}")
    
    return config if config else None


def disable_hp_syslog(
    printer_ip: str,
    write_community: str = 'private',
    timeout: int = 5
) -> bool:
    """
    Disable syslog on an HP printer.
    
    Args:
        printer_ip: IP address of the HP printer
        write_community: SNMP write community string
        timeout: SNMP timeout in seconds
        
    Returns:
        True if successful, False otherwise
    """
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            set_cmd,
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )
        from pysnmp.proto.rfc1902 import Integer
    except ImportError:
        return False
    
    import asyncio
    
    # Define async helper function for SNMP SET operation
    async def _disable_syslog():
        """Helper to perform async SNMP SET operation."""
        target = await UdpTransportTarget.create((printer_ip, 161), timeout=timeout, retries=1)
        error_indication, error_status, error_index, var_binds = await set_cmd(
            SnmpEngine(),
            CommunityData(write_community, mpModel=1),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(HP_SYSLOG_OIDS['syslog_enable']), Integer(0))
        )
        return error_indication, error_status, error_index, var_binds
    
    try:
        # Create event loop for async SNMP operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            error_indication, error_status, error_index, var_binds = loop.run_until_complete(
                _disable_syslog()
            )
        finally:
            loop.close()
        
        if error_indication or error_status:
            logger.error(f"Failed to disable syslog on {printer_ip}: {error_indication or error_status}")
            return False
        
        logger.info(f"Disabled syslog on HP printer {printer_ip}")
        return True
        
    except Exception as e:
        logger.error(f"Error disabling syslog on {printer_ip}: {e}")
        return False
