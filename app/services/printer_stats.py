"""
Printer Statistics - SNMP-based printer status and statistics
"""
import asyncio
import logging
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# Cache for printer stats (IP -> (timestamp, PrinterStats))
_stats_cache: Dict[str, tuple[float, 'PrinterStats']] = {}
_CACHE_TTL = 300  # 5 minutes


@dataclass
class PrinterStats:
    """Statistics and status information for a printer."""
    ip: str
    queried_at: datetime = field(default_factory=datetime.now)
    reachable: bool = False
    
    # General info
    name: str = ""
    model: str = ""
    serial_number: str = ""
    location: str = ""
    uptime: str = ""
    
    # Status
    status: str = "Unknown"
    status_message: str = ""
    
    # Page counts
    total_pages: int = 0
    color_pages: int = 0
    mono_pages: int = 0
    
    # Supplies (toner/ink levels as percentages)
    black_toner: int = -1  # -1 = unknown
    cyan_toner: int = -1
    magenta_toner: int = -1
    yellow_toner: int = -1
    
    # Paper trays
    trays: list = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "queried_at": self.queried_at.isoformat(),
            "reachable": self.reachable,
            "name": self.name,
            "model": self.model,
            "serial_number": self.serial_number,
            "location": self.location,
            "uptime": self.uptime,
            "status": self.status,
            "status_message": self.status_message,
            "total_pages": self.total_pages,
            "color_pages": self.color_pages,
            "mono_pages": self.mono_pages,
            "black_toner": self.black_toner,
            "cyan_toner": self.cyan_toner,
            "magenta_toner": self.magenta_toner,
            "yellow_toner": self.yellow_toner,
            "trays": self.trays
        }


# Standard Printer MIB OIDs
PRINTER_OIDS = {
    # System MIB
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
    
    # Host Resources MIB
    'hrDeviceDescr': '1.3.6.1.2.1.25.3.2.1.3.1',
    'hrPrinterStatus': '1.3.6.1.2.1.25.3.5.1.1.1',
    
    # Printer MIB
    'prtGeneralPrinterName': '1.3.6.1.2.1.43.5.1.1.16.1',
    'prtGeneralSerialNumber': '1.3.6.1.2.1.43.5.1.1.17.1',
    
    # Page counts (common locations)
    'prtMarkerLifeCount': '1.3.6.1.2.1.43.10.2.1.4.1.1',
    
    # HP-specific page count
    'hpPageCount': '1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.5.0',
    
    # Generic page count locations
    'pageCount1': '1.3.6.1.2.1.43.10.2.1.4.1.1',
    'pageCount2': '1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.6.0',
}

# Printer status codes from HR-MIB
PRINTER_STATUS_CODES = {
    1: "Other",
    2: "Unknown",
    3: "Idle",
    4: "Printing",
    5: "Warmup"
}


class PrinterStatsCollector:
    """Collects printer statistics via SNMP."""
    
    def __init__(self, community: str = 'public'):
        self.community = community
    
    def get_stats(self, ip: str, use_cache: bool = True) -> PrinterStats:
        """Get statistics for a single printer.
        
        Args:
            ip: Printer IP address
            use_cache: If True, return cached stats if available and fresh
        """
        # Check cache first
        if use_cache and ip in _stats_cache:
            timestamp, cached_stats = _stats_cache[ip]
            if time.time() - timestamp < _CACHE_TTL:
                logger.debug(f"Returning cached stats for {ip}")
                return cached_stats
        
        stats = PrinterStats(ip=ip)
        
        try:
            import asyncio
            from pysnmp.hlapi.v1arch.asyncio import (
                get_cmd, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity, SnmpDispatcher
            )
            
            results = {}
            
            async def query_oid(dispatcher, oid_name, oid_value):
                try:
                    error_indication, error_status, error_index, var_binds = await get_cmd(
                        dispatcher,
                        CommunityData(self.community),
                        await UdpTransportTarget.create((ip, 161), timeout=3, retries=1),
                        ObjectType(ObjectIdentity(oid_value))
                    )
                    
                    if not error_indication and not error_status:
                        for var_bind in var_binds:
                            value = var_bind[1]
                            str_value = str(value)
                            if str_value and 'No Such' not in str_value and 'noSuch' not in str_value.lower():
                                return (oid_name, value)
                except Exception as e:
                    logger.debug(f"SNMP OID {oid_name} error for {ip}: {e}")
                return None
            
            async def query_all():
                dispatcher = SnmpDispatcher()
                try:
                    tasks = [query_oid(dispatcher, name, oid) for name, oid in PRINTER_OIDS.items()]
                    query_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in query_results:
                        if result and not isinstance(result, Exception):
                            results[result[0]] = result[1]
                finally:
                    # Properly cleanup dispatcher
                    try:
                        dispatcher.transport_dispatcher.close_dispatcher()
                    except Exception:
                        pass
                    
                    # Cancel and await all pending tasks to prevent "Task was destroyed" warnings
                    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
            
            # Run queries
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(query_all())
            
            if results:
                stats.reachable = True
                self._parse_results(stats, results)
            
        except ImportError:
            logger.warning("pysnmp not installed")
        except Exception as e:
            logger.error(f"Error getting stats for {ip}: {e}")
        
        # Cache the result
        _stats_cache[ip] = (time.time(), stats)
        
        return stats
    
    def _parse_results(self, stats: PrinterStats, results: Dict):
        """Parse SNMP results into PrinterStats."""
        # Name
        if 'prtGeneralPrinterName' in results:
            stats.name = str(results['prtGeneralPrinterName'])
        elif 'sysName' in results:
            stats.name = str(results['sysName'])
        
        # Model
        if 'hrDeviceDescr' in results:
            stats.model = str(results['hrDeviceDescr'])
        elif 'sysDescr' in results:
            desc = str(results['sysDescr'])
            # Try to extract model from sysDescr
            if 'PID:' in desc:
                stats.model = desc.split('PID:')[1].split(',')[0].strip()
            else:
                stats.model = desc[:50]
        
        # Serial number
        if 'prtGeneralSerialNumber' in results:
            stats.serial_number = str(results['prtGeneralSerialNumber'])
        
        # Location
        if 'sysLocation' in results:
            stats.location = str(results['sysLocation'])
        
        # Uptime
        if 'sysUpTime' in results:
            ticks = int(results['sysUpTime'])
            days = ticks // 8640000
            hours = (ticks % 8640000) // 360000
            minutes = (ticks % 360000) // 6000
            stats.uptime = f"{days}d {hours}h {minutes}m"
        
        # Status
        if 'hrPrinterStatus' in results:
            status_code = int(results['hrPrinterStatus'])
            stats.status = PRINTER_STATUS_CODES.get(status_code, "Unknown")
        
        # Page counts
        for key in ['prtMarkerLifeCount', 'hpPageCount', 'pageCount1', 'pageCount2']:
            if key in results:
                try:
                    count = int(results[key])
                    if count > 0:
                        stats.total_pages = count
                        break
                except (ValueError, TypeError):
                    pass
    
    def get_toner_levels(self, ip: str) -> Dict[str, int]:
        """Get toner/supply levels for a printer."""
        levels = {}
        
        # Marker supplies OIDs (walk would be better but this gets common ones)
        supply_oids = {
            # prtMarkerSuppliesLevel - index 1-4 typically
            'supply1_level': '1.3.6.1.2.1.43.11.1.1.9.1.1',
            'supply2_level': '1.3.6.1.2.1.43.11.1.1.9.1.2',
            'supply3_level': '1.3.6.1.2.1.43.11.1.1.9.1.3',
            'supply4_level': '1.3.6.1.2.1.43.11.1.1.9.1.4',
            'supply1_max': '1.3.6.1.2.1.43.11.1.1.8.1.1',
            'supply2_max': '1.3.6.1.2.1.43.11.1.1.8.1.2',
            'supply3_max': '1.3.6.1.2.1.43.11.1.1.8.1.3',
            'supply4_max': '1.3.6.1.2.1.43.11.1.1.8.1.4',
            'supply1_desc': '1.3.6.1.2.1.43.11.1.1.6.1.1',
            'supply2_desc': '1.3.6.1.2.1.43.11.1.1.6.1.2',
            'supply3_desc': '1.3.6.1.2.1.43.11.1.1.6.1.3',
            'supply4_desc': '1.3.6.1.2.1.43.11.1.1.6.1.4',
        }
        
        try:
            import asyncio
            from pysnmp.hlapi.v1arch.asyncio import (
                get_cmd, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity, SnmpDispatcher
            )
            
            results = {}
            
            async def query_oid(dispatcher, oid_name, oid_value):
                try:
                    error_indication, error_status, error_index, var_binds = await get_cmd(
                        dispatcher,
                        CommunityData(self.community),
                        await UdpTransportTarget.create((ip, 161), timeout=2, retries=0),
                        ObjectType(ObjectIdentity(oid_value))
                    )
                    
                    if not error_indication and not error_status:
                        for var_bind in var_binds:
                            value = var_bind[1]
                            str_value = str(value)
                            if 'No Such' not in str_value:
                                return (oid_name, value)
                except Exception:
                    pass
                return None
            
            async def query_all():
                dispatcher = SnmpDispatcher()
                try:
                    tasks = [query_oid(dispatcher, name, oid) for name, oid in supply_oids.items()]
                    query_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in query_results:
                        if result and not isinstance(result, Exception):
                            results[result[0]] = result[1]
                finally:
                    # Properly cleanup dispatcher
                    try:
                        dispatcher.transport_dispatcher.close_dispatcher()
                    except Exception:
                        pass
                    
                    # Cancel and await all pending tasks to prevent "Task was destroyed" warnings
                    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
            
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(query_all())
            
            # Calculate percentages
            for i in range(1, 5):
                level_key = f'supply{i}_level'
                max_key = f'supply{i}_max'
                desc_key = f'supply{i}_desc'
                
                if level_key in results and max_key in results:
                    try:
                        level = int(results[level_key])
                        max_val = int(results[max_key])
                        if max_val > 0:
                            pct = int((level / max_val) * 100)
                            desc = str(results.get(desc_key, f'Supply {i}'))
                            # Try to identify color
                            desc_lower = desc.lower()
                            if 'black' in desc_lower or 'k ' in desc_lower:
                                levels['black'] = pct
                            elif 'cyan' in desc_lower:
                                levels['cyan'] = pct
                            elif 'magenta' in desc_lower:
                                levels['magenta'] = pct
                            elif 'yellow' in desc_lower:
                                levels['yellow'] = pct
                            else:
                                levels[desc[:20]] = pct
                    except (ValueError, TypeError):
                        pass
            
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Error getting toner levels for {ip}: {e}")
        
        return levels


# Global collector instance
_collector: Optional[PrinterStatsCollector] = None


def get_collector() -> PrinterStatsCollector:
    """Get the global stats collector."""
    global _collector
    if _collector is None:
        _collector = PrinterStatsCollector()
    return _collector


def get_stats(ip: str, use_cache: bool = True) -> PrinterStats:
    """Get statistics for a printer by IP.
    
    Args:
        ip: Printer IP address
        use_cache: If True, return cached stats if available and fresh (default: True)
    """
    return get_collector().get_stats(ip, use_cache=use_cache)


def get_toner_levels(ip: str) -> Dict[str, int]:
    """Get toner levels for a printer by IP."""
    return get_collector().get_toner_levels(ip)
