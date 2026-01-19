"""
Printer Discovery - mDNS and SNMP scanning
"""
import socket
import subprocess
import threading
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredPrinter:
    """Represents a discovered printer."""
    ip: str
    name: str = ""
    model: str = ""
    location: str = ""
    discovery_method: str = ""
    hostname: str = ""
    tcp_9100_open: bool = False
    snmp_available: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "name": self.name or f"Printer at {self.ip}",
            "model": self.model,
            "location": self.location,
            "discovery_method": self.discovery_method,
            "hostname": self.hostname,
            "tcp_9100_open": self.tcp_9100_open,
            "snmp_available": self.snmp_available
        }


class PrinterDiscovery:
    """Discovers printers on the network using various methods."""
    
    def __init__(self):
        self._discovered: Dict[str, DiscoveredPrinter] = {}
        self._lock = threading.Lock()
    
    def scan_single_ip(self, ip: str) -> List[DiscoveredPrinter]:
        """
        Scan a single IP address for printer services.
        
        Args:
            ip: The IP address to scan.
        """
        self._discovered = {}
        
        # Check common printer ports
        printer_ports = [9100, 515, 631]  # JetDirect, LPD, IPP
        tcp_open = False
        
        for port in printer_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    tcp_open = True
                    break
            except Exception:
                pass
        
        if tcp_open:
            printer = DiscoveredPrinter(
                ip=ip,
                discovery_method="TCP Scan",
                tcp_9100_open=True
            )
            self._discovered[ip] = printer
            
            # Try to get more info via SNMP
            self._query_snmp(ip)
        
        return list(self._discovered.values())
    
    def discover_all(self, network_cidr: str = None, timeout: int = 30) -> List[DiscoveredPrinter]:
        """
        Run all discovery methods and return found printers.
        
        Args:
            network_cidr: Network to scan (e.g., "192.168.1.0/24"). If None, auto-detect.
            timeout: Maximum time for discovery in seconds.
        """
        self._discovered = {}
        
        if not network_cidr:
            network_cidr = self._detect_network()
        
        if not network_cidr:
            logger.warning("Could not detect network for scanning")
            return []
        
        # Run discovery methods
        threads = []
        
        # mDNS discovery (fast, finds Bonjour-enabled printers)
        t1 = threading.Thread(target=self._discover_mdns, args=(timeout,))
        t1.start()
        threads.append(t1)
        
        # TCP 9100 scan (network sweep)
        t2 = threading.Thread(target=self._discover_tcp_9100, args=(network_cidr, timeout))
        t2.start()
        threads.append(t2)
        
        # SNMP discovery on found hosts
        t3 = threading.Thread(target=self._discover_snmp, args=(network_cidr, timeout))
        t3.start()
        threads.append(t3)
        
        # Wait for all threads
        for t in threads:
            t.join(timeout=timeout + 5)
        
        # Run SNMP enrichment after TCP/mDNS discovery completes
        self._enrich_with_snmp()
        
        return list(self._discovered.values())
    
    def _detect_network(self) -> Optional[str]:
        """Auto-detect the local network CIDR."""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse default gateway interface
                parts = result.stdout.split()
                if 'dev' in parts:
                    dev_idx = parts.index('dev')
                    interface = parts[dev_idx + 1]
                    
                    # Get network for this interface
                    result2 = subprocess.run(
                        ['ip', '-o', '-4', 'addr', 'show', interface],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result2.returncode == 0:
                        for line in result2.stdout.strip().split('\n'):
                            parts = line.split()
                            for part in parts:
                                if '/' in part and '.' in part:
                                    # Convert to network address
                                    network = ipaddress.ip_network(part, strict=False)
                                    return str(network)
        except Exception as e:
            logger.error(f"Error detecting network: {e}")
        return None
    
    def _discover_mdns(self, timeout: int):
        """Discover printers via mDNS/Bonjour."""
        try:
            from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
            
            class PrinterListener(ServiceListener):
                def __init__(self, discovery):
                    self.discovery = discovery
                
                def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                    info = zc.get_service_info(type_, name)
                    if info:
                        for addr in info.parsed_addresses():
                            if ':' not in addr:  # Skip IPv6
                                printer = DiscoveredPrinter(
                                    ip=addr,
                                    name=info.name.replace('._pdl-datastream._tcp.local.', '').replace('._ipp._tcp.local.', '').replace('._printer._tcp.local.', ''),
                                    discovery_method="mDNS",
                                    hostname=info.server or ""
                                )
                                self.discovery._add_discovered(printer)
                
                def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                    pass
                
                def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                    pass
            
            zc = Zeroconf()
            listener = PrinterListener(self)
            
            # Browse for printer services
            services = [
                "_pdl-datastream._tcp.local.",  # RAW/JetDirect printers
                "_ipp._tcp.local.",              # IPP printers
                "_printer._tcp.local.",          # Generic printers
                "_ipps._tcp.local.",             # IPP over TLS
            ]
            
            browsers = []
            for service in services:
                try:
                    browser = ServiceBrowser(zc, service, listener)
                    browsers.append(browser)
                except Exception:
                    pass
            
            # Wait for discovery
            import time
            time.sleep(min(timeout, 10))
            
            zc.close()
            
        except ImportError:
            logger.warning("zeroconf not installed, skipping mDNS discovery")
        except Exception as e:
            logger.error(f"mDNS discovery error: {e}")
    
    def _discover_tcp_9100(self, network_cidr: str, timeout: int):
        """Scan network for open TCP 9100 ports (RAW printing)."""
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            hosts = list(network.hosts())
            
            # Limit scan size
            if len(hosts) > 254:
                logger.warning(f"Network too large ({len(hosts)} hosts), limiting to /24")
                hosts = hosts[:254]
            
            def check_port(ip: str) -> Optional[str]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, 9100))
                    sock.close()
                    if result == 0:
                        return ip
                except Exception:
                    pass
                return None
            
            # Parallel scanning
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(check_port, str(ip)): str(ip) for ip in hosts}
                for future in as_completed(futures, timeout=timeout):
                    try:
                        result = future.result()
                        if result:
                            printer = DiscoveredPrinter(
                                ip=result,
                                discovery_method="TCP 9100",
                                tcp_9100_open=True
                            )
                            self._add_discovered(printer)
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"TCP 9100 scan error: {e}")
    
    def _discover_snmp(self, network_cidr: str, timeout: int):
        """Legacy method - SNMP now runs after discovery via _enrich_with_snmp."""
        pass
    
    def _enrich_with_snmp(self):
        """Enrich all discovered printers with SNMP data."""
        with self._lock:
            ips_to_query = list(self._discovered.keys())
        
        logger.info(f"Enriching {len(ips_to_query)} discovered printer(s) with SNMP data")
        
        for ip in ips_to_query:
            self._query_snmp(ip)
    
    def _query_snmp(self, ip: str):
        """Query a single host for SNMP printer info."""
        logger.debug(f"Querying SNMP on {ip}")
        
        # Common printer OIDs
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'prtGeneralPrinterName': '1.3.6.1.2.1.43.5.1.1.16.1',
            'hrDeviceDescr': '1.3.6.1.2.1.25.3.2.1.3.1',
        }
        
        results = {}
        
        try:
            # Try pysnmp 7.x async API first
            import asyncio
            from pysnmp.hlapi.v1arch.asyncio import (
                get_cmd, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity, SnmpDispatcher
            )
            
            async def query_oid(dispatcher, oid_name, oid_value):
                try:
                    error_indication, error_status, error_index, var_binds = await get_cmd(
                        dispatcher,
                        CommunityData('public'),
                        await UdpTransportTarget.create((ip, 161), timeout=2, retries=0),
                        ObjectType(ObjectIdentity(oid_value))
                    )
                    
                    if not error_indication and not error_status:
                        for var_bind in var_binds:
                            value = str(var_bind[1])
                            if value and 'No Such' not in value and 'noSuch' not in value.lower():
                                return (oid_name, value)
                except Exception as e:
                    logger.debug(f"SNMP OID {oid_name} error: {e}")
                return None
            
            async def query_all():
                dispatcher = SnmpDispatcher()
                try:
                    tasks = [query_oid(dispatcher, name, oid) for name, oid in oids.items()]
                    query_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in query_results:
                        if result and not isinstance(result, Exception):
                            results[result[0]] = result[1]
                finally:
                    dispatcher.transport_dispatcher.close_dispatcher()
            
            # Run the async queries
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(query_all())
            
        except ImportError as e:
            logger.warning(f"pysnmp not available: {e}")
        except Exception as e:
            logger.warning(f"SNMP query error for {ip}: {e}")
        
        logger.debug(f"SNMP results for {ip}: {results}")
        
        if results:
            with self._lock:
                if ip in self._discovered:
                    printer = self._discovered[ip]
                    printer.snmp_available = True
                    if 'prtGeneralPrinterName' in results:
                        printer.name = results['prtGeneralPrinterName']
                    elif 'sysName' in results and not printer.name:
                        printer.name = results['sysName']
                    # Prefer hrDeviceDescr for model (cleaner) over sysDescr (verbose)
                    if 'hrDeviceDescr' in results:
                        printer.model = results['hrDeviceDescr']
                    elif 'sysDescr' in results:
                        printer.model = results['sysDescr'][:100]  # Limit length
                    if 'sysLocation' in results:
                        printer.location = results['sysLocation']
                    if printer.discovery_method != "mDNS":
                        printer.discovery_method = "SNMP"
                    logger.info(f"SNMP enriched {ip}: name={printer.name}, model={printer.model}")
                else:
                    printer = DiscoveredPrinter(
                        ip=ip,
                        name=results.get('prtGeneralPrinterName', results.get('sysName', '')),
                        model=results.get('hrDeviceDescr', results.get('sysDescr', ''))[:100] if results.get('hrDeviceDescr') or results.get('sysDescr') else '',
                        location=results.get('sysLocation', ''),
                        discovery_method="SNMP",
                        snmp_available=True
                    )
                    self._discovered[ip] = printer
    
    def _add_discovered(self, printer: DiscoveredPrinter):
        """Thread-safe method to add a discovered printer."""
        with self._lock:
            if printer.ip in self._discovered:
                # Merge info
                existing = self._discovered[printer.ip]
                if printer.name and not existing.name:
                    existing.name = printer.name
                if printer.model and not existing.model:
                    existing.model = printer.model
                if printer.location and not existing.location:
                    existing.location = printer.location
                if printer.hostname and not existing.hostname:
                    existing.hostname = printer.hostname
                if printer.tcp_9100_open:
                    existing.tcp_9100_open = True
                if printer.snmp_available:
                    existing.snmp_available = True
                # Keep best discovery method
                if printer.discovery_method == "mDNS":
                    existing.discovery_method = "mDNS"
            else:
                self._discovered[printer.ip] = printer


# Global discovery instance
_discovery: Optional[PrinterDiscovery] = None


def get_discovery() -> PrinterDiscovery:
    """Get the global discovery instance."""
    global _discovery
    if _discovery is None:
        _discovery = PrinterDiscovery()
    return _discovery
