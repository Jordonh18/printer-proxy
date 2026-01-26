"""
Network operations handler - interfaces with privileged helper script
"""
import subprocess
import shlex
import json
from typing import Tuple, Optional, List, Dict, Any
import logging

from config.config import HELPER_SCRIPT, NETWORK_INTERFACE, DEFAULT_PORT

logger = logging.getLogger(__name__)


class NetworkError(Exception):
    """Exception for network operation failures."""
    pass


class NetworkManager:
    """Manages network operations through privileged helper script."""
    
    def __init__(self):
        self.interface = NETWORK_INTERFACE
        self.helper_script = str(HELPER_SCRIPT)
    
    def _run_helper(self, *args) -> Tuple[bool, str]:
        """Run the network helper script with sudo."""
        cmd = ['sudo', self.helper_script] + list(args)
        logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                logger.error(f"Helper script failed: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            logger.error("Helper script timed out")
            return False, "Operation timed out"
        except Exception as e:
            logger.error(f"Helper script error: {e}")
            return False, str(e)
    
    def add_secondary_ip(self, ip: str) -> Tuple[bool, str]:
        """Add a secondary IP address to the network interface."""
        success, output = self._run_helper('add-ip', self.interface, ip)
        if success:
            logger.info(f"Added secondary IP {ip} to {self.interface}")
        return success, output
    
    def remove_secondary_ip(self, ip: str) -> Tuple[bool, str]:
        """Remove a secondary IP address from the network interface."""
        success, output = self._run_helper('remove-ip', self.interface, ip)
        if success:
            logger.info(f"Removed secondary IP {ip} from {self.interface}")
        return success, output
    
    def add_nat_rule(self, source_ip: str, target_ip: str, 
                     port: int = DEFAULT_PORT) -> Tuple[bool, str]:
        """Add NAT/DNAT rule to redirect traffic."""
        success, output = self._run_helper(
            'add-nat', source_ip, target_ip, str(port)
        )
        if success:
            logger.info(f"Added NAT rule: {source_ip}:{port} -> {target_ip}:{port}")
        return success, output
    
    def remove_nat_rule(self, source_ip: str, target_ip: str,
                        port: int = DEFAULT_PORT) -> Tuple[bool, str]:
        """Remove NAT/DNAT rule."""
        success, output = self._run_helper(
            'remove-nat', source_ip, target_ip, str(port)
        )
        if success:
            logger.info(f"Removed NAT rule: {source_ip}:{port} -> {target_ip}:{port}")
        return success, output
    
    def get_secondary_ips(self) -> Tuple[bool, list]:
        """Get list of secondary IPs on the interface."""
        success, output = self._run_helper('list-ips', self.interface)
        if success:
            ips = [ip.strip() for ip in output.split('\n') if ip.strip()]
            return True, ips
        return False, []
    
    def get_nat_rules(self) -> Tuple[bool, str]:
        """Get current NAT rules."""
        success, output = self._run_helper('list-nat')
        return success, output
    
    def check_ip_conflict(self, ip: str) -> Tuple[bool, bool]:
        """
        Check if an IP is already in use on the network.
        Returns (success, is_in_use)
        """
        success, output = self._run_helper('check-ip', ip)
        if success:
            # Helper returns "in-use" or "available"
            return True, output.strip().lower() == 'in-use'
        return False, False
    
    def enable_redirect(self, source_ip: str, target_ip: str,
                        port: int = DEFAULT_PORT) -> Tuple[bool, str]:
        """
        Enable a complete redirect:
        1. Add secondary IP (claim the dead printer's IP)
        2. Add NAT rule to redirect traffic
        """
        # Step 1: Add secondary IP
        success, output = self.add_secondary_ip(source_ip)
        if not success:
            # Send failure event to integrations
            try:
                from app.services.integrations import dispatch_event, EventType
                dispatch_event(
                    EventType.REDIRECT_FAILED,
                    {
                        'source_ip': source_ip,
                        'target_ip': target_ip,
                        'port': port,
                        'operation': 'enable',
                        'step': 'add_secondary_ip',
                        'error': output,
                    },
                    severity='error'
                )
            except Exception as e:
                logger.error(f"Failed to dispatch redirect failed event: {e}")
            
            return False, f"Failed to add IP: {output}"
        
        # Step 2: Add NAT rule
        success, output = self.add_nat_rule(source_ip, target_ip, port)
        if not success:
            # Rollback: remove the IP we just added
            self.remove_secondary_ip(source_ip)
            
            # Send failure event to integrations
            try:
                from app.services.integrations import dispatch_event, EventType
                dispatch_event(
                    EventType.REDIRECT_FAILED,
                    {
                        'source_ip': source_ip,
                        'target_ip': target_ip,
                        'port': port,
                        'operation': 'enable',
                        'step': 'add_nat_rule',
                        'error': output,
                    },
                    severity='error'
                )
            except Exception as e:
                logger.error(f"Failed to dispatch redirect failed event: {e}")
            
            return False, f"Failed to add NAT rule: {output}"
        
        return True, "Redirect enabled successfully"
    
    def disable_redirect(self, source_ip: str, target_ip: str,
                         port: int = DEFAULT_PORT) -> Tuple[bool, str]:
        """
        Disable a redirect:
        1. Remove NAT rule
        2. Remove secondary IP
        """
        errors = []
        
        # Step 1: Remove NAT rule
        success, output = self.remove_nat_rule(source_ip, target_ip, port)
        if not success:
            errors.append(f"Failed to remove NAT rule: {output}")
        
        # Step 2: Remove secondary IP
        success, output = self.remove_secondary_ip(source_ip)
        if not success:
            errors.append(f"Failed to remove IP: {output}")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, "Redirect disabled successfully"
    
    # =========================================================================
    # Network Information Methods (Read-Only)
    # =========================================================================
    
    def get_interface_info(self, interface: Optional[str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Get detailed information about network interfaces.
        Returns JSON array of interface information.
        """
        args = ['interface-info']
        if interface:
            args.append(interface)
        
        success, output = self._run_helper(*args)
        if success:
            try:
                interfaces = json.loads(output)
                return True, interfaces
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse interface info JSON: {e}")
                return False, []
        return False, []
    
    def get_arp_table(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Get the ARP/neighbour table.
        Returns JSON array of ARP entries.
        """
        success, output = self._run_helper('arp-table')
        if success:
            try:
                arp_entries = json.loads(output)
                return True, arp_entries
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ARP table JSON: {e}")
                return False, []
        return False, []
    
    def get_routing_info(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Get routing and forwarding status.
        Returns JSON object with routing configuration.
        """
        success, output = self._run_helper('routing-info')
        if success:
            try:
                routing = json.loads(output)
                return True, routing
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse routing info JSON: {e}")
                return False, {}
        return False, {}
    
    def get_connection_stats(self, source_ip: str, target_ip: str, 
                              port: int = DEFAULT_PORT) -> Tuple[bool, Dict[str, Any]]:
        """
        Get connection statistics for a specific redirect.
        """
        success, output = self._run_helper('connection-stats', source_ip, target_ip, str(port))
        if success:
            try:
                stats = json.loads(output)
                return True, stats
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse connection stats JSON: {e}")
                return False, {}
        return False, {}
    
    # =========================================================================
    # Diagnostic Methods
    # =========================================================================
    
    def ping_test(self, ip: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform a ping test to an IP address.
        Returns result and RTT if successful.
        """
        success, output = self._run_helper('ping-test', ip)
        if success:
            try:
                result = json.loads(output)
                return True, result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ping test JSON: {e}")
                return False, {"ip": ip, "result": "error", "rtt_ms": None}
        return False, {"ip": ip, "result": "error", "rtt_ms": None}
    
    def arp_probe(self, ip: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform an ARP probe for an IP address.
        Returns whether there was a response and the MAC if available.
        """
        success, output = self._run_helper('arp-probe', ip)
        if success:
            try:
                result = json.loads(output)
                return True, result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ARP probe JSON: {e}")
                return False, {"ip": ip, "result": "error", "mac": ""}
        return False, {"ip": ip, "result": "error", "mac": ""}
    
    def tcp_test(self, ip: str, port: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Test TCP connection to an IP and port.
        Returns result and latency if successful.
        """
        success, output = self._run_helper('tcp-test', ip, str(port))
        if success:
            try:
                result = json.loads(output)
                return True, result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse TCP test JSON: {e}")
                return False, {"ip": ip, "port": port, "result": "error", "latency_ms": None}
        return False, {"ip": ip, "port": port, "result": "error", "latency_ms": None}
    
    def re_announce_arp(self, ip: str) -> Tuple[bool, str]:
        """
        Send gratuitous ARP for a claimed IP address.
        """
        return self._run_helper('re-announce-arp', self.interface, ip)
    
    # =========================================================================
    # Advanced / Raw Output Methods
    # =========================================================================
    
    def get_nat_rules_raw(self) -> Tuple[bool, str]:
        """Get raw iptables NAT rules output."""
        return self._run_helper('nat-rules-raw')
    
    def get_ip_addr_raw(self) -> Tuple[bool, str]:
        """Get raw ip addr show output."""
        return self._run_helper('ip-addr-raw')
    
    def get_ip_route_raw(self) -> Tuple[bool, str]:
        """Get raw ip route output."""
        return self._run_helper('ip-route-raw')
    
    def get_ip_rule_raw(self) -> Tuple[bool, str]:
        """Get raw ip rule output."""
        return self._run_helper('ip-rule-raw')


# Global instance
_network_manager: Optional[NetworkManager] = None


def get_network_manager() -> NetworkManager:
    """Get the global network manager instance."""
    global _network_manager
    if _network_manager is None:
        _network_manager = NetworkManager()
    return _network_manager
