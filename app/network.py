"""
Network operations handler - interfaces with privileged helper script
"""
import subprocess
import shlex
from typing import Tuple, Optional
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
            return False, f"Failed to add IP: {output}"
        
        # Step 2: Add NAT rule
        success, output = self.add_nat_rule(source_ip, target_ip, port)
        if not success:
            # Rollback: remove the IP we just added
            self.remove_secondary_ip(source_ip)
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


# Global instance
_network_manager: Optional[NetworkManager] = None


def get_network_manager() -> NetworkManager:
    """Get the global network manager instance."""
    global _network_manager
    if _network_manager is None:
        _network_manager = NetworkManager()
    return _network_manager
