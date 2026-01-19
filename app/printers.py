"""
Printer registry and status checking - Database driven
"""
import socket
import subprocess
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from config.config import (
    PING_TIMEOUT_SECONDS,
    TCP_CHECK_TIMEOUT_SECONDS,
    DEFAULT_PORT
)
from app.models import ActiveRedirect, get_db_connection


@dataclass
class Printer:
    """Printer data class."""
    id: str
    name: str
    ip: str
    protocols: List[str]
    location: str
    model: str
    department: str
    notes: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "protocols": self.protocols,
            "location": self.location,
            "model": self.model,
            "department": self.department,
            "notes": self.notes
        }
    
    @classmethod
    def from_row(cls, row) -> 'Printer':
        """Create a Printer from a database row."""
        protocols = row['protocols'].split(',') if row['protocols'] else ['raw']
        return cls(
            id=row['id'],
            name=row['name'],
            ip=row['ip'],
            protocols=protocols,
            location=row['location'] or '',
            model=row['model'] or '',
            department=row['department'] or '',
            notes=row['notes'] or ''
        )


class PrinterRegistry:
    """Manages the printer registry and status checks - Database driven."""
    
    def __init__(self):
        pass  # No initialization needed, all data comes from database
    
    def get_all(self) -> List[Printer]:
        """Get all registered printers."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM printers ORDER BY name")
        rows = cursor.fetchall()
        conn.close()
        return [Printer.from_row(row) for row in rows]
    
    def get_by_id(self, printer_id: str) -> Optional[Printer]:
        """Get a printer by ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM printers WHERE id = ?", (printer_id,))
        row = cursor.fetchone()
        conn.close()
        return Printer.from_row(row) if row else None
    
    def get_by_ip(self, ip: str) -> Optional[Printer]:
        """Get a printer by IP address."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM printers WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        conn.close()
        return Printer.from_row(row) if row else None
    
    def check_icmp_reachability(self, ip: str) -> bool:
        """Check if an IP is reachable via ICMP ping."""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(PING_TIMEOUT_SECONDS), ip],
                capture_output=True,
                timeout=PING_TIMEOUT_SECONDS + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def check_tcp_reachability(self, ip: str, port: int = DEFAULT_PORT) -> bool:
        """Check if a TCP port is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CHECK_TIMEOUT_SECONDS)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_printer_status(self, printer: Printer, use_cache: bool = True) -> Dict[str, Any]:
        """Get comprehensive status for a printer.
        
        Args:
            printer: The printer to check
            use_cache: If True, use cached status from background checks (fast).
                      If False, do live network checks (slow but accurate).
        """
        # Check for active redirect
        redirect = ActiveRedirect.get_by_source_printer(printer.id)
        is_redirected = redirect is not None
        
        # Check if this printer is a redirect target
        is_target = ActiveRedirect.is_target_in_use(printer.id)
        
        # Get reachability status
        if is_redirected:
            # Redirected printers are considered offline
            icmp_reachable = False
            tcp_reachable = False
        elif use_cache:
            # Use cached status from background health checks (FAST)
            cached = self._get_cached_status(printer.id)
            if cached:
                icmp_reachable = cached.get('icmp_ok', False)
                tcp_reachable = cached.get('tcp_9100_ok', False)
            else:
                # No cache yet, assume unknown (will be updated by background check)
                icmp_reachable = False
                tcp_reachable = False
        else:
            # Live check (SLOW - only use for specific operations)
            icmp_reachable = self.check_icmp_reachability(printer.ip)
            tcp_reachable = self.check_tcp_reachability(printer.ip)
        
        return {
            "printer": printer.to_dict(),
            "status": {
                "icmp_reachable": icmp_reachable,
                "tcp_reachable": tcp_reachable,
                "is_online": icmp_reachable or tcp_reachable,
                "is_redirected": is_redirected,
                "is_redirect_target": is_target,
                "redirect_info": {
                    "target_printer_id": redirect.target_printer_id if redirect else None,
                    "target_ip": redirect.target_ip if redirect else None,
                    "enabled_at": str(redirect.enabled_at) if redirect else None,
                    "enabled_by": redirect.enabled_by if redirect else None
                } if redirect else None
            }
        }
    
    def _get_cached_status(self, printer_id: str) -> Optional[Dict[str, Any]]:
        """Get cached health status for a printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM printer_status_cache WHERE printer_id = ?", (printer_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_all_statuses(self, use_cache: bool = True) -> List[Dict[str, Any]]:
        """Get status for all printers.
        
        Args:
            use_cache: If True, use cached status (fast). If False, do live checks (slow).
        """
        return [self.get_printer_status(p, use_cache=use_cache) for p in self.get_all()]
    
    def get_available_targets(self, exclude_printer_id: str = None, use_cache: bool = True) -> List[Printer]:
        """Get printers that can be used as redirect targets.
        
        Args:
            exclude_printer_id: Printer to exclude from results
            use_cache: If True, use cached status (fast). If False, do live checks.
        """
        available = []
        for printer in self.get_all():
            # Skip the excluded printer
            if exclude_printer_id and printer.id == exclude_printer_id:
                continue
            
            # Skip printers that are already being redirected
            if ActiveRedirect.get_by_source_printer(printer.id):
                continue
            
            # Skip printers that are already redirect targets
            if ActiveRedirect.is_target_in_use(printer.id):
                continue
            
            # Check if the printer is online (use cache for speed)
            if use_cache:
                cached = self._get_cached_status(printer.id)
                is_online = cached.get('is_online', False) if cached else False
            else:
                is_online = self.check_tcp_reachability(printer.ip)
            
            if is_online:
                available.append(printer)
        
        return available
    
    def add_printer(self, printer: Printer) -> bool:
        """Add a new printer to the database."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO printers (id, name, ip, protocols, location, model, department, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                printer.id,
                printer.name,
                printer.ip,
                ','.join(printer.protocols),
                printer.location,
                printer.model,
                printer.department,
                printer.notes
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding printer: {e}")
            return False
    
    def update_printer(self, printer: Printer) -> bool:
        """Update an existing printer in the database."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE printers 
                SET name = ?, ip = ?, protocols = ?, location = ?, 
                    model = ?, department = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                printer.name,
                printer.ip,
                ','.join(printer.protocols),
                printer.location,
                printer.model,
                printer.department,
                printer.notes,
                printer.id
            ))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
            return affected > 0
        except Exception as e:
            print(f"Error updating printer: {e}")
            return False
    
    def delete_printer(self, printer_id: str) -> bool:
        """Delete a printer from the database."""
        # Check if printer has active redirect
        if ActiveRedirect.get_by_source_printer(printer_id):
            return False
        if ActiveRedirect.is_target_in_use(printer_id):
            return False
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM printers WHERE id = ?", (printer_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
            return affected > 0
        except Exception as e:
            print(f"Error deleting printer: {e}")
            return False
    
    def ip_exists(self, ip: str, exclude_id: str = None) -> bool:
        """Check if an IP address is already in use by another printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        if exclude_id:
            cursor.execute("SELECT 1 FROM printers WHERE ip = ? AND id != ?", (ip, exclude_id))
        else:
            cursor.execute("SELECT 1 FROM printers WHERE ip = ?", (ip,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def id_exists(self, printer_id: str) -> bool:
        """Check if a printer ID already exists."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM printers WHERE id = ?", (printer_id,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def reload(self):
        """Reload is a no-op for database-driven registry."""
        pass  # Database is always current


# Global registry instance
_registry: Optional[PrinterRegistry] = None


def get_registry() -> PrinterRegistry:
    """Get the global printer registry instance."""
    global _registry
    if _registry is None:
        _registry = PrinterRegistry()
    return _registry
