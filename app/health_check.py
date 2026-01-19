"""
Health Check Scheduler - Background monitoring of printer health
"""
import threading
import time
import logging
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from app.models import get_db_connection
from app.printers import get_registry

logger = logging.getLogger(__name__)


@dataclass
class HealthCheckResult:
    """Result of a health check for a printer."""
    printer_id: str
    ip: str
    checked_at: datetime
    icmp_ok: bool = False
    tcp_9100_ok: bool = False
    is_online: bool = False
    response_time_ms: float = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "printer_id": self.printer_id,
            "ip": self.ip,
            "checked_at": self.checked_at.isoformat(),
            "icmp_ok": self.icmp_ok,
            "tcp_9100_ok": self.tcp_9100_ok,
            "is_online": self.is_online,
            "response_time_ms": self.response_time_ms
        }


def init_health_check_tables():
    """Create health check tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Health check history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS health_check_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            printer_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            icmp_ok BOOLEAN,
            tcp_9100_ok BOOLEAN,
            is_online BOOLEAN,
            response_time_ms REAL
        )
    """)
    
    # Create index for faster queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_health_check_printer 
        ON health_check_history(printer_id, checked_at DESC)
    """)
    
    # Printer status cache (latest status for each printer)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS printer_status_cache (
            printer_id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            last_checked TIMESTAMP,
            icmp_ok BOOLEAN,
            tcp_9100_ok BOOLEAN,
            is_online BOOLEAN,
            last_online TIMESTAMP,
            consecutive_failures INTEGER DEFAULT 0
        )
    """)
    
    conn.commit()
    conn.close()


class HealthChecker:
    """Performs health checks on printers."""
    
    def check_tcp(self, ip: str, port: int = 9100, timeout: float = 2.0) -> tuple:
        """Check if TCP port is open. Returns (success, response_time_ms)."""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000
            sock.close()
            return (result == 0, elapsed)
        except Exception:
            return (False, 0)
    
    def check_icmp(self, ip: str, timeout: float = 2.0) -> bool:
        """Check if host responds to ICMP ping."""
        import subprocess
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(int(timeout)), ip],
                capture_output=True,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_printer(self, printer_id: str, ip: str) -> HealthCheckResult:
        """Perform a full health check on a printer."""
        result = HealthCheckResult(
            printer_id=printer_id,
            ip=ip,
            checked_at=datetime.now()
        )
        
        # Check TCP 9100
        tcp_ok, response_time = self.check_tcp(ip)
        result.tcp_9100_ok = tcp_ok
        result.response_time_ms = response_time
        
        # Check ICMP
        result.icmp_ok = self.check_icmp(ip)
        
        # Consider online if TCP 9100 is accessible
        result.is_online = tcp_ok
        
        return result
    
    def save_result(self, result: HealthCheckResult):
        """Save health check result to database."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert into history
        cursor.execute("""
            INSERT INTO health_check_history 
            (printer_id, ip, checked_at, icmp_ok, tcp_9100_ok, is_online, response_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result.printer_id, result.ip, result.checked_at.isoformat(),
            result.icmp_ok, result.tcp_9100_ok, result.is_online, result.response_time_ms
        ))
        
        # Update status cache
        cursor.execute("""
            INSERT OR REPLACE INTO printer_status_cache 
            (printer_id, ip, last_checked, icmp_ok, tcp_9100_ok, is_online, last_online, consecutive_failures)
            VALUES (?, ?, ?, ?, ?, ?, 
                CASE WHEN ? THEN ? ELSE (SELECT last_online FROM printer_status_cache WHERE printer_id = ?) END,
                CASE WHEN ? THEN 0 ELSE COALESCE((SELECT consecutive_failures FROM printer_status_cache WHERE printer_id = ?), 0) + 1 END
            )
        """, (
            result.printer_id, result.ip, result.checked_at.isoformat(),
            result.icmp_ok, result.tcp_9100_ok, result.is_online,
            result.is_online, result.checked_at.isoformat(), result.printer_id,
            result.is_online, result.printer_id
        ))
        
        conn.commit()
        conn.close()
    
    def get_cached_status(self, printer_id: str) -> Optional[Dict]:
        """Get cached status for a printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM printer_status_cache WHERE printer_id = ?", (printer_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def get_history(self, printer_id: str, limit: int = 100) -> List[Dict]:
        """Get health check history for a printer."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM health_check_history 
            WHERE printer_id = ? 
            ORDER BY checked_at DESC 
            LIMIT ?
        """, (printer_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def cleanup_old_history(self, days: int = 30):
        """Remove health check history older than specified days."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute("DELETE FROM health_check_history WHERE checked_at < ?", (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted


class HealthCheckScheduler:
    """Background scheduler for periodic health checks."""
    
    def __init__(self, interval_seconds: int = 60):
        self.interval = interval_seconds
        self.checker = HealthChecker()
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the background health check thread."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"Health check scheduler started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop the background health check thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Health check scheduler stopped")
    
    def _run_loop(self):
        """Main loop for periodic health checks."""
        while self._running:
            try:
                self._check_all_printers()
            except Exception as e:
                logger.error(f"Health check error: {e}")
            
            # Sleep in small increments to allow quick shutdown
            for _ in range(self.interval):
                if not self._running:
                    break
                time.sleep(1)
    
    def _check_all_printers(self):
        """Check health of all registered printers."""
        try:
            registry = get_registry()
            printers = registry.get_all()

            if not printers:
                # No printers registered; skip network checks
                logger.debug("Health checks: no printers registered, skipping poll")
                # Still allow periodic cleanup of old history
                self._maybe_cleanup()
                return
            
            for printer in printers:
                if not self._running:
                    break
                
                try:
                    result = self.checker.check_printer(printer.id, printer.ip)
                    self.checker.save_result(result)
                    
                    if not result.is_online:
                        logger.warning(f"Printer {printer.id} ({printer.ip}) is OFFLINE")
                except Exception as e:
                    logger.error(f"Error checking printer {printer.id}: {e}")
            
            # Cleanup old history periodically (check if it's time)
            self._maybe_cleanup()
            
        except Exception as e:
            logger.error(f"Error in health check loop: {e}")
    
    def _maybe_cleanup(self):
        """Periodically clean up old history."""
        # Clean up once per day (approximated by checking a random condition)
        import random
        if random.random() < (1.0 / (24 * 60)):  # ~once per day at 1-min interval
            deleted = self.checker.cleanup_old_history(30)
            if deleted:
                logger.info(f"Cleaned up {deleted} old health check records")


# Global scheduler instance
_scheduler: Optional[HealthCheckScheduler] = None


def get_scheduler() -> HealthCheckScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = HealthCheckScheduler(interval_seconds=60)
    return _scheduler


def start_health_checks():
    """Start the background health check scheduler."""
    init_health_check_tables()
    scheduler = get_scheduler()
    scheduler.start()


def stop_health_checks():
    """Stop the background health check scheduler."""
    global _scheduler
    if _scheduler:
        _scheduler.stop()


def get_printer_health(printer_id: str) -> Optional[Dict]:
    """Get the latest health status for a printer."""
    checker = HealthChecker()
    return checker.get_cached_status(printer_id)


def get_printer_health_history(printer_id: str, limit: int = 100) -> List[Dict]:
    """Get health check history for a printer."""
    checker = HealthChecker()
    return checker.get_history(printer_id, limit)
