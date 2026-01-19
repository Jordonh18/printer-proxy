"""
Job Monitor - Background service for detecting and recording print jobs

This module monitors printers via SNMP to detect print activity:
1. Tracks page counter changes to detect when printing occurs
2. Parses HP event logs for job events (Print Started/Completed)
3. Records job history in the database

The monitor runs as a background thread and periodically polls printers.
"""
import asyncio
import logging
import threading
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# Job-related event codes from HP printers
JOB_EVENT_CODES = {
    8396: 'started',      # Print Started
    8700: 'completed',    # Print Completed
    8701: 'cancelled',    # Print Cancelled
    8702: 'failed',       # Print Failed
    18479: 'started',     # Another print start code
    18480: 'completed',   # Another print complete code
}


@dataclass
class PrinterState:
    """Tracks the state of a printer for job detection."""
    ip: str
    printer_id: str
    page_count: int = 0
    last_page_count: int = 0
    last_check: Optional[datetime] = None
    last_event_codes: List[int] = field(default_factory=list)
    pending_job_start: Optional[datetime] = None
    
    def pages_printed_since_last(self) -> int:
        """Get number of pages printed since last check."""
        if self.last_page_count == 0:
            return 0
        return max(0, self.page_count - self.last_page_count)


class JobMonitor:
    """Background service that monitors printers for print jobs."""
    
    def __init__(self, poll_interval: int = 30):
        """Initialize the job monitor.
        
        Args:
            poll_interval: How often to poll printers (seconds)
        """
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._printer_states: Dict[str, PrinterState] = {}
        self._lock = threading.Lock()
        self._app = None
        
    def init_app(self, app):
        """Initialize with Flask app context."""
        self._app = app
        
    def start(self):
        """Start the background monitoring thread."""
        if self._running:
            logger.warning("Job monitor already running")
            return
            
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Job monitor started (polling every {self.poll_interval}s)")
        
    def stop(self):
        """Stop the background monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Job monitor stopped")
        
    def _run(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._poll_printers()
            except Exception as e:
                logger.error(f"Error in job monitor loop: {e}")
            
            # Sleep in small increments so we can stop quickly
            for _ in range(self.poll_interval):
                if not self._running:
                    break
                time.sleep(1)
                
    def _poll_printers(self):
        """Poll all registered printers for job activity."""
        if not self._app:
            logger.debug("No app context, skipping poll")
            return
            
        with self._app.app_context():
            try:
                from app.printers import get_registry
                registry = get_registry()
                printers = registry.get_all()

                if not printers:
                    # No printers registered; avoid unnecessary polling
                    logger.debug("Job monitor: no printers registered, skipping poll")
                    return

                logger.info(f"Job monitor polling {len(printers)} printers")

                current_ips = {printer.ip for printer in printers}
                # Clean up stale states for removed printers to avoid memory growth
                with self._lock:
                    stale_ips = set(self._printer_states.keys()) - current_ips
                    for ip in stale_ips:
                        self._printer_states.pop(ip, None)

                for printer in printers:
                    try:
                        self._check_printer(printer)
                    except Exception as e:
                        logger.warning(f"Error checking printer {printer.ip}: {e}")
                        
            except Exception as e:
                logger.error(f"Error getting printer list: {e}")
                
    def _check_printer(self, printer):
        """Check a single printer for job activity."""
        from app.models import PrintJobHistory
        
        ip = printer.ip
        printer_id = printer.id  # String ID from printer registry
        
        # Get or create printer state
        with self._lock:
            if ip not in self._printer_states:
                self._printer_states[ip] = PrinterState(
                    ip=ip, 
                    printer_id=printer_id
                )
            state = self._printer_states[ip]
        
        # Get current page count
        current_page_count = self._get_page_count(ip)
        if current_page_count is None:
            logger.debug(f"Could not get page count for {ip}")
            return
            
        # Get job events from event log
        job_events = self._get_job_events(ip)
        
        now = datetime.utcnow()
        
        # Store previous page count for logging and calculation
        previous_page_count = state.page_count
        
        # Update state
        state.last_page_count = previous_page_count
        state.page_count = current_page_count
        state.last_check = now
        
        # Log page count - only log if we had a previous value (not first poll)
        if previous_page_count > 0:
            logger.info(f"Printer {ip}: page count = {current_page_count} (was {previous_page_count})")
        else:
            logger.info(f"Printer {ip}: initial page count = {current_page_count}")
        
        # Calculate pages printed (only meaningful after first poll)
        pages_printed = 0
        if previous_page_count > 0:
            pages_printed = current_page_count - previous_page_count
        
        if pages_printed > 0:
            logger.info(f"Detected {pages_printed} pages printed on {ip}")
            
            # Determine job status from events
            job_status = 'completed'
            for code, status in job_events:
                if status == 'failed':
                    job_status = 'failed'
                    break
                elif status == 'cancelled':
                    job_status = 'cancelled'
                    break
            
            # Record the job
            try:
                job = PrintJobHistory.record_job(
                    printer_id=printer_id,
                    job_id=int(time.time()),  # Use timestamp as job ID
                    document_name=f"Print Job",
                    username="",  # SNMP doesn't provide this
                    status=job_status,
                    pages=pages_printed,
                    copies=1,
                    size_bytes=0
                )
                if job:
                    logger.info(f"Recorded job: {pages_printed} pages on printer {printer_id}")
            except Exception as e:
                logger.error(f"Failed to record job: {e}")
        
        # Track pending job start events
        for code, status in job_events:
            if status == 'started' and state.pending_job_start is None:
                state.pending_job_start = now
            elif status in ('completed', 'cancelled', 'failed'):
                state.pending_job_start = None
                
        state.last_event_codes = [code for code, _ in job_events]
        
    def _get_page_count(self, ip: str) -> Optional[int]:
        """Get current page count from printer via SNMP."""
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                get_cmd, SnmpEngine, CommunityData, 
                UdpTransportTarget, ContextData, 
                ObjectType, ObjectIdentity
            )
            
            async def query():
                snmp_engine = SnmpEngine()
                try:
                    # prtMarkerLifeCount OID
                    page_count_oid = '1.3.6.1.2.1.43.10.2.1.4.1.1'
                    
                    err, status, idx, vb = await get_cmd(
                        snmp_engine,
                        CommunityData('public'),
                        await UdpTransportTarget.create((ip, 161), timeout=3, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(page_count_oid))
                    )
                    
                    if not err and not status and vb:
                        return int(vb[0][1])
                    return None
                finally:
                    snmp_engine.close_dispatcher()
            
            # Run in new event loop
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(query())
                return result
            finally:
                loop.close()
                
        except Exception as e:
            logger.debug(f"Error getting page count for {ip}: {e}")
            return None
            
    def _get_job_events(self, ip: str) -> List[Tuple[int, str]]:
        """Get recent job events from printer event log.
        
        Returns:
            List of (event_code, status) tuples for job-related events
        """
        try:
            from app.event_logs import get_printer_logs
            
            events = get_printer_logs(ip)
            job_events = []
            
            for event in events:
                if event.code in JOB_EVENT_CODES:
                    status = JOB_EVENT_CODES[event.code]
                    job_events.append((event.code, status))
                    
            return job_events
            
        except Exception as e:
            logger.debug(f"Error getting job events for {ip}: {e}")
            return []
            
    def get_printer_state(self, ip: str) -> Optional[PrinterState]:
        """Get the current state for a printer."""
        with self._lock:
            return self._printer_states.get(ip)
            
    def get_all_states(self) -> Dict[str, PrinterState]:
        """Get all printer states."""
        with self._lock:
            return dict(self._printer_states)
            
    def force_check(self, ip: str = None):
        """Force an immediate check of one or all printers."""
        if not self._app:
            return
            
        with self._app.app_context():
            try:
                from app.printers import get_registry
                registry = get_registry()
                
                if ip:
                    printer = registry.get_by_ip(ip)
                    if printer:
                        self._check_printer(printer)
                else:
                    for printer in registry.get_all():
                        self._check_printer(printer)
            except Exception as e:
                logger.error(f"Error in force_check: {e}")


# Global monitor instance
_job_monitor: Optional[JobMonitor] = None


def get_job_monitor() -> JobMonitor:
    """Get the global job monitor instance."""
    global _job_monitor
    if _job_monitor is None:
        _job_monitor = JobMonitor(poll_interval=30)
    return _job_monitor


def init_job_monitor(app, start: bool = True):
    """Initialize the job monitor with a Flask app.
    
    Args:
        app: Flask application instance
        start: Whether to start the monitor immediately
    """
    monitor = get_job_monitor()
    monitor.init_app(app)
    if start:
        monitor.start()
    return monitor
