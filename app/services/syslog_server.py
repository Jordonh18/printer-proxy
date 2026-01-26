"""
Syslog Receiver Server for Continuum

Receives RFC 5424 formatted syslog messages from printers on UDP port 514.
Features:
- Strict RFC 5424 validation (rejects malformed messages)
- Rate limiting per source IP
- Queue-based message processing with backpressure
- Automatic message cleanup based on retention policy
- Thread-safe database writes
"""

import logging
import socket
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from queue import Queue, Full
from socketserver import ThreadingUDPServer, BaseRequestHandler
from typing import Optional, Dict, Tuple, List

from syslog_rfc5424_parser import SyslogMessage, ParseError

logger = logging.getLogger(__name__)

# RFC 5424 Severity levels
SEVERITY_NAMES = {
    0: 'emergency',
    1: 'alert',
    2: 'critical',
    3: 'error',
    4: 'warning',
    5: 'notice',
    6: 'info',
    7: 'debug'
}

# RFC 5424 Facility names
FACILITY_NAMES = {
    0: 'kern',
    1: 'user',
    2: 'mail',
    3: 'daemon',
    4: 'auth',
    5: 'syslog',
    6: 'lpr',
    7: 'news',
    8: 'uucp',
    9: 'cron',
    10: 'authpriv',
    11: 'ftp',
    12: 'ntp',
    13: 'security',
    14: 'console',
    15: 'solaris-cron',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7'
}


@dataclass
class SyslogEntry:
    """Represents a parsed syslog message."""
    id: Optional[int]
    printer_id: Optional[str]
    printer_ip: str
    received_at: datetime
    facility: int
    severity: int
    hostname: Optional[str]
    app_name: Optional[str]
    proc_id: Optional[str]
    msg_id: Optional[str]
    message: str
    raw_message: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            'id': self.id,
            'printer_id': self.printer_id,
            'printer_ip': self.printer_ip,
            'received_at': self.received_at.isoformat() if self.received_at else None,
            'facility': self.facility,
            'facility_name': FACILITY_NAMES.get(self.facility, 'unknown'),
            'severity': self.severity,
            'severity_name': SEVERITY_NAMES.get(self.severity, 'unknown'),
            'hostname': self.hostname,
            'app_name': self.app_name,
            'proc_id': self.proc_id,
            'msg_id': self.msg_id,
            'message': self.message,
        }


class RateLimiter:
    """
    Token bucket rate limiter per source IP.
    Limits messages per IP to prevent flooding.
    """
    
    def __init__(self, max_messages_per_second: int = 100, burst_size: int = 500):
        self._max_rate = max_messages_per_second
        self._burst_size = burst_size
        self._tokens: Dict[str, float] = defaultdict(lambda: float(burst_size))
        self._last_update: Dict[str, float] = defaultdict(time.time)
        self._lock = threading.Lock()
        
        # Statistics
        self._accepted: Dict[str, int] = defaultdict(int)
        self._rejected: Dict[str, int] = defaultdict(int)
    
    def allow(self, source_ip: str) -> bool:
        """Check if a message from source_ip should be allowed."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update[source_ip]
            self._last_update[source_ip] = now
            
            # Add tokens based on elapsed time
            self._tokens[source_ip] = min(
                self._burst_size,
                self._tokens[source_ip] + elapsed * self._max_rate
            )
            
            if self._tokens[source_ip] >= 1.0:
                self._tokens[source_ip] -= 1.0
                self._accepted[source_ip] += 1
                return True
            else:
                self._rejected[source_ip] += 1
                return False
    
    def get_stats(self) -> Dict[str, Dict[str, int]]:
        """Get rate limiting statistics."""
        with self._lock:
            return {
                ip: {'accepted': self._accepted[ip], 'rejected': self._rejected[ip]}
                for ip in set(self._accepted.keys()) | set(self._rejected.keys())
            }
    
    def reset_stats(self):
        """Reset statistics."""
        with self._lock:
            self._accepted.clear()
            self._rejected.clear()


class MessageQueue:
    """
    Bounded queue for syslog messages with backpressure.
    Drops oldest messages when queue is full.
    """
    
    def __init__(self, max_size: int = 10000):
        self._queue: Queue = Queue(maxsize=max_size)
        self._max_size = max_size
        self._dropped = 0
        self._processed = 0
        self._lock = threading.Lock()
    
    def put(self, entry: SyslogEntry) -> bool:
        """
        Add a message to the queue.
        Returns True if added, False if dropped due to queue full.
        """
        try:
            self._queue.put_nowait(entry)
            return True
        except Full:
            with self._lock:
                self._dropped += 1
            return False
    
    def get(self, timeout: float = 1.0) -> Optional[SyslogEntry]:
        """Get a message from the queue with timeout."""
        try:
            entry = self._queue.get(timeout=timeout)
            with self._lock:
                self._processed += 1
            return entry
        except Exception:
            return None
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics."""
        with self._lock:
            return {
                'queued': self._queue.qsize(),
                'max_size': self._max_size,
                'processed': self._processed,
                'dropped': self._dropped
            }
    
    def reset_stats(self):
        """Reset statistics (keeps queued items)."""
        with self._lock:
            self._dropped = 0
            self._processed = 0


class SyslogHandler(BaseRequestHandler):
    """UDP request handler for syslog messages."""
    
    def handle(self):
        """Handle incoming syslog message."""
        try:
            data = self.request[0]
            source_ip = self.client_address[0]
            
            # Check rate limit
            if not self.server.rate_limiter.allow(source_ip):
                logger.debug(f"Rate limited message from {source_ip}")
                return
            
            # Decode message
            try:
                raw_message = data.decode('utf-8', errors='replace')
            except Exception as e:
                logger.debug(f"Failed to decode message from {source_ip}: {e}")
                return
            
            # Parse RFC 5424 message
            try:
                parsed = SyslogMessage.parse(raw_message)
            except ParseError as e:
                logger.debug(f"Rejected malformed RFC 5424 message from {source_ip}: {e}")
                self.server.stats['malformed'] += 1
                return
            except Exception as e:
                logger.debug(f"Failed to parse syslog from {source_ip}: {e}")
                self.server.stats['malformed'] += 1
                return
            
            # Extract priority to get facility and severity
            facility = parsed.facility if hasattr(parsed, 'facility') else 1
            severity = parsed.severity if hasattr(parsed, 'severity') else 6
            
            # Create entry
            entry = SyslogEntry(
                id=None,
                printer_id=None,  # Will be resolved during DB write
                printer_ip=source_ip,
                received_at=datetime.now(),
                facility=facility,
                severity=severity,
                hostname=parsed.hostname if hasattr(parsed, 'hostname') else None,
                app_name=parsed.appname if hasattr(parsed, 'appname') else None,
                proc_id=parsed.procid if hasattr(parsed, 'procid') else None,
                msg_id=parsed.msgid if hasattr(parsed, 'msgid') else None,
                message=parsed.msg if hasattr(parsed, 'msg') else str(parsed),
                raw_message=raw_message
            )
            
            # Add to queue
            if self.server.message_queue.put(entry):
                self.server.stats['received'] += 1
            else:
                self.server.stats['queue_dropped'] += 1
                
        except Exception as e:
            logger.error(f"Error handling syslog message: {e}")
            self.server.stats['errors'] += 1


class SyslogServer(ThreadingUDPServer):
    """
    Threaded UDP syslog server with rate limiting and queue management.
    """
    
    allow_reuse_address = True
    daemon_threads = True
    
    def __init__(
        self,
        port: int = 514,
        max_messages_per_second: int = 100,
        burst_size: int = 500,
        queue_size: int = 10000
    ):
        self.port = port
        self.rate_limiter = RateLimiter(max_messages_per_second, burst_size)
        self.message_queue = MessageQueue(queue_size)
        self.stats = defaultdict(int)
        
        try:
            super().__init__(('0.0.0.0', port), SyslogHandler)
            logger.info(f"Syslog server initialized on UDP port {port}")
        except OSError as e:
            logger.error(f"Failed to bind syslog server to port {port}: {e}")
            raise
    
    def get_stats(self) -> Dict:
        """Get comprehensive server statistics."""
        return {
            'port': self.port,
            'received': self.stats['received'],
            'malformed': self.stats['malformed'],
            'errors': self.stats['errors'],
            'queue_dropped': self.stats['queue_dropped'],
            'rate_limiting': self.rate_limiter.get_stats(),
            'queue': self.message_queue.get_stats()
        }


class SyslogReceiver:
    """
    Main syslog receiver service.
    Manages server, database writer, and cleanup tasks.
    """
    
    def __init__(
        self,
        db_path: str,
        port: int = 514,
        retention_days: int = 30,
        max_messages_per_second: int = 100,
        burst_size: int = 500,
        queue_size: int = 10000
    ):
        self._db_path = db_path
        self._port = port
        self._retention_days = retention_days
        
        self._server: Optional[SyslogServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._writer_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        
        self._max_messages_per_second = max_messages_per_second
        self._burst_size = burst_size
        self._queue_size = queue_size
        
        # Printer IP to ID cache
        self._printer_cache: Dict[str, str] = {}
        self._cache_lock = threading.Lock()
        self._cache_refresh_time = 0
        self._cache_ttl = 60  # Refresh cache every 60 seconds
    
    def _init_database(self):
        """Initialize the syslog messages table."""
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS printer_syslog_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    printer_id TEXT,
                    printer_ip TEXT NOT NULL,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    facility INTEGER,
                    severity INTEGER,
                    hostname TEXT,
                    app_name TEXT,
                    proc_id TEXT,
                    msg_id TEXT,
                    message TEXT NOT NULL,
                    raw_message TEXT,
                    FOREIGN KEY (printer_id) REFERENCES printers(id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_syslog_printer_time 
                ON printer_syslog_messages(printer_id, received_at DESC)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_syslog_ip_time 
                ON printer_syslog_messages(printer_ip, received_at DESC)
            ''')
            conn.commit()
            logger.info("Syslog messages table initialized")
        finally:
            conn.close()
    
    def _refresh_printer_cache(self):
        """Refresh the printer IP to ID cache."""
        now = time.time()
        if now - self._cache_refresh_time < self._cache_ttl:
            return
        
        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip FROM printers")
            rows = cursor.fetchall()
            conn.close()
            
            with self._cache_lock:
                self._printer_cache = {row[1]: row[0] for row in rows}
                self._cache_refresh_time = now
                
        except Exception as e:
            logger.error(f"Failed to refresh printer cache: {e}")
    
    def _get_printer_id(self, ip: str) -> Optional[str]:
        """Get printer ID for an IP address."""
        self._refresh_printer_cache()
        with self._cache_lock:
            return self._printer_cache.get(ip)
    
    def _writer_loop(self):
        """Background thread to write messages to database."""
        batch: List[SyslogEntry] = []
        batch_size = 100
        batch_timeout = 1.0
        last_write = time.time()
        
        while self._running:
            entry = self._server.message_queue.get(timeout=0.1)
            
            if entry:
                # Resolve printer ID
                entry.printer_id = self._get_printer_id(entry.printer_ip)
                batch.append(entry)
            
            # Write batch if full or timeout reached
            now = time.time()
            if batch and (len(batch) >= batch_size or now - last_write >= batch_timeout):
                self._write_batch(batch)
                batch = []
                last_write = now
        
        # Write remaining messages on shutdown
        if batch:
            self._write_batch(batch)
    
    def _write_batch(self, batch: List[SyslogEntry]):
        """Write a batch of messages to the database."""
        if not batch:
            return
        
        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            cursor.executemany('''
                INSERT INTO printer_syslog_messages 
                (printer_id, printer_ip, received_at, facility, severity, 
                 hostname, app_name, proc_id, msg_id, message, raw_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', [
                (
                    e.printer_id, e.printer_ip, e.received_at.isoformat(),
                    e.facility, e.severity, e.hostname, e.app_name,
                    e.proc_id, e.msg_id, e.message, e.raw_message
                )
                for e in batch
            ])
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Wrote {len(batch)} syslog messages to database")
            
        except Exception as e:
            logger.error(f"Failed to write syslog batch: {e}")
    
    def _cleanup_loop(self):
        """Background thread to clean up old messages."""
        cleanup_interval = 3600  # Check every hour
        
        while self._running:
            try:
                cutoff = datetime.now() - timedelta(days=self._retention_days)
                
                conn = sqlite3.connect(self._db_path)
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM printer_syslog_messages WHERE received_at < ?",
                    (cutoff.isoformat(),)
                )
                deleted = cursor.rowcount
                conn.commit()
                conn.close()
                
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} syslog messages older than {self._retention_days} days")
                    
            except Exception as e:
                logger.error(f"Error during syslog cleanup: {e}")
            
            # Wait for next cleanup cycle
            for _ in range(cleanup_interval):
                if not self._running:
                    break
                time.sleep(1)
    
    def start(self):
        """Start the syslog receiver service."""
        if self._running:
            return
        
        logger.info(f"Starting syslog receiver on port {self._port}")
        
        # Initialize database
        self._init_database()
        
        # Create server
        try:
            self._server = SyslogServer(
                port=self._port,
                max_messages_per_second=self._max_messages_per_second,
                burst_size=self._burst_size,
                queue_size=self._queue_size
            )
        except OSError as e:
            logger.error(f"Failed to start syslog server: {e}")
            return
        
        self._running = True
        
        # Start server thread
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name="syslog-server",
            daemon=True
        )
        self._server_thread.start()
        
        # Start writer thread
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name="syslog-writer",
            daemon=True
        )
        self._writer_thread.start()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="syslog-cleanup",
            daemon=True
        )
        self._cleanup_thread.start()
        
        logger.info("Syslog receiver started successfully")
    
    def stop(self):
        """Stop the syslog receiver service."""
        if not self._running:
            return
        
        logger.info("Stopping syslog receiver...")
        self._running = False
        
        if self._server:
            self._server.shutdown()
        
        # Wait for threads to finish
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=5)
        
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        
        logger.info("Syslog receiver stopped")
    
    def get_stats(self) -> Dict:
        """Get server statistics."""
        if self._server:
            return self._server.get_stats()
        return {'status': 'stopped'}
    
    def get_messages(
        self,
        printer_id: Optional[str] = None,
        printer_ip: Optional[str] = None,
        severity: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None
    ) -> Tuple[List[SyslogEntry], int]:
        """
        Get syslog messages with filtering.
        Returns (messages, total_count).
        """
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Build query
        conditions = []
        params = []
        
        if printer_id:
            conditions.append("printer_id = ?")
            params.append(printer_id)
        
        if printer_ip:
            conditions.append("printer_ip = ?")
            params.append(printer_ip)
        
        if severity is not None:
            conditions.append("severity <= ?")  # Include all equal or more severe
            params.append(severity)
        
        if search:
            conditions.append("message LIKE ?")
            params.append(f"%{search}%")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        # Get total count
        cursor.execute(
            f"SELECT COUNT(*) FROM printer_syslog_messages WHERE {where_clause}",
            params
        )
        total = cursor.fetchone()[0]
        
        # Get messages
        cursor.execute(f'''
            SELECT * FROM printer_syslog_messages 
            WHERE {where_clause}
            ORDER BY received_at DESC
            LIMIT ? OFFSET ?
        ''', params + [limit, offset])
        
        rows = cursor.fetchall()
        conn.close()
        
        messages = [
            SyslogEntry(
                id=row['id'],
                printer_id=row['printer_id'],
                printer_ip=row['printer_ip'],
                received_at=datetime.fromisoformat(row['received_at']) if row['received_at'] else None,
                facility=row['facility'],
                severity=row['severity'],
                hostname=row['hostname'],
                app_name=row['app_name'],
                proc_id=row['proc_id'],
                msg_id=row['msg_id'],
                message=row['message'],
                raw_message=row['raw_message']
            )
            for row in rows
        ]
        
        return messages, total
    
    def get_last_message_time(self, printer_ip: str) -> Optional[datetime]:
        """Get the timestamp of the last message from a printer IP."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT received_at FROM printer_syslog_messages 
            WHERE printer_ip = ? 
            ORDER BY received_at DESC 
            LIMIT 1
        ''', (printer_ip,))
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None


# Global syslog receiver instance
_syslog_receiver: Optional[SyslogReceiver] = None
_receiver_lock = threading.Lock()


def get_syslog_receiver() -> Optional[SyslogReceiver]:
    """Get the global syslog receiver instance."""
    return _syslog_receiver


def init_syslog_receiver(
    db_path: str,
    port: int = 514,
    retention_days: int = 30,
    enabled: bool = True
) -> Optional[SyslogReceiver]:
    """Initialize and start the syslog receiver."""
    global _syslog_receiver
    
    if not enabled:
        logger.info("Syslog receiver is disabled")
        return None
    
    with _receiver_lock:
        if _syslog_receiver is not None:
            return _syslog_receiver
        
        try:
            _syslog_receiver = SyslogReceiver(
                db_path=db_path,
                port=port,
                retention_days=retention_days
            )
            _syslog_receiver.start()
            return _syslog_receiver
        except Exception as e:
            logger.error(f"Failed to initialize syslog receiver: {e}")
            return None


def stop_syslog_receiver():
    """Stop the global syslog receiver."""
    global _syslog_receiver
    
    with _receiver_lock:
        if _syslog_receiver:
            _syslog_receiver.stop()
            _syslog_receiver = None
