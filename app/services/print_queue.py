"""
Print Queue - SNMP-based print queue monitoring

Queries printers via SNMP to get current print status.
Uses Host Resources MIB (hrPrinterStatus) and Printer MIB.

Note: HP printers don't expose job queue details (document name, owner, etc.)
via SNMP. We can only detect:
1. Whether the printer is currently printing (hrPrinterStatus = 4)
2. The console display message
3. Page count changes (for job history tracking)
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PrintJob:
    """Represents a print job in the queue."""
    job_id: int
    name: str = ""
    owner: str = ""
    status: str = "Unknown"
    pages: int = 0
    size_bytes: int = 0
    submitted_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "owner": self.owner,
            "status": self.status,
            "pages": self.pages,
            "size_bytes": self.size_bytes,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


# Printer status codes from Host Resources MIB
HR_PRINTER_STATUS = {
    1: "Other",
    2: "Unknown",
    3: "Idle",
    4: "Printing",
    5: "Warmup",
}


class PrintQueueCollector:
    """Collects print queue information via SNMP."""
    
    # SNMP OIDs for printer status
    STATUS_OIDS = {
        'hr_status': '1.3.6.1.2.1.25.3.5.1.1.1',       # hrPrinterStatus
        'display': '1.3.6.1.2.1.43.16.5.1.2.1.1',      # prtConsoleDisplayBufferText
        'page_count': '1.3.6.1.2.1.43.10.2.1.4.1.1',   # prtMarkerLifeCount
    }
    
    def __init__(self, community: str = 'public'):
        self.community = community
    
    def get_queue(self, ip: str) -> List[PrintJob]:
        """Get the current print queue for a printer.
        
        Note: HP printers don't expose job details via SNMP.
        We can only detect if printing is in progress.
        """
        jobs = []
        
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                get_cmd, SnmpEngine, CommunityData, 
                UdpTransportTarget, ContextData, 
                ObjectType, ObjectIdentity
            )
            
            async def query_status():
                snmp_engine = SnmpEngine()
                status_code = 0
                display_msg = ""
                
                try:
                    for name, oid in self.STATUS_OIDS.items():
                        try:
                            err, status, idx, vb = await get_cmd(
                                snmp_engine,
                                CommunityData(self.community),
                                await UdpTransportTarget.create((ip, 161), timeout=3, retries=1),
                                ContextData(),
                                ObjectType(ObjectIdentity(oid))
                            )
                            
                            if not err and not status and vb:
                                value = vb[0][1]
                                if name == 'hr_status':
                                    status_code = int(value)
                                elif name == 'display':
                                    if hasattr(value, 'prettyPrint'):
                                        display_msg = value.prettyPrint()
                                    else:
                                        display_msg = str(value)
                        except Exception as e:
                            logger.debug(f"Error querying {name}: {e}")
                    
                    # If printer is currently printing, show a job
                    if status_code == 4:  # Printing
                        job = PrintJob(
                            job_id=1,
                            name=display_msg or "Printing...",
                            owner="",
                            status="Printing",
                            pages=0
                        )
                        jobs.append(job)
                        
                finally:
                    snmp_engine.close_dispatcher()
                    
                    # Cancel and await all pending tasks to prevent "Task was destroyed" warnings
                    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    
                return jobs
            
            # Run async query
            loop = asyncio.new_event_loop()
            try:
                jobs = loop.run_until_complete(query_status())
            finally:
                loop.close()
            
        except ImportError:
            logger.warning("pysnmp not installed")
        except Exception as e:
            logger.debug(f"Error getting queue for {ip}: {e}")
        
        return jobs


# Global collector instance
_queue_collector: Optional[PrintQueueCollector] = None


def get_queue_collector() -> PrintQueueCollector:
    """Get the global queue collector."""
    global _queue_collector
    if _queue_collector is None:
        _queue_collector = PrintQueueCollector()
    return _queue_collector


def get_queue(ip: str) -> List[PrintJob]:
    """Get print queue for a printer by IP."""
    return get_queue_collector().get_queue(ip)
