"""
Job History - Database-backed print job history tracking

Stores and retrieves historical print job information.
"""
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class JobHistoryEntry:
    """Represents a historical print job."""
    id: int
    job_id: int
    printer_id: int
    name: str = ""
    owner: str = ""
    status: str = "Unknown"
    pages: int = 0
    copies: int = 1
    size_bytes: int = 0
    submitted_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "printer_id": self.printer_id,
            "name": self.name,
            "owner": self.owner,
            "status": self.status,
            "pages": self.pages,
            "copies": self.copies,
            "size_bytes": self.size_bytes,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


def get_history(printer_id: Optional[int] = None, limit: int = 100) -> List[JobHistoryEntry]:
    """Get job history from the database.
    
    Args:
        printer_id: Filter by printer ID (optional)
        limit: Maximum number of entries to return
        
    Returns:
        List of JobHistoryEntry objects
    """
    # Import here to avoid circular imports
    from app.models import PrintJobHistory
    
    try:
        query = PrintJobHistory.query.order_by(PrintJobHistory.submitted_at.desc())
        
        if printer_id is not None:
            query = query.filter_by(printer_id=printer_id)
        
        if limit:
            query = query.limit(limit)
        
        jobs = query.all()
        
        return [
            JobHistoryEntry(
                id=job.id,
                job_id=job.job_id,
                printer_id=job.printer_id,
                name=job.document_name or "",
                owner=job.username or "",
                status=job.status or "Unknown",
                pages=job.pages or 0,
                copies=job.copies or 1,
                size_bytes=job.size_bytes or 0,
                submitted_at=job.submitted_at,
                started_at=job.started_at,
                completed_at=job.completed_at
            )
            for job in jobs
        ]
    except Exception as e:
        logger.error(f"Error getting job history: {e}")
        return []


def add(
    printer_id: int,
    job_id: int,
    document_name: str = "",
    username: str = "",
    status: str = "completed",
    pages: int = 0,
    copies: int = 1,
    size_bytes: int = 0
) -> Optional[JobHistoryEntry]:
    """Add a job to the history database.
    
    Args:
        printer_id: ID of the printer
        job_id: Print job ID
        document_name: Name of the document
        username: User who submitted the job
        status: Job status
        pages: Number of pages
        copies: Number of copies
        size_bytes: Size in bytes
        
    Returns:
        The created JobHistoryEntry or None on error
    """
    # Import here to avoid circular imports
    from app.models import PrintJobHistory
    from app.extensions import db
    
    try:
        job = PrintJobHistory(
            printer_id=printer_id,
            job_id=job_id,
            document_name=document_name,
            username=username,
            status=status,
            pages=pages,
            copies=copies,
            size_bytes=size_bytes,
            submitted_at=datetime.utcnow(),
            completed_at=datetime.utcnow() if status == 'completed' else None
        )
        
        db.session.add(job)
        db.session.commit()
        
        return JobHistoryEntry(
            id=job.id,
            job_id=job.job_id,
            printer_id=job.printer_id,
            name=job.document_name or "",
            owner=job.username or "",
            status=job.status or "Unknown",
            pages=job.pages or 0,
            copies=job.copies or 1,
            size_bytes=job.size_bytes or 0,
            submitted_at=job.submitted_at,
            started_at=job.started_at,
            completed_at=job.completed_at
        )
    except Exception as e:
        logger.error(f"Error adding job to history: {e}")
        return None


def get_stats(printer_id: Optional[int] = None, days: int = 30) -> Dict[str, Any]:
    """Get job history statistics.
    
    Args:
        printer_id: Filter by printer ID (optional)
        days: Number of days to include
        
    Returns:
        Dictionary with stats (total_jobs, total_pages, etc.)
    """
    from datetime import timedelta
    from app.models import PrintJobHistory
    from sqlalchemy import func
    from app.extensions import db
    
    try:
        since = datetime.utcnow() - timedelta(days=days)
        
        query = db.session.query(
            func.count(PrintJobHistory.id).label('total_jobs'),
            func.sum(PrintJobHistory.pages).label('total_pages'),
            func.sum(PrintJobHistory.size_bytes).label('total_bytes')
        ).filter(PrintJobHistory.submitted_at >= since)
        
        if printer_id is not None:
            query = query.filter(PrintJobHistory.printer_id == printer_id)
        
        result = query.first()
        
        return {
            'total_jobs': result.total_jobs or 0,
            'total_pages': result.total_pages or 0,
            'total_bytes': result.total_bytes or 0,
            'days': days
        }
    except Exception as e:
        logger.error(f"Error getting job history stats: {e}")
        return {
            'total_jobs': 0,
            'total_pages': 0,
            'total_bytes': 0,
            'days': days
        }
