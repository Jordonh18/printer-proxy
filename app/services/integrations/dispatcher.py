"""
Integration Event Dispatcher

Central module for dispatching events to configured integrations.
This is the main entry point for all application events that need
to be sent to external services (logging, monitoring, alerting).
"""
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Standardized event types for integrations."""
    
    # Printer Events
    PRINTER_ADDED = 'printer.added'
    PRINTER_REMOVED = 'printer.removed'
    PRINTER_OFFLINE = 'printer.offline'
    PRINTER_ONLINE = 'printer.online'
    PRINTER_ERROR = 'printer.error'
    PRINTER_LOW_TONER = 'printer.low_toner'
    PRINTER_JAM = 'printer.jam'
    
    # Redirect Events
    REDIRECT_CREATED = 'redirect.created'
    REDIRECT_REMOVED = 'redirect.removed'
    REDIRECT_FAILED = 'redirect.failed'
    
    # Job Events
    JOB_STARTED = 'job.started'
    JOB_COMPLETED = 'job.completed'
    JOB_FAILED = 'job.failed'
    
    # Group Events
    GROUP_CREATED = 'group.created'
    GROUP_UPDATED = 'group.updated'
    GROUP_DELETED = 'group.deleted'
    
    # Workflow Events
    WORKFLOW_STARTED = 'workflow.started'
    WORKFLOW_COMPLETED = 'workflow.completed'
    WORKFLOW_FAILED = 'workflow.failed'
    
    # Security Events
    SECURITY_LOGIN_FAILED = 'security.login_failed'
    SECURITY_ACCOUNT_LOCKED = 'security.account_locked'
    SECURITY_UNAUTHORIZED_ACCESS = 'security.unauthorized_access'
    
    # System Events
    SYSTEM_ERROR = 'system.error'
    SYSTEM_WARNING = 'system.warning'
    SYSTEM_INFO = 'system.info'


class IntegrationEventDispatcher:
    """
    Dispatcher for sending events to configured integrations.
    
    This class provides a centralized interface for dispatching events
    from anywhere in the application to configured integrations.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._manager = None  # Lazy load to avoid circular imports
    
    def _get_manager(self):
        """Lazy load the integration manager."""
        if self._manager is None:
            from .manager import get_integration_manager
            self._manager = get_integration_manager()
        return self._manager
    
    def dispatch(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str = 'info',
        source: str = 'continuum',
    ) -> bool:
        """
        Dispatch an event to configured integrations (synchronous wrapper).
        
        Args:
            event_type: The type of event (use EventType enum values)
            event_data: Dictionary containing event details
            severity: Event severity (info, warning, error, critical)
            source: Source of the event (default: 'continuum')
        
        Returns:
            True if dispatched successfully (even if no integrations configured)
        """
        try:
            # Run async dispatch in event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    self.dispatch_async(event_type, event_data, severity, source)
                )
            finally:
                loop.close()
            return True
        except Exception as e:
            logger.error(f"Failed to dispatch event {event_type}: {e}")
            return False
    
    async def dispatch_async(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str = 'info',
        source: str = 'continuum',
    ):
        """
        Dispatch an event to configured integrations (async).
        
        Args:
            event_type: The type of event
            event_data: Dictionary containing event details
            severity: Event severity (info, warning, error, critical)
            source: Source of the event
        """
        try:
            manager = self._get_manager()
            
            # Enrich event data with standard fields
            enriched_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'source': source,
                **event_data,
            }
            
            # Send to integrations
            result = await manager.send_event(event_type, enriched_data)
            
            if result.get('sent', 0) > 0:
                logger.debug(
                    f"Event {event_type} sent to {result['sent']} integration(s)"
                )
            
            if result.get('failed', 0) > 0:
                logger.warning(
                    f"Event {event_type} failed for {result['failed']} integration(s)"
                )
                
        except Exception as e:
            logger.error(f"Error dispatching event {event_type}: {e}")


# Global dispatcher instance
_dispatcher: Optional[IntegrationEventDispatcher] = None


def get_dispatcher() -> IntegrationEventDispatcher:
    """Get the global event dispatcher instance."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = IntegrationEventDispatcher()
    return _dispatcher


def dispatch_event(
    event_type: str,
    event_data: Dict[str, Any],
    severity: str = 'info',
    source: str = 'continuum',
) -> bool:
    """
    Convenience function to dispatch an event to integrations.
    
    Args:
        event_type: The type of event (use EventType enum values)
        event_data: Dictionary containing event details
        severity: Event severity (info, warning, error, critical)
        source: Source of the event
    
    Returns:
        True if dispatched successfully
    
    Example:
        >>> dispatch_event(
        ...     EventType.PRINTER_OFFLINE,
        ...     {'printer_name': 'HP-101', 'printer_ip': '10.0.1.101'},
        ...     severity='warning'
        ... )
    """
    dispatcher = get_dispatcher()
    return dispatcher.dispatch(event_type, event_data, severity, source)
