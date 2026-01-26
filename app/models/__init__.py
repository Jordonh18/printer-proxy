"""
Database models for Continuum

This module re-exports all models from the base models file.
In the future, models can be split into separate files here.
"""

# Re-export everything from base models
from app.models.base import (
    get_db_connection,
    init_db,
    User,
    UserSession,
    PrinterGroup,
    GroupRedirectSchedule,
    PrinterRedirectSchedule,
    WorkflowRegistryNode,
    Workflow,
    ActiveRedirect,
    AuditLog,
    RedirectHistory,
    PrintJobHistory,
    PrinterErrorLog,
)


__all__ = [
    # Database utilities
    'get_db_connection',
    'init_db',
    # User models
    'User',
    'UserSession',
    # Printer models
    'PrinterGroup',
    # Redirect models
    'ActiveRedirect',
    'RedirectHistory',
    'GroupRedirectSchedule',
    'PrinterRedirectSchedule',
    # Workflow models
    'Workflow',
    'WorkflowRegistryNode',
    # Audit models
    'AuditLog',
    # Print job models
    'PrintJobHistory',
    'PrinterErrorLog',
]
