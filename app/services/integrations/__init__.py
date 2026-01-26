"""
Integrations Module for Continuum

This module provides a plugin-like architecture for third-party integrations,
focusing on syslog-based services (Splunk, Datadog, Elastic) with bidirectional
capability for sending logs and receiving events/alerts.
"""

from .base import (
    IntegrationBase,
    IntegrationError,
    IntegrationAuthError,
    IntegrationConnectionError,
    IntegrationRateLimitError,
    IntegrationValidationError,
    IntegrationStatus,
    AuthType,
)
from .registry import IntegrationRegistry, get_integration_registry
from .manager import IntegrationManager, get_integration_manager
from .crypto import CredentialEncryption
from .dispatcher import (
    get_dispatcher,
    dispatch_event,
    EventType,
    IntegrationEventDispatcher,
)

__all__ = [
    'IntegrationBase',
    'IntegrationError',
    'IntegrationAuthError',
    'IntegrationConnectionError',
    'IntegrationRateLimitError',
    'IntegrationValidationError',
    'IntegrationStatus',
    'AuthType',
    'IntegrationRegistry',
    'get_integration_registry',
    'IntegrationManager',
    'get_integration_manager',
    'CredentialEncryption',
    'get_dispatcher',
    'dispatch_event',
    'EventType',
    'IntegrationEventDispatcher',
]
