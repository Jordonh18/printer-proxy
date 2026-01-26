"""
Integration Registry.

Manages the catalog of available integrations and their handlers.
Uses a plugin-like architecture where each integration is self-contained.
"""

import json
import logging
from typing import Dict, List, Optional, Type
from .base import IntegrationBase, IntegrationMetadata, IntegrationCategory

logger = logging.getLogger(__name__)


class IntegrationRegistry:
    """
    Registry for all available integrations.
    
    Provides:
    - Registration of integration handlers
    - Discovery of available integrations
    - Filtering by category, capability, etc.
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
        self._integrations: Dict[str, Type[IntegrationBase]] = {}
        self._register_builtin_integrations()
    
    def _register_builtin_integrations(self):
        """Register built-in integrations."""
        # Import handlers here to avoid circular imports
        # Logging Integrations
        try:
            from .handlers.splunk import SplunkIntegration
            self.register(SplunkIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Splunk integration: {e}')
        
        try:
            from .handlers.datadog import DatadogIntegration
            self.register(DatadogIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Datadog integration: {e}')
        
        try:
            from .handlers.elastic import ElasticIntegration
            self.register(ElasticIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Elastic integration: {e}')
        
        try:
            from .handlers.syslog import SyslogIntegration
            self.register(SyslogIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Syslog integration: {e}')
        
        # Monitoring Integrations
        try:
            from .handlers.prometheus import PrometheusIntegration
            self.register(PrometheusIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Prometheus integration: {e}')
        
        try:
            from .handlers.grafana import GrafanaIntegration
            self.register(GrafanaIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Grafana integration: {e}')
        
        try:
            from .handlers.newrelic import NewRelicIntegration
            self.register(NewRelicIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load New Relic integration: {e}')
        
        try:
            from .handlers.nagios import NagiosIntegration
            self.register(NagiosIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Nagios integration: {e}')
        
        # Alerting Integrations
        try:
            from .handlers.pagerduty import PagerDutyIntegration
            self.register(PagerDutyIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load PagerDuty integration: {e}')
        
        try:
            from .handlers.opsgenie import OpsgenieIntegration
            self.register(OpsgenieIntegration)
        except ImportError as e:
            logger.warning(f'Failed to load Opsgenie integration: {e}')
        
        logger.info(f'Registered {len(self._integrations)} integrations')
    
    def sync_to_database(self):
        """
        Sync all registered integrations to the database.
        
        This ensures the integrations table is up-to-date with all
        available integrations from the registry.
        """
        from app.models import get_db_connection
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            for integration_class in self._integrations.values():
                metadata = integration_class.get_metadata()
                
                # Serialize capabilities and config schema
                capabilities = json.dumps([c.value for c in metadata.capabilities])
                config_schema = json.dumps([
                    {
                        'name': field.name,
                        'label': field.label,
                        'type': field.type,
                        'required': field.required,
                        'default': field.default,
                        'description': field.description,
                        'placeholder': field.placeholder,
                        'sensitive': field.sensitive,
                        'options': field.options,
                        'validation': field.validation,
                        'depends_on': field.depends_on,
                    }
                    for field in metadata.config_schema
                ])
                
                # Insert or update integration in database
                cursor.execute("""
                    INSERT INTO integrations (
                        id, name, description, category, icon, color, version, vendor,
                        auth_type, capabilities, config_schema, docs_url, support_url,
                        beta, deprecated, enabled, display_order
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        description = excluded.description,
                        category = excluded.category,
                        icon = excluded.icon,
                        color = excluded.color,
                        version = excluded.version,
                        vendor = excluded.vendor,
                        auth_type = excluded.auth_type,
                        capabilities = excluded.capabilities,
                        config_schema = excluded.config_schema,
                        docs_url = excluded.docs_url,
                        support_url = excluded.support_url,
                        beta = excluded.beta,
                        deprecated = excluded.deprecated,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    metadata.id,
                    metadata.name,
                    metadata.description,
                    metadata.category.value,
                    metadata.icon,
                    metadata.color,
                    metadata.version,
                    metadata.vendor,
                    metadata.auth_type.value,
                    capabilities,
                    config_schema,
                    metadata.docs_url,
                    metadata.support_url,
                    1 if metadata.beta else 0,
                    1 if metadata.deprecated else 0,
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f'Synced {len(self._integrations)} integrations to database')
            
        except Exception as e:
            logger.error(f'Failed to sync integrations to database: {e}')
    
    def register(self, integration_class: Type[IntegrationBase]) -> bool:
        """
        Register an integration handler.
        
        Args:
            integration_class: The integration class to register.
            
        Returns:
            True if registration was successful.
        """
        try:
            metadata = integration_class.get_metadata()
            
            if metadata.id in self._integrations:
                logger.warning(f'Integration {metadata.id} already registered, replacing')
            
            self._integrations[metadata.id] = integration_class
            logger.debug(f'Registered integration: {metadata.id} ({metadata.name})')
            return True
            
        except Exception as e:
            logger.error(f'Failed to register integration: {e}')
            return False
    
    def unregister(self, integration_id: str) -> bool:
        """
        Unregister an integration.
        
        Args:
            integration_id: The ID of the integration to unregister.
            
        Returns:
            True if unregistration was successful.
        """
        if integration_id in self._integrations:
            del self._integrations[integration_id]
            logger.info(f'Unregistered integration: {integration_id}')
            return True
        return False
    
    def get(self, integration_id: str) -> Optional[Type[IntegrationBase]]:
        """
        Get an integration class by ID.
        
        Args:
            integration_id: The ID of the integration.
            
        Returns:
            The integration class or None if not found.
        """
        return self._integrations.get(integration_id)
    
    def get_metadata(self, integration_id: str) -> Optional[IntegrationMetadata]:
        """
        Get integration metadata by ID.
        
        Args:
            integration_id: The ID of the integration.
            
        Returns:
            The integration metadata or None if not found.
        """
        integration = self.get(integration_id)
        if integration:
            return integration.get_metadata()
        return None
    
    def list_all(self) -> List[IntegrationMetadata]:
        """
        List all registered integrations.
        
        Returns:
            List of integration metadata.
        """
        return [cls.get_metadata() for cls in self._integrations.values()]
    
    def list_by_category(self, category: IntegrationCategory) -> List[IntegrationMetadata]:
        """
        List integrations by category.
        
        Args:
            category: The category to filter by.
            
        Returns:
            List of integration metadata in the category.
        """
        return [
            metadata for metadata in self.list_all()
            if metadata.category == category
        ]
    
    def search(self, query: str) -> List[IntegrationMetadata]:
        """
        Search integrations by name or description.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching integration metadata.
        """
        query_lower = query.lower()
        return [
            metadata for metadata in self.list_all()
            if query_lower in metadata.name.lower() or 
               query_lower in metadata.description.lower()
        ]
    
    def get_categories(self) -> Dict[str, int]:
        """
        Get a count of integrations per category.
        
        Returns:
            Dictionary mapping category to count.
        """
        categories: Dict[str, int] = {}
        for metadata in self.list_all():
            cat = metadata.category.value
            categories[cat] = categories.get(cat, 0) + 1
        return categories
    
    def create_instance(self, integration_id: str, connection_id: str,
                       config: dict, credentials: dict) -> Optional[IntegrationBase]:
        """
        Create an instance of an integration.
        
        Args:
            integration_id: The ID of the integration.
            connection_id: Unique ID for this connection instance.
            config: Configuration for the integration.
            credentials: Decrypted credentials.
            
        Returns:
            An integration instance or None if not found.
        """
        integration_class = self.get(integration_id)
        if not integration_class:
            logger.error(f'Integration not found: {integration_id}')
            return None
        
        try:
            return integration_class(
                connection_id=connection_id,
                config=config,
                credentials=credentials
            )
        except Exception as e:
            logger.error(f'Failed to create integration instance: {e}')
            return None


def get_integration_registry() -> IntegrationRegistry:
    """Get the singleton IntegrationRegistry instance."""
    return IntegrationRegistry()
