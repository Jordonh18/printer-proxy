"""
Integration Handlers Package.

Contains implementations for specific integration providers.
"""

# Logging Integrations
from .splunk import SplunkIntegration
from .datadog import DatadogIntegration
from .elastic import ElasticIntegration
from .syslog import SyslogIntegration

# Monitoring Integrations
from .prometheus import PrometheusIntegration
from .grafana import GrafanaIntegration
from .newrelic import NewRelicIntegration
from .nagios import NagiosIntegration

# Alerting Integrations
from .pagerduty import PagerDutyIntegration
from .opsgenie import OpsgenieIntegration

__all__ = [
    # Logging
    'SplunkIntegration',
    'DatadogIntegration',
    'ElasticIntegration',
    'SyslogIntegration',
    # Monitoring
    'PrometheusIntegration',
    'GrafanaIntegration',
    'NewRelicIntegration',
    'NagiosIntegration',
    # Alerting
    'PagerDutyIntegration',
    'OpsgenieIntegration',
]
