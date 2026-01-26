"""
Services module for Continuum

This module provides all business logic and background services.
Services are organized by domain.
"""

# Network management
from app.services.network_manager import NetworkManager, get_network_manager

# Discovery service
from app.services.discovery import (
    PrinterDiscovery,
    get_discovery,
    DiscoveredPrinter,
)

# Health check service
from app.services.health_check import (
    HealthCheckResult,
    HealthChecker,
    HealthCheckScheduler,
    get_scheduler,
    start_health_checks,
    stop_health_checks,
    init_health_check_tables,
    get_status as get_health_status,
    get_history as get_health_history,
)

# Job monitoring
from app.services.job_monitor import (
    PrinterState,
    JobMonitor,
    get_job_monitor,
    init_job_monitor,
)

# Printer registry
from app.services.printer_registry import (
    PrinterRegistry,
    get_registry,
    Printer,
)

# Notification services
from app.services.notification_sender import (
    NotificationChannel,
    SMTPNotificationChannel,
    NotificationManager as NotificationSender,
    get_notification_manager as get_notification_sender,
    notify,
    notify_printer_offline,
    notify_printer_online,
    notify_user_login,
    notify_printer_health_alert,
    notify_job_failure,
    notify_redirect_created,
    send_weekly_report,
    WeeklyReportScheduler,
    start_weekly_reports,
    stop_weekly_reports,
)
from app.services.notification_manager import (
    Notification,
    NotificationManager,
    get_notification_manager,
)

# Updater service
from app.services.updater import (
    UpdateManager,
    get_update_manager,
    init_updater,
)

# Workflow engine
from app.services.workflow_engine import (
    WorkflowEngine,
    get_workflow_engine,
    trigger_workflows_for_event,
)

# Event logs
from app.services.event_logs import (
    PrinterEvent,
    categorize_hp_event_code,
    get_logs,
    get_errors,
)

# Job history
from app.services.job_history import (
    JobHistoryEntry,
    get_history as get_job_history,
    add as add_job_to_history,
    get_stats as get_job_history_stats,
)

# Print queue
from app.services.print_queue import (
    PrintJob,
    PrintQueueCollector,
    get_queue_collector,
    get_queue,
)

# Printer stats
from app.services.printer_stats import (
    PrinterStats,
    PrinterStatsCollector,
    get_collector as get_stats_collector,
    get_stats,
    get_toner_levels,
)

# Settings
from app.services.settings import (
    SettingsManager,
    get_settings_manager,
    init_settings_table,
)


__all__ = [
    # Network
    'NetworkManager',
    'get_network_manager',
    # Discovery
    'PrinterDiscovery',
    'get_discovery',
    'DiscoveredPrinter',
    # Health check
    'HealthCheckResult',
    'HealthChecker',
    'HealthCheckScheduler',
    'get_scheduler',
    'start_health_checks',
    'stop_health_checks',
    'init_health_check_tables',
    'get_health_status',
    'get_health_history',
    # Job monitor
    'PrinterState',
    'JobMonitor',
    'get_job_monitor',
    'init_job_monitor',
    # Printer registry
    'PrinterRegistry',
    'get_registry',
    'Printer',
    # Notifications (notification_sender)
    'NotificationChannel',
    'SMTPNotificationChannel',
    'NotificationSender',
    'get_notification_sender',
    'notify',
    'notify_printer_offline',
    'notify_printer_online',
    'notify_user_login',
    'notify_printer_health_alert',
    'notify_job_failure',
    'notify_redirect_created',
    'send_weekly_report',
    'WeeklyReportScheduler',
    'start_weekly_reports',
    'stop_weekly_reports',
    # Notifications (notification_manager)
    'Notification',
    'NotificationManager',
    'get_notification_manager',
    # Updater
    'UpdateManager',
    'get_update_manager',
    'init_updater',
    # Workflow
    'WorkflowEngine',
    'get_workflow_engine',
    'trigger_workflows_for_event',
    # Event logs
    'PrinterEvent',
    'categorize_hp_event_code',
    'get_logs',
    'get_errors',
    # Job history
    'JobHistoryEntry',
    'get_job_history',
    'add_job_to_history',
    'get_job_history_stats',
    # Print queue
    'PrintJob',
    'PrintQueueCollector',
    'get_queue_collector',
    'get_queue',
    # Printer stats
    'PrinterStats',
    'PrinterStatsCollector',
    'get_stats_collector',
    'get_stats',
    'get_toner_levels',
    # Settings
    'SettingsManager',
    'get_settings_manager',
    'init_settings_table',
]
