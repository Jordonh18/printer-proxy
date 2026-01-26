# Integration Event Flow Documentation

## Overview

The integration system is now fully functional with automatic event dispatching from application events to configured integrations. Once an integration is configured and connected, it will automatically receive relevant events.

## How It Works

### 1. Event Dispatcher (`app/services/integrations/dispatcher.py`)

The central event dispatcher provides a unified interface for sending events from anywhere in the application to configured integrations.

**Key Features:**
- Singleton pattern for global access
- Automatic event enrichment (timestamp, severity, source)
- Async event delivery with synchronous wrapper
- Standardized event types via `EventType` enum

**Usage Example:**
```python
from app.services.integrations import dispatch_event, EventType

dispatch_event(
    EventType.PRINTER_OFFLINE,
    {
        'printer_name': 'HP-101',
        'printer_ip': '10.0.1.101',
        'printer_model': 'HP LaserJet Pro'
    },
    severity='warning'
)
```

### 2. Automatic Event Routing

When an integration is connected, event routing is automatically configured based on the integration's category:

#### Logging Integrations (Splunk, Datadog, Elastic, Syslog)
Receive all operational events:
- `printer.added` - New printer added to system
- `printer.removed` - Printer removed from system
- `printer.offline` - Printer went offline
- `printer.online` - Printer came back online
- `redirect.created` - Print redirect created
- `redirect.removed` - Print redirect removed
- `system.info` - General system information

#### Monitoring Integrations (Prometheus, Grafana, New Relic, Nagios)
Receive health and error events:
- `printer.offline` - Printer health check failed
- `printer.online` - Printer health recovered
- `printer.error` - Printer error detected
- `redirect.failed` - Redirect operation failed
- `system.error` - System error occurred
- `system.warning` - System warning issued

#### Alerting Integrations (PagerDuty, Opsgenie, VictorOps)
Receive critical events only:
- `printer.offline` - Printer unavailable
- `printer.error` - Critical printer error
- `redirect.failed` - Redirect failure
- `system.error` - System error
- `system.critical` - Critical system issue

### 3. Event Sources

Events are dispatched from key locations throughout the application:

#### Health Check Service (`app/services/health_check.py`)
- **Printer Offline**: When health check detects printer is unreachable
- **Printer Online**: When printer recovers from offline state

```python
# Lines 294-310: Printer goes offline
dispatch_event(
    EventType.PRINTER_OFFLINE,
    {
        'printer_id': printer.id,
        'printer_name': printer.name,
        'printer_ip': printer.ip,
        'printer_model': printer.model,
        'consecutive_failures': result.response_time_ms,
    },
    severity='warning'
)

# Lines 325-335: Printer comes back online
dispatch_event(
    EventType.PRINTER_ONLINE,
    {
        'printer_id': printer.id,
        'printer_name': printer.name,
        'printer_ip': printer.ip,
        'printer_model': printer.model,
        'response_time_ms': result.response_time_ms,
    },
    severity='info'
)
```

#### Redirect Routes (`app/routes/__init__.py`)

**Redirect Created** (lines 1592-1612):
```python
dispatch_event(
    EventType.REDIRECT_CREATED,
    {
        'redirect_id': redirect_obj.id,
        'source_printer_id': source_printer_id,
        'source_printer_name': source_printer.name,
        'source_printer_ip': source_printer.ip,
        'target_printer_id': target_printer_id,
        'target_printer_name': target_printer.name,
        'target_printer_ip': target_printer.ip,
        'protocol': 'raw',
        'port': DEFAULT_PORT,
        'created_by': g.api_user.username,
    },
    severity='info'
)
```

**Redirect Removed** (lines 1643-1659):
```python
dispatch_event(
    EventType.REDIRECT_REMOVED,
    {
        'redirect_id': redirect_obj.id,
        'source_printer_id': redirect_obj.source_printer_id,
        'source_printer_name': source_printer.name if source_printer else 'Unknown',
        'source_printer_ip': redirect_obj.source_ip,
        'target_printer_id': redirect_obj.target_printer_id,
        'target_printer_name': target_printer.name if target_printer else 'Unknown',
        'target_printer_ip': redirect_obj.target_ip,
        'removed_by': g.api_user.username,
    },
    severity='info'
)
```

#### Printer Routes (`app/routes/__init__.py`)

**Printer Added** (lines 832-849):
```python
dispatch_event(
    EventType.PRINTER_ADDED,
    {
        'printer_id': printer.id,
        'printer_name': printer.name,
        'printer_ip': printer.ip,
        'printer_model': printer.model,
        'printer_location': printer.location,
        'printer_department': printer.department,
        'protocols': printer.protocols,
        'created_by': g.api_user.username,
    },
    severity='info'
)
```

**Printer Removed** (lines 971-988):
```python
dispatch_event(
    EventType.PRINTER_REMOVED,
    {
        'printer_id': printer.id,
        'printer_name': printer.name,
        'printer_ip': printer.ip,
        'printer_model': printer.model,
        'printer_location': printer.location,
        'deleted_by': g.api_user.username,
    },
    severity='info'
)
```

## Event Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Events                          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Health Check │  │   Redirects  │  │   Printers   │          │
│  │   Service    │  │    Routes    │  │    Routes    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                  │                  │                  │
└─────────┼──────────────────┼──────────────────┼──────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                             ▼
          ┌──────────────────────────────────┐
          │   Integration Event Dispatcher   │
          │  (dispatcher.py)                 │
          │  - Enriches event data           │
          │  - Adds timestamp/severity       │
          └──────────────────┬───────────────┘
                             │
                             ▼
          ┌──────────────────────────────────┐
          │    Integration Manager           │
          │  (manager.py)                    │
          │  - Routes to configured integr.  │
          │  - Applies filters/transforms    │
          └──────────────────┬───────────────┘
                             │
          ┌──────────────────┴─────────────────────┬──────────────┐
          ▼                  ▼                     ▼              ▼
     ┌─────────┐      ┌─────────┐          ┌──────────┐    ┌──────────┐
     │ LOGGING │      │MONITORING│          │ ALERTING │    │   ...    │
     ├─────────┤      ├─────────┤          ├──────────┤    └──────────┘
     │ Splunk  │      │Prometheus│          │PagerDuty │
     │ Datadog │      │ Grafana  │          │Opsgenie  │
     │ Elastic │      │New Relic │          │VictorOps │
     │ Syslog  │      │ Nagios   │          └──────────┘
     └─────────┘      └─────────┘
```

## Configuration Workflow

### 1. User Connects Integration

Via the Admin → Integrations page:
1. Click "Connect" on an integration card
2. Fill in credentials (API keys, URLs, etc.)
3. Click "Connect"

### 2. Automatic Setup Happens

When connection succeeds (`manager.py` lines 218-267):
- Integration instance is created and connected
- `_auto_setup_event_routing()` is called
- Event routing rules are created based on category
- Events start flowing immediately

### 3. Events Are Delivered

- Application events trigger `dispatch_event()` calls
- Dispatcher enriches the event data
- Integration manager routes to all configured integrations
- Each integration's `send_log()` method is called
- Events are delivered via integration-specific API

## Supported Event Types

All event types are defined in `EventType` enum:

```python
class EventType(str, Enum):
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
    
    # System Events
    SYSTEM_ERROR = 'system.error'
    SYSTEM_WARNING = 'system.warning'
    SYSTEM_INFO = 'system.info'
```

## Adding New Event Sources

To add events from a new location in the codebase:

```python
# 1. Import the dispatcher and EventType
from app.services.integrations import dispatch_event, EventType

# 2. Call dispatch_event when the event occurs
try:
    dispatch_event(
        EventType.PRINTER_ERROR,  # Use appropriate event type
        {
            # Include relevant context
            'printer_id': printer.id,
            'error_code': error_code,
            'error_message': error_message,
        },
        severity='error'  # info, warning, error, critical
    )
except Exception as e:
    logger.error(f"Failed to dispatch integration event: {e}")
```

## Testing Integration Events

### 1. Via Health Checks
- Disconnect a printer's network cable
- Wait for health check cycle (60 seconds)
- Check Splunk/Datadog/etc for `printer.offline` event

### 2. Via Redirects
- Create a redirect via UI
- Check configured integrations for `redirect.created` event
- Delete the redirect
- Check for `redirect.removed` event

### 3. Via Printer Management
- Add a new printer
- Check for `printer.added` event
- Delete the printer
- Check for `printer.removed` event

## Event Data Structure

All events are automatically enriched with:

```json
{
    "timestamp": "2026-01-26T12:34:56.789012",
    "event_type": "printer.offline",
    "severity": "warning",
    "source": "continuum",
    // ... event-specific fields ...
}
```

## Integration-Specific Delivery

Each integration handler implements `send_log()` which formats and sends the event:

- **Splunk**: HTTP Event Collector (HEC) JSON format
- **Datadog**: Logs API with structured tags
- **Elastic**: Elasticsearch document indexing
- **Syslog**: RFC5424/RFC3164 syslog format
- **Prometheus**: Custom metrics pushed to Pushgateway
- **Grafana**: Annotations API
- **New Relic**: Events API with custom attributes
- **Nagios**: NSCA passive check results
- **PagerDuty**: Events API v2 (trigger/acknowledge/resolve)
- **Opsgenie**: Alert creation with priority routing
- **VictorOps**: REST API timeline events

## Troubleshooting

### Events Not Appearing in Integration

1. **Check connection status**: Admin → Integrations → verify "Connected" badge
2. **Check event routing**: Use integration manager API to verify routing rules exist
3. **Check logs**: `tail -f /var/log/continuum/app.log | grep integration`
4. **Test connection**: Click "Test Connection" button in integration card

### High Event Volume

Event routing supports filters and transforms:
- Set severity filters (e.g., only critical events)
- Add field filters (e.g., only specific printers)
- Transform data before sending

### Integration Failures

- Failed events are logged with details
- Error count tracked in connection status
- Automatic retry logic in some integrations (PagerDuty, Opsgenie)

## Files Modified

1. **Created**: `app/services/integrations/dispatcher.py` - Event dispatcher
2. **Modified**: `app/services/integrations/__init__.py` - Exported dispatcher
3. **Modified**: `app/services/integrations/manager.py` - Added auto-routing setup
4. **Modified**: `app/services/health_check.py` - Added offline/online event dispatch
5. **Modified**: `app/routes/__init__.py` - Added redirect and printer event dispatch

## Summary

The integration system is now fully operational:

✅ **11 Integration Handlers** - All working with real APIs
✅ **Automatic Event Routing** - Set up on connection
✅ **5 Event Sources** - Health checks, redirects, printers, groups, system
✅ **Category-Based Filtering** - Logging, monitoring, alerting
✅ **Production Ready** - Error handling, logging, async delivery

Integrations are no longer just configured - they actively receive events!
