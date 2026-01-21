# Workflow Variables & Data Flow System

This document explains how data flows between nodes in the Printer Proxy workflow engine.

## Overview

The workflow engine supports a **key-based variable system** that allows nodes to:
1. **Output data** - Each node can produce outputs that downstream nodes can access
2. **Reference variables** - Use `{{variable_name}}` syntax to reference data from upstream nodes
3. **Mix static and dynamic values** - Some inputs support dropdown selection while still allowing variable references

## Variable Syntax

Variables use double curly braces: `{{variable_name}}`

### Basic Variables
- `{{printer_id}}` - The ID of a printer
- `{{printer_name}}` - The name of a printer
- `{{timestamp}}` - ISO timestamp of the event

### Nested Variables
- `{{source_printer.name}}` - Access nested object properties
- `{{source_printer.ip}}` - Printer IP address
- `{{payload.custom_field}}` - Access webhook payload fields

## Node Outputs

### Trigger Nodes

#### `trigger.event` - Event Trigger
Fires when a printer or system event occurs.

| Output Key | Type | Description |
|------------|------|-------------|
| `event_type` | string | Type of event (printer_offline, printer_online, etc.) |
| `printer_id` | string | ID of the affected printer |
| `printer_name` | string | Name of the affected printer |
| `printer_ip` | string | IP address of the printer |
| `timestamp` | string | ISO timestamp when event occurred |

#### `trigger.health_change` - Health Change
Fires when a printer's health state changes.

| Output Key | Type | Description |
|------------|------|-------------|
| `printer_id` | string | ID of the printer |
| `printer_name` | string | Name of the printer |
| `printer_ip` | string | IP address of the printer |
| `previous_state` | string | Previous health state (online/offline) |
| `new_state` | string | New health state (online/offline) |
| `timestamp` | string | ISO timestamp of state change |

#### `trigger.webhook` - Webhook Trigger
Fires when an external webhook is received.

| Output Key | Type | Description |
|------------|------|-------------|
| `payload` | object | Full JSON payload from the webhook |
| `headers` | object | HTTP headers from the request |
| `timestamp` | string | ISO timestamp of receipt |

#### `trigger.schedule` - Schedule Trigger
Fires on a cron schedule.

| Output Key | Type | Description |
|------------|------|-------------|
| `scheduled_time` | string | Scheduled execution time |
| `actual_time` | string | Actual execution time |
| `timestamp` | string | ISO timestamp |

#### `trigger.queue_threshold` - Queue Threshold
Fires when print queue exceeds threshold.

| Output Key | Type | Description |
|------------|------|-------------|
| `printer_id` | string | ID of the printer |
| `printer_name` | string | Name of the printer |
| `queue_count` | number | Current jobs in queue |
| `threshold` | number | Configured threshold |
| `timestamp` | string | ISO timestamp |

### Action Nodes

#### `action.redirect` - Activate Redirect
Creates a printer redirect. Accepts dynamic source printer.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `source_printer_id` | string | ✅ Yes | Use `{{printer_id}}` or select from dropdown |
| `target_printer_id` | string | ✅ Yes | Target printer for redirect |
| `port` | number | ❌ No | Port number (default 9100) |

| Output Key | Type | Description |
|------------|------|-------------|
| `redirect_id` | string | ID of created redirect |
| `source_printer_id` | string | Source printer ID |
| `source_printer_name` | string | Source printer name |
| `source_printer_ip` | string | Source printer IP |
| `target_printer_id` | string | Target printer ID |
| `target_printer_name` | string | Target printer name |
| `target_printer_ip` | string | Target printer IP |
| `success` | boolean | Whether redirect was created |

#### `action.redirect.disable` - Deactivate Redirect
Disables an active redirect.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `source_printer_id` | string | ✅ Yes | Printer with active redirect |

| Output Key | Type | Description |
|------------|------|-------------|
| `source_printer_id` | string | Source printer ID |
| `success` | boolean | Whether redirect was disabled |

#### `action.notify.inapp` - In-App Notification
Creates an in-app notification for all users.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `title` | string | ✅ Yes | Notification title |
| `message` | string | ✅ Yes | Notification message (supports variables) |
| `link` | string | ✅ Yes | Optional link URL |

**Example message:** `Traffic from {{printer_name}} redirected to {{target_printer_name}}`

#### `action.notify.email` - Send Email
Sends an email notification.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `to` | string | ✅ Yes | Recipient email address |
| `subject` | string | ✅ Yes | Email subject |
| `body` | string | ✅ Yes | Email body (supports variables) |

#### `action.audit` - Audit Log Entry
Records an entry to the audit log.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `action` | string | ✅ Yes | Action type for audit |
| `details` | string | ✅ Yes | Details message (supports variables) |

### Logic Nodes

#### `logic.condition` - Condition
Branches workflow based on a condition.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `field` | string | ✅ Yes | Field to evaluate |
| `operator` | string | ❌ No | equals, not_equals, contains, etc. |
| `value` | string | ✅ Yes | Value to compare |

| Output Handle | Description |
|---------------|-------------|
| `true` | Condition matched |
| `false` | Condition not matched |

#### `logic.switch` - Switch
Routes to different outputs based on value.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `field` | string | ✅ Yes | Field to switch on |
| `cases` | object | ❌ No | Case definitions |

### Transform Nodes

#### `transform.template` - Template
Renders a template with variables.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `template` | string | ✅ Yes | Template with {{variables}} |

| Output Key | Type | Description |
|------------|------|-------------|
| `result` | string | Rendered template output |

#### `transform.set_variable` - Set Variable
Sets a custom variable for downstream nodes.

| Input Key | Type | Dynamic | Description |
|-----------|------|---------|-------------|
| `name` | string | ❌ No | Variable name |
| `value` | string | ✅ Yes | Variable value |

| Output Key | Type | Description |
|------------|------|-------------|
| `[name]` | any | The variable you set |

## Example Workflows

### Auto-Redirect on Printer Failure

```
[Health Change] → [Activate Redirect] → [In-App Notification]
     ↓                    ↓                      ↓
  Outputs:             Inputs:               Inputs:
  - printer_id         - source_printer_id    - message: "Traffic from 
  - printer_name         = {{printer_id}}       {{source_printer_name}} 
  - printer_ip         - target_printer_id      redirected to 
                         = (dropdown)           {{target_printer_name}}"
```

**Health Change Node:**
- Configured to detect "offline" state for a specific printer
- When triggered, outputs: `printer_id`, `printer_name`, `printer_ip`

**Activate Redirect Node:**
- `source_printer_id`: Set to `{{printer_id}}` (from Health Change)
- `target_printer_id`: Selected from dropdown (static backup printer)
- After execution, outputs: `source_printer_name`, `target_printer_name`, `redirect_id`

**In-App Notification Node:**
- `message`: `Traffic from {{source_printer_name}} redirected to {{target_printer_name}}`
- Variables are resolved from the cumulative context

### Webhook Integration

```
[Webhook Trigger] → [Condition] → [Activate Redirect]
                        ↓ false
                   [Audit Log]
```

**Webhook Trigger:**
- Receives external payload with `printer_id` and `action` fields
- Outputs: `payload.printer_id`, `payload.action`, `headers`, `timestamp`

**Condition Node:**
- `field`: `{{payload.action}}`
- `operator`: `equals`
- `value`: `redirect`

## Accessing Variables in the UI

When editing a node in the workflow editor:

1. **Text fields** - Type `{{` to see available variables from upstream nodes
2. **Select fields** - Some dropdowns show a "Use Variable" toggle
3. **Template fields** - Full variable syntax support with auto-complete

## Context Accumulation

Variables accumulate as the workflow executes:

1. **Trigger fires** → Context contains trigger outputs
2. **Action 1 executes** → Context now includes trigger + action 1 outputs
3. **Action 2 executes** → Context includes trigger + action 1 + action 2 outputs

Each node can access all variables from nodes that executed before it in the flow.

## Debugging Variables

To debug what variables are available at any point:

1. Add an **Audit Log** node
2. Set details to: `Context: {{__debug__}}`
3. Check the audit log for full context dump

## Best Practices

1. **Use descriptive node labels** - Helps identify which node produced which output
2. **Test with real data** - Create test workflows to verify variable resolution
3. **Check for required variables** - Ensure upstream nodes provide needed data
4. **Use Set Variable nodes** - Create aliases for complex variable paths
