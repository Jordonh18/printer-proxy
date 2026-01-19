#!/bin/bash
#
# Update Helper Script for Printer Proxy (APT-based)
# ===================================================
#
# SECURITY MODEL:
# - This script runs as root (via sudo from printer-proxy user)
# - Updates are performed via APT from the configured repository
# - Script runs as a SEPARATE PROCESS from the main app
#
set -euo pipefail

# Configuration
readonly LOCK_FILE="/tmp/printer-proxy-update.lock"
readonly STATE_FILE="/var/lib/printer-proxy/update_state.json"
readonly LOG_FILE="/var/log/printer-proxy/update.log"
readonly PACKAGE_NAME="printer-proxy"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true

# Cleanup function
cleanup() {
    local exit_code=$?
    rm -f "$LOCK_FILE"
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Update failed with exit code $exit_code"
        mark_failed "Update process failed"
    fi
}
trap cleanup EXIT

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Update state file helper
update_state() {
    local key="$1"
    local value="$2"
    if [[ -f "$STATE_FILE" ]]; then
        python3 -c "
import json
try:
    with open('$STATE_FILE', 'r') as f:
        data = json.load(f)
    data['$key'] = $value
    with open('$STATE_FILE', 'w') as f:
        json.dump(data, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    fi
}

mark_failed() {
    local error="$1"
    log "ERROR" "$error"
    update_state "update_in_progress" "false"
    update_state "update_error" "\"$error\""
}

mark_success() {
    update_state "update_in_progress" "false"
    update_state "update_error" "null"
}

# Acquire lock
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "ERROR" "Another update is already running (PID: $pid)"
            exit 1
        fi
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
    log "INFO" "Acquired update lock (PID: $$)"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root" >&2
        exit 1
    fi
}

# Perform APT update
do_apt_update() {
    log "INFO" "Running apt update..."
    if ! apt-get update -qq 2>&1 | tee -a "$LOG_FILE"; then
        log "WARN" "apt update had issues, continuing anyway..."
    fi
}

# Perform the upgrade
do_upgrade() {
    log "INFO" "Upgrading $PACKAGE_NAME via APT..."
    
    # Get current version
    local current_version
    current_version=$(dpkg-query --showformat='${Version}' --show "$PACKAGE_NAME" 2>/dev/null || echo "unknown")
    log "INFO" "Current version: $current_version"
    
    # Stop the service first
    log "INFO" "Stopping printer-proxy service..."
    systemctl stop printer-proxy.service 2>/dev/null || true
    
    # Perform the upgrade
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$PACKAGE_NAME" 2>&1 | tee -a "$LOG_FILE"; then
        log "INFO" "APT upgrade completed"
    else
        log "ERROR" "APT upgrade failed"
        # Try to restart service anyway
        systemctl start printer-proxy.service 2>/dev/null || true
        return 1
    fi
    
    # Get new version
    local new_version
    new_version=$(dpkg-query --showformat='${Version}' --show "$PACKAGE_NAME" 2>/dev/null || echo "unknown")
    log "INFO" "New version: $new_version"
    
    # Start the service
    log "INFO" "Starting printer-proxy service..."
    systemctl daemon-reload
    systemctl start printer-proxy.service
    
    # Verify service is running
    sleep 2
    if systemctl is-active --quiet printer-proxy.service; then
        log "INFO" "Service started successfully"
    else
        log "WARN" "Service may not have started correctly"
    fi
    
    mark_success
    log "INFO" "Update complete: $current_version -> $new_version"
    return 0
}

# Show current status
show_status() {
    echo "=== Printer Proxy Update Status ==="
    echo ""
    
    local installed_version
    installed_version=$(dpkg-query --showformat='${Version}' --show "$PACKAGE_NAME" 2>/dev/null || echo "not installed")
    echo "Installed version: $installed_version"
    
    local available_version
    available_version=$(apt-cache policy "$PACKAGE_NAME" 2>/dev/null | grep "Candidate:" | awk '{print $2}')
    echo "Available version: ${available_version:-unknown}"
    
    if [[ "$installed_version" != "$available_version" ]] && [[ -n "$available_version" ]] && [[ "$available_version" != "(none)" ]]; then
        echo ""
        echo "Update available!"
    else
        echo ""
        echo "You are on the latest version."
    fi
    
    echo ""
    if systemctl is-active --quiet printer-proxy.service; then
        echo "Service status: running"
    else
        echo "Service status: stopped"
    fi
}

# Main entry point
main() {
    case "${1:-}" in
        upgrade|update)
            check_root
            acquire_lock
            update_state "update_in_progress" "true"
            update_state "update_started_at" "\"$(date -Iseconds)\""
            do_apt_update
            do_upgrade
            ;;
        status)
            show_status
            ;;
        check)
            check_root
            do_apt_update
            show_status
            ;;
        *)
            echo "Usage: $0 {upgrade|update|status|check}"
            echo ""
            echo "Commands:"
            echo "  upgrade  - Upgrade printer-proxy to latest version"
            echo "  update   - Same as upgrade"
            echo "  status   - Show current version and available updates"
            echo "  check    - Update APT cache and show status"
            exit 1
            ;;
    esac
}

main "$@"
