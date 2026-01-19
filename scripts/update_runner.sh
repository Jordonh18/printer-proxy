#!/bin/bash
#
# Update Runner - Triggered by systemd when printer-proxy-update.service starts
#
# This script reads the update request file and executes the update via APT.
# It runs in its own systemd service, completely separate from printer-proxy.
#
set -euo pipefail

readonly REQUEST_FILE="/var/lib/printer-proxy/update_request.json"
readonly STATE_FILE="/var/lib/printer-proxy/update_state.json"
readonly LOG_FILE="/var/log/printer-proxy/update.log"
readonly HELPER_SCRIPT="/opt/printer-proxy/scripts/update_helper.sh"
readonly DATA_DIR="/var/lib/printer-proxy"

# Ensure required directories exist
mkdir -p "$DATA_DIR" 2>/dev/null || true
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

update_state() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
    
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{}' > "$STATE_FILE"
    fi
    
    python3 -c "
import json
import os
try:
    with open('$STATE_FILE', 'r') as f:
        data = json.load(f)
    data['$key'] = $value
    temp_file = '$STATE_FILE' + '.tmp'
    with open(temp_file, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(temp_file, '$STATE_FILE')
except Exception as e:
    print(f'Failed to update state: {e}')
" 2>&1 | tee -a "$LOG_FILE" || true
}

mark_failed() {
    local error="$1"
    log "ERROR" "$error"
    update_state "update_in_progress" "false"
    update_state "update_error" "\"$error\""
}

# Check if request file exists
if [[ ! -f "$REQUEST_FILE" ]]; then
    log "ERROR" "No update request file found at $REQUEST_FILE"
    exit 1
fi

# Parse the request file (just need version for logging with APT system)
log "INFO" "Reading update request..."
VERSION=$(python3 -c "import json; print(json.load(open('$REQUEST_FILE')).get('version', 'latest'))" 2>/dev/null) || VERSION="latest"

log "INFO" "Starting APT-based update to version $VERSION"

# Run the update helper script
if [[ -x "$HELPER_SCRIPT" ]]; then
    exec "$HELPER_SCRIPT" upgrade
else
    mark_failed "Update helper script not found or not executable"
    exit 1
fi
