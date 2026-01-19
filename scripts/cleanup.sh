#!/bin/bash
#
# Clean up all active redirects
# Use this script during shutdown or emergency cleanup
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
HELPER_SCRIPT="$SCRIPT_DIR/network_helper.sh"

# Default interface
INTERFACE="${PROXY_INTERFACE:-eth0}"

echo "=== Printer Proxy Cleanup ==="
echo ""

# Get all secondary IPs
echo "Removing secondary IPs from $INTERFACE..."
for ip in $(sudo "$HELPER_SCRIPT" list-ips "$INTERFACE"); do
    echo "  Removing IP: $ip"
    sudo "$HELPER_SCRIPT" remove-ip "$INTERFACE" "$ip" || true
done

# Flush NAT rules (be careful - this removes ALL nat rules)
echo ""
echo "Flushing NAT rules..."
sudo iptables -t nat -F PREROUTING 2>/dev/null || true
sudo iptables -t nat -F POSTROUTING 2>/dev/null || true

# Remove FORWARD rules for printer ports
echo "Cleaning FORWARD rules for common printer ports..."
for port in 9100 631 515; do
    sudo iptables -D FORWARD -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
done

echo ""
echo "Cleanup complete."
echo "Note: Database records of active redirects may still exist."
echo "Run the web application to synchronize state."
