#!/bin/bash
#
# Printer Proxy Network Helper Script
# 
# This script performs privileged network operations for the printer proxy.
# It should be called via sudo with a strict allowlist in sudoers.
#
# Usage:
#   network_helper.sh add-ip <interface> <ip>
#   network_helper.sh remove-ip <interface> <ip>
#   network_helper.sh add-nat <source_ip> <target_ip> <port>
#   network_helper.sh remove-nat <source_ip> <target_ip> <port>
#   network_helper.sh list-ips <interface>
#   network_helper.sh list-nat
#   network_helper.sh check-ip <ip>
#

set -euo pipefail

# Validate IP address format
validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Invalid IP address format: $ip" >&2
        exit 1
    fi
    
    # Check each octet
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            echo "Invalid IP address: $ip" >&2
            exit 1
        fi
    done
}

# Validate interface name (alphanumeric and limited special chars)
validate_interface() {
    local iface="$1"
    if [[ ! "$iface" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Invalid interface name: $iface" >&2
        exit 1
    fi
    
    # Check interface exists
    if ! ip link show "$iface" &>/dev/null; then
        echo "Interface does not exist: $iface" >&2
        exit 1
    fi
}

# Validate port number
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
        echo "Invalid port number: $port" >&2
        exit 1
    fi
}

# Add secondary IP to interface
add_ip() {
    local interface="$1"
    local ip="$2"
    
    validate_interface "$interface"
    validate_ip "$ip"
    
    # Check if IP already exists on the interface
    if ip addr show dev "$interface" | grep -q "inet $ip/"; then
        echo "IP $ip already exists on $interface"
        exit 0
    fi
    
    # Add IP with /32 prefix
    ip addr add "$ip/32" dev "$interface"
    
    # Ensure we respond to ARP requests for this IP
    # Send gratuitous ARP to update network caches
    if command -v arping &>/dev/null; then
        arping -c 3 -A -I "$interface" "$ip" &>/dev/null || true
    fi
    
    echo "Added IP $ip to $interface"
}

# Remove secondary IP from interface
remove_ip() {
    local interface="$1"
    local ip="$2"
    
    validate_interface "$interface"
    validate_ip "$ip"
    
    # Check if IP exists
    if ! ip addr show dev "$interface" | grep -q "inet $ip/"; then
        echo "IP $ip does not exist on $interface"
        exit 0
    fi
    
    # Remove IP
    ip addr del "$ip/32" dev "$interface" 2>/dev/null || \
    ip addr del "$ip/24" dev "$interface" 2>/dev/null || \
    ip addr del "$ip" dev "$interface" 2>/dev/null || true
    
    echo "Removed IP $ip from $interface"
}

# Add NAT/DNAT rule using iptables
add_nat() {
    local source_ip="$1"
    local target_ip="$2"
    local port="$3"
    
    validate_ip "$source_ip"
    validate_ip "$target_ip"
    validate_port "$port"
    
    # Enable IP forwarding if not already enabled
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Check if rule already exists
    if iptables -t nat -C PREROUTING -d "$source_ip" -p tcp --dport "$port" \
        -j DNAT --to-destination "$target_ip:$port" 2>/dev/null; then
        echo "NAT rule already exists"
        exit 0
    fi
    
    # Add DNAT rule for incoming traffic to the hijacked IP
    iptables -t nat -A PREROUTING -d "$source_ip" -p tcp --dport "$port" \
        -j DNAT --to-destination "$target_ip:$port"
    
    # Add FORWARD rule to allow the traffic
    iptables -A FORWARD -d "$target_ip" -p tcp --dport "$port" -j ACCEPT
    
    # Add SNAT/MASQUERADE for the return path
    iptables -t nat -A POSTROUTING -d "$target_ip" -p tcp --dport "$port" \
        -j MASQUERADE
    
    echo "Added NAT rule: $source_ip:$port -> $target_ip:$port"
}

# Remove NAT/DNAT rule
remove_nat() {
    local source_ip="$1"
    local target_ip="$2"
    local port="$3"
    
    validate_ip "$source_ip"
    validate_ip "$target_ip"
    validate_port "$port"
    
    # Remove DNAT rule
    iptables -t nat -D PREROUTING -d "$source_ip" -p tcp --dport "$port" \
        -j DNAT --to-destination "$target_ip:$port" 2>/dev/null || true
    
    # Remove FORWARD rule
    iptables -D FORWARD -d "$target_ip" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    
    # Remove MASQUERADE rule
    iptables -t nat -D POSTROUTING -d "$target_ip" -p tcp --dport "$port" \
        -j MASQUERADE 2>/dev/null || true
    
    echo "Removed NAT rule: $source_ip:$port -> $target_ip:$port"
}

# List secondary IPs on interface
list_ips() {
    local interface="$1"
    
    validate_interface "$interface"
    
    # Get all IPs except the primary
    ip addr show dev "$interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1
}

# List NAT rules
list_nat() {
    echo "=== PREROUTING (DNAT) Rules ==="
    iptables -t nat -L PREROUTING -n -v 2>/dev/null || echo "Unable to list PREROUTING rules"
    
    echo ""
    echo "=== POSTROUTING (SNAT/MASQUERADE) Rules ==="
    iptables -t nat -L POSTROUTING -n -v 2>/dev/null || echo "Unable to list POSTROUTING rules"
    
    echo ""
    echo "=== FORWARD Rules ==="
    iptables -L FORWARD -n -v 2>/dev/null || echo "Unable to list FORWARD rules"
}

# Check if IP is in use on the network
check_ip() {
    local ip="$1"
    
    validate_ip "$ip"
    
    # Use arping to check if IP is in use
    if command -v arping &>/dev/null; then
        if arping -c 2 -w 2 "$ip" 2>/dev/null | grep -q "reply from"; then
            echo "in-use"
        else
            echo "available"
        fi
    else
        # Fallback to ping
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            echo "in-use"
        else
            echo "available"
        fi
    fi
}

# Main command dispatcher
case "${1:-}" in
    add-ip)
        if [[ $# -ne 3 ]]; then
            echo "Usage: $0 add-ip <interface> <ip>" >&2
            exit 1
        fi
        add_ip "$2" "$3"
        ;;
    remove-ip)
        if [[ $# -ne 3 ]]; then
            echo "Usage: $0 remove-ip <interface> <ip>" >&2
            exit 1
        fi
        remove_ip "$2" "$3"
        ;;
    add-nat)
        if [[ $# -ne 4 ]]; then
            echo "Usage: $0 add-nat <source_ip> <target_ip> <port>" >&2
            exit 1
        fi
        add_nat "$2" "$3" "$4"
        ;;
    remove-nat)
        if [[ $# -ne 4 ]]; then
            echo "Usage: $0 remove-nat <source_ip> <target_ip> <port>" >&2
            exit 1
        fi
        remove_nat "$2" "$3" "$4"
        ;;
    list-ips)
        if [[ $# -ne 2 ]]; then
            echo "Usage: $0 list-ips <interface>" >&2
            exit 1
        fi
        list_ips "$2"
        ;;
    list-nat)
        list_nat
        ;;
    check-ip)
        if [[ $# -ne 2 ]]; then
            echo "Usage: $0 check-ip <ip>" >&2
            exit 1
        fi
        check_ip "$2"
        ;;
    *)
        echo "Unknown command: ${1:-}" >&2
        echo "Available commands: add-ip, remove-ip, add-nat, remove-nat, list-ips, list-nat, check-ip" >&2
        exit 1
        ;;
esac
