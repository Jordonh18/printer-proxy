#!/bin/bash
#
# Continuum Network Helper Script
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
#   network_helper.sh interface-info [interface]
#   network_helper.sh arp-table
#   network_helper.sh routing-info
#   network_helper.sh connection-stats <source_ip> <target_ip> <port>
#   network_helper.sh ping-test <ip>
#   network_helper.sh arp-probe <ip>
#   network_helper.sh tcp-test <ip> <port>
#   network_helper.sh re-announce-arp <interface> <ip>
#   network_helper.sh nat-rules-raw
#   network_helper.sh ip-addr-raw
#   network_helper.sh ip-route-raw
#   network_helper.sh ip-rule-raw
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
    
    # Get all IPs except the primary (first one)
    # Skip the first IP address which is the primary
    ip addr show dev "$interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | tail -n +2
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

# Get detailed interface information (JSON format)
interface_info() {
    local interface="${1:-}"
    
    # If no interface specified, get all interfaces
    if [[ -z "$interface" ]]; then
        # Get list of all non-loopback interfaces
        interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | cut -d'@' -f1)
    else
        validate_interface "$interface"
        interfaces="$interface"
    fi
    
    echo "["
    first=true
    for iface in $interfaces; do
        if [[ "$first" != true ]]; then
            echo ","
        fi
        first=false
        
        # Get interface details
        local state="down"
        local mac=""
        local mtu=""
        local speed=""
        local primary_ip=""
        local cidr=""
        local gateway=""
        local vlan=""
        
        # State (UP/DOWN)
        if ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
            state="up"
        elif ip link show "$iface" 2>/dev/null | grep -q "state DOWN"; then
            state="down"
        else
            state="unknown"
        fi
        
        # MAC address
        mac=$(ip link show "$iface" 2>/dev/null | awk '/link\/ether/ {print $2}')
        
        # MTU
        mtu=$(ip link show "$iface" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}')
        
        # Link speed (if available via ethtool)
        if command -v ethtool &>/dev/null; then
            speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/ {print $2}')
        fi
        
        # Primary IP and CIDR
        ip_info=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / && !/secondary/ {print $2; exit}')
        if [[ -n "$ip_info" ]]; then
            primary_ip="${ip_info%/*}"
            cidr="${ip_info#*/}"
        fi
        
        # Default gateway (if this interface is used)
        gateway=$(ip route show default 2>/dev/null | awk -v iface="$iface" '/dev/{if($5==iface) print $3}')
        
        # VLAN ID (from interface name like eth0.100)
        if [[ "$iface" =~ \.[0-9]+$ ]]; then
            vlan="${iface##*.}"
        fi
        
        cat <<EOF
  {
    "name": "$iface",
    "state": "$state",
    "mac": "$mac",
    "mtu": "$mtu",
    "speed": "${speed:-unknown}",
    "primary_ip": "$primary_ip",
    "cidr": "$cidr",
    "gateway": "$gateway",
    "vlan": "$vlan"
  }
EOF
    done
    echo "]"
}

# Get ARP/neighbour table (JSON format)
arp_table() {
    echo "["
    first=true
    
    # Use ip neigh show for ARP table
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        # Parse: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        local ip=$(echo "$line" | awk '{print $1}')
        local iface=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
        local mac=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')
        local state=$(echo "$line" | awk '{print $NF}')
        
        # Skip if no valid data
        [[ -z "$ip" || -z "$iface" ]] && continue
        
        if [[ "$first" != true ]]; then
            echo ","
        fi
        first=false
        
        cat <<EOF
  {
    "ip": "$ip",
    "mac": "${mac:-}",
    "interface": "$iface",
    "state": "$state"
  }
EOF
    done < <(ip neigh show 2>/dev/null)
    echo "]"
}

# Get routing information (JSON format)
routing_info() {
    # Check if IP forwarding is enabled
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    
    # Check if NAT is active (any rules in nat table)
    local nat_active="false"
    if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "DNAT"; then
        nat_active="true"
    fi
    
    # Check for policy routing (ip rules other than default)
    local policy_routing="false"
    if [[ $(ip rule show 2>/dev/null | wc -l) -gt 3 ]]; then
        policy_routing="true"
    fi
    
    # Get default route
    local default_route=$(ip route show default 2>/dev/null | head -1)
    local default_gw=$(echo "$default_route" | awk '{print $3}')
    local default_iface=$(echo "$default_route" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    
    cat <<EOF
{
  "ip_forwarding": $([ "$ip_forward" = "1" ] && echo "true" || echo "false"),
  "nat_enabled": $nat_active,
  "policy_routing": $policy_routing,
  "default_gateway": "$default_gw",
  "default_interface": "$default_iface"
}
EOF
}

# Get connection statistics for a redirect
connection_stats() {
    local source_ip="$1"
    local target_ip="$2"
    local port="$3"
    
    validate_ip "$source_ip"
    validate_ip "$target_ip"
    validate_port "$port"
    
    # Count established connections to target
    local conn_count=0
    if command -v ss &>/dev/null; then
        conn_count=$(ss -tn state established dst "$target_ip:$port" 2>/dev/null | wc -l)
        ((conn_count > 0)) && ((conn_count--))  # Subtract header line
    fi
    
    # Get byte counters from iptables (if available)
    local bytes=0
    local bytes_line=$(iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep "$source_ip" | grep "dpt:$port" | head -1)
    if [[ -n "$bytes_line" ]]; then
        bytes=$(echo "$bytes_line" | awk '{print $2}')
    fi
    
    cat <<EOF
{
  "source_ip": "$source_ip",
  "target_ip": "$target_ip",
  "port": $port,
  "active_connections": $conn_count,
  "bytes_forwarded": "$bytes"
}
EOF
}

# Ping test for diagnostics
ping_test() {
    local ip="$1"
    
    validate_ip "$ip"
    
    local result
    local rtt=""
    
    if ping -c 3 -W 2 "$ip" &>/dev/null; then
        result="success"
        rtt=$(ping -c 3 -W 2 "$ip" 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    else
        result="failed"
    fi
    
    cat <<EOF
{
  "ip": "$ip",
  "result": "$result",
  "rtt_ms": "${rtt:-null}"
}
EOF
}

# ARP probe for diagnostics
arp_probe() {
    local ip="$1"
    
    validate_ip "$ip"
    
    local result="no_response"
    local mac=""
    
    if command -v arping &>/dev/null; then
        local output=$(arping -c 2 -w 2 "$ip" 2>/dev/null)
        if echo "$output" | grep -q "reply from"; then
            result="response"
            mac=$(echo "$output" | grep "reply from" | head -1 | awk -F'[\\[\\]]' '{print $2}')
        fi
    else
        result="arping_not_available"
    fi
    
    cat <<EOF
{
  "ip": "$ip",
  "result": "$result",
  "mac": "$mac"
}
EOF
}

# TCP connection test for diagnostics
tcp_test() {
    local ip="$1"
    local port="$2"
    
    validate_ip "$ip"
    validate_port "$port"
    
    local result="failed"
    local latency=""
    
    # Use timeout and bash's /dev/tcp
    local start_time=$(date +%s%N)
    if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
        result="success"
        local end_time=$(date +%s%N)
        latency=$(( (end_time - start_time) / 1000000 ))  # Convert to ms
    fi
    
    cat <<EOF
{
  "ip": "$ip",
  "port": $port,
  "result": "$result",
  "latency_ms": ${latency:-null}
}
EOF
}

# Re-announce ARP for a claimed IP
re_announce_arp() {
    local interface="$1"
    local ip="$2"
    
    validate_interface "$interface"
    validate_ip "$ip"
    
    if command -v arping &>/dev/null; then
        # Send gratuitous ARP
        arping -c 3 -A -I "$interface" "$ip" &>/dev/null
        echo "ARP announcement sent for $ip on $interface"
    else
        echo "Error: arping not available" >&2
        exit 1
    fi
}

# Raw iptables NAT rules output
nat_rules_raw() {
    echo "# iptables -t nat -S"
    iptables -t nat -S 2>/dev/null || echo "Unable to list NAT rules"
}

# Raw ip addr output
ip_addr_raw() {
    echo "# ip addr show"
    ip addr show 2>/dev/null || echo "Unable to show addresses"
}

# Raw ip route output
ip_route_raw() {
    echo "# ip route show"
    ip route show 2>/dev/null || echo "Unable to show routes"
    echo ""
    echo "# ip route show table all | head -50"
    ip route show table all 2>/dev/null | head -50 || echo "Unable to show all routes"
}

# Raw ip rule output
ip_rule_raw() {
    echo "# ip rule show"
    ip rule show 2>/dev/null || echo "Unable to show rules"
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
    interface-info)
        # Optional interface argument
        interface_info "${2:-}"
        ;;
    arp-table)
        arp_table
        ;;
    routing-info)
        routing_info
        ;;
    connection-stats)
        if [[ $# -ne 4 ]]; then
            echo "Usage: $0 connection-stats <source_ip> <target_ip> <port>" >&2
            exit 1
        fi
        connection_stats "$2" "$3" "$4"
        ;;
    ping-test)
        if [[ $# -ne 2 ]]; then
            echo "Usage: $0 ping-test <ip>" >&2
            exit 1
        fi
        ping_test "$2"
        ;;
    arp-probe)
        if [[ $# -ne 2 ]]; then
            echo "Usage: $0 arp-probe <ip>" >&2
            exit 1
        fi
        arp_probe "$2"
        ;;
    tcp-test)
        if [[ $# -ne 3 ]]; then
            echo "Usage: $0 tcp-test <ip> <port>" >&2
            exit 1
        fi
        tcp_test "$2" "$3"
        ;;
    re-announce-arp)
        if [[ $# -ne 3 ]]; then
            echo "Usage: $0 re-announce-arp <interface> <ip>" >&2
            exit 1
        fi
        re_announce_arp "$2" "$3"
        ;;
    nat-rules-raw)
        nat_rules_raw
        ;;
    ip-addr-raw)
        ip_addr_raw
        ;;
    ip-route-raw)
        ip_route_raw
        ;;
    ip-rule-raw)
        ip_rule_raw
        ;;
    *)
        echo "Unknown command: ${1:-}" >&2
        echo "Available commands: add-ip, remove-ip, add-nat, remove-nat, list-ips, list-nat, check-ip, interface-info, arp-table, routing-info, connection-stats, ping-test, arp-probe, tcp-test, re-announce-arp, nat-rules-raw, ip-addr-raw, ip-route-raw, ip-rule-raw" >&2
        exit 1
        ;;
esac
