# Printer Proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://ubuntu.com/)

A network traffic redirection solution for network printers that uses NAT and iptables to transparently redirect print jobs from a failed printer to a working replacement without requiring client reconfiguration.

> **Note:** This software is currently in beta. The core network redirection functionality is stable and production-ready. Job monitoring and printer event logs are experimental features.

## Installation

Install Printer Proxy via the official APT repository:

```bash
# 1. Add the GPG signing key
curl -fsSL https://apt.jordonh.me/gpg-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/printer-proxy.gpg

# 2. Add the repository
echo "deb [signed-by=/usr/share/keyrings/printer-proxy.gpg] https://apt.jordonh.me stable main" | sudo tee /etc/apt/sources.list.d/printer-proxy.list

# 3. Install
sudo apt update
sudo apt install printer-proxy
```

## Upgrading

```bash
sudo apt update
sudo apt upgrade printer-proxy
```

## Initial Setup

1. Access the web interface: `https://<server-ip>`
2. Accept the self-signed certificate warning
3. Create an administrator account on the setup page
4. Log in with your new credentials

## Overview

Printer Proxy operates at the network layer to intercept and redirect TCP print traffic destined for a failed printer to an alternative target. When a printer fails, the proxy server claims the failed printer's IP address as a secondary interface and applies DNAT rules to forward incoming connections to a working printer.

### How It Works

```
                           ┌──────────────────────────────────────┐
                           │         Printer Proxy Server         │
                           │                                      │
                           │  1. Claims 192.168.1.10 as secondary │
                           │  2. Applies DNAT rule in iptables    │
                           │  3. Forwards traffic to target       │
                           └──────────────────────────────────────┘
                                          ▲           │
                       Print to           │           │ Forwarded
                    192.168.1.10:9100     │           │ to target
                                          │           ▼
┌──────────────────┐                      │           ┌───────────────────────┐
│   Client PC      │──────────────────────┘           │   Working Printer     │
│                  │                                  │   192.168.1.20        │
│  No changes      │                                  │   Receives jobs       │
│  required        │                                  └───────────────────────┘
└──────────────────┘
```

## Features

### Network Management
- **Secondary IP Assignment**: Dynamically assigns IP addresses to network interfaces
- **NAT/DNAT Rules**: Creates iptables rules for transparent traffic forwarding
- **Port Support**: TCP 9100 (RAW printing), with configurable port support

### Printer Discovery
- **mDNS/Bonjour**: Discovers printers advertising via multicast DNS
- **SNMP Scanning**: Scans network ranges for SNMP-enabled devices
- **Manual Entry**: Supports manual printer registration

### Health Monitoring
- **Background Polling**: Monitors printer availability via ICMP and TCP
- **Health History**: Tracks uptime/downtime over time
- **Status Dashboard**: Real-time status indicators

### Automatic Updates
- Updates are delivered via APT repository
- Check for updates in the Settings page
- Updates are applied automatically with service restart

## System Requirements

- Ubuntu 20.04+ or Debian 11+
- Python 3.9+
- Root/sudo access for iptables manipulation
- Network interface capable of multiple IP addresses

## Development

```bash
# Clone repository
git clone https://github.com/Jordonh18/printer-proxy.git
cd printer-proxy

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python run.py
```

## Building

```bash
# Build .deb package
./scripts/build-deb.sh
```

## License

MIT License - see [LICENSE](LICENSE) for details.
