# Continuum

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://ubuntu.com/)
[![GitHub release](https://img.shields.io/github/v/release/Jordonh18/continuum)](https://github.com/Jordonh18/continuum/releases)
[![GitHub issues](https://img.shields.io/github/issues/Jordonh18/continuum)](https://github.com/Jordonh18/continuum/issues)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/Jordonh18/continuum?utm_source=oss&utm_medium=github&utm_campaign=Jordonh18%2Fcontinuum&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)

A modern network printer management platform with transparent traffic redirection. When a printer fails, Continuum automatically redirects print jobs to working printers using NAT/iptables, no client reconfiguration required.

## Features

### Printer Management
- **Automatic Discovery**: Find printers via mDNS, SNMP scanning, or manual entry
- **Health Monitoring**: Real-time status tracking with ICMP and TCP checks
- **Job Tracking**: Monitor print jobs and page counts via SNMP
- **Statistics & Analytics**: Historical data and uptime reports

### Network Redirection
- **Transparent Failover**: Automatically redirect traffic from failed printers to working replacements
- **Secondary IP Assignment**: Dynamically claims failed printer IPs as network aliases
- **NAT/DNAT Rules**: iptables-based traffic forwarding for seamless redirection
- **Protocol Support**: RAW (9100), IPP (631), LPR (515)
- **Group Redirects**: Schedule redirects for multiple printers simultaneously

### Workflow Automation
- **Visual Workflow Builder**: Drag-and-drop interface for creating automation
- **Triggers**: Schedule-based, event-based, or manual workflow execution
- **Actions**: Printer operations, redirects, notifications, HTTP requests, email
- **Conditions**: Branch logic based on printer status, time, or custom variables

### Notifications & Alerts
- **Multi-Channel**: Email, Slack, Discord, Microsoft Teams, webhooks
- **Event Types**: Printer offline/online, redirect changes, job completion, workflow events
- **Custom Rules**: Configure notification preferences per event type

### Security & Access
- **JWT Authentication**: Secure API access with token-based auth
- **User Management**: Create users, set passwords, manage permissions
- **MFA Support**: TOTP-based two-factor authentication
- **Account Lockout**: Brute-force protection with configurable thresholds
- **API Tokens**: Generate tokens for programmatic access
- **Rate Limiting**: Protect against abuse with configurable rate limits

### Modern Web Interface
- **React + TypeScript**: Fast, responsive single-page application
- **Dark Mode**: System-aware theme switching
- **Real-Time Updates**: Live status updates via polling
- **Mobile-Friendly**: Responsive design for any device

### System & Deployment
- **APT Repository**: Easy installation and automatic updates
- **Systemd Integration**: Native service management
- **Nginx Reverse Proxy**: Production-ready HTTPS setup
- **Self-Signed Certificates**: Auto-generated SSL for development

## Installation

### Via APT Repository (Recommended)

```bash
# Add the GPG signing key
curl -fsSL https://apt.jordonh.me/gpg-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/continuum.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/continuum.gpg] https://apt.jordonh.me stable main" | sudo tee /etc/apt/sources.list.d/continuum.list

# Install Continuum
sudo apt update
sudo apt install continuum
```

### Manual Installation

```bash
# Download the latest .deb package
wget https://github.com/Jordonh18/continuum/releases/latest/download/continuum_VERSION_all.deb

# Install
sudo dpkg -i continuum_VERSION_all.deb
sudo apt-get install -f  # Install dependencies
```

## Quick Start

1. **Access the Web UI**: Navigate to `https://<server-ip>` (accept the self-signed certificate warning)
2. **Create Admin Account**: Complete the initial setup wizard
3. **Discover Printers**: Use the discovery tool to find printers on your network
4. **Create Redirect**: Select a failed printer and redirect it to a working one

## How It Works

```
                           ┌──────────────────────────────────────┐
                           │       Continuum Server           │
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

Continuum operates at the network layer, intercepting TCP print traffic destined for a failed printer and transparently redirecting it to a working replacement. The proxy server claims the failed printer's IP address as a secondary interface and applies DNAT rules to forward connections, clients continue printing without any configuration changes.

## Upgrading

```bash
sudo apt update
sudo apt upgrade continuum
```

The service will automatically restart after upgrade.

## Development

### Prerequisites
- Python 3.9+
- Node.js 18+ and npm
- Linux with iptables support

### Setup

```bash
# Clone repository
git clone https://github.com/Jordonh18/continuum.git
cd continuum

# Backend setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend setup
cd frontend
npm install
npm run build

# Run development server (backend on :8080)
cd ..
python run.py
```

### Building

```bash
# Build .deb package
./scripts/build-deb.sh

# Package will be in builds/
```

## System Requirements

- **OS**: Ubuntu 20.04+ or Debian 11+
- **Python**: 3.9 or higher
- **Permissions**: Root/sudo access for iptables manipulation
- **Network**: Interface capable of multiple IP addresses

## Project Structure

```
continuum/
├── app/                    # Backend application
│   ├── models/            # Database models
│   ├── routes/            # API endpoints
│   ├── services/          # Business logic (health check, discovery, etc.)
│   └── utils/             # Authentication, rate limiting, etc.
├── frontend/              # React + TypeScript SPA
│   └── src/
│       ├── components/    # UI components
│       ├── pages/         # Page components
│       └── lib/           # API client, utilities
├── scripts/               # Build and utility scripts
├── debian/                # Debian packaging files
└── config/                # Application configuration

```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- **Documentation**: [GitHub Wiki](https://github.com/Jordonh18/continuum/wiki)
- **Issue Tracker**: [GitHub Issues](https://github.com/Jordonh18/continuum/issues)
- **APT Repository**: [https://apt.jordonh.me](https://apt.jordonh.me)

