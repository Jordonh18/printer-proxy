# Copilot Instructions for Printer Proxy

## Project Overview

Printer Proxy is a Flask web application that redirects network print traffic via NAT/iptables. When a printer fails, clients continue printing to the same IP while traffic is forwarded to a working printer.

## Architecture

### Core Components

- **Flask App Factory**: [app/__init__.py](app/__init__.py) - Uses `create_app()` pattern with blueprints (`main_bp`, `auth_bp`, `api_bp`)
- **Routes**: [app/routes.py](app/routes.py) - All web routes and API endpoints
- **Models**: [app/models.py](app/models.py) - SQLite database with raw SQL (no ORM)
- **Network Manager**: [app/network.py](app/network.py) - Calls privileged bash helper via sudo
- **Network Helper**: [scripts/network_helper.sh](scripts/network_helper.sh) - Bash script for iptables/NAT operations (runs as root)

### Data Flow for Redirects

1. User creates redirect via web UI → [app/routes.py](app/routes.py#L126)
2. `NetworkManager` calls `network_helper.sh` via sudo
3. Helper script adds secondary IP + NAT rules with iptables
4. Print traffic to broken IP is forwarded to target printer

### Background Services

Started in `create_app()` when not in debug reloader:
- **Health Checker** ([app/health_check.py](app/health_check.py)) - Polls printer status via ICMP/TCP
- **Job Monitor** ([app/job_monitor.py](app/job_monitor.py)) - Tracks print jobs via SNMP page counters

## Development Workflow

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run development server (port 8080)
python run.py

# Build Debian package
./scripts/build-deb.sh

# Bump version (updates app/version.py only)
./scripts/bump-version.sh patch|minor|major
```

## Key Conventions

### Version Management

Single source of truth: [app/version.py](app/version.py). Build scripts read from here.

### Database Access

Use raw SQLite connections - no ORM. Pattern from [app/models.py](app/models.py):
```python
conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("SELECT * FROM printers WHERE id = ?", (printer_id,))
row = cursor.fetchone()
conn.close()
```

### Network Operations

Never run iptables directly. Always use `NetworkManager` which calls `network_helper.sh`:
```python
network = get_network_manager()
success, output = network.add_nat_rule(source_ip, target_ip, port)
```

### Printer Discovery

Uses mDNS (zeroconf) and SNMP scanning. See [app/discovery.py](app/discovery.py).

### Authentication

Flask-Login with bcrypt password hashing. Account lockout after failed attempts. See [app/auth.py](app/auth.py).

## File Locations (Production)

| Path | Purpose |
|------|---------|
| `/opt/printer-proxy/` | Application code |
| `/var/lib/printer-proxy/` | SQLite database, secrets |
| `/var/log/printer-proxy/` | Application logs |

Config auto-detects install vs development mode in [config/config.py](config/config.py#L82).

## Testing Notes

- No test suite currently exists
- Manual testing requires Linux with iptables permissions
- Use `python run.py` for development (auto-reload enabled)
