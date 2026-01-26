"""
Continuum Configuration
Auto-detects network settings from the host machine.
"""
import os
import socket
import subprocess
import secrets
from pathlib import Path


def _get_default_interface() -> str:
    """Auto-detect the default network interface."""
    try:
        # Get the interface used for the default route
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout:
            # Parse: "default via X.X.X.X dev eth0 ..."
            parts = result.stdout.split()
            if 'dev' in parts:
                return parts[parts.index('dev') + 1]
    except Exception:
        pass
    
    # Fallback: try common interface names
    for iface in ['eth0', 'ens33', 'ens160', 'enp0s3', 'enp0s25']:
        if Path(f'/sys/class/net/{iface}').exists():
            return iface
    
    return 'eth0'


def _get_management_ip(interface: str) -> str:
    """Auto-detect the management IP from the network interface."""
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', interface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    # Parse: "inet 192.168.1.10/24 ..."
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return parts[1].split('/')[0]
    except Exception:
        pass
    
    # Fallback: get hostname IP
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return '127.0.0.1'


def _get_or_create_secret_key(data_dir: Path) -> str:
    """Get secret key from file or generate a new one."""
    secret_file = data_dir / '.secret_key'
    
    try:
        if secret_file.exists():
            return secret_file.read_text().strip()
    except Exception:
        pass
    
    # Generate new secret key
    secret_key = secrets.token_hex(32)
    
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(secret_key)
        secret_file.chmod(0o600)
    except Exception:
        pass
    
    return secret_key


# =============================================================================
# Path Configuration
# =============================================================================

# Detect if running from installed location or development
_installed_path = Path('/opt/continuum')
_is_installed = _installed_path.exists() and (
    Path('/etc/systemd/system/continuum.service').exists() or
    Path('/lib/systemd/system/continuum.service').exists()
)

if _is_installed:
    BASE_DIR = _installed_path
    CONFIG_DIR = Path('/etc/continuum')
    DATA_DIR = Path('/var/lib/continuum')
    LOG_DIR = Path('/var/log/continuum')
else:
    BASE_DIR = Path(__file__).parent.parent
    CONFIG_DIR = BASE_DIR / 'config'
    DATA_DIR = BASE_DIR / 'app' / 'data'
    LOG_DIR = BASE_DIR / 'logs'

# Ensure directories exist
for _dir in [DATA_DIR, LOG_DIR]:
    try:
        _dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass

# =============================================================================
# Network Configuration (Auto-detected)
# =============================================================================

# Network interface - auto-detect or use environment override
NETWORK_INTERFACE = os.environ.get('PROXY_INTERFACE') or _get_default_interface()

# Management IP - auto-detect or use environment override
MANAGEMENT_IP = os.environ.get('PROXY_MGMT_IP') or _get_management_ip(NETWORK_INTERFACE)

# =============================================================================
# Application Paths
# =============================================================================

DATABASE_PATH = DATA_DIR / 'continuum.db'
HELPER_SCRIPT = BASE_DIR / 'scripts' / 'network_helper.sh'

# =============================================================================
# Web Application Settings
# =============================================================================

SECRET_KEY = os.environ.get('SECRET_KEY') or _get_or_create_secret_key(DATA_DIR)
SESSION_TIMEOUT_MINUTES = 30

# =============================================================================
# Protocol Configuration
# =============================================================================

SUPPORTED_PROTOCOLS = {
    'raw': 9100,
    'ipp': 631,
    'lpr': 515
}

DEFAULT_PROTOCOL = 'raw'
DEFAULT_PORT = 9100

# =============================================================================
# Health Check Settings
# =============================================================================

PING_TIMEOUT_SECONDS = 2
TCP_CHECK_TIMEOUT_SECONDS = 3

# =============================================================================
# Logging Configuration
# =============================================================================

# Use structured JSON logging in production, human-readable in development
LOG_STRUCTURED = os.environ.get('LOG_STRUCTURED', 'false').lower() == 'true'

# Log format for human-readable logs
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Log file rotation settings
LOG_MAX_SIZE_MB = 10
LOG_BACKUP_COUNT = 5

# Log levels by module (can be overridden via environment)
LOG_LEVEL_DEFAULT = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOG_LEVEL_NETWORK = os.environ.get('LOG_LEVEL_NETWORK', 'INFO').upper()
LOG_LEVEL_DISCOVERY = os.environ.get('LOG_LEVEL_DISCOVERY', 'INFO').upper()
LOG_LEVEL_HEALTH = os.environ.get('LOG_LEVEL_HEALTH', 'INFO').upper()

# =============================================================================
# Security Settings
# =============================================================================

MIN_PASSWORD_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = False
PASSWORD_REQUIRE_SPECIAL = True

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# =============================================================================
# JWT Settings
# =============================================================================

JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or _get_or_create_secret_key(DATA_DIR) + '-jwt'
JWT_ACCESS_TOKEN_EXPIRES_HOURS = 24
JWT_REFRESH_TOKEN_EXPIRES_DAYS = 30

# =============================================================================
# Syslog Server Settings
# =============================================================================

SYSLOG_SERVER_ENABLED = os.environ.get('SYSLOG_SERVER_ENABLED', 'true').lower() == 'true'
SYSLOG_SERVER_PORT = int(os.environ.get('SYSLOG_SERVER_PORT', '514'))
SYSLOG_RETENTION_DAYS = int(os.environ.get('SYSLOG_RETENTION_DAYS', '30'))
SYSLOG_MAX_MESSAGES_PER_SECOND = int(os.environ.get('SYSLOG_MAX_MESSAGES_PER_SECOND', '100'))
SYSLOG_BURST_SIZE = int(os.environ.get('SYSLOG_BURST_SIZE', '500'))
SYSLOG_QUEUE_SIZE = int(os.environ.get('SYSLOG_QUEUE_SIZE', '10000'))
