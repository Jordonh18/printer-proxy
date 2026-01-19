"""
Auto-Update System - Uses APT repository for updates.

Architecture:
- Background thread periodically runs 'apt update' to check for new versions
- Updates are performed via 'apt upgrade printer-proxy'
- The update process is handled by a separate systemd service
- This ensures the update process survives when the main service restarts
"""
import json
import time
import logging
import threading
import fcntl
import subprocess
import re
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict

from app.version import __version__

logger = logging.getLogger(__name__)

# APT Configuration
APT_REPO_URL = "https://apt.jordonh.me"
PACKAGE_NAME = "printer-proxy"

# Paths
DATA_DIR = Path("/var/lib/printer-proxy")
DEV_DATA_DIR = Path(__file__).parent.parent / "data"
UPDATE_STATE_FILE = "update_state.json"
UPDATE_SERVICE = "printer-proxy-update.service"

# Check intervals
CHECK_INTERVAL_SECONDS = 6 * 60 * 60  # 6 hours between checks
UPDATE_TIMEOUT_SECONDS = 5 * 60  # 5 minutes max for update


@dataclass
class UpdateState:
    """Persistent state for the update system."""
    last_check: Optional[str] = None
    available_version: Optional[str] = None
    release_notes: Optional[str] = None
    update_in_progress: bool = False
    update_started_at: Optional[str] = None
    update_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UpdateState':
        known_fields = {k for k in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)
    
    def is_update_stale(self) -> bool:
        """Check if an in-progress update has timed out."""
        if not self.update_in_progress or not self.update_started_at:
            return False
        try:
            started = datetime.fromisoformat(self.update_started_at)
            return datetime.now() - started > timedelta(seconds=UPDATE_TIMEOUT_SECONDS)
        except (ValueError, TypeError):
            return True


class UpdateManager:
    """Manages checking for and applying updates via APT.
    
    Thread-safe singleton with file-based state persistence.
    """
    _instance: Optional['UpdateManager'] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self._data_dir = self._get_data_dir()
        self._state = UpdateState()
        self._state_lock = threading.Lock()
        self._check_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._load_state()
    
    @classmethod
    def get_instance(cls) -> 'UpdateManager':
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance
    
    def _get_data_dir(self) -> Path:
        """Get the appropriate data directory."""
        if DATA_DIR.exists():
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                return DATA_DIR
            except PermissionError:
                logger.warning(f"No write permission for {DATA_DIR}, using dev directory")
        DEV_DATA_DIR.mkdir(parents=True, exist_ok=True)
        return DEV_DATA_DIR
    
    def _load_state(self):
        """Load persisted update state with file locking."""
        state_file = self._data_dir / UPDATE_STATE_FILE
        try:
            if state_file.exists():
                with open(state_file, 'r') as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    try:
                        data = json.load(f)
                        self._state = UpdateState.from_dict(data)
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.warning(f"Failed to load update state: {e}")
            self._state = UpdateState()
    
    def _save_state(self):
        """Save update state with atomic write."""
        state_file = self._data_dir / UPDATE_STATE_FILE
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            temp_file = state_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(self._state.to_dict(), f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            temp_file.replace(state_file)
        except Exception as e:
            logger.error(f"Failed to save update state: {e}")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current update state for API responses."""
        with self._state_lock:
            self._load_state()
            
            # Auto-clear stale updates
            if self._state.update_in_progress and self._state.is_update_stale():
                logger.warning("Clearing stale update state")
                self._state.update_in_progress = False
                self._state.update_error = "Update timed out"
                self._save_state()
            
            state = self._state.to_dict()
            state['current_version'] = __version__
            state['update_available'] = self._is_newer_version(
                self._state.available_version, __version__
            ) if self._state.available_version else False
            state['apt_repo_url'] = APT_REPO_URL
            return state
    
    def _parse_version(self, version: str) -> Tuple[Tuple[int, ...], str]:
        """Parse version string into comparable tuple."""
        version = version.lstrip('v')
        pre_release = ''
        if '-' in version:
            version, pre_release = version.split('-', 1)
        try:
            parts = tuple(int(p) for p in version.split('.'))
        except ValueError:
            parts = (0,)
        return parts, pre_release
    
    def _is_newer_version(self, new_version: Optional[str], current_version: str) -> bool:
        """Compare semantic versions."""
        if not new_version:
            return False
        try:
            new_parts, new_pre = self._parse_version(new_version)
            cur_parts, cur_pre = self._parse_version(current_version)
            
            if new_parts != cur_parts:
                return new_parts > cur_parts
            
            # Pre-release versions are older than release versions
            if cur_pre and not new_pre:
                return True
            if new_pre and not cur_pre:
                return False
            return new_pre > cur_pre
        except Exception as e:
            logger.error(f"Version comparison failed: {e}")
            return False
    
    def _get_apt_available_version(self) -> Optional[str]:
        """Query APT for the available version of printer-proxy."""
        try:
            result = subprocess.run(
                ['apt-cache', 'policy', PACKAGE_NAME],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return None
            
            # Parse output to find candidate version
            for line in result.stdout.split('\n'):
                if 'Candidate:' in line:
                    version = line.split('Candidate:')[1].strip()
                    if version and version != '(none)':
                        return version
            
            return None
        except Exception as e:
            logger.error(f"Failed to get APT version: {e}")
            return None

    def _get_upgrade_candidate_version(self) -> Optional[str]:
        """Use a dry-run upgrade to detect the candidate version."""
        try:
            result = subprocess.run(
                ['apt-get', '-s', 'install', '--only-upgrade', PACKAGE_NAME],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return None

            # Example: Inst printer-proxy [1.0.0-beta.2] (1.0.1 stable [all])
            match = re.search(rf"Inst\s+{re.escape(PACKAGE_NAME)}\s+\[[^\]]+\]\s+\(([^)\s]+)", result.stdout)
            if match:
                return match.group(1)

            # Example: Inst printer-proxy (1.0.1 stable [all])
            match = re.search(rf"Inst\s+{re.escape(PACKAGE_NAME)}\s+\(([^)\s]+)", result.stdout)
            if match:
                return match.group(1)

            return None
        except Exception as e:
            logger.warning(f"Failed to get upgrade candidate: {e}")
            return None

    def _get_repo_available_version(self) -> Optional[str]:
        """Query the APT repository Packages file for available version."""
        try:
            packages_url = f"{APT_REPO_URL}/dists/stable/main/binary-all/Packages"
            with urllib.request.urlopen(packages_url, timeout=15) as resp:
                content = resp.read().decode('utf-8', errors='ignore')

            current_pkg = False
            for line in content.splitlines():
                if line.startswith('Package:'):
                    current_pkg = line.split(':', 1)[1].strip() == PACKAGE_NAME
                elif current_pkg and line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()

            return None
        except Exception as e:
            logger.warning(f"Failed to read repo Packages file: {e}")
            return None
    
    def check_for_updates(self, force: bool = False) -> Tuple[bool, Optional[str]]:
        """Check APT repository for available updates."""
        with self._state_lock:
            self._load_state()
            
            if self._state.update_in_progress and not self._state.is_update_stale():
                return False, "Update already in progress"
            
            # Rate limiting (check at most every 5 minutes unless forced)
            if not force and self._state.last_check:
                try:
                    last = datetime.fromisoformat(self._state.last_check)
                    if datetime.now() - last < timedelta(seconds=300):
                        has_update = self._is_newer_version(self._state.available_version, __version__)
                        return has_update, None
                except ValueError:
                    pass
        
        logger.info("Checking for updates via APT...")
        
        try:
            # Refresh APT cache using helper (non-interactive)
            helper_path = Path("/opt/printer-proxy/scripts/update_helper.sh")
            if helper_path.exists():
                result = subprocess.run(
                    ['sudo', '-n', str(helper_path), 'check'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    logger.warning(f"APT cache refresh failed: {result.stderr.strip()}")
            
            # Check available version
            available = self._get_apt_available_version()
            repo_available = None
            upgrade_available = self._get_upgrade_candidate_version()
            if upgrade_available and self._is_newer_version(upgrade_available, available or __version__):
                available = upgrade_available
            if not available:
                repo_available = self._get_repo_available_version()
            elif not self._is_newer_version(available, __version__):
                repo_available = self._get_repo_available_version()
                if repo_available and self._is_newer_version(repo_available, available):
                    available = repo_available
            
            with self._state_lock:
                self._state.last_check = datetime.now().isoformat()
                
                if available and self._is_newer_version(available, __version__):
                    self._state.available_version = available
                    self._state.update_error = None
                    logger.info(f"Update available: {__version__} -> {available}")
                elif available:
                    self._state.available_version = available
                elif repo_available:
                    self._state.available_version = repo_available
                
                self._save_state()
                return self._is_newer_version(self._state.available_version, __version__), None
                
        except subprocess.TimeoutExpired:
            return False, "apt update timed out"
        except Exception as e:
            logger.error(f"Update check failed: {e}")
            return False, str(e)
    
    def start_update(self) -> Tuple[bool, str]:
        """Start the update process by triggering the update service."""
        with self._state_lock:
            self._load_state()
            
            if self._state.update_in_progress and not self._state.is_update_stale():
                return False, "Update already in progress"
            
            if not self._state.available_version:
                return False, "No update available"
            
            if not self._is_newer_version(self._state.available_version, __version__):
                return False, "Already on latest version"
            
            version = self._state.available_version
            
            # Mark update as in progress
            self._state.update_in_progress = True
            self._state.update_started_at = datetime.now().isoformat()
            self._state.update_error = None
            self._save_state()
        
        logger.info(f"Starting update to version {version}")
        
        # Write update request file for update service
        try:
            request_file = self._data_dir / "update_request.json"
            request_file.parent.mkdir(parents=True, exist_ok=True)
            with open(request_file, 'w') as f:
                json.dump({
                    "version": version,
                    "requested_at": datetime.now().isoformat()
                }, f)
        except Exception as e:
            error_msg = f"Failed to write update request: {e}"
            logger.error(error_msg)
            with self._state_lock:
                self._state.update_in_progress = False
                self._state.update_error = error_msg
                self._save_state()
            return False, error_msg

        # Trigger the update service
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'start', UPDATE_SERVICE],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                error_msg = f"Failed to start update service: {result.stderr}"
                logger.error(error_msg)
                with self._state_lock:
                    self._state.update_in_progress = False
                    self._state.update_error = error_msg
                    self._save_state()
                return False, error_msg
            
            logger.info("Update service started successfully")
            return True, f"Update to version {version} started"
            
        except subprocess.TimeoutExpired:
            return False, "Timed out starting update service"
        except Exception as e:
            error_msg = f"Failed to start update: {e}"
            logger.error(error_msg, exc_info=True)
            with self._state_lock:
                self._state.update_in_progress = False
                self._state.update_error = error_msg
                self._save_state()
            return False, error_msg
    
    def clear_update_state(self):
        """Clear update state after restart."""
        with self._state_lock:
            self._state.update_in_progress = False
            self._state.update_started_at = None
            self._state.update_error = None
            self._save_state()
    
    def start_background_checks(self):
        """Start background thread for periodic update checks."""
        if self._check_thread and self._check_thread.is_alive():
            return
        
        self._stop_event.clear()
        self._check_thread = threading.Thread(
            target=self._background_check_loop,
            name="UpdateChecker",
            daemon=True
        )
        self._check_thread.start()
        logger.info("Background update checker started")
    
    def stop_background_checks(self):
        """Stop the background check thread."""
        self._stop_event.set()
        if self._check_thread:
            self._check_thread.join(timeout=5)
    
    def _background_check_loop(self):
        """Background loop that periodically checks for updates."""
        time.sleep(30)  # Initial delay
        
        while not self._stop_event.is_set():
            try:
                self.check_for_updates()
            except Exception as e:
                logger.error(f"Background update check failed: {e}")
            
            self._stop_event.wait(CHECK_INTERVAL_SECONDS)


def get_update_manager() -> UpdateManager:
    """Get the update manager singleton."""
    return UpdateManager.get_instance()


def init_updater(start_background: bool = True) -> UpdateManager:
    """Initialize the update system."""
    manager = get_update_manager()
    
    # Clear stale update state
    with manager._state_lock:
        manager._load_state()
        if manager._state.update_in_progress and manager._state.is_update_stale():
            logger.info("Clearing stale update state on startup")
            manager.clear_update_state()
    
    if start_background:
        manager.start_background_checks()
    
    return manager
