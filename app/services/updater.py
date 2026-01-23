"""
Auto-Update System - Uses APT repository for updates.

Architecture:
- Background thread periodically runs 'apt update' to check for new versions
- Updates are performed via 'apt upgrade continuum'
- The update process spawns systemctl restart
"""
import time
import logging
import threading
import subprocess
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple

from app.version import __version__

logger = logging.getLogger(__name__)

# APT Configuration
APT_REPO_URL = "https://apt.jordonh.me"
PACKAGE_NAME = "continuum"

# Check intervals
CHECK_INTERVAL_SECONDS = 6 * 60 * 60  # 6 hours between checks


class UpdateManager:
    """Manages checking for and applying updates via APT.
    
    Thread-safe singleton.
    """
    _instance: Optional['UpdateManager'] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self._check_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_check: Optional[datetime] = None
        self._available_version: Optional[str] = None
        self._update_in_progress = False
    
    @classmethod
    def get_instance(cls) -> 'UpdateManager':
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance
    
    def get_state(self) -> dict:
        """Get current update state for API responses."""
        return {
            'current_version': __version__,
            'available_version': self._available_version,
            'update_available': self._is_newer_version(self._available_version, __version__) if self._available_version else False,
            'update_in_progress': self._update_in_progress,
            'last_check': self._last_check.isoformat() if self._last_check else None,
            'apt_repo_url': APT_REPO_URL
        }
    
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
        """Query APT for the available version of continuum."""
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

    def check_for_updates(self, force: bool = False) -> Tuple[bool, Optional[str]]:
        """Check APT repository for available updates."""
        # Rate limiting (check at most every 5 minutes unless forced)
        if not force and self._last_check:
            if datetime.now() - self._last_check < timedelta(seconds=300):
                has_update = self._is_newer_version(self._available_version, __version__)
                return has_update, None
        
        logger.info("Checking for updates via APT...")
        
        try:
            # Refresh APT cache using helper (non-interactive)
            helper_path = Path("/opt/continuum/scripts/update_helper.sh")
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
            
            self._last_check = datetime.now()
            
            if available and self._is_newer_version(available, __version__):
                self._available_version = available
                logger.info(f"Update available: {__version__} -> {available}")
                return True, None
            elif available:
                self._available_version = available
                return False, None
            
            return False, None
                
        except subprocess.TimeoutExpired:
            return False, "apt update timed out"
        except Exception as e:
            logger.error(f"Update check failed: {e}")
            return False, str(e)
    
    def start_update(self) -> Tuple[bool, str]:
        """Start the update process by spawning apt upgrade + systemctl restart."""
        if self._update_in_progress:
            return False, "Update already in progress"
        
        if not self._available_version:
            return False, "No update available"
        
        if not self._is_newer_version(self._available_version, __version__):
            return False, "Already on latest version"
        
        version = self._available_version
        self._update_in_progress = True
        
        logger.info(f"Starting update to version {version}")

        # Trigger the update service (which does apt upgrade + restart)
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'start', 'continuum-update.service'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                error_msg = f"Failed to start update service: {result.stderr}"
                logger.error(error_msg)
                self._update_in_progress = False
                return False, error_msg
            
            logger.info("Update service started successfully")
            return True, f"Update to version {version} started"
            
        except subprocess.TimeoutExpired:
            self._update_in_progress = False
            return False, "Timed out starting update service"
        except Exception as e:
            error_msg = f"Failed to start update: {e}"
            logger.error(error_msg, exc_info=True)
            self._update_in_progress = False
            return False, error_msg
    
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
    
    if start_background:
        manager.start_background_checks()
    
    return manager
