"""
Notification system for Printer Proxy

This module provides a unified interface for sending notifications
through various channels (SMTP, Teams, etc.). New channels can be
added by implementing a new notifier class and registering it.
"""
import smtplib
import ssl
import logging
import json
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from app.settings import get_settings_manager
from app.models import get_db_connection

logger = logging.getLogger(__name__)


class NotificationChannel(ABC):
    """Base class for notification channels."""
    
    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Return the channel name (e.g., 'smtp', 'teams')."""
        pass
    
    @abstractmethod
    def is_configured(self, settings: Dict[str, Any]) -> bool:
        """Check if the channel is properly configured."""
        pass
    
    @abstractmethod
    def is_enabled(self, settings: Dict[str, Any]) -> bool:
        """Check if the channel is enabled."""
        pass
    
    @abstractmethod
    def send(self, subject: str, message: str, settings: Dict[str, Any], 
             html_message: Optional[str] = None) -> bool:
        """Send a notification. Returns True on success."""
        pass


class SMTPNotificationChannel(NotificationChannel):
    """SMTP email notification channel."""
    
    @property
    def channel_name(self) -> str:
        return 'smtp'
    
    def is_configured(self, settings: Dict[str, Any]) -> bool:
        """Check if SMTP is properly configured."""
        smtp = settings.get('notifications', {}).get('smtp', {})
        # Remove to_addresses from required fields
        required = ['host', 'port', 'from_address']
        return all(smtp.get(field) for field in required)
    
    def is_enabled(self, settings: Dict[str, Any]) -> bool:
        """Check if SMTP notifications are enabled."""
        return settings.get('notifications', {}).get('smtp', {}).get('enabled', False)
    
    def send(self, subject: str, message: str, settings: Dict[str, Any],
             html_message: Optional[str] = None, recipient_emails: Optional[list] = None) -> bool:
        """Send email notification via SMTP.
        
        Args:
            subject: Email subject
            message: Plain text message
            settings: Application settings dict
            html_message: Optional HTML version of message
            recipient_emails: List of recipient email addresses (required)
        
        Returns:
            True if email sent successfully, False otherwise
        """
        smtp_settings = settings.get('notifications', {}).get('smtp', {})
        
        if not self.is_configured(settings):
            logger.warning("SMTP not properly configured")
            return False
        
        if not recipient_emails:
            logger.warning("No recipient emails provided")
            return False
        
        try:
            host = smtp_settings['host']
            port = int(smtp_settings['port'])
            from_address = smtp_settings['from_address']
            username = smtp_settings.get('username', '')
            password = smtp_settings.get('password', '')
            use_tls = smtp_settings.get('use_tls', True)
            use_ssl = smtp_settings.get('use_ssl', False)
            
            # Ensure recipient_emails is a list
            if isinstance(recipient_emails, str):
                recipient_emails = [addr.strip() for addr in recipient_emails.split(',') if addr.strip()]
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_address
            msg['To'] = ', '.join(recipient_emails)
            msg['X-Mailer'] = 'Printer-Proxy-Notifier'
            
            # Add plain text part
            msg.attach(MIMEText(message, 'plain'))
            
            # Add HTML part if provided
            if html_message:
                msg.attach(MIMEText(html_message, 'html'))
            
            # Connect and send
            if use_ssl:
                # Direct SSL connection (port 465)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as server:
                    if username and password:
                        server.login(username, password)
                    server.sendmail(from_address, recipient_emails, msg.as_string())
            else:
                # Standard connection, optionally with STARTTLS (port 587 or 25)
                with smtplib.SMTP(host, port, timeout=30) as server:
                    server.ehlo()
                    if use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        server.ehlo()
                    if username and password:
                        server.login(username, password)
                    server.sendmail(from_address, recipient_emails, msg.as_string())
            
            logger.info(f"Email notification sent to {recipient_emails}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP recipients refused: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False


class NotificationManager:
    """
    Unified notification manager that handles all notification channels.
    
    Usage:
        from app.notifications import notify
        
        # Send to all enabled channels
        notify("Printer Alert", "Printer HP-LaserJet is offline!")
        
        # Or with HTML
        notify("Printer Alert", "Plain text", html_message="<b>HTML version</b>")
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._channels: List[NotificationChannel] = []
        self._register_default_channels()
    
    def _register_default_channels(self):
        """Register built-in notification channels."""
        self._channels.append(SMTPNotificationChannel())
        # Future: self._channels.append(TeamsNotificationChannel())
        # Future: self._channels.append(SlackNotificationChannel())
    
    def register_channel(self, channel: NotificationChannel):
        """Register a new notification channel."""
        self._channels.append(channel)
    
    def get_channels(self) -> List[NotificationChannel]:
        """Get all registered channels."""
        return self._channels
    
    def get_enabled_channels(self) -> List[NotificationChannel]:
        """Get all enabled and configured channels."""
        settings = get_settings_manager().get_all()
        return [
            ch for ch in self._channels 
            if ch.is_enabled(settings) and ch.is_configured(settings)
        ]
    
    def send(self, subject: str, message: str, html_message: Optional[str] = None) -> Dict[str, bool]:
        """
        Send notification to all enabled channels.
        
        Args:
            subject: Notification subject/title
            message: Plain text message body
            html_message: Optional HTML message body
            
        Returns:
            Dict mapping channel names to success status
        """
        settings = get_settings_manager().get_all()
        results = {}
        
        for channel in self._channels:
            if channel.is_enabled(settings) and channel.is_configured(settings):
                try:
                    success = channel.send(subject, message, settings, html_message)
                    results[channel.channel_name] = success
                except Exception as e:
                    logger.error(f"Error sending via {channel.channel_name}: {e}")
                    results[channel.channel_name] = False
            else:
                # Skip disabled/unconfigured channels silently
                pass
        
        if not results:
            logger.debug("No notification channels are enabled and configured")
        
        return results
    
    def test_channel(self, channel_name: str) -> tuple[bool, str]:
        """
        Test a specific notification channel.
        
        Returns:
            Tuple of (success, message)
        """
        settings = get_settings_manager().get_all()
        
        for channel in self._channels:
            if channel.channel_name == channel_name:
                if not channel.is_configured(settings):
                    return False, f"{channel_name.upper()} is not properly configured"
                
                try:
                    success = channel.send(
                        subject="Printer Proxy - Test Notification",
                        message="This is a test notification from Printer Proxy. If you received this, your notification settings are working correctly.",
                        settings=settings,
                        html_message="""
                        <html>
                        <body style="font-family: Arial, sans-serif; padding: 20px;">
                            <h2 style="color: #333;">Printer Proxy - Test Notification</h2>
                            <p>This is a test notification from <strong>Printer Proxy</strong>.</p>
                            <p>If you received this, your notification settings are working correctly.</p>
                            <hr style="border: 1px solid #eee;">
                            <p style="color: #888; font-size: 12px;">
                                Sent at: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
                            </p>
                        </body>
                        </html>
                        """
                    )
                    if success:
                        return True, f"Test notification sent successfully via {channel_name.upper()}"
                    else:
                        return False, f"Failed to send test notification via {channel_name.upper()}"
                except Exception as e:
                    return False, f"Error testing {channel_name.upper()}: {str(e)}"
        
        return False, f"Unknown channel: {channel_name}"


# Singleton instance
_notification_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    """Get the singleton notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager


def notify(subject: str, message: str, html_message: Optional[str] = None) -> Dict[str, bool]:
    """
    Send notification to all enabled channels.
    
    This is the primary interface for sending notifications throughout the app.
    
    Usage:
        from app.notifications import notify
        
        # Simple notification
        notify("Alert", "Something happened!")
        
        # With HTML
        notify("Alert", "Plain text", html_message="<b>Rich HTML</b>")
    
    Args:
        subject: Notification subject/title
        message: Plain text message body
        html_message: Optional HTML message body
        
    Returns:
        Dict mapping channel names to success status (empty if no channels enabled)
    """
    return get_notification_manager().send(subject, message, html_message)


def notify_printer_offline(printer_name: str, printer_ip: str):
    """Send notification when a printer goes offline to users with offline_alerts enabled."""
    from app.notification_manager import get_notification_manager as get_notif_mgr
    
    users = get_users_with_preference('offline_alerts')
    if not users:
        return

    group_id = get_printer_group_id_by_ip(printer_ip)
    subscriptions = get_group_subscriptions('offline_alerts')
    
    # Create in-app notifications for all users with this preference
    notif_mgr = get_notif_mgr()
    for user in users:
        user_groups = subscriptions.get(user['id'], [])
        if user_groups:
            if not group_id or group_id not in user_groups:
                continue
        notif_mgr.create_notification(
            user_id=user['id'],
            type='error',
            title=f"{printer_name} is offline.",
            message="",
            link=f"/printers"
        )
    
    recipient_emails = [u['email'] for u in users if u['email'] and (
        not subscriptions.get(u['id']) or (group_id and group_id in subscriptions.get(u['id'], []))
    )]
    if not recipient_emails:
        return
    
    subject = f"Printer Offline: {printer_name}"
    message = f"Printer '{printer_name}' ({printer_ip}) is now offline."
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #dc3545;">Printer Offline Alert</h2>
        <p>The following printer is no longer responding:</p>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Printer</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_name}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>IP Address</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_ip}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    # Send via SMTP to users with offline_alerts enabled
    settings = get_settings_manager().get_all()
    if settings.get('notifications', {}).get('smtp', {}).get('enabled'):
        channel = SMTPNotificationChannel()
        if channel.is_configured(settings):
            channel.send(subject, message, settings, html_message, recipient_emails=recipient_emails)


def notify_printer_online(printer_name: str, printer_ip: str):
    """Send notification when a printer comes back online to users with offline_alerts enabled."""
    from app.notification_manager import get_notification_manager as get_notif_mgr
    
    users = get_users_with_preference('offline_alerts')
    if not users:
        return

    group_id = get_printer_group_id_by_ip(printer_ip)
    subscriptions = get_group_subscriptions('offline_alerts')
    
    # Create in-app notifications for all users with this preference
    notif_mgr = get_notif_mgr()
    for user in users:
        user_groups = subscriptions.get(user['id'], [])
        if user_groups:
            if not group_id or group_id not in user_groups:
                continue
        notif_mgr.create_notification(
            user_id=user['id'],
            type='success',
            title=f"{printer_name} is now responding.",
            message="",
            link=f"/printers"
        )
    
    recipient_emails = [u['email'] for u in users if u['email'] and (
        not subscriptions.get(u['id']) or (group_id and group_id in subscriptions.get(u['id'], []))
    )]
    if not recipient_emails:
        return
    
    subject = f"Printer Online: {printer_name}"
    message = f"Printer '{printer_name}' ({printer_ip}) is now back online."
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #10b981;">Printer Online</h2>
        <p>The following printer is now responding:</p>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Printer</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_name}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>IP Address</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_ip}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    # Send via SMTP to users with offline_alerts enabled
    settings = get_settings_manager().get_all()
    if settings.get('notifications', {}).get('smtp', {}).get('enabled'):
        channel = SMTPNotificationChannel()
        if channel.is_configured(settings):
            channel.send(subject, message, settings, html_message, recipient_emails=recipient_emails)


def get_users_with_preference(preference_key: str) -> List[Dict[str, Any]]:
    """
    Get all users who have a specific notification preference enabled.
    
    Args:
        preference_key: The preference to check (e.g., 'security_events', 'offline_alerts')
        
    Returns:
        List of user dicts with id, username, email
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, notification_preferences FROM users WHERE is_active = 1")
    rows = cursor.fetchall()
    conn.close()
    
    default_prefs = {
        'health_alerts': True,
        'offline_alerts': True,
        'job_failures': True,
        'security_events': True,
        'weekly_reports': False
    }

    users_with_pref = []
    for row in rows:
        prefs_json = row['notification_preferences']
        if prefs_json:
            try:
                prefs = json.loads(prefs_json)
            except (json.JSONDecodeError, TypeError):
                prefs = default_prefs
        else:
            prefs = default_prefs

        if prefs.get(preference_key, False):
            users_with_pref.append({
                'id': row['id'],
                'username': row['username'],
                'email': row['email']
            })
    
    return users_with_pref


def get_group_subscriptions(preference_key: str) -> Dict[int, List[int]]:
    """Get group subscription mapping for users by preference key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, group_id FROM user_group_subscriptions WHERE preference_key = ?",
        (preference_key,)
    )
    rows = cursor.fetchall()
    conn.close()

    mapping: Dict[int, List[int]] = {}
    for row in rows:
        mapping.setdefault(row['user_id'], []).append(row['group_id'])
    return mapping


def get_printer_group_id_by_ip(printer_ip: str) -> Optional[int]:
    """Get group ID for a printer by IP (if assigned)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM printers WHERE ip = ?", (printer_ip,))
    printer_row = cursor.fetchone()
    if not printer_row:
        conn.close()
        return None

    printer_id = printer_row['id']
    cursor.execute(
        "SELECT group_id FROM printer_group_members WHERE printer_id = ?",
        (printer_id,)
    )
    group_row = cursor.fetchone()
    conn.close()
    return group_row['group_id'] if group_row else None


def notify_user_login(username: str, ip_address: str, user_agent: str, user_id: int):
    """Send notification to a user when they log in (security event)."""
    # Check if this user has security_events enabled
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email, notification_preferences FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return
    
    # Parse preferences
    prefs_json = row['notification_preferences']
    if not prefs_json:
        return
    
    try:
        prefs = json.loads(prefs_json)
        if not prefs.get('security_events', False):
            return  # User has security events disabled
    except (json.JSONDecodeError, TypeError):
        return
    
    email = row['email']
    if not email:
        return  # No email configured for this user
    
    # Send notification only to this user's email
    subject = f"Security Alert: Login to Printer Proxy"
    message = f"""
A successful login was detected on your Printer Proxy account.

Username: {username}
IP Address: {ip_address}
User Agent: {user_agent}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If this was not you, please change your password immediately and contact your administrator.
    """.strip()
    
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #ffc107;">Security Alert: Login Detected</h2>
        <p>A successful login was detected on your Printer Proxy account.</p>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Username</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{username}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>IP Address</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{ip_address}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Device</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{user_agent}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
        <p style="color: #dc3545;"><strong>If this was not you, please change your password immediately and contact your administrator.</strong></p>
    </body>
    </html>
    """
    
    # Send directly via SMTP to this user's email only
    settings = get_settings_manager().get_all()
    smtp_settings = settings.get('notifications', {}).get('smtp', {})
    
    if not smtp_settings.get('enabled'):
        return  # SMTP not enabled
    
    channel = SMTPNotificationChannel()
    if channel.is_configured(settings):
        # Send only to this specific user's email
        channel.send(subject, message, settings, html_message, recipient_emails=[email])


def notify_printer_health_alert(printer_name: str, printer_ip: str, alert_type: str, details: str):
    """Send health alert notification to users who have health_alerts enabled."""
    users = get_users_with_preference('health_alerts')
    if not users:
        return
    
    recipient_emails = [u['email'] for u in users if u['email']]
    if not recipient_emails:
        return
    
    subject = f"Health Alert: {printer_name} - {alert_type}"
    message = f"""
Printer health alert detected:

Printer: {printer_name}
IP Address: {printer_ip}
Alert Type: {alert_type}
Details: {details}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """.strip()
    
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #ffc107;">Printer Health Alert</h2>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Printer</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_name}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>IP Address</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_ip}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Alert Type</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{alert_type}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Details</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{details}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    # Send via SMTP to users with health_alerts enabled
    settings = get_settings_manager().get_all()
    if settings.get('notifications', {}).get('smtp', {}).get('enabled'):
        channel = SMTPNotificationChannel()
        if channel.is_configured(settings):
            channel.send(subject, message, settings, html_message, recipient_emails=recipient_emails)


def notify_job_failure(printer_name: str, printer_ip: str, error_details: str):
    """Send job failure notification to users who have job_failures enabled."""
    users = get_users_with_preference('job_failures')
    if not users:
        return
    
    recipient_emails = [u['email'] for u in users if u['email']]
    if not recipient_emails:
        return
    
    subject = f"Print Job Failure: {printer_name}"
    message = f"""
A print job has failed:

Printer: {printer_name}
IP Address: {printer_ip}
Error: {error_details}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """.strip()
    
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #dc3545;">Print Job Failure</h2>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Printer</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_name}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>IP Address</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{printer_ip}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Error</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{error_details}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    # Send via SMTP to users with job_failures enabled
    settings = get_settings_manager().get_all()
    if settings.get('notifications', {}).get('smtp', {}).get('enabled'):
        channel = SMTPNotificationChannel()
        if channel.is_configured(settings):
            channel.send(subject, message, settings, html_message, recipient_emails=recipient_emails)


def notify_redirect_created(source_printer: str, target_printer: str, created_by: str):
    """Send notification when a redirect is created."""
    subject = f"Redirect Created: {source_printer} -> {target_printer}"
    message = f"A redirect has been created from '{source_printer}' to '{target_printer}' by {created_by}."
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #17a2b8;">Redirect Created</h2>
        <p>A new print redirect has been configured:</p>
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>From</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{source_printer}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>To</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{target_printer}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Created By</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{created_by}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Time</strong></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    return notify(subject, message, html_message)


def send_weekly_report():
    """Generate and send weekly report to users who have weekly_reports enabled."""
    users = get_users_with_preference('weekly_reports')
    if not users:
        logger.info("No users have weekly reports enabled, skipping")
        return

    subscriptions = get_group_subscriptions('weekly_reports')

    from app.printers import get_registry
    registry = get_registry()
    all_printers = registry.get_all()
    all_statuses = registry.get_all_statuses()

    settings = get_settings_manager().get_all()
    if not settings.get('notifications', {}).get('smtp', {}).get('enabled'):
        return

    channel = SMTPNotificationChannel()
    if not channel.is_configured(settings):
        return

    for user in users:
        email = user.get('email')
        if not email:
            continue

        group_ids = subscriptions.get(user['id'], [])
        printer_ids = None
        if group_ids:
            conn = get_db_connection()
            cursor = conn.cursor()
            placeholders = ",".join(["?"] * len(group_ids))
            cursor.execute(
                f"SELECT printer_id FROM printer_group_members WHERE group_id IN ({placeholders})",
                group_ids
            )
            printer_rows = cursor.fetchall()
            conn.close()
            printer_ids = [row['printer_id'] for row in printer_rows]

        if printer_ids is not None:
            filtered_printers = [p for p in all_printers if p.id in printer_ids]
            filtered_statuses = [s for s in all_statuses if s.get('printer', {}).get('id') in printer_ids]
        else:
            filtered_printers = all_printers
            filtered_statuses = all_statuses

        total_printers = len(filtered_printers)
        online_printers = sum(1 for p in filtered_statuses if p.get('is_online', False))

        conn = get_db_connection()
        cursor = conn.cursor()

        if printer_ids is not None and printer_ids:
            placeholders = ",".join(["?"] * len(printer_ids))
            cursor.execute(
                f"""
                SELECT COUNT(*) as job_count, COALESCE(SUM(pages), 0) as total_pages
                FROM print_job_history
                WHERE recorded_at >= datetime('now', '-7 days')
                AND printer_id IN ({placeholders})
                """,
                printer_ids
            )
        else:
            cursor.execute("""
                SELECT COUNT(*) as job_count, COALESCE(SUM(pages), 0) as total_pages
                FROM print_job_history
                WHERE recorded_at >= datetime('now', '-7 days')
            """)
        job_row = cursor.fetchone()
        job_count = job_row['job_count'] if job_row else 0
        total_pages = job_row['total_pages'] if job_row else 0

        if printer_ids is not None and printer_ids:
            placeholders = ",".join(["?"] * len(printer_ids))
            cursor.execute(
                f"SELECT COUNT(*) as redirect_count FROM active_redirects WHERE source_printer_id IN ({placeholders})",
                printer_ids
            )
        else:
            cursor.execute("SELECT COUNT(*) as redirect_count FROM active_redirects")
        redirect_row = cursor.fetchone()
        redirect_count = redirect_row['redirect_count'] if redirect_row else 0

        if printer_ids is not None and printer_ids:
            placeholders = ",".join(["?"] * len(printer_ids))
            cursor.execute(
                f"""
                SELECT action, timestamp, username, details
                FROM audit_log
                WHERE timestamp >= datetime('now', '-7 days')
                AND (source_printer_id IN ({placeholders}) OR target_printer_id IN ({placeholders}))
                ORDER BY timestamp DESC
                LIMIT 10
                """,
                (*printer_ids, *printer_ids)
            )
        else:
            cursor.execute("""
                SELECT action, timestamp, username, details
                FROM audit_log
                WHERE timestamp >= datetime('now', '-7 days')
                AND action IN ('REDIRECT_CREATED', 'REDIRECT_REMOVED', 'PRINTER_ADDED', 'PRINTER_REMOVED')
                ORDER BY timestamp DESC
                LIMIT 10
            """)
        recent_events = cursor.fetchall()
        conn.close()

        week_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        week_end = datetime.now().strftime('%Y-%m-%d')

        scope_label = "All Printers" if printer_ids is None else "Group Scope"
        subject = f"Printer Proxy Weekly Report ({week_start} to {week_end})"

        message = f"""
Printer Proxy Weekly Report
Period: {week_start} to {week_end}
Scope: {scope_label}

=== Summary ===
Total Printers: {total_printers}
Online Printers: {online_printers}
Offline Printers: {total_printers - online_printers}
Active Redirects: {redirect_count}

=== Print Statistics ===
Total Jobs: {job_count}
Total Pages: {total_pages:,}

=== Recent Activity ===
"""

        if recent_events:
            for event in recent_events:
                event_time = event['timestamp'][:19] if event['timestamp'] else 'Unknown'
                message += f"\n{event_time} - {event['action']} by {event['username']}"
                if event['details']:
                    message += f" ({event['details']})"
        else:
            message += "\nNo significant events this week."

        events_html = ""
        if recent_events:
            for event in recent_events:
                event_time = event['timestamp'][:19] if event['timestamp'] else 'Unknown'
                events_html += f"""
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">{event_time}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{event['action']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{event['username']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{event['details'] or '—'}</td>
                </tr>
                """
        else:
            events_html = '<tr><td colspan="4" style="padding: 8px; text-align: center; color: #888;">No significant events this week</td></tr>'

        html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #333;">Printer Proxy Weekly Report</h2>
            <p style="color: #666;">Period: {week_start} to {week_end}</p>
            <p style="color: #666;">Scope: {scope_label}</p>
            
            <h3 style="color: #333; margin-top: 30px;">Summary</h3>
            <table style="border-collapse: collapse; margin: 10px 0; width: 100%;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa; width: 200px;"><strong>Total Printers</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{total_printers}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Online Printers</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: #28a745;">{online_printers}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Offline Printers</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: #dc3545;">{total_printers - online_printers}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Active Redirects</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{redirect_count}</td>
                </tr>
            </table>
            
            <h3 style="color: #333; margin-top: 30px;">Print Statistics</h3>
            <table style="border-collapse: collapse; margin: 10px 0; width: 100%;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa; width: 200px;"><strong>Total Jobs</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{job_count:,}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; background: #f8f9fa;"><strong>Total Pages</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{total_pages:,}</td>
                </tr>
            </table>
            
            <h3 style="color: #333; margin-top: 30px;">Recent Activity</h3>
            <table style="border-collapse: collapse; margin: 10px 0; width: 100%;">
                <thead>
                    <tr style="background: #f8f9fa;">
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Time</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Action</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">User</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Details</th>
                    </tr>
                </thead>
                <tbody>
                    {events_html}
                </tbody>
            </table>
            
            <hr style="margin: 30px 0; border: 1px solid #eee;">
            <p style="color: #888; font-size: 12px;">
                This is an automated weekly report from Printer Proxy.<br>
                You can disable these reports in your notification preferences.
            </p>
        </body>
        </html>
        """

        channel.send(subject, message, settings, html_message, recipient_emails=[email])


class WeeklyReportScheduler:
    """Background scheduler for weekly reports."""
    
    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the weekly report scheduler."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Weekly report scheduler started")
    
    def stop(self):
        """Stop the weekly report scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Weekly report scheduler stopped")
    
    def _run_loop(self):
        """Main loop - checks once per hour if it's time to send the weekly report."""
        last_sent_week = None
        
        while self._running:
            try:
                now = datetime.now()
                # Send report on Monday at 8:00 AM
                if now.weekday() == 0 and now.hour == 8:  # Monday
                    current_week = now.isocalendar()[1]
                    if last_sent_week != current_week:
                        send_weekly_report()
                        last_sent_week = current_week
            except Exception as e:
                logger.error(f"Error in weekly report scheduler: {e}")
            
            # Sleep for 1 hour
            for _ in range(3600):
                if not self._running:
                    break
                time.sleep(1)


# Global weekly report scheduler instance
_weekly_scheduler: Optional[WeeklyReportScheduler] = None


def start_weekly_reports():
    """Start the weekly report scheduler."""
    global _weekly_scheduler
    if _weekly_scheduler is None:
        _weekly_scheduler = WeeklyReportScheduler()
    _weekly_scheduler.start()


def stop_weekly_reports():
    """Stop the weekly report scheduler."""
    global _weekly_scheduler
    if _weekly_scheduler:
        _weekly_scheduler.stop()
