"""
Notification system for Printer Proxy

This module provides a unified interface for sending notifications
through various channels (SMTP, Teams, etc.). New channels can be
added by implementing a new notifier class and registering it.
"""
import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime

from app.settings import get_settings_manager

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
        required = ['host', 'port', 'from_address', 'to_addresses']
        return all(smtp.get(field) for field in required)
    
    def is_enabled(self, settings: Dict[str, Any]) -> bool:
        """Check if SMTP notifications are enabled."""
        return settings.get('notifications', {}).get('smtp', {}).get('enabled', False)
    
    def send(self, subject: str, message: str, settings: Dict[str, Any],
             html_message: Optional[str] = None) -> bool:
        """Send email notification via SMTP."""
        smtp_settings = settings.get('notifications', {}).get('smtp', {})
        
        if not self.is_configured(settings):
            logger.warning("SMTP not properly configured")
            return False
        
        try:
            host = smtp_settings['host']
            port = int(smtp_settings['port'])
            from_address = smtp_settings['from_address']
            to_addresses = smtp_settings['to_addresses']
            username = smtp_settings.get('username', '')
            password = smtp_settings.get('password', '')
            use_tls = smtp_settings.get('use_tls', True)
            use_ssl = smtp_settings.get('use_ssl', False)
            
            # Parse to_addresses if it's a string
            if isinstance(to_addresses, str):
                to_addresses = [addr.strip() for addr in to_addresses.split(',') if addr.strip()]
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_address
            msg['To'] = ', '.join(to_addresses)
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
                    server.sendmail(from_address, to_addresses, msg.as_string())
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
                    server.sendmail(from_address, to_addresses, msg.as_string())
            
            logger.info(f"Email notification sent to {to_addresses}")
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
    """Send notification when a printer goes offline."""
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
        <p>Please check the printer and consider setting up a redirect if needed.</p>
    </body>
    </html>
    """
    return notify(subject, message, html_message)


def notify_printer_online(printer_name: str, printer_ip: str):
    """Send notification when a printer comes back online."""
    subject = f"Printer Online: {printer_name}"
    message = f"Printer '{printer_name}' ({printer_ip}) is now online."
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #28a745;">Printer Online Alert</h2>
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
    return notify(subject, message, html_message)


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
