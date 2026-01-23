"""
Notification management system with SSE support

This module handles storing notifications in the database,
managing real-time delivery via Server-Sent Events, and
queuing notifications for offline users.
"""
import json
import logging
import queue
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from app.models import get_db_connection

logger = logging.getLogger(__name__)


@dataclass
class Notification:
    """Represents a user notification."""
    id: Optional[int] = None
    user_id: int = 0
    type: str = 'info'  # info, success, warning, error
    title: str = ''
    message: str = ''
    link: Optional[str] = None
    is_read: bool = False
    created_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'type': self.type,
            'title': self.title,
            'message': self.message,
            'link': self.link,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
        }
    
    @classmethod
    def from_db_row(cls, row) -> 'Notification':
        """Create Notification from database row."""
        return cls(
            id=row[0],
            user_id=row[1],
            type=row[2],
            title=row[3],
            message=row[4],
            link=row[5],
            is_read=bool(row[6]),
            created_at=datetime.fromisoformat(row[7]) if row[7] else None,
            read_at=datetime.fromisoformat(row[8]) if row[8] else None,
        )


class NotificationManager:
    """Manages notification storage and real-time delivery."""
    
    def __init__(self):
        """Initialize notification manager."""
        # SSE connections: {user_id: queue.Queue}
        self._connections: Dict[int, List[queue.Queue]] = {}
        self._lock = threading.Lock()
    
    def create_notification(
        self,
        user_id: int,
        type: str,
        title: str,
        message: str,
        link: Optional[str] = None
    ) -> Optional[Notification]:
        """
        Create and store a new notification.
        
        Args:
            user_id: ID of the user to notify
            type: Notification type (info, success, warning, error)
            title: Notification title
            message: Notification message
            link: Optional link for the notification
        
        Returns:
            Created Notification object or None on error
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO notifications (user_id, type, title, message, link)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, type, title, message, link))
            
            notification_id = cursor.lastrowid
            conn.commit()
            
            # Fetch the created notification
            cursor.execute("""
                SELECT id, user_id, type, title, message, link, is_read, created_at, read_at
                FROM notifications WHERE id = ?
            """, (notification_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                notification = Notification.from_db_row(row)
                # Broadcast to connected clients
                self._broadcast_to_user(user_id, notification)
                return notification
            
            return None
            
        except Exception as e:
            logger.error(f"Error creating notification: {e}")
            return None
    
    def broadcast_notification(
        self,
        user_ids: List[int],
        type: str,
        title: str,
        message: str,
        link: Optional[str] = None
    ):
        """
        Broadcast a notification to multiple users.
        
        Args:
            user_ids: List of user IDs to notify
            type: Notification type
            title: Notification title
            message: Notification message
            link: Optional link
        """
        for user_id in user_ids:
            self.create_notification(user_id, type, title, message, link)
    
    def get_user_notifications(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
        unread_only: bool = False
    ) -> List[Notification]:
        """
        Get notifications for a user.
        
        Args:
            user_id: User ID
            limit: Maximum number of notifications to return
            offset: Offset for pagination
            unread_only: If True, return only unread notifications
        
        Returns:
            List of Notification objects
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if unread_only:
                cursor.execute("""
                    SELECT id, user_id, type, title, message, link, is_read, created_at, read_at
                    FROM notifications
                    WHERE user_id = ? AND is_read = 0
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (user_id, limit, offset))
            else:
                cursor.execute("""
                    SELECT id, user_id, type, title, message, link, is_read, created_at, read_at
                    FROM notifications
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (user_id, limit, offset))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [Notification.from_db_row(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error fetching notifications: {e}")
            return []
    
    def get_unread_count(self, user_id: int) -> int:
        """Get count of unread notifications for a user."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM notifications
                WHERE user_id = ? AND is_read = 0
            """, (user_id,))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count
            
        except Exception as e:
            logger.error(f"Error getting unread count: {e}")
            return 0
    
    def mark_as_read(self, notification_id: int, user_id: int) -> bool:
        """Mark a notification as read."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE notifications
                SET is_read = 1, read_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
            """, (notification_id, user_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return success
            
        except Exception as e:
            logger.error(f"Error marking notification as read: {e}")
            return False
    
    def mark_all_as_read(self, user_id: int) -> bool:
        """Mark all notifications as read for a user."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE notifications
                SET is_read = 1, read_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND is_read = 0
            """, (user_id,))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error marking all notifications as read: {e}")
            return False
    
    def delete_notification(self, notification_id: int, user_id: int) -> bool:
        """Delete a notification."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM notifications
                WHERE id = ? AND user_id = ?
            """, (notification_id, user_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return success
            
        except Exception as e:
            logger.error(f"Error deleting notification: {e}")
            return False
    
    # ============================================================================
    # SSE Connection Management
    # ============================================================================
    
    def register_connection(self, user_id: int) -> queue.Queue:
        """
        Register a new SSE connection for a user.
        
        Returns:
            Queue for sending notifications to this connection
        """
        with self._lock:
            if user_id not in self._connections:
                self._connections[user_id] = []
            
            # Create a new queue for this connection
            q = queue.Queue(maxsize=100)
            self._connections[user_id].append(q)
            
            logger.info(f"Registered SSE connection for user {user_id}")
            return q
    
    def unregister_connection(self, user_id: int, q: queue.Queue):
        """Unregister an SSE connection."""
        with self._lock:
            if user_id in self._connections:
                if q in self._connections[user_id]:
                    self._connections[user_id].remove(q)
                
                # Clean up empty lists
                if not self._connections[user_id]:
                    del self._connections[user_id]
            
            logger.info(f"Unregistered SSE connection for user {user_id}")
    
    def _broadcast_to_user(self, user_id: int, notification: Notification):
        """Broadcast notification to all connected clients for a user."""
        with self._lock:
            if user_id in self._connections:
                # Send to all active connections for this user
                dead_queues = []
                for q in self._connections[user_id]:
                    try:
                        q.put_nowait(notification)
                    except queue.Full:
                        logger.warning(f"Queue full for user {user_id}, dropping notification")
                        dead_queues.append(q)
                    except Exception as e:
                        logger.error(f"Error broadcasting to user {user_id}: {e}")
                        dead_queues.append(q)
                
                # Clean up dead queues
                for q in dead_queues:
                    if q in self._connections[user_id]:
                        self._connections[user_id].remove(q)


# Global notification manager instance
_notification_manager = None


def get_notification_manager() -> NotificationManager:
    """Get the global notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager
