import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { toast as sonnerToast } from 'sonner';
import { toast } from '@/lib/toast';
import api from '@/lib/api';

export interface Notification {
  id: number;
  user_id: number;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  link?: string;
  is_read: boolean;
  created_at: string;
  read_at?: string;
}

export interface NotificationListResponse {
  notifications: Notification[];
}

export interface UnreadCountResponse {
  count: number;
}

// API client for notifications
export const notificationsApi = {
  getNotifications: async (params?: { limit?: number; offset?: number; unread_only?: boolean }): Promise<NotificationListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    if (params?.unread_only) searchParams.set('unread_only', 'true');
    
    const response = await api.get(`/notifications?${searchParams.toString()}`);
    return response.data;
  },

  getUnreadCount: async (): Promise<UnreadCountResponse> => {
    const response = await api.get('/notifications/unread-count');
    return response.data;
  },

  markAsRead: async (notificationId: number): Promise<void> => {
    await api.post(`/notifications/${notificationId}/read`);
  },

  markAllAsRead: async (): Promise<void> => {
    await api.post('/notifications/read-all');
  },

  deleteNotification: async (notificationId: number): Promise<void> => {
    await api.delete(`/notifications/${notificationId}`);
  },
};

/**
 * Hook for SSE connection to receive real-time notifications
 */
export function useNotificationStream() {
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    let isMounted = true;

    const connect = () => {
      // Get JWT token from localStorage
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('No auth token, skipping notification stream');
        return;
      }

      // Create EventSource with auth token in URL
      const url = `/api/notifications/stream`;
      const eventSource = new EventSource(url);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        if (isMounted) {
          console.log('Notification stream connected');
          setIsConnected(true);
        }
      };

      eventSource.addEventListener('message', (event) => {
        if (!isMounted) return;

        try {
          const data = JSON.parse(event.data);

          if (data.type === 'connected') {
            console.log('SSE connection established');
          } else if (data.type === 'notification') {
            const notification: Notification = data.notification;
            
            // Show toast notification
            const toastFn = sonnerToast[notification.type] || sonnerToast.info;
            toastFn(notification.title, {
              description: notification.message,
              action: notification.link ? {
                label: 'View',
                onClick: () => window.location.href = notification.link!,
              } : undefined,
            });

            // Invalidate queries to refresh data
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
            queryClient.invalidateQueries({ queryKey: ['notifications', 'unread-count'] });
          } else if (data.type === 'unread_count') {
            // Update unread count in cache
            queryClient.setQueryData(['notifications', 'unread-count'], { count: data.count });
          }
        } catch (error) {
          console.error('Error parsing SSE message:', error);
        }
      });

      eventSource.onerror = () => {
        if (!isMounted) return;

        console.log('Notification stream disconnected, reconnecting...');
        setIsConnected(false);
        eventSource.close();

        // Reconnect after delay
        reconnectTimeoutRef.current = setTimeout(() => {
          if (isMounted) {
            connect();
          }
        }, 3000);
      };
    };

    connect();

    return () => {
      isMounted = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [queryClient]);

  return { isConnected };
}

/**
 * Hook for fetching notifications list
 */
export function useNotifications(params?: { limit?: number; offset?: number; unread_only?: boolean }) {
  return useQuery({
    queryKey: ['notifications', params],
    queryFn: () => notificationsApi.getNotifications(params),
  });
}

/**
 * Hook for fetching unread count
 */
export function useUnreadCount() {
  return useQuery({
    queryKey: ['notifications', 'unread-count'],
    queryFn: notificationsApi.getUnreadCount,
  });
}

/**
 * Hook for marking notification as read with optimistic updates
 */
export function useMarkAsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: notificationsApi.markAsRead,
    onMutate: async (notificationId) => {
      // Cancel outgoing queries
      await queryClient.cancelQueries({ queryKey: ['notifications'] });

      // Snapshot previous value
      const previousNotifications = queryClient.getQueryData(['notifications']);
      const previousCount = queryClient.getQueryData(['notifications', 'unread-count']);

      // Optimistically update notification
      queryClient.setQueriesData({ queryKey: ['notifications'] }, (old: any) => {
        if (!old?.notifications) return old;
        return {
          ...old,
          notifications: old.notifications.map((n: Notification) =>
            n.id === notificationId ? { ...n, is_read: true, read_at: new Date().toISOString() } : n
          ),
        };
      });

      // Optimistically update count
      queryClient.setQueryData(['notifications', 'unread-count'], (old: any) => ({
        count: Math.max(0, (old?.count || 0) - 1),
      }));

      return { previousNotifications, previousCount };
    },
    onError: (_err, _notificationId, context) => {
      // Rollback on error
      if (context?.previousNotifications) {
        queryClient.setQueryData(['notifications'], context.previousNotifications);
      }
      if (context?.previousCount) {
        queryClient.setQueryData(['notifications', 'unread-count'], context.previousCount);
      }
      toast.error('Failed to mark as read');
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications', 'unread-count'] });
    },
  });
}

/**
 * Hook for marking all notifications as read
 */
export function useMarkAllAsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: notificationsApi.markAllAsRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.setQueryData(['notifications', 'unread-count'], { count: 0 });
      toast.success('All notifications marked as read');
    },
    onError: () => {
      toast.error('Failed to mark all as read');
    },
  });
}

/**
 * Hook for deleting a notification with optimistic updates
 */
export function useDeleteNotification() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: notificationsApi.deleteNotification,
    onMutate: async (notificationId) => {
      await queryClient.cancelQueries({ queryKey: ['notifications'] });

      const previousNotifications = queryClient.getQueryData(['notifications']);
      const previousCount = queryClient.getQueryData(['notifications', 'unread-count']);

      // Find if the notification being deleted is unread
      const notification = (previousNotifications as any)?.notifications?.find(
        (n: Notification) => n.id === notificationId
      );
      const wasUnread = notification && !notification.is_read;

      // Optimistically remove notification
      queryClient.setQueriesData({ queryKey: ['notifications'] }, (old: any) => {
        if (!old?.notifications) return old;
        return {
          ...old,
          notifications: old.notifications.filter((n: Notification) => n.id !== notificationId),
        };
      });

      // Optimistically update count if it was unread
      if (wasUnread) {
        queryClient.setQueryData(['notifications', 'unread-count'], (old: any) => ({
          count: Math.max(0, (old?.count || 0) - 1),
        }));
      }

      return { previousNotifications, previousCount };
    },
    onError: (_err, _notificationId, context) => {
      if (context?.previousNotifications) {
        queryClient.setQueryData(['notifications'], context.previousNotifications);
      }
      if (context?.previousCount) {
        queryClient.setQueryData(['notifications', 'unread-count'], context.previousCount);
      }
      toast.error('Failed to delete notification');
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications', 'unread-count'] });
    },
  });
}
