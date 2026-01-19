import axios from 'axios';
import type { AuthResponse, User, SmtpSettings } from '@/types/api';

const API_BASE = '/api';

// Create axios instance with interceptors
const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const setAuthToken = (accessToken: string | null) => {
  if (accessToken) {
    api.defaults.headers.common.Authorization = `Bearer ${accessToken}`;
  } else {
    delete api.defaults.headers.common.Authorization;
  }
};

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE}/auth/refresh`, {}, {
            headers: {
              Authorization: `Bearer ${refreshToken}`,
            },
          });

          const { access_token } = response.data;
          localStorage.setItem('access_token', access_token);
          setAuthToken(access_token);

          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        } catch {
          // Refresh failed, clear tokens and redirect to login
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
        }
      } else {
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/login', { username, password });
    return response.data;
  },

  logout: async (): Promise<void> => {
    await api.post('/auth/logout');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  },

  me: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },
};

// Printers API
export const printersApi = {
  getAll: async () => {
    const response = await api.get('/printers');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get(`/printers/${id}`);
    return response.data;
  },

  create: async (data: {
    name: string;
    ip: string;
    location?: string;
    model?: string;
    department?: string;
    notes?: string;
    protocols?: string[];
  }) => {
    const response = await api.post('/printers', data);
    return response.data;
  },

  update: async (id: string, data: { name?: string; ip?: string; location?: string; model?: string }) => {
    const response = await api.put(`/printers/${id}`, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete(`/printers/${id}`);
    return response.data;
  },

  check: async (id: string) => {
    const response = await api.get(`/printers/${id}/check`);
    return response.data;
  },

  getStats: async (id: string) => {
    const response = await api.get(`/printers/${id}/stats`);
    return response.data;
  },

  getHealth: async (id: string) => {
    const response = await api.get(`/printers/${id}/health`);
    return response.data;
  },

  refresh: async (id: string) => {
    const response = await api.get(`/printers/${id}/refresh`);
    return response.data;
  },
};

// Dashboard API
export const dashboardApi = {
  getStatus: async () => {
    const response = await api.get('/dashboard/status');
    return response.data;
  },
};

// Redirects API
export const redirectsApi = {
  getAll: async () => {
    const response = await api.get('/redirects');
    return response.data;
  },

  create: async (data: { source_printer_id: string; target_printer_id: string }) => {
    const response = await api.post('/redirects', data);
    return response.data;
  },

  delete: async (id: number) => {
    const response = await api.delete(`/redirects/${id}`);
    return response.data;
  },
};

// Users API
export const usersApi = {
  getAll: async () => {
    const response = await api.get('/users');
    return response.data;
  },

  getById: async (id: number) => {
    const response = await api.get(`/users/${id}`);
    return response.data;
  },

  create: async (data: { username: string; password: string; role: string; is_active?: boolean }) => {
    const response = await api.post('/users', data);
    return response.data;
  },

  update: async (id: number, data: { role?: string; is_active?: boolean; password?: string }) => {
    const response = await api.put(`/users/${id}`, data);
    return response.data;
  },

  delete: async (id: number) => {
    const response = await api.delete(`/users/${id}`);
    return response.data;
  },
};

// Audit logs API
export const auditLogsApi = {
  getAll: async (params?: { limit?: number; offset?: number; action?: string; username?: string }) => {
    const response = await api.get('/audit-logs', { params });
    return response.data;
  },
};

// Discovery API
export const discoveryApi = {
  scan: async (subnet?: string) => {
    const response = await api.post('/discovery/scan', { subnet });
    return response.data;
  },
};

// App info API
export const appApi = {
  getInfo: async () => {
    const response = await api.get('/info');
    return response.data;
  },
};

// Update API
export const updateApi = {
  getStatus: async () => {
    const response = await api.get('/update/status');
    return response.data;
  },

  check: async () => {
    const response = await api.post('/update/check');
    return response.data;
  },

  start: async () => {
    const response = await api.post('/update/start');
    return response.data;
  },
};

// Settings API
export const settingsApi = {
  getAll: async () => {
    const response = await api.get('/settings');
    return response.data;
  },

  getSmtp: async (): Promise<{ success: boolean; settings: SmtpSettings }> => {
    const response = await api.get('/settings/notifications/smtp');
    return response.data;
  },

  updateSmtp: async (settings: Partial<SmtpSettings>) => {
    const response = await api.post('/settings/notifications/smtp', settings);
    return response.data;
  },

  testSmtp: async () => {
    const response = await api.post('/settings/notifications/smtp/test');
    return response.data;
  },
};

export default api;
