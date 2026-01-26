import axios from 'axios';
import type {
  AuthResponse,
  User,
  SmtpSettings,
  PrinterGroup,
  PrinterGroupDetail,
  Workflow,
  WorkflowRegistryNode,
  WorkflowEdge,
  WorkflowNode,
  NetworkOverview,
  NetworkInterface,
  ArpEntry,
  RoutingInfo,
  PortInfo,
  SafetyInfo,
  DiagnosticResult,
} from '@/types/api';

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

// Track consecutive network failures
let consecutiveNetworkFailures = 0;
const MAX_FAILURES_BEFORE_UNAVAILABLE = 3;

// Callback for notifying backend status changes
let onBackendStatusChange: ((available: boolean) => void) | null = null;

export function setBackendStatusCallback(callback: (available: boolean) => void) {
  onBackendStatusChange = callback;
}

// Response interceptor to handle token refresh and network errors
api.interceptors.response.use(
  (response) => {
    // Reset failure count on successful response
    consecutiveNetworkFailures = 0;
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    const requestUrl = (originalRequest?.url || '').toString();

    // Check if this is a network error (no response from server)
    if (!error.response && error.code === 'ERR_NETWORK') {
      consecutiveNetworkFailures++;
      
      // After multiple failures, notify that backend is unavailable
      if (consecutiveNetworkFailures >= MAX_FAILURES_BEFORE_UNAVAILABLE) {
        if (onBackendStatusChange) {
          onBackendStatusChange(false);
        }
      }
      
      return Promise.reject(error);
    }

    // Reset failure count if we got any response (even errors)
    consecutiveNetworkFailures = 0;

    if (requestUrl.includes('/auth/login') || requestUrl.includes('/auth/refresh')) {
      return Promise.reject(error);
    }

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
  login: async (username: string, password: string, options?: { totp?: string; recovery_code?: string }): Promise<AuthResponse> => {
    const payload: { username: string; password: string; totp?: string; recovery_code?: string } = {
      username,
      password,
    };
    if (options?.totp) payload.totp = options.totp;
    if (options?.recovery_code) payload.recovery_code = options.recovery_code;
    const response = await api.post<AuthResponse>('/auth/login', payload);
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

  updateMe: async (data: {
    username: string;
    email?: string | null;
    theme?: string;
    language?: string;
    timezone?: string;
  }): Promise<User> => {
    const response = await api.put<User>('/auth/me', data);
    return response.data;
  },

  setupMfa: async (): Promise<{ otpauth_uri: string; issuer: string; account: string }> => {
    const response = await api.post('/auth/mfa/setup');
    return response.data;
  },

  verifyMfa: async (code: string): Promise<{ recovery_codes: string[] }> => {
    const response = await api.post('/auth/mfa/verify', { code });
    return response.data;
  },

  disableMfa: async (data: { password?: string; code?: string }): Promise<{ message: string }> => {
    const response = await api.post('/auth/mfa/disable', data);
    return response.data;
  },

  setupStatus: async (): Promise<{ setup_required: boolean }> => {
    const response = await api.get('/auth/setup');
    return response.data;
  },

  createInitialAdmin: async (data: { username: string; password: string; email?: string | null; full_name?: string | null }): Promise<{ message: string }> => {
    const response = await api.post('/auth/setup', data);
    return response.data;
  },

  getSessions: async (): Promise<Array<{
    id: number;
    created_at: string | null;
    last_used: string | null;
    revoked_at: string | null;
    ip_address: string | null;
    user_agent: string | null;
    is_current: boolean;
  }>> => {
    const response = await api.get('/auth/sessions');
    return response.data;
  },

  revokeSession: async (id: number): Promise<{ message: string }> => {
    const response = await api.post(`/auth/sessions/${id}/revoke`);
    return response.data;
  },

  getNotificationPreferences: async (): Promise<{
    health_alerts: boolean;
    offline_alerts: boolean;
    job_failures: boolean;
    security_events: boolean;
    weekly_reports: boolean;
  }> => {
    const response = await api.get('/auth/me/notifications');
    return response.data;
  },

  updateNotificationPreferences: async (data: {
    health_alerts?: boolean;
    offline_alerts?: boolean;
    job_failures?: boolean;
    security_events?: boolean;
    weekly_reports?: boolean;
  }): Promise<{
    health_alerts: boolean;
    offline_alerts: boolean;
    job_failures: boolean;
    security_events: boolean;
    weekly_reports: boolean;
  }> => {
    const response = await api.put('/auth/me/notifications', data);
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
    syslog_enabled?: boolean;
    snmp_version?: 'v2c' | 'v3';
    snmp_read_community?: string;
    snmp_write_community?: string;
    snmp_v3_username?: string;
    snmp_v3_auth_protocol?: string;
    snmp_v3_auth_password?: string;
    snmp_v3_priv_protocol?: string;
    snmp_v3_priv_password?: string;
  }) => {
    const response = await api.post('/printers', data);
    return response.data;
  },

  update: async (id: string, data: { name?: string; ip?: string; location?: string; model?: string; syslog_enabled?: boolean; snmp_version?: 'v2c' | 'v3'; snmp_read_community?: string; snmp_write_community?: string; snmp_v3_username?: string; snmp_v3_auth_protocol?: string; snmp_v3_auth_password?: string; snmp_v3_priv_protocol?: string; snmp_v3_priv_password?: string }) => {
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

  getQueue: async (id: string) => {
    const response = await api.get(`/printers/${id}/queue`);
    return response.data;
  },

  getJobHistory: async (id: string) => {
    const response = await api.get(`/printers/${id}/jobs`);
    return response.data;
  },

  getAudit: async (id: string) => {
    const response = await api.get(`/printers/${id}/audit`);
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

  // Syslog methods
  getSyslogMessages: async (id: string, params?: { limit?: number; offset?: number; severity?: number; search?: string }) => {
    const response = await api.get(`/printers/${id}/syslog`, { params });
    return response.data;
  },

  getSyslogConfig: async (id: string) => {
    const response = await api.get(`/printers/${id}/syslog-config`);
    return response.data;
  },

  updateSyslogConfig: async (id: string, data: { syslog_enabled: boolean }) => {
    const response = await api.put(`/printers/${id}/syslog-config`, data);
    return response.data;
  },

  testSyslogConnection: async (id: string) => {
    const response = await api.post(`/printers/${id}/test-syslog`);
    return response.data;
  },

  autoConfigureSyslog: async (id: string, data: { write_community?: string; save_community?: boolean }) => {
    const response = await api.post(`/printers/${id}/auto-configure-syslog`, data);
    return response.data;
  },
};

// Dashboard API
export const dashboardApi = {
  getStatus: async () => {
    const response = await api.get('/dashboard/status');
    return response.data;
  },
  getAnalytics: async () => {
    const response = await api.get('/dashboard/analytics');
    return response.data;
  },
};

// Workflow API
export const workflowApi = {
  getRegistry: async (): Promise<WorkflowRegistryNode[]> => {
    const response = await api.get('/workflow-registry');
    return response.data;
  },

  getAll: async (): Promise<Workflow[]> => {
    const response = await api.get('/workflows');
    return response.data;
  },

  getById: async (id: string): Promise<Workflow> => {
    const response = await api.get(`/workflows/${id}`);
    return response.data;
  },

  create: async (data: { name: string; description?: string }): Promise<Workflow> => {
    const response = await api.post('/workflows', data);
    return response.data;
  },

  update: async (id: string, data: {
    name?: string;
    description?: string;
    is_active?: boolean;
    nodes?: WorkflowNode[];
    edges?: WorkflowEdge[];
    ui_state?: Record<string, unknown> | null;
  }): Promise<Workflow> => {
    const response = await api.put(`/workflows/${id}`, data);
    return response.data;
  },

  delete: async (id: string): Promise<{ status: string }> => {
    const response = await api.delete(`/workflows/${id}`);
    return response.data;
  },

  validateConnection: async (id: string, data: {
    source_node_id: string;
    target_node_id: string;
    source_handle?: string | null;
    target_handle?: string | null;
    source_node_type?: string | null;
    target_node_type?: string | null;
  }): Promise<{ valid: boolean; message: string }> => {
    const response = await api.post(`/workflows/${id}/validate-connection`, data);
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

// Printer Groups API
export const printerGroupsApi = {
  getAll: async (): Promise<{ groups: PrinterGroup[] }> => {
    const response = await api.get('/printer-groups');
    return response.data;
  },

  getById: async (id: number): Promise<PrinterGroupDetail> => {
    const response = await api.get(`/printer-groups/${id}`);
    return response.data;
  },

  create: async (data: { name: string; description?: string }): Promise<PrinterGroupDetail> => {
    const response = await api.post('/printer-groups', data);
    return response.data;
  },

  update: async (id: number, data: { name: string; description?: string }): Promise<PrinterGroupDetail> => {
    const response = await api.put(`/printer-groups/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<{ message: string }> => {
    const response = await api.delete(`/printer-groups/${id}`);
    return response.data;
  },

  setPrinters: async (id: number, printer_ids: string[]): Promise<PrinterGroupDetail> => {
    const response = await api.put(`/printer-groups/${id}/printers`, { printer_ids });
    return response.data;
  },
};

// Group Redirect Schedules API
export const groupRedirectSchedulesApi = {
  getAll: async (group_id?: number): Promise<{ schedules: any[] }> => {
    const response = await api.get('/group-redirect-schedules', {
      params: group_id ? { group_id } : undefined,
    });
    return response.data;
  },

  create: async (data: { group_id: number; target_printer_id: string; start_at: string; end_at?: string | null }): Promise<any> => {
    const response = await api.post('/group-redirect-schedules', data);
    return response.data;
  },

  update: async (id: number, data: { target_printer_id: string; start_at: string; end_at?: string | null; enabled: boolean }): Promise<any> => {
    const response = await api.put(`/group-redirect-schedules/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<{ message: string }> => {
    const response = await api.delete(`/group-redirect-schedules/${id}`);
    return response.data;
  },
};

// Printer Redirect Schedules API
export const printerRedirectSchedulesApi = {
  getAll: async (source_printer_id?: string): Promise<{ schedules: any[] }> => {
    const response = await api.get('/printer-redirect-schedules', {
      params: source_printer_id ? { source_printer_id } : undefined,
    });
    return response.data;
  },

  create: async (data: { source_printer_id: string; target_printer_id: string; start_at: string; end_at?: string | null }): Promise<any> => {
    const response = await api.post('/printer-redirect-schedules', data);
    return response.data;
  },

  update: async (id: number, data: { target_printer_id: string; start_at: string; end_at?: string | null; enabled: boolean }): Promise<any> => {
    const response = await api.put(`/printer-redirect-schedules/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<{ message: string }> => {
    const response = await api.delete(`/printer-redirect-schedules/${id}`);
    return response.data;
  },
};

// Notification Subscriptions API
export const notificationSubscriptionsApi = {
  get: async (preference?: string): Promise<{ preference?: string; group_ids?: number[]; subscriptions?: Record<string, number[]> }> => {
    const response = await api.get('/notifications/subscriptions', {
      params: preference ? { preference } : undefined,
    });
    return response.data;
  },

  update: async (preference: string, group_ids: number[]): Promise<{ preference: string; group_ids: number[] }> => {
    const response = await api.put('/notifications/subscriptions', { preference, group_ids });
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
};

// Admin API
export const adminApi = {
  getSmtp: async (): Promise<{ success: boolean; settings: SmtpSettings }> => {
    const response = await api.get('/settings/notifications/smtp');
    return response.data;
  },

  updateSmtp: async (settings: Partial<SmtpSettings>) => {
    const response = await api.post('/settings/notifications/smtp', settings);
    return response.data;
  },

  testSmtp: async (settings: Partial<SmtpSettings>) => {
    const response = await api.post('/settings/notifications/smtp/test', settings);
    return response.data;
  },
};

// API Tokens
export const apiTokensApi = {
  list: async () => {
    const response = await api.get('/auth/me/tokens');
    return response.data;
  },

  create: async (data: { name: string; permissions: string[]; expires_in_days?: number }) => {
    const response = await api.post('/auth/me/tokens', data);
    return response.data;
  },

  delete: async (tokenId: number) => {
    const response = await api.delete(`/auth/me/tokens/${tokenId}`);
    return response.data;
  },

  getPermissions: async () => {
    const response = await api.get('/auth/me/tokens/permissions');
    return response.data;
  },
};

// Network API
export const networkApi = {
  /**
   * Get complete network overview for the Networking page.
   * Combines interface info, claimed IPs, routing status, and redirect stats.
   */
  getOverview: async (): Promise<NetworkOverview> => {
    const response = await api.get('/network/overview');
    return response.data;
  },

  /**
   * Get detailed network interface information.
   */
  getInterfaces: async (): Promise<{ success: boolean; interfaces: NetworkInterface[] }> => {
    const response = await api.get('/network/interfaces');
    return response.data;
  },

  /**
   * Get ARP/neighbour table.
   */
  getArpTable: async (onlyOwned = false): Promise<{ success: boolean; entries: ArpEntry[] }> => {
    const response = await api.get('/network/arp-table', { params: { only_owned: onlyOwned } });
    return response.data;
  },

  /**
   * Get routing and NAT status information.
   */
  getRouting: async (): Promise<{ success: boolean; routing: RoutingInfo }> => {
    const response = await api.get('/network/routing');
    return response.data;
  },

  /**
   * Get current NAT rules (formatted).
   */
  getNatRules: async (): Promise<{ success: boolean; rules: string }> => {
    const response = await api.get('/network/nat-rules');
    return response.data;
  },

  /**
   * Get information about intercepted ports.
   */
  getPorts: async (): Promise<{ success: boolean; ports: PortInfo[] }> => {
    const response = await api.get('/network/ports');
    return response.data;
  },

  /**
   * Get safety guardrail settings and status.
   */
  getSafety: async (): Promise<{ success: boolean; safety: SafetyInfo }> => {
    const response = await api.get('/network/safety');
    return response.data;
  },

  /**
   * Update a safety guardrail setting.
   */
  updateSafetySetting: async (key: string, enabled: boolean): Promise<{ success: boolean }> => {
    const response = await api.post('/network/safety', { key, enabled });
    return response.data;
  },

  /**
   * Check if sudo is available without password.
   */
  checkSudoStatus: async (): Promise<{ sudo_available: boolean }> => {
    const response = await api.get('/network/sudo-status');
    return response.data;
  },

  /**
   * Authenticate with sudo password for development mode.
   */
  authenticateSudo: async (password: string): Promise<{ success: boolean; error?: string }> => {
    const response = await api.post('/network/sudo-auth', { password });
    return response.data;
  },

  // Diagnostics
  diagnostics: {
    /**
     * Ping test diagnostic.
     */
    ping: async (ip: string): Promise<{ success: boolean; result: DiagnosticResult }> => {
      const response = await api.post('/network/diagnostics/ping', { ip });
      return response.data;
    },

    /**
     * ARP probe diagnostic.
     */
    arpProbe: async (ip: string): Promise<{ success: boolean; result: DiagnosticResult }> => {
      const response = await api.post('/network/diagnostics/arp-probe', { ip });
      return response.data;
    },

    /**
     * TCP connection test diagnostic.
     */
    tcpTest: async (ip: string, port: number): Promise<{ success: boolean; result: DiagnosticResult }> => {
      const response = await api.post('/network/diagnostics/tcp-test', { ip, port });
      return response.data;
    },

    /**
     * Re-announce ARP for a claimed IP.
     * Requires confirmation.
     */
    reAnnounceArp: async (ip: string, confirm = false): Promise<{ 
      success: boolean; 
      message?: string; 
      error?: string;
      requires_confirmation?: boolean;
    }> => {
      const response = await api.post('/network/diagnostics/re-announce-arp', { ip, confirm });
      return response.data;
    },
  },

  // Advanced (admin only)
  advanced: {
    /**
     * Get raw ip addr show output.
     */
    getIpAddr: async (): Promise<{ success: boolean; output: string }> => {
      const response = await api.get('/network/advanced/ip-addr');
      return response.data;
    },

    /**
     * Get raw ip route output.
     */
    getIpRoute: async (): Promise<{ success: boolean; output: string }> => {
      const response = await api.get('/network/advanced/ip-route');
      return response.data;
    },

    /**
     * Get raw ip rule output.
     */
    getIpRule: async (): Promise<{ success: boolean; output: string }> => {
      const response = await api.get('/network/advanced/ip-rule');
      return response.data;
    },

    /**
     * Get raw iptables NAT rules output.
     */
    getNatRules: async (): Promise<{ success: boolean; output: string }> => {
      const response = await api.get('/network/advanced/nat-rules');
      return response.data;
    },
  },
};

// ============================================================================
// Integrations API
// ============================================================================

import type {
  IntegrationMetadata,
  IntegrationConnection,
  IntegrationConnectionHealth,
  IntegrationEventType,
  IntegrationEventRouting,
  IntegrationConnectionHistoryEntry,
} from '@/types/api';

export const integrationsApi = {
  // Catalog
  getCatalog: async (params?: { category?: string; search?: string }): Promise<{
    integrations: IntegrationMetadata[];
    categories: Record<string, number>;
  }> => {
    const response = await api.get('/integrations/catalog', { params });
    return response.data;
  },

  getIntegration: async (integrationId: string): Promise<IntegrationMetadata> => {
    const response = await api.get(`/integrations/catalog/${integrationId}`);
    return response.data;
  },

  // Connections
  listConnections: async (params?: { 
    integration_id?: string; 
    include_disabled?: boolean;
  }): Promise<{ connections: IntegrationConnection[] }> => {
    const response = await api.get('/integrations/connections', { params });
    return response.data;
  },

  getConnection: async (connectionId: string): Promise<IntegrationConnection> => {
    const response = await api.get(`/integrations/connections/${connectionId}`);
    return response.data;
  },

  createConnection: async (data: {
    integration_id: string;
    name: string;
    description?: string;
    config: Record<string, unknown>;
    credentials: Record<string, string>;
  }): Promise<{ connection_id: string; message: string }> => {
    const response = await api.post('/integrations/connections', data);
    return response.data;
  },

  updateConnection: async (connectionId: string, data: {
    name?: string;
    description?: string;
    config?: Record<string, unknown>;
    credentials?: Record<string, string>;
    enabled?: boolean;
  }): Promise<{ message: string }> => {
    const response = await api.put(`/integrations/connections/${connectionId}`, data);
    return response.data;
  },

  deleteConnection: async (connectionId: string): Promise<{ message: string }> => {
    const response = await api.delete(`/integrations/connections/${connectionId}`);
    return response.data;
  },

  // Connection Actions
  testConnection: async (connectionId: string): Promise<{
    success: boolean;
    health: IntegrationConnectionHealth;
  }> => {
    const response = await api.post(`/integrations/connections/${connectionId}/test`);
    return response.data;
  },

  connectIntegration: async (connectionId: string): Promise<{ message: string }> => {
    const response = await api.post(`/integrations/connections/${connectionId}/connect`);
    return response.data;
  },

  disconnectIntegration: async (connectionId: string): Promise<{ message: string }> => {
    const response = await api.post(`/integrations/connections/${connectionId}/disconnect`);
    return response.data;
  },

  // Event Routing
  getEventRouting: async (connectionId: string): Promise<{ routings: IntegrationEventRouting[] }> => {
    const response = await api.get(`/integrations/connections/${connectionId}/routing`);
    return response.data;
  },

  setEventRouting: async (connectionId: string, data: {
    event_type: string;
    enabled?: boolean;
    filters?: Record<string, unknown>;
    transform?: Record<string, unknown>;
    priority?: number;
  }): Promise<{ message: string }> => {
    const response = await api.post(`/integrations/connections/${connectionId}/routing`, data);
    return response.data;
  },

  // Event Types
  listEventTypes: async (): Promise<{ event_types: IntegrationEventType[] }> => {
    const response = await api.get('/integrations/events');
    return response.data;
  },

  // Connection History
  getConnectionHistory: async (connectionId: string, params?: { limit?: number }): Promise<{
    history: IntegrationConnectionHistoryEntry[];
  }> => {
    const response = await api.get(`/integrations/connections/${connectionId}/history`, { params });
    return response.data;
  },
};

export default api;
