// User types
export interface User {
  id: number;
  username: string;
  full_name?: string | null;
  email?: string | null;
  role: 'admin' | 'operator' | 'viewer';
  is_active: boolean;
  last_login: string | null;
  created_at: string | null;
  mfa_enabled?: boolean;
  theme?: 'system' | 'light' | 'dark';
  language?: string;
  timezone?: string;
  current_session_id?: number | null;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: User;
}

// Printer types
export interface Printer {
  id: string;
  name: string;
  ip: string;
  location?: string;
  model?: string;
  department?: string;
  notes?: string;
  protocols?: string[];
}

export interface PrinterStatus {
  printer: Printer;
  group?: {
    id: number;
    name: string;
  } | null;
  status?: {
    icmp_reachable: boolean;
    tcp_reachable: boolean;
    is_online: boolean;
    is_redirected: boolean;
    is_redirect_target: boolean;
    redirect_info?: {
      target_printer_id?: string | null;
      target_ip?: string | null;
      enabled_at?: string | null;
      enabled_by?: string | null;
    } | null;
  };
  is_online: boolean;
  icmp_reachable: boolean;
  tcp_reachable: boolean;
  has_redirect: boolean;
  is_target: boolean;
  redirect_target?: Printer | null;
  redirect_source?: Printer | null;
}

export interface PrinterStats {
  total_pages: number;
  color_pages: number;
  mono_pages: number;
  uptime: string;
}

export interface TonerLevel {
  color: string;
  level: number;
  capacity: number;
}

// Redirect types
export interface ActiveRedirect {
  id: number;
  source_printer_id: string;
  source_ip: string;
  target_printer_id: string;
  target_ip: string;
  protocol: string;
  port: number;
  enabled_at: string;
  enabled_by: string;
}

export interface PrinterRedirectSchedule {
  id: number;
  source_printer_id: string;
  source_printer_name?: string;
  target_printer_id: string;
  target_printer_name?: string;
  start_at: string;
  end_at?: string | null;
  enabled: boolean;
  is_active: boolean;
  last_activated_at?: string | null;
  last_deactivated_at?: string | null;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

// Audit log types
export interface AuditLog {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  details: string;
  source_printer_id?: string;
  target_printer_id?: string;
  source_ip?: string;
  target_ip?: string;
  success: boolean;
  error_message?: string;
}

// App info
export interface AppInfo {
  version: string;
  version_string: string;
  app_name: string;
}

export interface DashboardAnalytics {
  top_pages: Array<{
    printer_id: string;
    name: string;
    total_pages: number;
    uptime_hours?: number;
  }>;
  daily_volume: Array<{
    day: string;
    total_pages: number;
    total_jobs: number;
  }>;
}

// Notification settings
export interface SmtpSettings {
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  password: string;
  from_address: string;
  use_tls: boolean;
  use_ssl: boolean;
}

// Health check types
export interface HealthStatus {
  printer_id: string;
  is_online: boolean;
  icmp_ok: boolean;
  tcp_ok: boolean;
  response_time_ms: number | null;
  last_check: string;
}

// Discovery types
export interface DiscoveredPrinter {
  ip: string;
  name: string;
  model?: string;
  mac?: string;
}

// API Tokens
export interface APIToken {
  id: number;
  user_id: number;
  name: string;
  permissions: string[];
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  token?: string; // Only included on creation
}

export interface TokenPermissions {
  role: string;
  permissions: string[];
  grouped: Record<string, string[]>;
  all_scopes: Record<string, string[]>;
}

export interface PrinterGroup {
  id: number;
  name: string;
  description?: string | null;
  printer_count: number;
  owner_user_id?: number | null;
  owner_username?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface PrinterGroupDetail extends PrinterGroup {
  printer_ids: string[];
}

