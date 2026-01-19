// User types
export interface User {
  id: number;
  username: string;
  role: 'admin' | 'operator' | 'viewer';
  is_active: boolean;
  last_login: string | null;
  created_at: string | null;
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
}

export interface PrinterStatus {
  printer: Printer;
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

// Audit log types
export interface AuditLog {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  details: string;
  source_printer_id?: string;
  target_printer_id?: string;
  success: boolean;
  error_message?: string;
}

// App info
export interface AppInfo {
  version: string;
  version_string: string;
  app_name: string;
}

// Notification settings
export interface SmtpSettings {
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  password: string;
  from_address: string;
  to_addresses: string;
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
