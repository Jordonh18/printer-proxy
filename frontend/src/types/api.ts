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

// Workflow types
export interface WorkflowPort {
  id: string;
  label?: string;
  type?: string;
  required?: boolean;
}

export interface WorkflowConfigFieldOption {
  label: string;
  value: string;
}

export interface WorkflowConfigFieldValidation {
  pattern?: string;
  patternMessage?: string;
  min?: number;
  max?: number;
  minLength?: number;
  maxLength?: number;
}

export interface WorkflowConfigField {
  key: string;
  label: string;
  type: 'string' | 'number' | 'boolean' | 'select' | 'email' | 'textarea' | 'url' | 'printer_id' | 'json';
  placeholder?: string;
  options?: WorkflowConfigFieldOption[];
  readOnly?: boolean;
  helperText?: string;
  supportsDynamic?: boolean;
  /** Variable types this field can accept (e.g., ['string', 'email']). Empty = accepts all string-like types */
  acceptsTypes?: string[];
  required?: boolean;
  validation?: WorkflowConfigFieldValidation;
  /** Field group for UI organization */
  group?: string;
  /** Icon name for the field */
  icon?: string;
  /** Width hint: 'full' | 'half' */
  width?: 'full' | 'half';
}

export interface WorkflowOutputSchema {
  key: string;
  type: 'string' | 'number' | 'boolean' | 'object' | string;
  description: string;
}

export interface WorkflowRegistryNode {
  id: number;
  key: string;
  node_key?: string;
  name: string;
  description: string;
  category: 'trigger' | 'action' | 'transform' | 'conditional' | 'integration' | string;
  color: string;
  icon?: string;
  inputs: WorkflowPort[];
  outputs: WorkflowPort[];
  output_schema?: Array<{
    key: string;
    type: string;
    description: string;
  }>;
  config_schema?: {
    fields: WorkflowConfigField[];
  } | null;
  default_properties?: Record<string, unknown>;
  allow_multiple_inputs?: boolean;
  enabled: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface WorkflowNode {
  id: string;
  type: string;
  label?: string;
  position: {
    x: number;
    y: number;
  };
  properties?: Record<string, unknown>;
}

export interface WorkflowEdge {
  id: string | number;
  source: string;
  target: string;
  sourceHandle?: string | null;
  targetHandle?: string | null;
}

export interface Workflow {
  id: string;
  name: string;
  description?: string | null;
  is_active: boolean;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  ui_state?: Record<string, unknown> | null;
  nodes?: WorkflowNode[];
  edges?: WorkflowEdge[];
}

// ============================================================================
// Network Types
// ============================================================================

export interface NetworkInterface {
  name: string;
  state: 'up' | 'down' | 'unknown';
  mac: string;
  mtu: string;
  speed: string;
  primary_ip: string;
  cidr: string;
  gateway: string;
  vlan: string;
  is_secondary?: boolean;
}

export interface ClaimedIP {
  ip: string;
  interface: string;
  owner_type: 'redirect' | 'workflow' | 'manual' | 'unknown';
  owner_id: number | null;
  owner_name: string | null;
  status: 'active' | 'pending' | 'error' | 'orphaned';
  redirect_info?: {
    source_printer_id: string | null;
    source_printer_name: string | null;
    target_printer_id: string | null;
    target_printer_name: string | null;
    port: number | null;
    enabled_at: string | null;
    enabled_by: string | null;
  } | null;
}

export interface RoutingInfo {
  ip_forwarding: boolean;
  nat_enabled: boolean;
  policy_routing: boolean;
  default_gateway: string | null;
  default_interface: string | null;
}

export interface TrafficFlow {
  redirect_id: number;
  source_ip: string;
  source_port: number;
  target_ip: string;
  target_port: number;
  protocol: string;
  nat_type: string;
  interface: string;
  source_printer_name: string;
  target_printer_name: string;
  active_connections: number;
  bytes_forwarded: string;
  enabled_at: string;
  enabled_by: string;
}

export interface NetworkWarning {
  type: 'error' | 'warning' | 'info';
  message: string;
  remediation?: string;
}

export interface NetworkOverview {
  interfaces: NetworkInterface[];
  claimed_ips: ClaimedIP[];
  routing: RoutingInfo;
  traffic_flows: TrafficFlow[];
  warnings: NetworkWarning[];
  ports_intercepted: number[];
  default_interface: string;
}

export interface ArpEntry {
  ip: string;
  mac: string;
  interface: string;
  state: string;
}

export interface PortInfo {
  port: number;
  protocol: string;
  name: string;
  redirect_count: number;
  redirects: Array<{
    id: number;
    source_ip: string;
    target_ip: string;
  }>;
  status: 'active' | 'available';
}

export interface SafetyInfo {
  ip_conflict_detection: boolean;
  refuse_active_ips: boolean;
  arp_rate_limiting: boolean;
  max_claimed_ips_per_interface: number;
  current_claimed_count: number;
  warnings: string[];
}

export interface DiagnosticResult {
  ip: string;
  port?: number;
  result: 'success' | 'failed' | 'error' | 'response' | 'no_response' | 'arping_not_available';
  rtt_ms?: number | null;
  latency_ms?: number | null;
  mac?: string;
}

// ============================================================================
// Integration Types
// ============================================================================

export interface IntegrationConfigFieldOption {
  value: string;
  label: string;
}

export interface IntegrationConfigFieldValidation {
  min?: number;
  max?: number;
  pattern?: string;
}

export interface IntegrationConfigField {
  name: string;
  label: string;
  type: 'text' | 'password' | 'url' | 'number' | 'select' | 'multiselect' | 'boolean' | 'json';
  required: boolean;
  default?: unknown;
  description?: string;
  placeholder?: string;
  sensitive?: boolean;
  options?: IntegrationConfigFieldOption[];
  validation?: IntegrationConfigFieldValidation;
  depends_on?: Record<string, unknown>;
}

export interface IntegrationMetadata {
  id: string;
  name: string;
  description: string;
  category: 'logging' | 'monitoring' | 'alerting' | 'ticketing' | 'communication' | 'security' | 'automation';
  auth_type: 'none' | 'api_key' | 'oauth2' | 'basic' | 'token' | 'webhook_secret' | 'certificate';
  capabilities: string[];
  icon: string;
  color: string;
  version: string;
  vendor: string;
  docs_url?: string;
  support_url?: string;
  config_schema?: IntegrationConfigField[];
  required_scopes?: string[];
  optional_scopes?: string[];
  webhook_config?: {
    supported: boolean;
    signature_header?: string;
    signature_algorithm?: string;
  };
  beta?: boolean;
  deprecated?: boolean;
}

export interface IntegrationConnection {
  id: string;
  integration_id: string;
  name: string;
  description?: string;
  user_id: number;
  config: Record<string, unknown>;
  credentials?: Record<string, string>;
  status: 'disconnected' | 'connecting' | 'connected' | 'error' | 'rate_limited' | 'authenticating' | 'pending_oauth';
  last_connected_at?: string | null;
  last_error?: string | null;
  error_count: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  integration?: {
    id: string;
    name: string;
    category: string;
    icon: string;
    color: string;
  };
}

export interface IntegrationConnectionHealth {
  status: string;
  last_check?: string;
  last_success?: string;
  last_error?: string;
  response_time_ms?: number;
  details?: Record<string, unknown>;
}

export interface IntegrationEventType {
  type: string;
  description: string;
  category: string;
}

export interface IntegrationEventRouting {
  event_type: string;
  enabled: boolean;
  filters: Record<string, unknown>;
  transform?: Record<string, unknown>;
  priority: number;
}

export interface IntegrationConnectionHistoryEntry {
  id: number;
  action: string;
  details?: Record<string, unknown>;
  status?: string;
  error_message?: string;
  created_at: string;
}


