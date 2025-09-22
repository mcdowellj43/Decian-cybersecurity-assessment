// Core types for the cybersecurity assessment platform

export interface Organization {
  id: string;
  name: string;
  settings: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Agent {
  id: string;
  org_id: string;
  hostname: string;
  version: string;
  last_seen: string;
  configuration: AgentConfiguration;
  status: 'online' | 'offline' | 'error';
}

export interface AgentConfiguration {
  modules: string[];
  settings: Record<string, any>;
}

export interface Assessment {
  id: string;
  org_id: string;
  agent_id: string;
  start_time: string;
  end_time?: string;
  status: 'running' | 'completed' | 'failed' | 'pending';
  metadata: AssessmentMetadata;
  results?: AssessmentResult[];
  overall_risk_score?: number;
}

export interface AssessmentMetadata {
  hostname: string;
  os_version: string;
  agent_version: string;
  modules_run: string[];
  total_checks: number;
}

export interface AssessmentResult {
  id: string;
  assessment_id: string;
  check_type: CheckType;
  result_data: any;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
  recommendations?: string[];
}

export interface Report {
  id: string;
  assessment_id: string;
  template_version: string;
  html_content: string;
  created_at: string;
  title: string;
  organization_name: string;
}

// Assessment module types
export type CheckType =
  | 'accounts-bypass-pass-policy'
  | 'DC-open-ports-check'
  | 'DNS-config-check'
  | 'EOL-software-check'
  | 'enabled-inactive-accounts'
  | 'network-protocols-check'
  | 'pshell-exec-policy-check'
  | 'service-accounts-domain-admin'
  | 'privileged-accounts-no-expire'
  | 'win-feature-security-check'
  | 'win-firewall-status-check'
  | 'win-update-check'
  | 'password-crack'
  | 'kerberoasted-accounts'
  | 'smb-signing-check';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type AssessmentStatus = 'pending' | 'running' | 'completed' | 'failed';

// Dashboard specific types
export interface DashboardStats {
  total_assessments: number;
  active_agents: number;
  average_risk_score: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

export interface RiskTrend {
  date: string;
  risk_score: number;
  assessments_count: number;
}

export interface ModuleStatus {
  name: string;
  display_name: string;
  status: 'enabled' | 'disabled';
  last_run?: string;
  findings_count: number;
  risk_level: RiskLevel;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    total_pages: number;
  };
}

// Form types
export interface AssessmentRequest {
  agent_id: string;
  modules: string[];
  configuration?: Record<string, any>;
}

export interface ReportGenerationRequest {
  assessment_id: string;
  template?: string;
  include_remediation?: boolean;
  include_technical_details?: boolean;
}

// User and authentication types
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user' | 'viewer';
  organizationId: string;
  organizationName: string;
  created_at?: string;
  last_login?: string;
}

export interface AuthUser extends User {}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  tokens: AuthTokens;
}

export interface RegisterRequest {
  email: string;
  name: string;
  password: string;
  organizationName?: string;
}

// Navigation and UI types
export interface NavigationItem {
  name: string;
  href: string;
  icon: any; // Lucide icon component
  current?: boolean;
  badge?: string | number;
}

export interface TableColumn<T = any> {
  key: keyof T;
  header: string;
  sortable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
}