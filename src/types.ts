export type RoleName = 'ADMIN' | 'SECURITY_ANALYST';
export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertStatus = 'New' | 'Acknowledged' | 'Investigating' | 'Resolved' | 'False Positive';
export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
export type IndicatorType = 'ipv4' | 'domain' | 'url' | 'hash';

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: RoleName;
  is_active: number;
  failed_login_attempts?: number;
  locked_until?: string | null;
  last_login_at?: string | null;
  created_at?: string;
  auth_provider?: 'local' | 'firebase';
}

export interface SecurityEvent {
  id: number;
  event_uid: string;
  timestamp: string;
  source_ip: string;
  username: string;
  event_type: string;
  description: string;
  severity: SeverityLevel;
  user_agent: string;
  detection_status: string;
  rule_triggered: string | null;
  is_demo?: number;
}

export interface DetectionRule {
  id: number;
  rule_code: string;
  name: string;
  description: string;
  event_type_target: string;
  threshold: number;
  time_window_minutes: number;
  severity: SeverityLevel;
  is_enabled: number;
  alerts_triggered_count?: number;
  last_triggered_at?: string | null;
}

export interface AuditLogEntry {
  id: number;
  user_id: number | null;
  username: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string;
  ip_address: string;
  created_at: string;
}

export interface AlertRecord {
  id: number;
  alert_uid: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: AlertStatus;
  rule_id: number;
  rule_code: string;
  rule_name: string;
  source_ip: string;
  target_username: string;
  assigned_to: number | null;
  assigned_username: string;
  investigation_notes: string;
  explanation: string;
  event_count: number;
  window_start: string;
  window_end: string;
  created_at: string;
  updated_at: string;
  is_demo?: number;
}

export interface IncidentRecord {
  id: number;
  incident_uid: string;
  title: string;
  description: string;
  priority: SeverityLevel;
  status: IncidentStatus;
  alert_id: number | null;
  alert_uid?: string | null;
  assigned_to: number | null;
  assigned_username?: string;
  created_by: number;
  created_by_username?: string;
  resolution_summary: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  is_demo?: number;
}

export interface ThreatIndicator {
  id: number;
  indicator_type: 'ipv4' | 'domain' | 'url' | 'hash';
  indicator_value: string;
  reputation_score: number;
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  source: string;
  raw_summary: string;
  queried_by_username?: string;
  cached_until: string;
  created_at: string;
}

export interface DashboardPayload {
  days: number;
  refreshIntervalSeconds: number;
  kpis: {
    totalEvents: number;
    totalAlerts: number;
    criticalAlerts: number;
    highRiskEvents: number;
    openIncidents: number;
    resolvedIncidents: number;
  };
  demoCounts?: {
    events: number;
    alerts: number;
    incidents: number;
  };
  charts: {
    eventsOverTime: Array<{ day: string; count: number }>;
    alertsBySeverity: Array<{ severity: string; count: number }>;
    incidentsByStatus: Array<{ status: string; count: number }>;
    eventCategories: Array<{ event_type: string; count: number }>;
    detectionTrends: Array<{ day: string; count: number }>;
  };
  recentActivity: SecurityEvent[];
  activeAlertsPreview: Array<{
    id: number;
    alert_uid: string;
    title: string;
    severity: SeverityLevel;
    status: AlertStatus;
    source_ip: string;
    created_at: string;
    rule_code: string;
    is_demo?: number;
  }>;
}
