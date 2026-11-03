// Mirrors the pydantic contracts in src/api/schemas.py.

export type Role = 'readonly' | 'analyst' | 'admin';
export type AlertStatus = 'unresolved' | 'safe' | 'malicious';
export type IpControlAction =
  'force_unblock' | 'trust' | 'clear_trust' | 'suppress_auto_block' | 'clear_override';

export interface CurrentUser {
  username: string;
  role: Role;
}

export interface Alert {
  id: number;
  event_id: number | null;
  ip: string;
  ip_scope: string | null;
  endpoint: string;
  type: string;
  severity: string;
  status: AlertStatus;
  message: string;
  confidence: number;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string | null;
  country: string | null;
  country_code: string | null;
  city: string | null;
  subdivision: string | null;
  accuracy_radius_km: number | null;
  reputation_status: string | null;
  current_state: string | null;
  current_score: number;
  lifetime_score: number;
  alert_count: number;
  malicious_count: number;
  block_count: number;
  offense_streak: number;
  whitelist: boolean;
  analyst_override: string | null;
  manual_blocked: boolean;
  blocked_reason: string | null;
  threshold_reached: boolean;
  total_alert_count: number;
  safe_alert_count: number;
  unresolved_alert_count: number;
  malicious_alert_count: number;
  alert_hold_active: boolean;
  reputation_reasons: string[];
  block_countdown_seconds: number | null;
  cooldown_countdown_seconds: number | null;
}

export interface BlockedIp {
  ip: string;
  reputation_status: string;
  current_state: string | null;
  current_score: number;
  blocked_reason: string | null;
  manual_blocked: boolean;
  whitelist: boolean;
  analyst_override: string | null;
  alert_hold_active: boolean;
  reputation_reasons: string[];
  block_countdown_seconds: number | null;
  cooldown_countdown_seconds: number | null;
}

export interface MapPoint {
  ip: string;
  lat: number;
  lon: number;
  severity: string;
  type: string;
  country: string | null;
  city: string | null;
  subdivision: string | null;
  accuracy_radius_km: number | null;
  organization: string | null;
  is_hosting_provider: boolean;
}

export interface DashboardStats {
  alert_type_counts: { type: string; count: number }[];
  severity_counts: { severity: string; count: number }[];
  top_ips: { ip: string; alert_count: number; current_state: string; current_score: number }[];
  alerts_per_hour: { hour: string; count: number }[];
  hours_window: number;
}

export interface ReputationTransition {
  id: number;
  ip: string;
  old_state: string;
  new_state: string;
  score_before: number;
  score_after: number;
  trigger_reason: string;
  manual_or_auto: string;
  created_at: string;
}

export interface DashboardView {
  analytics: DashboardStats;
  alert_summary: { loaded: number; unresolved: number; safe: number; malicious: number };
  state_counts: Record<string, number>;
  blocked_ips: BlockedIp[];
  top_offenders: BlockedIp[];
  recent_transitions: ReputationTransition[];
}

export interface AlertsView {
  alerts: Alert[];
  alert_types: string[];
  blocked_ip_count: number;
}

export interface AlertFilters {
  type: string;
  severity: string;
  status: string;
  ip: string;
  blockedOnly: boolean;
}
