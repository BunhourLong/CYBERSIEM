import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';

import {
  AlertFilters,
  AlertStatus,
  AlertsView,
  BlockedIp,
  CurrentUser,
  DashboardView,
  IpControlAction,
  MapPoint,
  Alert,
} from './models';

const ALERT_LIMIT = 100;
const SUPPRESS_SECONDS = 3600;

// URLs are relative on purpose: they resolve against <base href>, so the same
// build works at / and behind the stack proxy at /siem/.
@Injectable({ providedIn: 'root' })
export class SiemApi {
  private readonly http = inject(HttpClient);

  me() {
    return this.http.get<CurrentUser>('api/auth/me');
  }

  login(username: string, password: string) {
    return this.http.post<CurrentUser>('api/auth/login', { username, password });
  }

  logout() {
    return this.http.post<void>('api/auth/logout', null);
  }

  dashboard() {
    return this.http.get<DashboardView>('api/ui/dashboard');
  }

  mapPoints() {
    return this.http.get<MapPoint[]>('api/ui/map-points');
  }

  alerts(filters: AlertFilters) {
    let params = new HttpParams().set('limit', ALERT_LIMIT);
    if (filters.type) params = params.set('type', filters.type);
    if (filters.severity) params = params.set('severity', filters.severity);
    if (filters.status) params = params.set('status', filters.status);
    if (filters.ip) params = params.set('ip', filters.ip);
    if (filters.blockedOnly) params = params.set('blocked_only', true);
    return this.http.get<AlertsView>('api/ui/alerts', { params });
  }

  setAlertStatus(alertId: number, status: AlertStatus) {
    return this.http.post<Alert>(`api/alerts/${alertId}/status`, { status });
  }

  blockIp(ip: string, endpoint: string) {
    return this.http.post<BlockedIp>('api/blocked-ips', {
      ip,
      endpoint,
      reason: 'Manual block requested by analyst',
    });
  }

  releaseIp(ip: string) {
    return this.http.delete<BlockedIp>(`api/blocked-ips/${encodeURIComponent(ip)}`);
  }

  ipControl(ip: string, action: IpControlAction) {
    const duration_seconds = action === 'suppress_auto_block' ? SUPPRESS_SECONDS : undefined;
    return this.http.post<BlockedIp>('api/ip-controls', { ip, action, duration_seconds });
  }

  clearAlerts() {
    return this.http.delete<{ deleted: number }>('api/alerts');
  }
}

/** Human-readable message for a failed API call. */
export function apiErrorMessage(error: unknown): string {
  if (!(error instanceof HttpErrorResponse)) {
    return 'Something went wrong. Please try again.';
  }
  if (error.status === 0) {
    return 'Cannot reach the Cappa API.';
  }
  const detail: unknown = error.error?.detail;
  if (typeof detail === 'string' && detail) {
    return detail;
  }
  return `Request failed (HTTP ${error.status}).`;
}
