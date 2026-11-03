import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { catchError, of, switchMap, timer } from 'rxjs';

import {
  Tone,
  enforcementWindow,
  formatScore,
  humanize,
  percentOf,
  severityTone,
  stateTone,
} from '../../core/format';
import { BlockedIp, DashboardView, MapPoint } from '../../core/models';
import { SiemApi } from '../../core/siem-api';
import { AppHeader } from '../../shared/app-header/app-header';
import { AttackMap } from './attack-map/attack-map';

const REFRESH_MS = 15_000;

/** Bar fill colour for a reputation state (brighter than the text tone). */
function stateBar(state: string): string {
  switch (state) {
    case 'blocked':
      return 'red';
    case 'throttled':
      return 'orange';
    case 'suspicious':
      return 'amber';
    default:
      return 'zinc';
  }
}

function severityBar(severity: string): string {
  switch (severity) {
    case 'high':
      return 'red';
    case 'medium':
      return 'amber';
    default:
      return 'emerald';
  }
}

@Component({
  imports: [AppHeader, AttackMap, DatePipe, RouterLink],
  selector: 'app-dashboard',
  styleUrl: './dashboard.css',
  templateUrl: './dashboard.html',
})
export class Dashboard {
  private readonly api = inject(SiemApi);

  protected readonly view = signal<DashboardView | null>(null);
  protected readonly loadFailed = signal(false);
  protected readonly mapPoints = signal<MapPoint[] | null>(null);
  protected readonly mapFailed = signal(false);

  protected readonly humanize = humanize;
  protected readonly formatScore = formatScore;

  protected readonly topCategories = computed(() => {
    const rows = this.view()?.analytics.alert_type_counts ?? [];
    const max = Math.max(1, ...rows.map((row) => row.count));
    return rows.slice(0, 6).map((row) => ({
      ...row,
      label: humanize(row.type),
      percent: percentOf(row.count, max),
    }));
  });

  protected readonly severityTotal = computed(() =>
    (this.view()?.analytics.severity_counts ?? []).reduce((sum, row) => sum + row.count, 0),
  );

  protected readonly severities = computed(() =>
    (this.view()?.analytics.severity_counts ?? []).map((row) => ({
      ...row,
      tone: severityTone(row.severity, 'soft'),
      bar: severityBar(row.severity),
      percent: percentOf(row.count, this.severityTotal()),
    })),
  );

  protected readonly topIps = computed(() => {
    const rows = this.view()?.analytics.top_ips ?? [];
    const max = Math.max(1, ...rows.map((row) => row.alert_count));
    return rows.slice(0, 8).map((row) => ({
      ...row,
      tone: stateTone(row.current_state, 'muted'),
      bar: stateBar(row.current_state),
      percent: percentOf(row.alert_count, max),
    }));
  });

  protected readonly hourly = computed(() => {
    const rows = this.view()?.analytics.alerts_per_hour ?? [];
    const max = Math.max(1, ...rows.map((row) => row.count));
    return {
      bars: rows.map((row) => ({ ...row, height: Math.max(percentOf(row.count, max), 4) })),
      total: rows.reduce((sum, row) => sum + row.count, 0),
      first: rows.at(0)?.hour ?? null,
      last: rows.at(-1)?.hour ?? null,
    };
  });

  protected readonly snapshot = computed(() => {
    const view = this.view();
    const summary = view?.alert_summary;
    const rows: { label: string; value: number; tone: Tone }[] = [
      { label: 'Loaded alerts', value: summary?.loaded ?? 0, tone: 'bright' },
      { label: 'Blocked IPs', value: view?.blocked_ips.length ?? 0, tone: 'red' },
      { label: 'Unresolved', value: summary?.unresolved ?? 0, tone: 'amber' },
      { label: 'Malicious', value: summary?.malicious ?? 0, tone: 'red' },
      { label: 'Safe', value: summary?.safe ?? 0, tone: 'emerald' },
    ];
    return rows;
  });

  protected readonly reputationStates = computed(() => {
    const counts = this.view()?.state_counts ?? {};
    const states: { key: string; label: string; tone: Tone }[] = [
      { key: 'trusted', label: 'Trusted', tone: 'emerald' },
      { key: 'unknown', label: 'Unknown', tone: 'bright' },
      { key: 'suspicious', label: 'Suspicious', tone: 'amber' },
      { key: 'throttled', label: 'Throttled', tone: 'orange' },
      { key: 'blocked', label: 'Blocked', tone: 'red' },
    ];
    return states.map((state) => ({ ...state, value: counts[state.key] ?? 0 }));
  });

  constructor() {
    timer(0, REFRESH_MS)
      .pipe(
        switchMap(() => this.api.dashboard().pipe(catchError(() => of(null)))),
        takeUntilDestroyed(),
      )
      .subscribe((view) => {
        // Keep showing the last good data if a refresh fails.
        if (view) {
          this.view.set(view);
        }
        this.loadFailed.set(!view);
      });

    timer(0, REFRESH_MS)
      .pipe(
        switchMap(() => this.api.mapPoints().pipe(catchError(() => of(null)))),
        takeUntilDestroyed(),
      )
      .subscribe((points) => {
        this.mapFailed.set(!points);
        this.mapPoints.set(points ?? []);
      });
  }

  protected offenderTone(offender: BlockedIp): Tone {
    return stateTone(offender.current_state, 'strong');
  }

  protected offenderWindow(offender: BlockedIp): string {
    return enforcementWindow(offender) ?? '-';
  }

  protected blockCountdown(blocked: BlockedIp): string {
    return blocked.block_countdown_seconds && blocked.block_countdown_seconds > 0
      ? `${blocked.block_countdown_seconds}s`
      : 'until analyst review';
  }
}
