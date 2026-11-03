import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, ParamMap, Params, Router } from '@angular/router';
import {
  Observable,
  Subject,
  catchError,
  debounceTime,
  finalize,
  merge,
  of,
  switchMap,
  timer,
} from 'rxjs';

import {
  confidenceLevel,
  describeAttack,
  isBlocked,
  isSuppressed,
  isTrusted,
  metadataEntries,
  observedEvidence,
  pendingReviewCount,
} from '../../core/alert-insights';
import {
  Tone,
  enforcementWindow,
  formatScore,
  humanize,
  joinPresent,
  severityTone,
  stateTone,
} from '../../core/format';
import { Alert, AlertFilters, AlertStatus, AlertsView, IpControlAction } from '../../core/models';
import { Session } from '../../core/session';
import { SiemApi, apiErrorMessage } from '../../core/siem-api';
import { AppHeader } from '../../shared/app-header/app-header';

const POLL_MS = 5_000;
const IP_FILTER_DEBOUNCE_MS = 600;
const EXPANDED_STORAGE_KEY = 'cybersiem-expanded-alerts';
const CLEAR_ALL_KEY = 'all-alerts';

const EMPTY_FILTERS: AlertFilters = {
  type: '',
  severity: '',
  status: '',
  ip: '',
  blockedOnly: false,
};

const STATUS_ACTIONS: readonly { status: AlertStatus; label: string }[] = [
  { status: 'unresolved', label: 'Unresolved' },
  { status: 'safe', label: 'Safe' },
  { status: 'malicious', label: 'Malicious' },
];

const STATUS_TONES: Record<AlertStatus, Tone> = {
  unresolved: 'amber',
  safe: 'emerald',
  malicious: 'red',
};

function sameFilters(a: AlertFilters, b: AlertFilters): boolean {
  return (
    a.type === b.type &&
    a.severity === b.severity &&
    a.status === b.status &&
    a.ip === b.ip &&
    a.blockedOnly === b.blockedOnly
  );
}

function filtersFromQuery(params: ParamMap): AlertFilters {
  return {
    type: params.get('type') ?? '',
    severity: params.get('severity') ?? '',
    status: params.get('status') ?? '',
    ip: params.get('ip') ?? '',
    blockedOnly: params.get('blocked_only') === 'true',
  };
}

function filtersToQuery(filters: AlertFilters): Params {
  return {
    type: filters.type || null,
    severity: filters.severity || null,
    status: filters.status || null,
    ip: filters.ip || null,
    blocked_only: filters.blockedOnly ? 'true' : null,
  };
}

function loadExpandedIds(): ReadonlySet<number> {
  try {
    const stored: unknown = JSON.parse(localStorage.getItem(EXPANDED_STORAGE_KEY) ?? '[]');
    return new Set(Array.isArray(stored) ? stored.map(Number).filter(Number.isFinite) : []);
  } catch {
    return new Set();
  }
}

function toRow(alert: Alert) {
  const confidence = confidenceLevel(alert.confidence);
  // Confidence levels reuse the severity colours (high = red, medium = amber).
  const confidenceTone = severityTone(confidence, 'muted');
  return {
    alert,
    stateLabel: alert.current_state || 'trusted',
    stateTone: (alert.current_state === 'unknown'
      ? 'strong'
      : stateTone(alert.current_state, 'emerald')) as Tone,
    severityTone: severityTone(alert.severity, 'strong'),
    statusTone: STATUS_TONES[alert.status] ?? 'emerald',
    confidence,
    confidenceTone,
    confidenceDetailTone: (confidenceTone === 'muted' ? 'strong' : confidenceTone) as Tone,
    description: describeAttack(alert.type),
    evidence: observedEvidence(alert.metadata),
    metadata: metadataEntries(alert.metadata),
    location: joinPresent([alert.city, alert.subdivision, alert.country]),
    nonPublicScope: alert.ip_scope && alert.ip_scope !== 'public' ? alert.ip_scope : null,
    enforcement:
      (alert.current_state || alert.reputation_status || 'trusted') +
      (alert.blocked_reason ? ` (${humanize(alert.blocked_reason)})` : ''),
    enforcementWindow: enforcementWindow(alert, 'blocked ') ?? 'no active timer',
    analystControls: alert.whitelist ? 'whitelisted' : alert.analyst_override || 'none',
    blocked: isBlocked(alert),
    trusted: isTrusted(alert),
    suppressed: isSuppressed(alert),
    pendingReview: pendingReviewCount(alert),
  };
}

@Component({
  imports: [AppHeader, DatePipe, ReactiveFormsModule],
  selector: 'app-alerts',
  styleUrl: './alerts.css',
  templateUrl: './alerts.html',
})
export class Alerts {
  private readonly api = inject(SiemApi);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly session = inject(Session);

  protected readonly statusActions = STATUS_ACTIONS;
  protected readonly clearAllKey = CLEAR_ALL_KEY;
  protected readonly humanize = humanize;
  protected readonly formatScore = formatScore;

  protected readonly filterForm = inject(NonNullableFormBuilder).group({ ...EMPTY_FILTERS });
  protected readonly filters = signal<AlertFilters>(EMPTY_FILTERS, { equal: sameFilters });
  protected readonly view = signal<AlertsView | null>(null);
  protected readonly loadFailed = signal(false);
  protected readonly actionError = signal<string | null>(null);
  protected readonly expanded = signal<ReadonlySet<number>>(loadExpandedIds());
  private readonly busy = signal<ReadonlySet<string>>(new Set());
  private readonly reload$ = new Subject<void>();

  protected readonly rows = computed(() => (this.view()?.alerts ?? []).map(toRow));
  protected readonly isFiltered = computed(() => !sameFilters(this.filters(), EMPTY_FILTERS));

  /** Known types, plus the active filter so a URL-provided type stays selected. */
  protected readonly alertTypes = computed(() => {
    const types = this.view()?.alert_types ?? [];
    const active = this.filters().type;
    return active && !types.includes(active) ? [...types, active] : types;
  });

  constructor() {
    const initial = filtersFromQuery(this.route.snapshot.queryParamMap);
    this.filterForm.setValue(initial, { emitEvent: false });
    this.filters.set(initial);

    // Dropdowns and the checkbox apply at once; the IP box waits for typing to pause.
    const { ip, ...immediate } = this.filterForm.controls;
    merge(
      ...Object.values(immediate).map((control) => control.valueChanges),
      ip.valueChanges.pipe(debounceTime(IP_FILTER_DEBOUNCE_MS)),
    )
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.applyFilters());

    // Poll every 5s, restart on filter changes, and reload right after actions.
    toObservable(this.filters)
      .pipe(
        switchMap((filters) =>
          merge(timer(0, POLL_MS), this.reload$).pipe(
            switchMap(() => this.api.alerts(filters).pipe(catchError(() => of(null)))),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((view) => {
        this.loadFailed.set(!view);
        if (view) {
          this.view.set(view);
          this.forgetHiddenRows(view);
        }
      });

    // Keep the URL shareable: /alerts?type=…&severity=…
    effect(() => {
      const queryParams = filtersToQuery(this.filters());
      untracked(() => {
        void this.router.navigate([], { relativeTo: this.route, queryParams, replaceUrl: true });
      });
    });

    effect(() => {
      const ids = [...this.expanded()];
      try {
        localStorage.setItem(EXPANDED_STORAGE_KEY, JSON.stringify(ids));
      } catch {
        // Storage can be unavailable (private mode); expansion just won't persist.
      }
    });
  }

  protected applyFilters(): void {
    const value = this.filterForm.getRawValue();
    this.filters.set({ ...value, ip: value.ip.trim() });
  }

  protected clearFilters(): void {
    this.filterForm.setValue({ ...EMPTY_FILTERS }, { emitEvent: false });
    this.filters.set(EMPTY_FILTERS);
  }

  protected toggle(alertId: number): void {
    this.expanded.update((ids) => {
      const next = new Set(ids);
      if (!next.delete(alertId)) {
        next.add(alertId);
      }
      return next;
    });
  }

  protected isBusy(key: string): boolean {
    return this.busy().has(key);
  }

  protected setStatus(alert: Alert, status: AlertStatus): void {
    this.run(`alert:${alert.id}`, this.api.setAlertStatus(alert.id, status));
  }

  protected blockIp(alert: Alert): void {
    this.run(`ip:${alert.ip}`, this.api.blockIp(alert.ip, alert.endpoint));
  }

  protected releaseIp(alert: Alert): void {
    this.run(`ip:${alert.ip}`, this.api.releaseIp(alert.ip));
  }

  protected controlIp(alert: Alert, action: IpControlAction): void {
    this.run(`ip:${alert.ip}`, this.api.ipControl(alert.ip, action));
  }

  protected clearAllAlerts(): void {
    if (confirm('Delete ALL alerts permanently? This cannot be undone.')) {
      this.run(CLEAR_ALL_KEY, this.api.clearAlerts());
    }
  }

  private run(key: string, request: Observable<unknown>): void {
    if (this.isBusy(key)) {
      return;
    }
    this.setBusy(key, true);
    this.actionError.set(null);
    request.pipe(finalize(() => this.setBusy(key, false))).subscribe({
      next: () => this.reload$.next(),
      error: (error: unknown) => {
        // 401/403 are handled globally by the auth interceptor.
        const handled =
          error instanceof HttpErrorResponse && (error.status === 401 || error.status === 403);
        if (!handled) {
          this.actionError.set(apiErrorMessage(error));
          this.reload$.next();
        }
      },
    });
  }

  private setBusy(key: string, busy: boolean): void {
    this.busy.update((keys) => {
      const next = new Set(keys);
      if (busy) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }

  /** Drop remembered expansions for alerts no longer in the list. */
  private forgetHiddenRows(view: AlertsView): void {
    const visible = new Set(view.alerts.map((alert) => alert.id));
    this.expanded.update((ids) => {
      const kept = [...ids].filter((id) => visible.has(id));
      return kept.length === ids.size ? ids : new Set(kept);
    });
  }
}
