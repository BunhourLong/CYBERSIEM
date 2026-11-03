import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { CurrentUser } from './models';
import { SiemApi } from './siem-api';

@Injectable({ providedIn: 'root' })
export class Session {
  private readonly api = inject(SiemApi);
  private readonly router = inject(Router);
  private readonly current = signal<CurrentUser | null>(null);

  readonly user = this.current.asReadonly();
  readonly isAnalyst = computed(() => ['analyst', 'admin'].includes(this.current()?.role ?? ''));
  readonly isAdmin = computed(() => this.current()?.role === 'admin');

  /** The signed-in user, or null when there is no valid session cookie. */
  async load(): Promise<CurrentUser | null> {
    const cached = this.current();
    if (cached) {
      return cached;
    }
    try {
      const user = await firstValueFrom(this.api.me());
      this.current.set(user);
      return user;
    } catch (error) {
      if (error instanceof HttpErrorResponse && error.status === 401) {
        return null;
      }
      throw error;
    }
  }

  async login(username: string, password: string): Promise<void> {
    this.current.set(await firstValueFrom(this.api.login(username, password)));
  }

  async logout(): Promise<void> {
    try {
      await firstValueFrom(this.api.logout());
    } finally {
      this.clear();
      await this.router.navigateByUrl('/login');
    }
  }

  /** Forget the cached user, e.g. after the server reports the session expired. */
  clear(): void {
    this.current.set(null);
  }
}
