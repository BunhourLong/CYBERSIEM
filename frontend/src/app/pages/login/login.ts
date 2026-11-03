import { Component, inject, input, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';

import { Session } from '../../core/session';
import { apiErrorMessage } from '../../core/siem-api';

@Component({
  imports: [ReactiveFormsModule],
  selector: 'app-login',
  styleUrl: './login.css',
  templateUrl: './login.html',
})
export class Login {
  /** Where to go after signing in (set by the auth guard). */
  readonly returnUrl = input<string>();

  private readonly session = inject(Session);
  private readonly router = inject(Router);

  protected readonly form = inject(NonNullableFormBuilder).group({
    username: ['', Validators.required],
    password: ['', Validators.required],
  });
  protected readonly error = signal<string | null>(null);
  protected readonly submitting = signal(false);

  protected async submit(): Promise<void> {
    if (this.form.invalid || this.submitting()) {
      this.form.markAllAsTouched();
      return;
    }
    this.submitting.set(true);
    this.error.set(null);
    const { username, password } = this.form.getRawValue();
    try {
      await this.session.login(username, password);
      await this.router.navigateByUrl(this.safeReturnUrl());
    } catch (error) {
      this.error.set(apiErrorMessage(error));
      this.form.controls.password.reset();
    } finally {
      this.submitting.set(false);
    }
  }

  /** Only follow in-app paths, never another origin. */
  private safeReturnUrl(): string {
    const url = this.returnUrl();
    return url && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/login')
      ? url
      : '/dashboard';
  }
}
