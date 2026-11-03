import { Component, inject, input, signal } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';

import { Session } from '../../core/session';

@Component({
  imports: [RouterLink, RouterLinkActive],
  selector: 'app-header',
  styleUrl: './app-header.css',
  templateUrl: './app-header.html',
})
export class AppHeader {
  readonly subtitle = input.required<string>();
  /** Dashboard link and sign-out only (used by the access-denied screen). */
  readonly minimal = input(false);

  protected readonly session = inject(Session);
  protected readonly signingOut = signal(false);

  protected async signOut(): Promise<void> {
    this.signingOut.set(true);
    try {
      await this.session.logout();
    } finally {
      this.signingOut.set(false);
    }
  }
}
