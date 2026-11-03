import { Component, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';

import { Session } from '../../core/session';
import { AppHeader } from '../../shared/app-header/app-header';

@Component({
  imports: [AppHeader, RouterLink],
  selector: 'app-denied',
  styleUrl: './denied.css',
  templateUrl: './denied.html',
})
export class Denied {
  /** Minimum role the rejected screen or action needs (query param). */
  readonly required = input<string>();

  protected readonly session = inject(Session);
}
