import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Session } from './session';

async function loadUserOrNull(session: Session) {
  try {
    return await session.load();
  } catch {
    // API unreachable: treat as signed out so the login screen can report it.
    return null;
  }
}

function loginUrl(router: Router, returnUrl: string) {
  return router.createUrlTree(['/login'], { queryParams: { returnUrl } });
}

/** Any signed-in user. */
export const authGuard: CanActivateFn = async (_route, state) => {
  const router = inject(Router);
  const user = await loadUserOrNull(inject(Session));
  return user ? true : loginUrl(router, state.url);
};

/** Analyst or admin; read-only users land on the access-denied screen. */
export const analystGuard: CanActivateFn = async (_route, state) => {
  const router = inject(Router);
  const session = inject(Session);
  if (!(await loadUserOrNull(session))) {
    return loginUrl(router, state.url);
  }
  return session.isAnalyst()
    ? true
    : router.createUrlTree(['/denied'], { queryParams: { required: 'analyst' } });
};

/** The login screen is only for signed-out visitors. */
export const guestGuard: CanActivateFn = async () => {
  const router = inject(Router);
  const user = await loadUserOrNull(inject(Session));
  return user ? router.createUrlTree(['/dashboard']) : true;
};
