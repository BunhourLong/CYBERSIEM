import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

import { Session } from './session';

/**
 * Session expiry (401) sends the user back to the login screen; a role
 * rejection (403) shows the access-denied screen. Auth calls handle their own
 * errors, so they are left alone.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const session = inject(Session);

  return next(req).pipe(
    catchError((error: unknown) => {
      if (error instanceof HttpErrorResponse && !req.url.startsWith('api/auth/')) {
        if (error.status === 401) {
          session.clear();
          void router.navigate(['/login'], { queryParams: { returnUrl: router.url } });
        } else if (error.status === 403) {
          const detail = String(error.error?.detail ?? '');
          const required = detail.toLowerCase().startsWith('admin') ? 'admin' : 'analyst';
          void router.navigate(['/denied'], { queryParams: { required } });
        }
      }
      return throwError(() => error);
    }),
  );
};
