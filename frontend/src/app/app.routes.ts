import { Routes } from '@angular/router';

import { analystGuard, authGuard, guestGuard } from './core/auth-guard';

// Every path here must also be served the SPA shell by FastAPI (src/api/main.py).
export const routes: Routes = [
  {
    path: 'login',
    title: 'Cappa Login',
    canActivate: [guestGuard],
    loadComponent: () => import('./pages/login/login').then((m) => m.Login),
  },
  {
    path: 'dashboard',
    title: 'Cappa Dashboard',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/dashboard/dashboard').then((m) => m.Dashboard),
  },
  {
    path: 'alerts',
    title: 'Cappa Alerts',
    canActivate: [analystGuard],
    loadComponent: () => import('./pages/alerts/alerts').then((m) => m.Alerts),
  },
  {
    path: 'denied',
    title: 'Cappa — Access Denied',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/denied/denied').then((m) => m.Denied),
  },
  { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
  { path: '**', redirectTo: 'dashboard' },
];
