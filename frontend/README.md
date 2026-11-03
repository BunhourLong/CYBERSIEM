# Cappa UI

Angular 22 front end for the Cappa SIEM. See the "Frontend Development" section of the
root README for how it is built and served.

```
src/app/
├── core/                 # SiemApi (HTTP), Session, route guards, interceptor, helpers
├── shared/app-header/    # Top bar used by every signed-in screen
└── pages/
    ├── login/            # /login
    ├── dashboard/        # /dashboard (+ attack-map/ Leaflet component)
    ├── alerts/           # /alerts   (analyst or admin)
    └── denied/           # /denied   (role check failed)
```

Each component has its own `.html`, `.ts` and `.css` file. Global tokens and shared
primitives (buttons, panels, tables, tone colours) are in `src/styles.css`.

```bash
npm ci
npm start        # dev server on :4200, proxies /api to localhost:8000
npm test         # Vitest unit tests
npm run build    # dist/cappa/browser (copied into the api image)
```

API URLs are relative (`api/...`) so the same build works at `/` and behind the stack
proxy at `/siem/`, which rewrites `<base href>`.
