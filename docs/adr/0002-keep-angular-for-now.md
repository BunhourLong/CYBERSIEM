# 0002. Keep the Angular UI for now
Date: 2026-11-03 · Status: proposed
## Context
Server-rendered HTML views were replaced with an Angular 22 app of about 2,700 lines across login, dashboard, map, alerts and denied screens. The owner's other projects mostly use React, and moving to React was suggested as a possibility.
## Decision
Keep Angular until a feature needs something it can't reasonably do. Spend the effort on tests and security work instead, which a framework change wouldn't improve.
## Alternatives considered
- Rewrite in React + Vite now — matches other projects and shares habits, but costs several sessions, adds regressions with no user-visible gain, and fixes no known issue.
- Rewrite later as part of P2 incident screens — a sensible moment to revisit if the UI grows a lot.
## Consequences
- No rewrite cost, and the working UI ships sooner.
- A framework that differs from the owner's other projects, so less sharing between them.
- To reverse: the JSON API is already separate, and generated types (T-020) make a screen-by-screen port easier later.
