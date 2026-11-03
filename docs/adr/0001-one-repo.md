# 0001. Keep one repository
Date: 2026-11-03 · Status: accepted
## Context
The API, engine and Angular UI live together, and the API image builds and serves the UI. One person maintains it, mostly with AI agents that work best with everything in reach.
## Decision
Keep a single repository with `src/`, `frontend/`, `docker/` and `stack/`. A change to the API contract and its UI ships in one diff, and one gate covers both.
## Alternatives considered
- Separate frontend and backend repos — two gates and versioned contract sync with no independent team or release cadence to justify it.
- Formal monorepo tooling (Nx, Turborepo) — one Python app and one Angular app don't need it; Taskfile is enough.
## Consequences
- One `task check`, one CI, atomic contract changes, and agents never lack context.
- CI runs both stacks on every change; path filters can trim that if it gets slow.
- To reverse: `git subtree split` on `frontend/`.
