---
name: verify
description: Run CyberSIEM's checks (lint, tests, frontend tests and build, security scans, detection eval) and report only failures. Use before committing any task.
---

Run the narrowest check that covers the change, then the full gate:

1. Python in one area changed: `task test -- tests/unit/<file>.py 2>&1 | tail -n 60`.
2. Then the gate: delegate `task check` to the `test-runner` agent (it returns failures only).
3. Detection or scoring changed: delegate `task eval` to `test-runner`, and report any false-positive or detection rate that moved.
4. `src/api/schemas.py` or `frontend/src/app/core/models.ts` changed: confirm both changed together.
5. Docker or NGINX config changed: delegate `task security:infra` to `test-runner`. Then `docker compose -f docker/docker-compose.yml config -q`, exporting dummy values for required secrets, and start the stack if the task's checks need it.
6. Auth, secrets, dependencies or workflows changed: delegate the matching `task security:<name>` to `test-runner`.

`task check` has no Python tests until T-001 lands, so say that instead of implying Python was tested.

Report in ≤ 8 lines: PASS/FAIL per step, and for failures the `path:line` + one-line cause. Never paste full logs.
