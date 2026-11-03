---
name: verify
description: Run CyberSIEM's checks (lint, tests, frontend tests and build, security scans, detection eval) and report only failures. Use before committing any task.
---

Run the narrowest check that covers the change, then the full gate:

1. Python in one area changed: `task test -- tests/unit/<file>.py 2>&1 | tail -n 60`.
2. Then the gate: `task brief -- check` (one line on a pass, the tail on a failure).
3. Detection or scoring changed: `task brief -- eval`, and report any false-positive or detection rate that moved.
4. `src/api/schemas.py` or `frontend/src/app/core/models.ts` changed: confirm both changed together.
5. Docker or NGINX config changed: `task brief -- security:infra`. Then `docker compose -f docker/docker-compose.yml config -q`, exporting dummy values for required secrets, and start the stack if the task's checks need it.
6. Auth, secrets, dependencies or workflows changed: the matching `task brief -- security:<name>`.

`task check` has no Python tests until T-001 lands, so say that instead of implying Python was tested.

Report in ≤ 8 lines: PASS/FAIL per step, and for failures the `path:line` + one-line cause. Never paste full logs.
