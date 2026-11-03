---
paths:
  - "src/**/*.py"
  - "tests/**/*.py"
  - "scripts/**/*.py"
---

# Python rules
- Python 3.12, `from __future__ import annotations` as the surrounding modules do. Dependencies through `uv` after T-001.
- Domain rules (detectors, `evaluate_ip_reputation`) are pure: no database, no filesystem, no `datetime.now()` where a `now` can be passed in.
- SQL is parameterized in `repository.py` only. Routes don't write SQL.
- Query endpoints bound `limit`, `offset` and `hours`, and in-memory per-IP state gets eviction.
- Config parsing must not silently fall back on security settings.
- Logging: never log passwords, cookies, session secrets or full `DATABASE_URL`.
- Tests: `tests/unit` needs no services; `tests/integration` runs against real Postgres.
