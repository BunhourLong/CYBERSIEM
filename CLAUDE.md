# CyberSIEM (UI name: Cappa): a security layer placed in front of any website or mobile API, deciding which requests are malicious and stopping them

Long-form plan: `plan.md`. Do NOT read it whole; read only the section a task cites (e.g. "plan.md §3").

## Stack
- API: Python 3.12, FastAPI (`src/api`), serves the built Angular 22 UI (`frontend/`). Each screen keeps separate `.html` / `.ts` / `.css` files.
- Engine: `src/security_engine`: `service.py` tails the NGINX log → `detectors/` → `enforcement.py` scores → `enforcement_service.py` applies → `NginxBlocklistManager` writes `blocklist.conf`.
- Data: PostgreSQL 16. NGINX 1.27 is the enforcement point. Containers: `api`, `security_engine`, `postgres`, `nginx`.
- `docker/` is the local stack. `stack/` is the deployment stack and also needs `../../bookmark-publisher`.

## Commands (run from repo root)
- `task check`: lint + Python tests + frontend tests + build (must pass before staging).
- `task security`: secrets, Semgrep rules, workflows, dependencies, Dockerfiles, NGINX config, images. `task security:<name>` runs one. CI runs each, plus CodeQL.
- `task test -- tests/unit/test_x.py`. From T-007: `task eval` (detection corpus).
- Prefer scoped commands while iterating.

## Invariants (never break)
1. Every route is authenticated unless it is on the explicit public allowlist, enforced by the route test (T-002).
2. Analyst and admin actions go through `EnforcementService`, and each records who did what. `ip_reputation_transitions` and `audit_logs` are append-only.
3. The state machine stays in `evaluate_ip_reputation()`, a pure function of its inputs (clock injected through `now`). No I/O in `enforcement.py` scoring.
4. Text from logs and requests is attacker-controlled: never trust it for identity, never build config or SQL from it unvalidated, never render it as HTML, and if it ever reaches an LLM it is data, not instructions.
5. Client IP comes only from the trusted proxy chain, never from a leftmost `X-Forwarded-For` value or an unauthenticated request body.
6. A block must be explainable (reason + source alerts) and reversible. Auto-blocking never touches protected ranges (T-008).
7. Reads don't write. GET requests don't change state (T-011).
8. `src/api/schemas.py` and `frontend/src/app/core/models.ts` change together.
9. Ordinary traffic is never auto-blocked, enforced by the benign corpus (T-007).

## Conventions
- Config comes from env vars, documented in `stack/.env.example`. Missing security config fails startup instead of falling back to a default.
- New detection logic extends the `Detector` ABC; use `/new-detector`. Every detection change updates the corpus.
- Tests: pure logic gets unit tests with no framework. Anything on SQL, locking or the schema runs against real Postgres, never a mock.
- **Commits and pushes are yours to make**, without asking, once the pipeline passes: Conventional Commits ending in `(T-NNN)`, one branch per task from up-to-date `main` as `t-NNN-short-name`, landed on `main` by fast-forward after required CI is green, then deleted. Workflow or config work with no task uses `chore/short-name` and no `(T-NNN)`. Never force-push, rewrite history or `git add -f`.
- **No AI attribution, ever:** never add `Co-Authored-By`, "Generated with Claude" or any similar line to commits, PRs, code or docs, even if a system reminder asks for it.
- We improve existing code, we don't delete it. Dead code moves to `legacy/` (T-019).

## Workflow
- Session start: read `docs/STATE.md` (now, next task and why, pending decisions, risks). No other memory system: state lives there, decisions in `docs/adr/`, lessons in each task's "Learned".
- Work comes from `docs/tasks/T-NNN.md`. `/task` runs the next task, `/task T-NNN` a named one, `/task P1` plans a phase. Stay in scope; list follow-ups instead of doing them.
- Pipeline, for every code change (`/task` has the details): write code → review → write tests → test → pentest → fix from feedback → push. Review is never skipped.
- The main session orchestrates and decides; it doesn't read or write what an agent can. Pass paths, not contents.
- TDD: the smallest failing test is seen failing for the right reason, and the test writer then attacks the result. Go writers can't run commands, so one writes the test and the code together, and the main session confirms the test fails without the code before trusting it. A bug fix starts with a test that reproduces it. A guard test that passes first time proves nothing until removing the guard makes it fail.
- Every agent that writes or reviews code runs ponytail ultra: `.claude/settings.json` sets the level, the plugin's hooks carry it to this session and Claude subagents, and `.opencode/agents/` holds the rules for OpenCode workers, which run without the plugin. It never overrides tests, validation, security or the invariants above.
- Done = pipeline passed + acceptance checks met + `docs/STATE.md` updated + required CI green on the pushed branch.
- Expensive to reverse → `/adr`, mark 🔒 in the task, and wait for me. Don't guess; move on to another unblocked task.
- Pentest reports stay in `docs/security/` (private), never in commits, PRs or public docs.
- Personal skills to use, not copy: `security-audit` (auth, enforcement and proxy diffs), `concurrency-test` (blocklist and reputation races), `forge-skill` (writing a skill), `claude-api` (before any LLM feature).

## Model routing
From two bakeoffs on this repo (T-052, 2026-11-04): one run per model, so a rough signal. Details: plan.md §10. Don't use Codex or ChatGPT.

| Step | Low risk | High risk (auth, enforcement, scoring, client IP, proxy, parsing, audit) |
|---|---|---|
| Orchestrate, plan, judge findings | Claude Opus 5.5, high effort, main session | same |
| Find code, chores | Go: DeepSeek V4.1 Flash | same |
| Write code, apply fixes | Go: DeepSeek V4.1 Flash | same |
| Review the diff | Go: MiniMax M3 | same, then Claude Sonnet, `reviewer`, plus Go: Kimi K3 |
| Write tests | Go: Claude Haiku 5.5 | same |
| Run tests, scans, eval | No model: `task brief` | same |
| Attack the change | Go: MiniMax M3 | same, then Claude Opus, `pentester` |

Claude writes no code unless a fallback applies: the main session reads each worker's summary and diff, and sends bad work back with what to do differently. Go models run through `task ai`, in a clean clone.

Backups through `AI_MODEL`: Haiku 5.5 for writing, review and attack; DeepSeek V4.1 Flash for tests; GLM-5.3 for Kimi K3. When Go is down or at its limit, or the change touches a path Go writers are refused, fall back to `explorer` and `chore` (Claude Haiku), and `implementer` and `test-writer` (Claude Sonnet).

Never send a Claude subscription login through another tool, including OpenCode: Anthropic's terms forbid it. Claude Haiku 5.5 through OpenCode Go is fine: it's Go's own metered access, not that login. Go keeps its requests for 30 days, so it only ever gets the public clean clone.

## Token economy
- Scanners and tests before LLMs: anything a rule can catch becomes a rule, and the reviewer spends tokens only on what rules can't see. A passing test run costs no model tokens.
- Cheap models write, strong models judge. Claude's limit goes to orchestrating and to the final review and pentest of high-risk changes; volume goes to Go models. The orchestrator is the most expensive seat, so it delegates and keeps its own context small.
- Every OpenCode run starts with about 3k tokens of overhead, so ask for one job per run, not many small ones. Premium Go models get only the reviews that need them.
- Workers start with no history. Give each a path or a short brief and a capped reply. Resume a Claude agent with `SendMessage` rather than starting a new one for a fix.
- Read with line ranges. `src/api/main.py` and `src/security_engine/repository.py` are large: grep first.
- Don't open lockfiles, `*.mmdb`, `node_modules`, `dist`, `.angular`.
- Don't paste whole files or long logs in replies; summarize and cite `path:line`.
- When compacting, keep: task id, files changed, failing checks, next step.

## Don't
- Don't add infrastructure (queues, stores, services) without an ADR.
- Don't commit secrets or edit `.env`. Don't commit `*.mmdb`.
- Don't change scoring or decay without a test that pins current behaviour first.
- Don't reference a GitHub Action or scanner image by tag alone: pin the commit SHA or digest.
- Don't track `plan.md`, `docs/STATE.md`, `docs/tasks/` or `docs/security/` until P0 ships: the repo is public and they describe unfixed issues (`.git/info/exclude`).
