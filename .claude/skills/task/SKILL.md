---
name: task
description: Orchestrate CyberSIEM tasks end to end through the subagent pipeline (code, review, tests, pentest, fixes, push), or plan a phase's backlog.
disable-model-invocation: true
argument-hint: "[T-NNN | Pn | empty for the next task]"
---

Target: $ARGUMENTS

- Empty: read `docs/STATE.md` and take its next task. If it has no file yet, create it from `docs/tasks/_TEMPLATE.md` and its row in plan.md §5.
- `T-NNN`: run that task.
- `Pn`: plan that phase (last section), not a task.

You orchestrate and decide. Agents do the work. Stay cheap: pass each agent the task file's path, not its contents, and don't re-read what an agent reports unless a decision needs it.

## Pipeline
1. **Load.** Read the task file. `rg --no-ignore -l '<module>' docs/tasks`, then read only those files' "Learned" sections. If a 🔒 item is undecided, record it in `docs/STATE.md` and skip to the next unblocked task; stop if there's none. Don't guess a 🔒 decision.
2. **Branch** from up-to-date `main`: `git switch -c t-NNN-short-name`.
3. **Write code:** `implementer`. Pass the task file and the patterns `explorer` found, if any.
4. **Review:** `reviewer`, against the task file. On blocking findings, resume the same `implementer` with `SendMessage` (it keeps its context, which is cheaper than a new agent), then review again.
5. **Write tests:** `test-writer`. A failing test it reports is a bug: resume `implementer`, not the test.
6. **Test:** `test-runner` runs `task check`, plus `task eval` if detection or scoring changed, plus any `task security:<name>` that `/verify` lists for this change.
7. **Pentest:** `pentester`. For a diff touching auth, enforcement, scoring, client IP, proxy config or anything parsing request text, invoke it with `effort: high`. Save the report to `docs/security/T-NNN.md` (private).
8. **Fix:** judge each finding yourself; agents can be wrong. Real → resume `implementer`, ask `test-writer` for a regression test, rerun steps 4 and 6. False → note why in the private report. Max 2 fix rounds across the task, then stop and write it up in `docs/STATE.md`, with nothing pushed.
9. **Close:** tick the task's checks, set `Status: done`, fill in "Learned" and "Follow-ups", and rewrite `docs/STATE.md` (under 40 lines).
10. **Commit and push:** `git add` the task's files, commit with a Conventional Commit ending in `(T-NNN)`, then `task ship`. The message states what changed, not how to exploit what it fixes. No AI attribution.
11. **Land:** watch the branch's CI (`gh run watch --exit-status`). When `check`, `secrets`, `rules`, `code` and `workflows` are green, then `git switch main && git pull --ff-only && git merge --ff-only <branch> && git push`. On red, treat it as a test failure in step 6. Scanner results that fail outside this diff become follow-ups (T-021), not blockers.

Never push with an open High pentest finding, a failing required check, or a skipped review. Never force-push or rewrite history.

**Skips:** docs-only changes skip steps 5 and 7. Config-only changes skip step 5 unless the task says otherwise. Review is never skipped.

## Then
Take the next task on a fresh branch. After 3 tasks, or when context passes about 40%, stop, name the next task and tell me to run /clear. Also stop on a 🔒 with nothing else unblocked, a failed fix round, or a change you'd want me to look at first.

## Plan a phase
Use Opus for this step only (`/model opus`).
1. Run the previous phase's exit criteria from plan.md §5. If any fails, report it and stop.
2. Read this phase's rows and only the sections they need. Create one `docs/tasks/T-NNN.md` per row from the template. Keep each session-sized, and make the last task prove the exit criteria.
3. Mark 🔒 anything expensive to reverse.
4. Update `docs/STATE.md`, show me the list and wait for my OK.
