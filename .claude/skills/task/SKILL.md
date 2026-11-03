---
name: task
description: Orchestrate CyberSIEM tasks end to end through the mixed-model pipeline (code, review, tests, pentest, fixes, push), or plan a phase's backlog.
disable-model-invocation: true
argument-hint: "[T-NNN | Pn | empty for the next task]"
---

Target: $ARGUMENTS

- Empty: read `docs/STATE.md` and take its next task. If it has no file yet, create it from `docs/tasks/_TEMPLATE.md` and its row in plan.md §5.
- `T-NNN`: run that task.
- `Pn`: plan that phase (last section), not a task.

You orchestrate and decide. Workers do the work. Stay cheap: give workers paths and short briefs, and read their replies, not their transcripts.

## Pick the tier first
**High risk:** the diff touches auth, sessions, enforcement, scoring, client IP, proxy config, request or log parsing, or audit. **Low risk:** everything else, such as docs, tests of existing behaviour, UI, Docker, CI, and mechanical refactors.

| Step | Low risk | High risk |
|---|---|---|
| Find code | `task ai -- explore <prompt-file>` | same |
| Write code | `task ai -- write <prompt-file>` | `implementer` (Claude Sonnet) |
| Review | `reviewer` (Claude Sonnet) | same, plus `task ai -- review <prompt-file>` |
| Write tests | `task ai -- tests <prompt-file>` (Claude Haiku 5.5) | `test-writer` (Claude Sonnet) |
| Run tests | `task brief -- check` | same |
| Pentest | `task ai -- attack` with an attacker prompt, for code changes | `pentester` (Claude Opus, `effort: high`) |

Prompt files go in `.scan/` (ignored). Inside cmux, prefix `AI_WATCH=1` so the job opens a split I can watch. `task ai` sees only committed code, so commit your work on the task branch before each call. For a review, tell it to read `REVIEW.diff`. Go writers can't run commands. `task ai` applies their patch to your working tree, and **you must read that diff before running tests**, because tests execute whatever was written. Keep a prompt under 200 words, and state its word limit. Never paste `docs/security/` or customer data into one. If a Go model fails or hits a limit, retry once with `AI_MODEL` (for tests: `AI_MODEL=opencode-go/kimi-k3.1-pro`), then fall back to the Claude agents `explorer`, `chore`, `implementer` or `test-writer`.

## Pipeline
1. **Load.** Read the task file. `rg --no-ignore -l '<module>' docs/tasks`, then read only those files' "Learned" sections. If a 🔒 item is undecided, record it in `docs/STATE.md` and skip to the next unblocked task; stop if there's none. Don't guess a 🔒 decision.
2. **Branch** from up-to-date `main`: `git switch -c t-NNN-short-name`.
3. **Write code**, by tier. For a Claude `implementer`, pass the task file's path. For a Go writer, put the goal, files, first failing test and out-of-scope list in the prompt file.
4. **Review:** always the Claude `reviewer`, against the task file. On blocking findings, fix through the same worker: resume `implementer` with `SendMessage`, or rerun `task ai -- write` with the findings. Then review again.
5. **Write tests**, by tier. Read every test before running it: reject any that can't fail, only exercise mocks, or assert too little. A real failing test is a bug: send it to the code's writer, not back to the test.
6. **Test:** `task brief -- check`, plus `task brief -- eval` if detection or scoring changed, plus any `task brief -- security:<name>` that `/verify` lists.
7. **Pentest**, by tier. Save the report to `docs/security/T-NNN.md` (private). Docs-only changes skip this step and step 5, and config-only changes skip step 5 unless the task says otherwise. Review is never skipped.
8. **Fix:** judge every finding yourself. Outside models can be wrong, and never apply one blindly. Real → send it to the writer, add a regression test, rerun steps 4 and 6. False → note why in the private report. Max 2 fix rounds across the task, then stop and write it up in `docs/STATE.md`, with nothing pushed.
9. **Close:** tick the task's checks, set `Status: done`, fill in "Learned" and "Follow-ups", and rewrite `docs/STATE.md` (under 40 lines).
10. **Commit and push:** commit with a Conventional Commit ending in `(T-NNN)`, then `task ship`. The message states what changed, not how to exploit what it fixes. No AI attribution.
11. **Land:** watch the branch's CI (`gh run watch --exit-status`). When `check`, `secrets`, `rules`, `code` and `workflows` are green, then `git switch main && git pull --ff-only && git merge --ff-only <branch> && git push`. On red, treat it as a test failure in step 6. Scanner results that fail outside this diff become follow-ups (T-021), not blockers.

Never push with an open High pentest finding, a failing required check, or a skipped review. Never force-push or rewrite history.

## Then
Take the next task on a fresh branch. After 3 tasks, or when context passes about 40%, stop, name the next task and tell me to run /clear. Also stop on a 🔒 with nothing else unblocked, a failed fix round, or a change you'd want me to look at first.

## Plan a phase
1. Run the previous phase's exit criteria from plan.md §5. If any fails, report it and stop.
2. Read this phase's rows and only the sections they need. Create one `docs/tasks/T-NNN.md` per row from the template. Keep each session-sized, mark each low or high risk, and make the last task prove the exit criteria.
3. Mark 🔒 anything expensive to reverse.
4. Update `docs/STATE.md`, show me the list and wait for my OK.
