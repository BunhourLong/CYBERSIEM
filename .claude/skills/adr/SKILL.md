---
name: adr
description: Write a short architecture decision record for a choice that is expensive to reverse.
disable-model-invocation: true
argument-hint: "[decision title]"
---

Write an ADR for: $ARGUMENTS

1. Find the next number: `ls docs/adr | sort | tail -n 1`.
2. Create `docs/adr/NNNN-kebab-title.md`, max 30 lines:

```
# NNNN. Title
Date: YYYY-MM-DD · Status: proposed | accepted
## Context
(3–5 lines: the problem and constraints)
## Decision
(what we chose, one paragraph)
## Alternatives considered
- Option — why not (one line each, max 3)
## Consequences
- (good and bad, max 4 bullets; how we'd reverse it)
```
3. If it changes a CLAUDE.md invariant or a plan.md section, update that line too and mention it in the suggested commit message.
4. ADRs are tracked and the repo is public: describe decisions, not unfixed vulnerabilities.
