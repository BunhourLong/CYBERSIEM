#!/usr/bin/env bash
# Second opinion from another vendor's model on this branch's committed changes.
# It reads a clean clone, so untracked private docs never reach the provider.
set -euo pipefail

model="${SECOND_OPINION_MODEL:-gpt-5.6-terra}"
repo="$(git rev-parse --show-toplevel)"
output="$repo/.scan/second-opinion.txt"
errors="$repo/.scan/second-opinion.err"

if [ -n "$(git -C "$repo" ls-files plan.md docs/STATE.md docs/tasks docs/security)" ]; then
  echo "Private docs are tracked, so they would reach the provider. Aborting." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$repo/.scan"
: > "$output"
git clone -q "$repo" "$work/repo"

# Prefer origin/main: a stale local main would widen the diff.
base=refs/heads/main
git -C "$repo" show-ref --verify -q refs/remotes/origin/main && base=refs/remotes/origin/main
git -C "$work/repo" fetch -q "$repo" "$base:refs/heads/review-base"

prompt='Review the output of `git diff review-base...HEAD` in this read-only repository, reading other files only to check a concrete risk.

This service reads NGINX logs, scores client IPs and blocks them. Request and log text is attacker-controlled.

Report only real bugs and security problems: wrong behaviour, trust-boundary violations, ways to block an innocent client, availability failures. No style notes. If you find nothing, say so.

Return at most 250 words: a numbered list, most severe first, each with path:line, the concrete failure, and the smallest fix. Report only what you can support from the code.'

if ! codex exec -C "$work/repo" -m "$model" --sandbox read-only --ephemeral -o "$output" "$prompt" > /dev/null 2> "$errors" < /dev/null; then
  echo "codex failed:" >&2
  tail -n 5 "$errors" >&2
  exit 1
fi
[ -s "$output" ] || { echo "codex returned nothing" >&2; exit 1; }
cat "$output"
