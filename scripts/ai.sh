#!/usr/bin/env bash
# Run one bounded job on an OpenCode Go model, like a subagent reached over the shell.
# It works in a history-free clone of HEAD, so untracked private docs never reach the provider.
# Usage: scripts/ai.sh <explore|write|tests|review> <prompt-file>
set -euo pipefail

role="${1:-}"
prompt_file="${2:-}"
case "$role" in
  explore) agent=reader; model=opencode-go/deepseek-v4.1-flash ;;
  write)   agent=writer; model=opencode-go/deepseek-v4.1-flash ;;
  tests)   agent=writer; model=opencode-go/claude-haiku-5-5 ;;
  review)  agent=reader; model=opencode-go/gemini-4-argon ;;
  *) echo "Usage: scripts/ai.sh <explore|write|tests|review> <prompt-file>" >&2; exit 2 ;;
esac
model="${AI_MODEL:-$model}"
[ -s "$prompt_file" ] || { echo "Prompt file is missing or empty: $prompt_file" >&2; exit 2; }

repo="$(git rev-parse --show-toplevel)"
scan="$repo/.scan"
events="$scan/ai-$role.jsonl"
errors="$scan/ai-$role.err"
reply="$scan/ai-$role.txt"
patch="$scan/ai-$role.patch"
mkdir -p "$scan"
: > "$patch"

if [ -n "$(git -C "$repo" ls-files plan.md docs/STATE.md docs/tasks docs/security)" ]; then
  echo "Private docs are tracked, so they would reach the provider. Aborting." >&2
  exit 1
fi
if [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "Commit first: this job only sees committed code." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone -q --depth 1 --no-tags "file://$repo" "$work/repo"

# Prefer origin/main: a stale local main would widen the diff under review.
base=main
git -C "$repo" show-ref --verify -q refs/remotes/origin/main && base=origin/main
git -C "$repo" diff "$base...HEAD" > "$work/repo/REVIEW.diff"

status=0
# Claude config on this machine is private and adds tokens, so OpenCode shouldn't load it.
OPENCODE_DISABLE_CLAUDE_CODE=1 opencode run --dir "$work/repo" -m "$model" --agent "$agent" --format json "$(cat "$prompt_file")" \
  > "$events" 2> "$errors" < /dev/null || status=$?

api_error="$(jq -r 'select(.type=="error") | .error.data.message // .error.name' "$events" 2>/dev/null || echo "unreadable output")"
if [ "$status" -ne 0 ] || [ -n "$api_error" ]; then
  echo "opencode failed: ${api_error:-exit $status}" >&2
  tail -n 5 "$errors" >&2
  exit 1
fi

jq -r 'select(.type=="text") | .part.text' "$events" > "$reply"
jq -r --arg role "$role" --arg model "$model" \
  'select(.type=="step_finish") | .part | [(now | todate), $role, $model, .cost, .tokens.input, .tokens.cache.read, .tokens.output] | @tsv' \
  "$events" >> "$scan/ai-usage.tsv"
[ -s "$reply" ] || { echo "opencode returned nothing" >&2; exit 1; }

if [ "$agent" = writer ]; then
  rm -f "$work/repo/REVIEW.diff"
  git -C "$work/repo" add -A
  changed="$(git -C "$work/repo" diff --cached --no-renames --name-only)"

  # Permission rules only cover the edit tool, so check what actually changed before applying it.
  if printf '%s\n' "$changed" | grep -qE '^(\.github|\.claude|\.opencode|scripts)/|^(Taskfile\.yml|opencode\.json|CLAUDE\.md)$|(^|/)\.env|\.mmdb$'; then
    echo "Refused: the job changed a protected path:" >&2
    printf '%s\n' "$changed" >&2
    exit 1
  fi
  if [ "$role" = tests ] && printf '%s\n' "$changed" | grep -vE '^tests/|\.spec\.ts$' | grep -q .; then
    echo "Refused: a test job changed non-test files:" >&2
    printf '%s\n' "$changed" >&2
    exit 1
  fi

  git -C "$work/repo" diff --cached --no-renames --binary > "$patch"
  [ ! -s "$patch" ] || git -C "$repo" apply "$patch"
fi

cat "$reply"
