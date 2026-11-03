#!/usr/bin/env bash
# Run one bounded job on an OpenCode Go model, like a subagent reached over the shell.
# It works in a clean clone of HEAD, so untracked private docs never reach the provider.
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
mkdir -p "$scan"

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
git clone -q "$repo" "$work/repo"

# Prefer origin/main: a stale local main would widen the diff under review.
base=refs/heads/main
git -C "$repo" show-ref --verify -q refs/remotes/origin/main && base=refs/remotes/origin/main
git -C "$work/repo" fetch -q "$repo" "$base:refs/heads/review-base"

status=0
opencode run --dir "$work/repo" -m "$model" --agent "$agent" --format json "$(cat "$prompt_file")" \
  > "$events" 2> "$errors" < /dev/null || status=$?

jq -r 'select(.type=="text") | .part.text' "$events" > "$reply"
jq -r --arg role "$role" --arg model "$model" \
  'select(.type=="step_finish") | .part | [(now | todate), $role, $model, .cost, .tokens.input, .tokens.cache.read, .tokens.output] | @tsv' \
  "$events" >> "$scan/ai-usage.tsv"

api_error="$(jq -r 'select(.type=="error") | .error.data.message // .error.name' "$events")"
if [ "$status" -ne 0 ] || [ -n "$api_error" ]; then
  echo "opencode failed: ${api_error:-exit $status}" >&2
  tail -n 5 "$errors" >&2
  exit 1
fi
[ -s "$reply" ] || { echo "opencode returned nothing" >&2; exit 1; }

if [ "$agent" = writer ]; then
  git -C "$work/repo" add -A
  git -C "$work/repo" diff --cached --binary > "$scan/ai-$role.patch"
  [ ! -s "$scan/ai-$role.patch" ] || git -C "$repo" apply "$scan/ai-$role.patch"
fi

cat "$reply"
