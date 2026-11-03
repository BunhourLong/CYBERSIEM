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
  tests)   agent=writer; model=opencode-go/kimi-k3.1-pro ;;
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
trap 'rm -rf "$work" ${config:+"$config"}' EXIT
git clone -q --depth 1 --no-tags "file://$repo" "$work/repo"

# Prefer origin/main: a stale local main would widen the diff under review.
base=main
git -C "$repo" show-ref --verify -q refs/remotes/origin/main && base=origin/main
git -C "$repo" diff "$base...HEAD" > "$work/repo/REVIEW.diff"

# Keep .git out of the job's reach: a written .git/config could run code when git reads it later.
mv "$work/repo/.git" "$work/git"

# AI_WATCH=1 runs the job in a new Warp tab so you can follow it, and waits for it here.
watch_job() {
  local name="ai-$role-$$" waited=0
  config="$HOME/.warp/tab_configs/$name.toml"
  cp "$prompt_file" "$work/prompt"
  {
    printf 'work=%q events=%q errors=%q model=%q agent=%q\n' "$work" "$events" "$errors" "$model" "$agent"
    cat <<'EOF'
status=1
trap 'echo "$status" > "$work/done"' EXIT
touch "$work/started"
OPENCODE_DISABLE_CLAUDE_CODE=1 opencode run --dir "$work/repo" -m "$model" --agent "$agent" --format json "$(cat "$work/prompt")" \
  2> "$errors" < /dev/null | tee "$events" | jq --unbuffered -r '
    if .type == "text" then .part.text
    elif .type == "tool_use" then "-> \(.part.tool) \(.part.state.input | tostring | .[0:120])"
    elif .type == "error" then "ERROR: \(.error.data.message // .error.name)"
    else empty end'
status=${PIPESTATUS[0]}
echo; echo "Job finished. You can close this tab."
EOF
  } > "$work/run.sh"
  mkdir -p "$(dirname "$config")"
  printf 'name = "%s"\n\n[[panes]]\nid = "job"\ntype = "terminal"\ndirectory = "%s"\ncommands = ["bash %s/run.sh"]\n' \
    "$name" "$repo" "$work" > "$config"
  open "warp://tab_config/$name"
  until [ -s "$work/done" ]; do
    sleep 1
    waited=$((waited + 1))
    if [ "$waited" -ge 1800 ] || { [ "$waited" -ge 60 ] && [ ! -e "$work/started" ]; }; then
      echo "The Warp tab didn't start or finish the job." >&2
      status=1
      return
    fi
  done
  status="$(cat "$work/done")"
}

status=0
# Claude config on this machine is private and adds tokens, so OpenCode shouldn't load it.
if [ -n "${AI_WATCH:-}" ]; then
  watch_job
else
  OPENCODE_DISABLE_CLAUDE_CODE=1 opencode run --dir "$work/repo" -m "$model" --agent "$agent" --format json "$(cat "$prompt_file")" \
    > "$events" 2> "$errors" < /dev/null || status=$?
fi

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
  clone_git() { git --git-dir="$work/git" --work-tree="$work/repo" -c core.quotePath=false "$@"; }
  clone_git add -A
  changed="$(clone_git diff --cached --no-renames --name-only)"

  # Permission rules only cover the edit tool, so check what actually changed before applying it.
  if grep -qE '^(\.github|\.claude|\.opencode|scripts)/|^(Taskfile\.yml|opencode\.json|CLAUDE\.md)$|(^|/)\.env|\.mmdb$' <<< "$changed"; then
    echo "Refused: the job changed a protected path:" >&2
    printf '%s\n' "$changed" >&2
    exit 1
  fi
  if [ "$role" = tests ] && [ -n "$changed" ] && grep -qvE '^tests/|\.spec\.ts$' <<< "$changed"; then
    echo "Refused: a test job changed non-test files:" >&2
    printf '%s\n' "$changed" >&2
    exit 1
  fi

  clone_git diff --cached --no-renames --binary > "$patch"
  [ ! -s "$patch" ] || git -C "$repo" apply "$patch"
fi

cat "$reply"
