#!/usr/bin/env bash
# Run one bounded job on an OpenCode Go model, like a subagent reached over the shell.
# It works in a history-free clone of HEAD, so untracked private docs never reach the provider.
# Usage: scripts/ai.sh <explore|write|tests|review|attack> <prompt-file>
set -euo pipefail

role="${1:-}"
prompt_file="${2:-}"
case "$role" in
  explore) agent=reader; model=opencode-go/deepseek-v4.1-flash ;;
  write)   agent=writer; model=opencode-go/deepseek-v4.1-flash ;;
  tests)   agent=writer; model=opencode-go/claude-haiku-5-5 ;;
  review)  agent=reader; model=opencode-go/glm-5.2 ;;
  attack)  agent=reader; model=opencode-go/claude-haiku-5-5 ;;
  *) echo "Usage: scripts/ai.sh <explore|write|tests|review|attack> <prompt-file>" >&2; exit 2 ;;
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
server=""
surface=""
cleanup() {
  if [ -n "$surface" ]; then
    # Keep a watched job readable for 10 minutes after it ends.
    # shortcut: the kill could hit a reused PID if the server died early, upgrade if that ever happens.
    nohup bash -c 'sleep 600; cmux close-surface --surface "$1"; kill "$2"; rm -rf "$3"' _ "$surface" "$server" "$work" > /dev/null 2>&1 &
    return
  fi
  [ -z "$server" ] || kill "$server" 2> /dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
git clone -q --depth 1 --no-tags "file://$repo" "$work/repo"

# Prefer origin/main: a stale local main would widen the diff under review.
base=main
git -C "$repo" show-ref --verify -q refs/remotes/origin/main && base=origin/main
git -C "$repo" diff "$base...HEAD" > "$work/repo/REVIEW.diff"

# Keep .git out of the job's reach: a written .git/config could run code when git reads it later.
mv "$work/repo/.git" "$work/git"

# AI_WATCH=1 shows the job's real OpenCode interface in a new cmux split. Run from inside cmux.
watch_job() {
  local url="" session="" waited=0 job
  openssl rand -hex 16 > "$work/password"
  OPENCODE_SERVER_PASSWORD="$(cat "$work/password")"
  export OPENCODE_SERVER_PASSWORD
  # Start in the clone, so the server never treats the real repo as its project.
  (cd "$work/repo" && OPENCODE_DISABLE_CLAUDE_CODE=1 exec opencode serve > "$work/serve.log" 2>&1 < /dev/null) &
  server=$!
  until [ -n "$url" ] || [ "$waited" -ge 30 ]; do
    sleep 1
    waited=$((waited + 1))
    url="$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$work/serve.log" | head -n 1 || true)"
  done
  [ -n "$url" ] || { echo "opencode serve didn't start." >&2; status=1; return; }

  OPENCODE_DISABLE_CLAUDE_CODE=1 opencode run --attach "$url" --dir "$work/repo" -m "$model" --agent "$agent" --format json "$(cat "$prompt_file")" \
    > "$events" 2> "$errors" < /dev/null &
  job=$!
  waited=0
  until [ -n "$session" ] || ! kill -0 "$job" 2> /dev/null || [ "$waited" -ge 60 ]; do
    sleep 1
    waited=$((waited + 1))
    session="$(head -n 1 "$events" | jq -r '.sessionID // empty' 2> /dev/null || true)"
  done
  if [ -n "$session" ]; then
    surface="$(cmux new-split right --command "OPENCODE_SERVER_PASSWORD=\$(cat $work/password) opencode attach $url --dir $work/repo -s $session" 2> /dev/null \
      | grep -oE 'surface:[0-9]+' | head -n 1 || true)"
  fi
  [ -n "$surface" ] || echo "Couldn't open a cmux split, so this job runs unseen." >&2
  wait "$job" || status=$?

  # `run --attach` can exit before the last step's events arrive, so take the result from the saved session.
  if [ "$status" -ne 0 ] || [ -z "$session" ] || grep -q '"type":"error"' "$events"; then
    return
  fi
  waited=0
  until session_finished || [ "$waited" -ge 120 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  # A patch must never be taken from a clone that a running or failed job may still be changing.
  session_finished || { echo "The session didn't finish cleanly." >&2; status=1; return; }
  jq -c '.messages[] | select(.info.role == "assistant") | .parts[]
    | {text: "text", "step-finish": "step_finish", tool: "tool_use"}[.type] as $type
    | select($type) | {type: $type, part: .}' "$work/session.json" > "$events"
}

session_finished() {
  (cd "$work/repo" && OPENCODE_DISABLE_CLAUDE_CODE=1 opencode export "$session" > "$work/session.json" 2> /dev/null) || return 1
  jq -e '.messages[-1].info | .error == null and ((.finish // "") | . != "" and . != "tool-calls")' "$work/session.json" > /dev/null 2>&1
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
  # -z stops git quoting unusual names, which would slip past the anchored patterns below.
  changed="$(clone_git diff --cached --no-renames --name-only -z | tr '\0' '\n')"

  # Permission rules only cover the edit tool, so check what actually changed before applying it.
  if grep -qiE '^(\.github|\.claude|\.opencode|scripts)/|^(Taskfile\.yml|opencode\.json|CLAUDE\.md)$|(^|/)\.env|\.mmdb$' <<< "$changed"; then
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
