#!/usr/bin/env bash
# Score OpenCode models on one job, each in its own worktree. Jobs stay private: they can name unfixed issues.
# Usage: scripts/bakeoff.sh <job-dir> <model>...
# A job dir holds: role (a scripts/ai.sh role), base (a commit), prompt.md, score.sh, optional setup.sh.
set -euo pipefail

job_dir="$(cd "${1:?job dir}" && pwd)"
shift
repo="$(git rev-parse --show-toplevel)"
job="$(basename "$job_dir")"
role="$(cat "$job_dir/role")"
out="$repo/.scan/bakeoff2"
mkdir -p "$out/$job"

work=""
cleanup() { [ -z "$work" ] || git -C "$repo" worktree remove --force "$work" 2> /dev/null || true; }
trap cleanup EXIT

# OpenCode's own total: it also counts runs that failed or timed out before reporting a cost.
total_spend() { opencode stats 2> /dev/null | grep -oE 'Total Cost +\$[0-9.,]+' | grep -oE '[0-9.,]+$' | tr -d ','; }
start_spend="$(total_spend)"

for model in "$@"; do
  spent="$(awk -v a="$(total_spend)" -v b="$start_spend" 'BEGIN {print a - b}')"
  if awk -v s="$spent" -v m="${BAKEOFF_MAX_USD:-3}" 'BEGIN {exit !(s >= m)}'; then
    echo "Budget reached at \$$spent, stopping before $model" >&2
    exit 0
  fi

  work="$(mktemp -d)"
  rmdir "$work"
  git -C "$repo" worktree add -q --detach "$work" "$(cat "$job_dir/base")"
  [ ! -x "$job_dir/setup.sh" ] || "$job_dir/setup.sh" "$work"

  started="$(date +%s)"
  code=0
  # The job gets its own process group, so a timeout also stops opencode, not only the wrapper. The repo's ai.sh runs, not the base commit's.
  (cd "$work" && AI_MODEL="$model" perl -e '
    $t = shift; setpgrp(0, 0); $p = fork // die; if (!$p) { exec @ARGV }
    $SIG{ALRM} = sub { $SIG{TERM} = "IGNORE"; kill "TERM", -$$; sleep 2; kill "KILL", -$$ };
    alarm $t; waitpid($p, 0); exit($? >> 8 || ($? ? 142 : 0))' "${BAKEOFF_TIMEOUT:-900}" \
    bash "$repo/scripts/ai.sh" "$role" "$job_dir/prompt.md") > "$out/$job/last.log" 2>&1 || code=$?
  seconds=$(($(date +%s) - started))

  # Column 4 of ai-usage.tsv is each step's cost.
  cost="$(awk -F'\t' '{s += $4} END {printf "%.4f", s + 0}' "$work/.scan/ai-usage.tsv" 2> /dev/null || echo 0)"
  name="${model//\//_}"
  reply="$out/$job/$name.txt"
  cp "$work/.scan/ai-$role.txt" "$reply" 2> /dev/null || : > "$reply"
  cp "$work/.scan/ai-$role.patch" "$out/$job/$name.patch" 2> /dev/null || true

  score="$("$job_dir/score.sh" "$work" "$reply" 2>> "$out/$job/last.log" | tail -n 1 || true)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$job" "$model" "$code" "${score:-none}" "$cost" "$seconds" >> "$out/results.tsv"
  printf '%s %s exit=%s score=%s $%s %ss\n' "$job" "$model" "$code" "${score:-none}" "$cost" "$seconds"

  cleanup
  work=""
done
