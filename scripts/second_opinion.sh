#!/usr/bin/env bash
# Second opinion from another vendor's model on this branch's committed changes.
# It reads a clean clone, so untracked private docs never reach the provider.
set -euo pipefail

model="${SECOND_OPINION_MODEL:-gpt-5.6-terra}"
repo="$(git rev-parse --show-toplevel)"
output="$repo/.scan/second-opinion.txt"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$repo/.scan"
: > "$output"
git clone -q "$repo" "$work/repo"
git -C "$work/repo" fetch -q "$repo" main:refs/heads/review-base

prompt='Review the output of `git diff review-base...HEAD` in this read-only repository, reading other files only to check a concrete risk.

This service reads NGINX logs, scores client IPs and blocks them. Request and log text is attacker-controlled.

Report only real bugs and security problems: wrong behaviour, trust-boundary violations, ways to block an innocent client, availability failures. No style notes. If you find nothing, say so.

Return at most 250 words: a numbered list, most severe first, each with path:line, the concrete failure, and the smallest fix. Report only what you can support from the code.'

codex exec -C "$work/repo" -m "$model" --sandbox read-only --ephemeral -o "$output" "$prompt" > /dev/null 2>&1 < /dev/null
cat "$output"
