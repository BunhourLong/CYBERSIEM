#!/usr/bin/env bash
# Run a noisy command and spend no model tokens on a pass: one line if it passes, the tail if it fails.
# Usage: scripts/brief.sh <command...>
mkdir -p .scan
if "$@" > .scan/last-run.log 2>&1; then
  echo "PASS: $*"
else
  status=$?
  echo "FAIL ($status): $*"
  tail -n 60 .scan/last-run.log
  exit "$status"
fi
