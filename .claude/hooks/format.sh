#!/usr/bin/env bash
# PostToolUse hook: format the file just edited. Silent, and never fails the edit.
file=$(jq -r '.tool_input.file_path // empty')
cd "$CLAUDE_PROJECT_DIR" || exit 0
[ -f "$file" ] || exit 0
case "$file" in
  # `*` matches `/`, so a `..` could pass the patterns below and format outside the project.
  */../*) ;;
  "$CLAUDE_PROJECT_DIR"/frontend/src/*) (cd frontend && npx prettier --write --log-level silent --ignore-unknown "$file") ;;
  "$CLAUDE_PROJECT_DIR"/*.py) uv run --locked -q ruff format -q "$file" ;;
esac > /dev/null 2>&1
exit 0
