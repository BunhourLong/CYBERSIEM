#!/usr/bin/env bash
# PreToolUse hook: block edits to env files, GeoIP databases and applied migrations. Silent when allowed.
input=$(cat)
file=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')
[ -z "$file" ] && exit 0

case "$file" in
  *.env.example) exit 0 ;;
  *.env|*/.env|*.env.*)
    echo "Blocked: do not edit env files. Document new keys in stack/.env.example instead." >&2
    exit 2 ;;
  *.mmdb)
    echo "Blocked: GeoIP databases are not edited or committed." >&2
    exit 2 ;;
  */migrations/versions/*)
    if [ -f "$file" ] && git ls-files --error-unmatch "$file" >/dev/null 2>&1; then
      echo "Blocked: $file is already committed. Add a new migration." >&2
      exit 2
    fi ;;
esac
exit 0
