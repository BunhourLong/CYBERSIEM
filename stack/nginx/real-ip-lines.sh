#!/bin/sh
# Print one nginx set_real_ip_from directive per comma-separated TRUSTED_PROXY_CIDRS entry.

set -f
TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS:-}

IFS=','
for cidr in $TRUSTED_PROXY_CIDRS; do
    case "$cidr" in
        *[!0-9a-fA-F:./]*)
            echo "invalid TRUSTED_PROXY_CIDRS entry: $cidr" >&2
            exit 1
            ;;
        */0)
            echo "refusing default route as a trusted proxy: $cidr" >&2
            exit 1
            ;;
    esac
    printf 'set_real_ip_from %s;\n' "$cidr"
done
