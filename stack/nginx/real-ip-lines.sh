#!/bin/sh
# Print one nginx set_real_ip_from directive per comma-separated TRUSTED_PROXY_CIDRS entry.

set -f
TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS:-}

case "$TRUSTED_PROXY_CIDRS" in
    ,*|*,|*,,*)
        echo "invalid TRUSTED_PROXY_CIDRS: empty entry" >&2
        exit 1
        ;;
esac

lines=
IFS=','
for cidr in $TRUSTED_PROXY_CIDRS; do
    case "$cidr" in
        *[!0-9a-fA-F:./]*)
            echo "invalid TRUSTED_PROXY_CIDRS entry: $cidr" >&2
            exit 1
            ;;
        */*)
            prefix=${cidr#*/}
            case "$prefix" in
                ''|*[!0-9]*)
                    echo "invalid TRUSTED_PROXY_CIDRS prefix: $cidr" >&2
                    exit 1
                    ;;
            esac
            case "$cidr" in
                */*/*)
                    echo "invalid TRUSTED_PROXY_CIDRS prefix: $cidr" >&2
                    exit 1
                    ;;
            esac
            case "${cidr%%/*}" in
                *:*) min=32 ;;
                *) min=8 ;;
            esac
            while [ "${#prefix}" -gt 1 ] && [ "${prefix#0}" != "$prefix" ]; do
                prefix=${prefix#0}
            done
            [ "$prefix" -ge "$min" ] || {
                echo "refusing too-wide trusted proxy: $cidr" >&2
                exit 1
            }
            ;;
    esac
    lines="${lines}set_real_ip_from $cidr;
"
done
[ -z "$lines" ] || printf '%s' "$lines"
