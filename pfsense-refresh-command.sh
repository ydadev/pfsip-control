#!/bin/sh
set -eu

set -- ${SSH_ORIGINAL_COMMAND:-}
[ "$#" -eq 2 ] && [ "$1" = "refresh" ] || {
    echo "Only: refresh ALIAS" >&2
    exit 64
}

alias_name=$2
case "$alias_name" in
    *[!A-Za-z0-9_]*|'')
        echo "Invalid alias" >&2
        exit 64
        ;;
esac

/etc/rc.update_urltables now forceupdate "$alias_name"
test -f "/var/db/aliastables/${alias_name}.txt" || {
    echo "URL Table alias not found" >&2
    exit 66
}

/sbin/pfctl -t "$alias_name" -T show >/dev/null
echo "Updated ${alias_name}"
