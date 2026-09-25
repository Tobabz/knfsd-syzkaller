#!/bin/sh
# Retire the Phase 3 domain after NFS connections drain, before netns delete.
set -eu

root=${1:?usage: frozen_phase3_cleanup.sh ROOT SERVER_NS CLIENT0_NS CLIENT1_NS}
server_ns=${2:?missing server namespace}
control=/sys/kernel/debug/sunrpc_fuzz/domain_control

case "$root" in
    /tmp/frozen-nfs.*) ;;
    *) echo "unsafe lane root: $root" >&2; exit 2 ;;
esac

test -s "$root/lane_epoch"
epoch=$(cat "$root/lane_epoch")
case "$epoch" in
    ''|*[!0-9]*) echo "invalid lane epoch: $epoch" >&2; exit 1 ;;
esac
test "$epoch" -gt 0
test -w "$control"

ip netns exec "$server_ns" nsenter -t 1 -m -- sh -c \
    'printf "retire 0 %s\n" "$1" > "$2"' sh "$epoch" "$control"
