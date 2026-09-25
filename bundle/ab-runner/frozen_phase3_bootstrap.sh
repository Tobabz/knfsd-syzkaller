#!/bin/sh
# Namespace-local Phase 3 correlation-domain bootstrap. Guest use only.
set -eu

root=${1:?usage: frozen_phase3_bootstrap.sh ROOT SERVER_NS CLIENT0_NS CLIENT1_NS}
server_ns=${2:?missing server namespace}
client0_ns=${3:?missing client0 namespace}
client1_ns=${4:?missing client1 namespace}

case "$root" in
    /tmp/frozen-nfs.*) ;;
    *) echo "unsafe lane root: $root" >&2; exit 2 ;;
esac

directory=/sys/kernel/debug/sunrpc_fuzz
control=$directory/domain_control
domain=$directory/domain
test -w "$control"
test -r "$domain"

in_netns_with_host_mounts()
{
    ns=$1
    shift
    # `ip netns exec` creates a short-lived mount namespace for its
    # namespace-specific bind mounts.  Re-enter only PID 1's mount namespace
    # so the target network namespace is retained while the host debugfs
    # mount (and the SUNRPC control files) remain visible.
    ip netns exec "$ns" nsenter -t 1 -m -- "$@"
}

in_netns_with_host_mounts "$server_ns" sh -c \
    'printf "create 0\n" > "$1"' sh "$control"
server_state=$(in_netns_with_host_mounts "$server_ns" cat "$domain")
set -- $server_state
test "$#" -eq 6
test "$1" = lane_id
test "$2" = 0
test "$3" = lane_epoch
epoch=$4
test "$5" = active
test "$6" = 1
case "$epoch" in
    ''|*[!0-9]*) echo "invalid kernel lane epoch: $epoch" >&2; exit 1 ;;
esac
test "$epoch" -gt 0

for ns in "$client0_ns" "$client1_ns"; do
    in_netns_with_host_mounts "$ns" sh -c \
        'printf "join 0 %s\n" "$1" > "$2"' sh "$epoch" "$control"
    state=$(in_netns_with_host_mounts "$ns" cat "$domain")
    test "$state" = "lane_id 0 lane_epoch $epoch active 1"
done

printf '%s\n' "$epoch" > "$root/lane_epoch"
printf '%s\n' "$server_state" > "$root/phase3-domain"
