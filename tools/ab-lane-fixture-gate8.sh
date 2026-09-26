#!/bin/sh
# S3 Gate 8 lane-script wrapper (porting adaptation).
#
# The frozen image boots frozen-phase9-fixture.service (4-lane sunrpc_fuzz
# domain, epochs 1-4) before ssh.  Gate 8's bootstrap.sh then writes
# "create 0" to domain_control, which fails (debugfs EIO => "printf: I/O
# error") because lane 0 already exists.  Mirrors the retirement prelude
# proven in tools/ab-lane-fixture-v42.sh: stop the service (its ExecStop is
# /opt/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager), then run
# the original phase1 lane body verbatim below.
set -eu
action=${1:-}
case "$action" in
    setup)
        systemctl stop frozen-phase9-fixture.service >/dev/null 2>&1 || \
            /opt/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager >/dev/null 2>&1 || true
        ;;
esac
# ==== original bundle/ab-runner/frozen_phase1_lane.sh body (verbatim) ====
#!/bin/sh
# Disposable-VM Phase 1 lane fixture. Never run this on the host.
set -eu

action=${1:?usage: frozen_phase1_lane.sh setup|status|cleanup ROOT}
root=${2:?usage: frozen_phase1_lane.sh setup|status|cleanup ROOT}

case "$root" in
    /tmp/frozen-nfs.*) ;;
    *) echo "unsafe lane root: $root" >&2; exit 2 ;;
esac

server_ns=fnfs-l0-s
client0_ns=fnfs-l0-c0
client1_ns=fnfs-l0-c1
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
pre_mount_hook=${FROZEN_NFS_PRE_MOUNT_HOOK:-}
pre_cleanup_hook=${FROZEN_NFS_PRE_CLEANUP_HOOK:-}

wait_ready()
{
    file=$1
    pid=$2
    log=$3
    count=0
    while ! test -e "$file"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "lane keeper exited before creating $file" >&2
            test ! -f "$log" || tail -n 80 "$log" >&2
            return 1
        fi
        count=$((count + 1))
        if test "$count" -ge 300; then
            echo "timeout waiting for $file" >&2
            test ! -f "$log" || tail -n 80 "$log" >&2
            return 1
        fi
        sleep 0.1
    done
}

namespace_pids()
{
    ip netns pids "$1" 2>/dev/null || true
}

stop_namespace()
{
    ns=$1
    pids=$(namespace_pids "$ns")
    if test -n "$pids"; then
        kill $pids 2>/dev/null || true
        sleep 0.2
        pids=$(namespace_pids "$ns")
        test -z "$pids" || kill -KILL $pids 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
}

namespace_exists()
{
    ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$1"
}

cleanup()
{
    for item in client0 client1; do
        pid_file="$root/$item.pid"
        if test -s "$pid_file"; then
            pid=$(cat "$pid_file")
            nsenter -t "$pid" -m -n -- umount "$root/$item/mnt" 2>/dev/null || true
        fi
    done

    if test -s "$root/server.pid"; then
        pid=$(cat "$root/server.pid")
        nsenter -t "$pid" -m -n -- sh -c \
            'test ! -e /proc/fs/nfsd/threads || printf "0\n" > /proc/fs/nfsd/threads; exportfs -au 2>/dev/null || true' \
            2>/dev/null || true
    fi

    # A later-phase fixture can retire namespace-local state after all NFS
    # connections have drained but while the server netns still exists.
    if test -s "$root/pre_cleanup_hook"; then
        hook=$(cat "$root/pre_cleanup_hook")
        test -x "$hook"
        "$hook" "$root" "$server_ns" "$client0_ns" "$client1_ns"
    fi

    stop_namespace "$client0_ns"
    stop_namespace "$client1_ns"
    stop_namespace "$server_ns"
    ! namespace_exists "$client0_ns"
    ! namespace_exists "$client1_ns"
    ! namespace_exists "$server_ns"
    rm -rf "$root"
}

setup_client()
{
    index=$1
    ns=$2
    server_ip=$3
    identifier="frozen-lane0-client$index"
    mount_dir="$root/client$index/mnt"
    ready="$root/client$index.ready"

    ip netns exec "$ns" sh -c \
        'printf "%s\n" "$1" > /sys/fs/nfs/net/nfs_client/identifier' sh "$identifier"
    actual=$(ip netns exec "$ns" cat /sys/fs/nfs/net/nfs_client/identifier)
    test "$actual" = "$identifier"
    printf '%s\n' "$actual" > "$root/client$index.identifier"

    ip netns exec "$ns" unshare --mount --propagation private sh -c '
        set -eu
        root=$1
        index=$2
        server_ip=$3
        mount_dir="$root/client$index/mnt"
        ready="$root/client$index.ready"
        mkdir -p "$mount_dir"
        mount.nfs4 -o vers=4.1,minorversion=1,proto=tcp,port=2049,sec=sys,actimeo=0,lookupcache=none,nosharecache \
            "$server_ip:/" "$mount_dir"
        grep -F " $mount_dir nfs4 " /proc/mounts > "$root/client$index.mount"
        touch "$ready"
        exec sleep 86400
    ' sh "$root" "$index" "$server_ip" >"$root/client$index.log" 2>&1 &
    pid=$!
    printf '%s\n' "$pid" > "$root/client$index.pid"
    wait_ready "$ready" "$pid" "$root/client$index.log"
    kill -0 "$pid"
}

status()
{
    test -d "$root"
    test "$(cat /sys/module/nfs/parameters/localio_enabled)" = N
    for index in 0 1; do
        pid=$(cat "$root/client$index.pid")
        kill -0 "$pid"
        nsenter -t "$pid" -m -n -- mountpoint -q "$root/client$index/mnt"
        nsenter -t "$pid" -m -n -- grep -Eq \
            " $root/client$index/mnt nfs4 .*vers=4\\.1.*proto=tcp" /proc/mounts
    done
    test "$(cat "$root/client0.identifier")" != "$(cat "$root/client1.identifier")"
    server_pid=$(cat "$root/server.pid")
    kill -0 "$server_pid"
    threads=$(nsenter -t "$server_pid" -m -n -- cat /proc/fs/nfsd/threads)
    test "$threads" -ge 2
    versions=$(nsenter -t "$server_pid" -m -n -- cat /proc/fs/nfsd/versions)
    printf '%s\n' "$versions" | grep -Eq '(^| )\+4\.1( |$)'
    tcp_connections=$(nsenter -t "$server_pid" -m -n -- awk \
        '$2 ~ /:0801$/ && $4 == "01" { count++ } END { print count + 0 }' /proc/net/tcp)
    test "$tcp_connections" -ge 2
    printf '{"localio":"N","server_threads":%s,"tcp_connections":%s,"client0_identifier":"%s","client1_identifier":"%s"}\n' \
        "$threads" "$tcp_connections" "$(cat "$root/client0.identifier")" "$(cat "$root/client1.identifier")"
}

case "$action" in
cleanup)
    cleanup
    exit 0
    ;;
status)
    status
    exit 0
    ;;
setup)
    ;;
*)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac

cleanup
trap 'rc=$?; trap - EXIT; if test "$rc" -ne 0; then cleanup || true; fi; exit "$rc"' EXIT
mkdir -p "$root/server/export" "$root/server/nfsd" \
    "$root/server/state/nfs" "$root/server/state/rpcbind" \
    "$root/client0/mnt" "$root/client1/mnt" "$root/sync"
if test -n "$pre_cleanup_hook"; then
    case "$pre_cleanup_hook" in
        /*) ;;
        *) echo "pre-cleanup hook must be an absolute path" >&2; exit 2 ;;
    esac
    test -x "$pre_cleanup_hook"
    printf '%s\n' "$pre_cleanup_hook" > "$root/pre_cleanup_hook"
fi

ip netns add "$server_ns"
ip netns add "$client0_ns"
ip netns add "$client1_ns"

ip link add fz0c0 type veth peer name fz0s0
ip link set fz0c0 netns "$client0_ns"
ip link set fz0s0 netns "$server_ns"
ip link add fz0c1 type veth peer name fz0s1
ip link set fz0c1 netns "$client1_ns"
ip link set fz0s1 netns "$server_ns"

ip -n "$server_ns" link set lo up
ip -n "$server_ns" addr add 10.77.0.1/30 dev fz0s0
ip -n "$server_ns" link set fz0s0 up
ip -n "$server_ns" addr add 10.77.0.5/30 dev fz0s1
ip -n "$server_ns" link set fz0s1 up

ip -n "$client0_ns" link set lo up
ip -n "$client0_ns" addr add 10.77.0.2/30 dev fz0c0
ip -n "$client0_ns" link set fz0c0 up
ip -n "$client1_ns" link set lo up
ip -n "$client1_ns" addr add 10.77.0.6/30 dev fz0c1
ip -n "$client1_ns" link set fz0c1 up

# Later Frozen Baseline phases need namespace-local state before the first
# transport connection.  The hook is deliberately absent by default, and is
# run only after deterministic addressing is complete but before knfsd or an
# NFS mount can create a TCP connection.
if test -n "$pre_mount_hook"; then
    test -x "$pre_mount_hook"
    "$pre_mount_hook" "$root" "$server_ns" "$client0_ns" "$client1_ns"
fi

ip netns exec "$server_ns" unshare --mount --propagation private sh -c '
    set -eu
    root=$1
    mkdir -p /proc/fs/nfsd /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery /var/lib/nfs/nfsdcld /run/rpcbind
    mount --bind "$root/server/state/nfs" /var/lib/nfs
    mount --bind "$root/server/state/rpcbind" /run/rpcbind
    mkdir -p /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery /var/lib/nfs/nfsdcld
    touch /var/lib/nfs/etab /var/lib/nfs/rmtab
    mount -t tmpfs -o mode=0755 frozen-lane0 "$root/server/export"
    mkdir -p "$root/server/export/shared"
    printf "frozen lane fixture\n" > "$root/server/export/shared/fixture"
    mount -t nfsd nfsd /proc/fs/nfsd
    mountpoint -q /var/lib/nfs/rpc_pipefs || mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs
    printf "%s\n" "-2 -3 +4" > /proc/fs/nfsd/versions
    printf "10\n" > /proc/fs/nfsd/nfsv4leasetime
    printf "10\n" > /proc/fs/nfsd/nfsv4gracetime
    exportfs -i -o rw,sync,insecure,no_subtree_check,no_root_squash,fsid=0 \
        "10.77.0.0/29:$root/server/export"
    rpcbind -w
    rpc.mountd --no-nfs-version 3 --no-udp --port 20048
    nfsdcld
    printf "tcp 2049\n" > /proc/fs/nfsd/portlist
    printf "4\n" > /proc/fs/nfsd/threads
    touch "$root/server.ready"
    exec sleep 86400
' sh "$root" >"$root/server.log" 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" > "$root/server.pid"
wait_ready "$root/server.ready" "$server_pid" "$root/server.log"
kill -0 "$server_pid"

ip netns exec "$client0_ns" ping -c 1 -W 2 10.77.0.1 >/dev/null
ip netns exec "$client1_ns" ping -c 1 -W 2 10.77.0.5 >/dev/null

setup_client 0 "$client0_ns" 10.77.0.1
setup_client 1 "$client1_ns" 10.77.0.5
status
trap - EXIT
