#!/bin/sh
# The NFS lane fixture: copied from the host into /run at guest boot.
# The boot wrapper checks the copy against the run's expected SHA-256.
#
# Every lane has one knfsd and one NFS-Ganesha behind a wire relay (nfs-proxy),
# and two client namespaces that mount both.  Variants are selected by
# environment variables, never by a copy of this file.  boot-fixture.sh reads
# the NFS version from the VM kernel command line.  This file runs from its
# per-VM copy and must not stop the fixture service itself.
#
#   KOOV_TMPFS_SIZE   bound the per-lane tmpfs (default 256m).  The original
#                     mounts it with no size=, so a runaway corpus program
#                     can exhaust guest RAM; the resulting OOM kill is then
#                     indistinguishable from a kernel bug.  This is a
#                     pre-existing defect, unrelated to Ganesha.
#   SERVER_IMPL       both (default) | knfsd | ganesha.  knfsd and ganesha
#                     skip the relay and are for diagnosis only
#   SERVER_PORT       NFS port the clients mount (default 2049)
#   KOOV_KNFS_PORT    knfsd listen port (default: SERVER_PORT, or 20490 in
#                     "both", leaving 2049 for the relay)
#   KOOV_GANESHA_PORT Ganesha listen port (default: SERVER_PORT, or 20491 in
#                     "both")
#   KOOV_GANESHA_ASAN_OPTIONS / KOOV_UBSAN_OPTIONS
#                     passed to the Ganesha process; with ASan requested,
#                     keep the daemon in the foreground so its ASan reports
#                     reach the per-lane server.log rather than /dev/null.
#   NFS_VERSION       3 | 4.0 | 4.1 (default) | 4.2
#
# In both mode, a listener on .1:2049 and .5:2049 sends records to knfsd
# :20490 and Ganesha :20491 respectively.  Each of the two client namespaces
# mounts BOTH destinations; /mnt remains the original primary alias.
# The executor client0/client1 aliases both select knfsd, preserving the
# two-client shared-filesystem contract of the normal corpus.
#
# Why "both" uses two storage trees (knfsd tmpfs, Ganesha ext4): knfsd and
# Ganesha must never co-own mutable filesystem state.  Both clients see the
# same tree within a backend, while the two backends remain independent.
# The proxy selects ONE backend from the destination IP and returns that
# backend's own NFS response.
# NFS_VERSION applies to both backends. Ganesha V15.6 exports its
# separate bounded ext4 filesystem through FSAL_VFS.

# Disposable-VM multi-lane fixture. Never run this on the host.
set -eu

action=${1:?usage: lane.sh setup ROOT 1|2|4 | status ROOT | cleanup ROOT}
root=${2:?usage: lane.sh setup ROOT 1|2|4 | status ROOT | cleanup ROOT}

case "$root" in
    /tmp/frozen-phase9.*) ;;
    *) echo "unsafe Phase 9 root: $root" >&2; exit 2 ;;
esac
root_suffix=${root#/tmp/frozen-phase9.}
case "$root_suffix" in
    ''|*[!A-Za-z0-9]*) echo "unsafe Phase 9 root: $root" >&2; exit 2 ;;
esac

deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH

domain_directory=/sys/kernel/debug/sunrpc_fuzz
domain_control=$domain_directory/domain_control
domain_state=$domain_directory/domain
executor_root=/syz-nfs-lanes
nfs_version=${NFS_VERSION:-4.${NFS_MINOR_VERSION:-1}}
case "$nfs_version" in
    3) nfs_minor_version=; nfs_mount_type=nfs ;;
    4.0|4.1|4.2) nfs_minor_version=${nfs_version#4.}; nfs_mount_type=nfs4 ;;
    *) echo "NFS_VERSION must be 3, 4.0, 4.1, or 4.2" >&2; exit 2 ;;
esac
# KOOV: server selection + tmpfs bound.  See the header of this file.
server_port=${SERVER_PORT:-2049}
case "$server_port" in
    ''|*[!0-9]*) echo "SERVER_PORT must be a number" >&2; exit 2 ;;
esac
test "$server_port" -ge 1 && test "$server_port" -le 65535 || {
    echo "SERVER_PORT out of range" >&2; exit 2; }
server_impl=${SERVER_IMPL:-both}
case "$server_impl" in
    knfsd|ganesha|both) ;;
    *) echo "SERVER_IMPL must be knfsd, ganesha, or both" >&2; exit 2 ;;
esac
tmpfs_size=${KOOV_TMPFS_SIZE:-256m}
# KOOV: per-backend listen ports.  In "both" mode the relay keeps 2049 and
# each backend listens on its own port behind it.
knfsd_port=${KOOV_KNFS_PORT:-}
ganesha_port=${KOOV_GANESHA_PORT:-}
if [ -z "$knfsd_port" ]; then
    case "$server_impl" in
        both) knfsd_port=20490 ;;
        *) knfsd_port=$server_port ;;
    esac
fi
if [ -z "$ganesha_port" ]; then
    case "$server_impl" in
        ganesha) ganesha_port=$server_port ;;
        both) ganesha_port=20491 ;;
        *) ganesha_port=0 ;;
    esac
fi
export server_port server_impl tmpfs_size knfsd_port ganesha_port nfs_version
# deps is needed inside the sh -c block: the Ganesha FSAL bind-mounts source
# from the injected tree, and that path must not be hardcoded twice.
export deps
# server_ns is read by the ganesha failure diagnostic, which runs inside
# the separate sh -c; setup_lane assigns it per lane and this marks it for
# export so the assignment propagates.  Matched as a whole line: a
# substring test for "export server_ns" also matches the E12 label above.
export server_ns
export executor_root
export KOOV_GANESHA_ASAN_OPTIONS KOOV_UBSAN_OPTIONS KOOV_GANESHA_DEBUG

valid_count()
{
    case "$1" in
        1|2|4) return 0 ;;
        *) return 1 ;;
    esac
}

lane_server_ns()
{
    printf 'f9l%ss\n' "$1"
}

lane_client_ns()
{
    printf 'f9l%sc%s\n' "$1" "$2"
}

lane_link()
{
    printf 'f9%s%s%s\n' "$1" "$2" "$3"
}

namespace_exists()
{
    ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$1"
}

# mountpoint(1) stat()s the NFS root.  An intermittently slow/failed GETATTR
# can make it report "not mounted" while the mount still exists; cleanup must
# never walk such a mount with rm -rf.  The kernel mount table is authoritative
# for this fixture's fixed (space-free) paths.
nfs_mount_exists()
{
    awk -v target="$1" '$2 == target && ($3 == "nfs" || $3 == "nfs4") { found = 1 }
        END { exit !found }' /proc/mounts
}

mount_lane_export()
{
    mount_ns=$1
    mount_ip=$2
    mount_port=$3
    mount_backend=$4
    mount_lane=$5
    mount_target=$6
    if [ "$nfs_version" = 3 ]; then
        mount_export=$root/lane$mount_lane/server/export
        mount_mountport=20048
        if [ "$mount_backend" = ganesha ]; then
            mount_export=$root/lane$mount_lane/server/export-ganesha
            mount_mountport=20049
        fi
        nsenter --net="/run/netns/$mount_ns" -- \
            mount.nfs -o "vers=3,proto=tcp,port=$mount_port,mountproto=tcp,mountport=$mount_mountport,nolock,sec=sys,actimeo=0,lookupcache=none,nosharecache" \
            "$mount_ip:$mount_export" "$mount_target"
    else
        nsenter --net="/run/netns/$mount_ns" -- \
            mount.nfs4 -o "vers=$nfs_version,minorversion=$nfs_minor_version,proto=tcp,port=$mount_port,sec=sys,actimeo=0,lookupcache=none,nosharecache" \
            "$mount_ip:/" "$mount_target"
    fi
}

namespace_pids()
{
    ip netns pids "$1" 2>/dev/null || true
}

pid_in_named_netns()
{
    pid_check_pid=$1
    pid_check_ns=$2
    test -n "$pid_check_pid"
    kill -0 "$pid_check_pid" 2>/dev/null
    test -e "/proc/$pid_check_pid/ns/net"
    test -e "/run/netns/$pid_check_ns"
    test "$(stat -Lc '%d:%i' "/proc/$pid_check_pid/ns/net")" = \
        "$(stat -Lc '%d:%i' "/run/netns/$pid_check_ns")"
}

stop_namespace()
{
    stop_ns=$1
    namespace_exists "$stop_ns" || return 0
    stop_pids=$(namespace_pids "$stop_ns")
    if test -n "$stop_pids"; then
        kill $stop_pids 2>/dev/null || true
        stop_wait=0
        while test -n "$(namespace_pids "$stop_ns")" && \
            test "$stop_wait" -lt 20; do
            stop_wait=$((stop_wait + 1))
            sleep 0.1
        done
        stop_pids=$(namespace_pids "$stop_ns")
        if test -n "$stop_pids"; then
            kill -KILL $stop_pids 2>/dev/null || true
            stop_wait=0
            while test -n "$(namespace_pids "$stop_ns")" && \
                test "$stop_wait" -lt 50; do
                stop_wait=$((stop_wait + 1))
                sleep 0.1
            done
        fi
    fi
    test -z "$(namespace_pids "$stop_ns")" || return 1
    ip netns del "$stop_ns" 2>/dev/null || return 1
    ! namespace_exists "$stop_ns"
}

wait_ready()
{
    ready_file=$1
    ready_pid=$2
    ready_log=$3
    ready_count=0
    while ! test -e "$ready_file"; do
        if ! kill -0 "$ready_pid" 2>/dev/null; then
            echo "lane keeper exited before creating $ready_file" >&2
            test ! -f "$ready_log" || tail -n 80 "$ready_log" >&2
            return 1
        fi
        ready_count=$((ready_count + 1))
        if test "$ready_count" -ge 300; then
            echo "timeout waiting for $ready_file" >&2
            test ! -f "$ready_log" || tail -n 80 "$ready_log" >&2
            return 1
        fi
        sleep 0.1
    done
}

# Retain the target network namespace while re-entering PID 1's mount
# namespace, where the runner mounted debugfs and the domain controls live.
in_netns_with_host_mounts()
{
    domain_ns=$1
    shift
    ip netns exec "$domain_ns" nsenter -t 1 -m -- "$@"
}

create_domain()
{
    domain_lane=$1
    domain_server=$2
    domain_client0=$3
    domain_client1=$4
    domain_root=$root/lane$domain_lane

    test -w "$domain_control"
    test -r "$domain_state"
    in_netns_with_host_mounts "$domain_server" sh -c \
        'printf "create %s\n" "$1" > "$2"' sh \
        "$domain_lane" "$domain_control"
    domain_server_value=$(in_netns_with_host_mounts \
        "$domain_server" cat "$domain_state")
    set -- $domain_server_value
    test "$#" -eq 6
    test "$1" = lane_id
    test "$2" -eq "$domain_lane"
    test "$3" = lane_epoch
    domain_epoch=$4
    test "$5" = active
    test "$6" -eq 1
    case "$domain_epoch" in
        ''|*[!0-9]*) echo "invalid kernel lane epoch: $domain_epoch" >&2; return 1 ;;
    esac
    test "$domain_epoch" -gt 0
	# Persist the server-created epoch before joining clients so cleanup can
	# retire a partially initialized domain if either join fails.
	printf '%s\n' "$domain_epoch" > "$domain_root/lane_epoch"

    for domain_ns in "$domain_client0" "$domain_client1"; do
        in_netns_with_host_mounts "$domain_ns" sh -c \
            'printf "join %s %s\n" "$1" "$2" > "$3"' sh \
            "$domain_lane" "$domain_epoch" "$domain_control"
        domain_client_value=$(in_netns_with_host_mounts \
            "$domain_ns" cat "$domain_state")
        test "$domain_client_value" = \
            "lane_id $domain_lane lane_epoch $domain_epoch active 1"
    done

    printf '%s\n' "$domain_server_value" > "$domain_root/server.domain"
    printf '%s\n' "$domain_client_value" > "$domain_root/clients.domain"
}

setup_client()
{
    client_lane=$1
    client_index=$2
    client_ns=$3
    client_server_ip=$4
    client_server_port=$5
    client_backend=$6
    client_root=$root/lane$client_lane
    client_identifier=frozen-phase9-lane${client_lane}-client${client_index}
    client_mount=$client_root/client$client_index/mnt
    client_ready=$client_root/client$client_index.ready

    ip netns exec "$client_ns" sh -c \
        'printf "%s\n" "$1" > /sys/fs/nfs/net/nfs_client/identifier' sh \
        "$client_identifier"
    client_actual=$(ip netns exec "$client_ns" \
        cat /sys/fs/nfs/net/nfs_client/identifier)
    test "$client_actual" = "$client_identifier"
    printf '%s\n' "$client_actual" > \
        "$client_root/client$client_index.identifier"

    # Keep the NFS superblock in the fixture's source mount namespace.  The
    # executor later clones only one proc-specific subtree into its own
    # private sandbox.  nsenter changes only the network namespace here;
    # unlike `ip netns exec`, it cannot create a helper mount namespace that
    # would make the resulting NFS mount impossible to import safely.
    mount_lane_export "$client_ns" "$client_server_ip" "$client_server_port" \
        "$client_backend" "$client_lane" "$client_mount"
    grep -F " $client_mount $nfs_mount_type " /proc/mounts > \
        "$client_root/client$client_index.mount"
    touch "$client_ready"
    nsenter --net="/run/netns/$client_ns" -- sh -c 'exec sleep 86400' \
        >"$client_root/client$client_index.log" 2>&1 &
    client_pid=$!
    printf '%s\n' "$client_pid" > "$client_root/client$client_index.pid"
    wait_ready "$client_ready" "$client_pid" \
        "$client_root/client$client_index.log"
    kill -0 "$client_pid"
}

setup_cross_mount()
{
    cross_lane=$1
    cross_client=$2
    cross_ns=$3
    cross_backend=$4
    cross_ip=$5
    cross_mount=$root/lane$cross_lane/client$cross_client/$cross_backend
    mkdir -p "$cross_mount"
    mount_lane_export "$cross_ns" "$cross_ip" "$server_port" \
        "$cross_backend" "$cross_lane" "$cross_mount"
    grep -F " $cross_mount $nfs_mount_type " /proc/mounts > \
        "$root/lane$cross_lane/client$cross_client.$cross_backend.mount"
}

setup_lane()
{
    setup_lane_id=$1
    setup_lane_root=$root/lane$setup_lane_id
    setup_server_ns=$(lane_server_ns "$setup_lane_id")
    server_ns=$setup_server_ns
    setup_client0_ns=$(lane_client_ns "$setup_lane_id" 0)
    setup_client1_ns=$(lane_client_ns "$setup_lane_id" 1)
    setup_server0_link=$(lane_link "$setup_lane_id" s 0)
    setup_client0_link=$(lane_link "$setup_lane_id" c 0)
    setup_server1_link=$(lane_link "$setup_lane_id" s 1)
    setup_client1_link=$(lane_link "$setup_lane_id" c 1)
    setup_server0_ip=10.89.$setup_lane_id.1
    setup_client0_ip=10.89.$setup_lane_id.2
    setup_server1_ip=10.89.$setup_lane_id.5
    setup_client1_ip=10.89.$setup_lane_id.6

    mkdir -p "$setup_lane_root/server/export" \
        "$setup_lane_root/server/export-ganesha" \
        "$setup_lane_root/server/state/nfs" \
        "$setup_lane_root/server/state/run" \
        "$setup_lane_root/client0/mnt" "$setup_lane_root/client1/mnt"
    if [ "$server_impl" = both ]; then
        # Bind only this directory, not the proc-N parent with .lane_id,
        # into the executor sandbox at /nfs-lane/control.
        mkdir -m 0700 -p "$executor_root/proc-$setup_lane_id/control" \
            "$setup_lane_root/server/deltas"
    fi

    ip netns add "$setup_server_ns"
    ip netns add "$setup_client0_ns"
    ip netns add "$setup_client1_ns"

    ip link add "$setup_client0_link" type veth peer name "$setup_server0_link"
    ip link set "$setup_client0_link" netns "$setup_client0_ns"
    ip link set "$setup_server0_link" netns "$setup_server_ns"
    ip link add "$setup_client1_link" type veth peer name "$setup_server1_link"
    ip link set "$setup_client1_link" netns "$setup_client1_ns"
    ip link set "$setup_server1_link" netns "$setup_server_ns"

    ip -n "$setup_server_ns" link set lo up
    ip -n "$setup_server_ns" addr add "$setup_server0_ip/30" dev "$setup_server0_link"
    ip -n "$setup_server_ns" link set "$setup_server0_link" up
    ip -n "$setup_server_ns" addr add "$setup_server1_ip/30" dev "$setup_server1_link"
    ip -n "$setup_server_ns" link set "$setup_server1_link" up
    ip -n "$setup_client0_ns" link set lo up
    ip -n "$setup_client0_ns" addr add "$setup_client0_ip/30" dev "$setup_client0_link"
    ip -n "$setup_client0_ns" link set "$setup_client0_link" up
    ip -n "$setup_client1_ns" link set lo up
    ip -n "$setup_client1_ns" addr add "$setup_client1_ip/30" dev "$setup_client1_link"
    ip -n "$setup_client1_ns" link set "$setup_client1_link" up

    if [ "$server_impl" = both ]; then
        # The two destinations belong to one server namespace.  A packet
        # from .2 to .5 enters through .1; no L3 forwarding or NAT is used.
        ip -n "$setup_client0_ns" route add \
            "10.89.$setup_lane_id.4/30" via "$setup_server0_ip"
        ip -n "$setup_client1_ns" route add \
            "10.89.$setup_lane_id.0/30" via "$setup_server1_ip"
    fi

    # The immutable correlation domain must exist in all three network
    # namespaces before knfsd starts or either client creates a connection.
    create_domain "$setup_lane_id" "$setup_server_ns" \
        "$setup_client0_ns" "$setup_client1_ns"

    ip netns exec "$setup_server_ns" unshare --mount --propagation private sh -c '
        set -eu
        root=$1
        lane=$2
        export_network=$3
        lane_root="$root/lane$lane"
        mkdir -p /proc/fs/nfsd /var/lib/nfs/rpc_pipefs \
            /var/lib/nfs/v4recovery /var/lib/nfs/nfsdcld
        mount --bind "$lane_root/server/state/nfs" /var/lib/nfs
        # rpcbind uses /run/rpcbind.sock and /run/rpcbind.pid.  Isolate the
        # whole runtime directory so four server netns can run concurrently.
        mount --bind "$lane_root/server/state/run" /run
        mkdir -p /run/rpcbind
        mkdir -p /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery \
            /var/lib/nfs/nfsdcld
        touch /var/lib/nfs/etab /var/lib/nfs/rmtab
        mount -t tmpfs -o mode=0755,size="$tmpfs_size" "frozen-phase9-lane$lane" \
            "$lane_root/server/export"
        mkdir -p "$lane_root/server/export/shared"
        printf "frozen Phase 9 lane %s fixture\n" "$lane" > \
            "$lane_root/server/export/shared/fixture"
        # KOOV: knfsd backend.  Skipped entirely when Ganesha is the only
        # server; "both" runs this and the Ganesha block below side by side.
        if [ "$server_impl" = knfsd ] || [ "$server_impl" = both ]; then
        mount -t nfsd nfsd /proc/fs/nfsd
        mountpoint -q /var/lib/nfs/rpc_pipefs || \
            mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs
        rpcbind -w
        if [ "$nfs_version" = 3 ]; then
            rpcbind_wait=0
            until rpcinfo -p 127.0.0.1 >/dev/null 2>&1; do
                rpcbind_wait=$((rpcbind_wait + 1))
                test "$rpcbind_wait" -lt 50 || {
                    echo "KOOV: rpcbind did not become ready" >&2
                    exit 1
                }
                sleep 0.1
            done
        fi
        if [ "$nfs_version" = 3 ]; then
            printf "%s\n" "-2 +3 -4" > /proc/fs/nfsd/versions
        else
            printf "%s\n" "-2 -3 +4" > /proc/fs/nfsd/versions
        fi
        printf "10\n" > /proc/fs/nfsd/nfsv4leasetime
        printf "10\n" > /proc/fs/nfsd/nfsv4gracetime
        exportfs -i -o rw,sync,insecure,no_subtree_check,no_root_squash,fsid=0 \
            "$export_network:$lane_root/server/export"
        if [ "$nfs_version" = 3 ]; then
            rpc.mountd --no-nfs-version 2 --no-udp --port 20048
        else
            rpc.mountd --no-nfs-version 3 --no-udp --port 20048
        fi
        nfsdcld
        printf "tcp $knfsd_port\n" > /proc/fs/nfsd/portlist
        printf "4\n" > /proc/fs/nfsd/threads
        fi
        # KOOV: Ganesha V15 VFS does not export tmpfs. Use a bounded ext4
        # loop image for its separate tree; knfsd keeps its tmpfs.
        #
        # NOTE: no apostrophe may appear anywhere in this block.  It is one
        # single-quoted argument to sh -c, and a stray quote in a comment
        # closes the string early and re-parses the rest as shell code.
        # tools/lane-quote-lint.sh enforces this.
        if [ "$server_impl" = ganesha ] || [ "$server_impl" = both ]; then
            command -v ganesha.nfsd >/dev/null 2>&1 || {
                echo "KOOV: ganesha.nfsd not on PATH; inject bundle/src/guest-deps-ganesha.tar.gz" >&2
                exit 1
            }
            command -v dbus-daemon >/dev/null 2>&1 || {
                echo "KOOV: dbus-daemon not on PATH; Ganesha requires a system bus" >&2
                exit 1
            }
            # Ganesha registers itself with rpcbind for every enabled protocol
            # and treats a failed registration as fatal, so the daemon needs
            # rpcbind even though a client mounting a pinned port never queries
            # it.  The knfsd branch already starts it in both mode, so only
            # the Ganesha-only mode starts another rpcbind process here.
            if [ "$server_impl" = ganesha ]; then
                rpcbind -w
            fi
            mkdir -p /var/lib/nfs/ganesha /run/ganesha
            truncate -s "$tmpfs_size" "$lane_root/server/ganesha.ext4"
            mkfs.ext4 -F -q "$lane_root/server/ganesha.ext4"
            mount -t ext4 -o loop "$lane_root/server/ganesha.ext4" \
                "$lane_root/server/export-ganesha"
            mkdir -p "$lane_root/server/export-ganesha/shared"
            printf "frozen Phase 9 lane %s Ganesha fixture\n" "$lane" > \
                "$lane_root/server/export-ganesha/shared/fixture"
            # A system bus, private to this lane.  Ganesha calls
            # dbus_bus_get(DBUS_BUS_SYSTEM) and offers no way to turn that off:
            # with no bus it logs "DBUS not initialized, service thread
            # exiting", the thread returns, and the server shuts down again
            # right after printing NFS SERVER INITIALIZED.  Debian system.conf
            # would also demand a messagebus user, which a debootstrap guest
            # does not have, so write a minimal one with no <user> element and
            # point Ganesha at it through DBUS_SYSTEM_BUS_ADDRESS instead of
            # the global /run/dbus socket.  Runs as root, per lane, torn down
            # with the namespace.
            #
            # Every step below is guarded rather than left to set -e.  A bare
            # failing command under set -e kills this block with NO diagnostic
            # at all, because the output of the block goes to server.log and
            # the output of the command was sent to a file nothing reads.
            # That is exactly how one run reported nothing but "lane keeper
            # exited" and cost a whole guest boot.
            if ! test -s /etc/machine-id; then
                lane_machine_id=$(head -c 16 /dev/urandom 2>/dev/null \
                    | od -An -tx1 2>/dev/null | tr -d " \n" || true)
                if test -z "$lane_machine_id"; then
                    lane_machine_id=0123456789abcdef0123456789abcdef
                fi
                if ! printf "%s\n" "$lane_machine_id" > /etc/machine-id; then
                    echo "KOOV: cannot write /etc/machine-id for dbus-daemon" >&2
                    exit 1
                fi
            fi
            cat > "$lane_root/server/dbus-system.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=$lane_root/server/dbus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
  </policy>
</busconfig>
EOF
            if ! LD_LIBRARY_PATH="$deps/usr/lib/ganesha-extra:$LD_LIBRARY_PATH" \
                    dbus-daemon --config-file="$lane_root/server/dbus-system.conf" \
                    --fork --print-address=1 --print-pid=1 \
                    >"$lane_root/server/dbus.info" 2>&1; then
                echo "KOOV: dbus-daemon failed to start" >&2
                test ! -f "$lane_root/server/dbus.info" || \
                    cat "$lane_root/server/dbus.info" >&2
                exit 1
            fi
            dbus_address=$(sed -n "1p" "$lane_root/server/dbus.info")
            dbus_pid=$(sed -n "2p" "$lane_root/server/dbus.info")
            case "$dbus_address" in
                unix:*) ;;
                *) echo "KOOV: dbus-daemon did not report a unix address: $dbus_address" >&2
                   test ! -f "$lane_root/server/dbus.info" || \
                       cat "$lane_root/server/dbus.info" >&2
                   exit 1 ;;
            esac
            case "$dbus_pid" in
                ""|*[!0-9]*) echo "KOOV: dbus-daemon pid not a number: $dbus_pid" >&2
                   exit 1 ;;
            esac
            kill -0 "$dbus_pid" 2>/dev/null || {
                echo "KOOV: dbus-daemon reported pid $dbus_pid but it is gone" >&2
                test ! -f "$lane_root/server/dbus.info" || \
                    cat "$lane_root/server/dbus.info" >&2
                exit 1
            }
            printf "%s\n" "$dbus_pid" > "$lane_root/server/dbus.pid"
            printf "%s\n" "$dbus_address" > "$lane_root/server/dbus.address"
            # Every key below was checked against the Ganesha parser tables in
            # src/support/nfs_read_conf.c, because a key in the wrong BLOCK is
            # not visible locally -- the guest reports it as "Unknown
            # parameter" only after boot, and silently ignores it:
            #   * NFS_Protocols is an NFS_CORE_PARAM key (core_options).  The
            #     export Protocols only RESTRICTS an export; it does not enable
            #     anything at the core.  Select only the requested major
            #     version; the default 3,4 enables unwanted V3/UDP listeners.
    #   * Plugins_Dir is also an NFS_CORE_PARAM key
    #     (ganesha_modules_loc).  The -p option selects the PID lock, not
    #     the plugin directory, and
            #     fsal_manager.c builds the path as "%s/libfsal%s.so", so this
            #     is how the injected VFS plugin is found at all -- and it
            #     avoids mutating the guest outside this private mountns.
            #   * Graceless / UseGetpwnam / DomainName / Only_Numeric_Owners
            #     live in the NFSv4 block (version4_params[]), NOT in
            #     NFS_CORE_PARAM.  UseGetpwnam must be true because
            #     GETPWNAMDEF is false in a USE_NFSIDMAP build, and the
            #     libnfsidmap path died with "Failed initializing ID Mapper"
            #     (no /etc/idmapd.conf, no nfs keyring).  It is also what this
            #     lane wants: sec=sys, no_root_squash, numeric owners.
            #   * The export Protocols list has no 4.1 token; values are
            #     [3, 4, NFS3, NFS4, V3, V4, NFSv3, NFSv4, 9P].  4.0 vs 4.1 is
            #     negotiated per session by the client.  V3 uses its real
            #     export path and a separate pinned MOUNT port.
            #   * Pseudo MUST be "/".  With an absolute export path, Ganesha
            #     4.3 logged "make_pseudofs_node ... CREATE export-ganesha",
            #     i.e. a pseudo node named after the export: the client root
            #     then held an "export-ganesha" directory instead of the tree,
            #     and the corpus path shared/... resolved to ENOENT.  Pseudo = /
            #     is what matches knfsd, where exportfs $net:$path exposes the
            #     tree at the mount root.  Getting this wrong cost two guest
            #     boots: first EROFS on a pseudoroot create, then ENOENT on
            #     shared/, which looked like two unrelated failures.
            ganesha_protocol=4
            ganesha_mnt_port=0
            if [ "$nfs_version" = 3 ]; then
                ganesha_protocol=3
                ganesha_mnt_port=20049
            fi
            printf "%s\n" \
                "NFS_CORE_PARAM {" \
                "    Enable_NLM = false;" \
                "    Enable_RQUOTA = false;" \
                "    NFS_Protocols = $ganesha_protocol;" \
                "    NFS_Port = $ganesha_port;" \
                "    MNT_Port = $ganesha_mnt_port;" \
                "    Rquota_Port = 0;" \
                "    Plugins_Dir = $deps/usr/lib/ganesha;" \
                "}" \
                "NFSv4 {" \
                "    Graceless = true;" \
                "    UseGetpwnam = true;" \
                "    DomainName = localdomain;" \
                "    Only_Numeric_Owners = true;" \
                "}" \
                "EXPORT {" \
                "    Export_id = 1;" \
                "    Path = $lane_root/server/export-ganesha;" \
                "    Pseudo = /;" \
                "    Access_Type = RW;" \
                "    Squash = no_root_squash;" \
                "    Protocols = $ganesha_protocol;" \
                "    Transports = TCP;" \
                "    SecType = sys;" \
                "    FSAL {" \
                "        Name = VFS;" \
                "    }" \
                "}" > "$lane_root/server/ganesha.conf"
            (
                test -z "${KOOV_GANESHA_ASAN_OPTIONS:-}" || \
                    export ASAN_OPTIONS="$KOOV_GANESHA_ASAN_OPTIONS"
                export UBSAN_OPTIONS="${KOOV_UBSAN_OPTIONS:-print_stacktrace=1}"
                export DBUS_SYSTEM_BUS_ADDRESS="$dbus_address"
                # Keep the actual daemon PID in this lane and avoid the
                # host-wide pgrep result from another lane.
                exec ganesha.nfsd -F -p "$lane_root/server/ganesha.lock" \
                    -f "$lane_root/server/ganesha.conf" \
                    -N "${KOOV_GANESHA_DEBUG:-NIV_WARN}" \
                    -L "$lane_root/server/ganesha.log"
            ) &
            ganesha_pid=$!
            ganesha_hex=$(printf "%04X" "$ganesha_port")
            ganesha_wait=0
            ganesha_listening=0
            while test "$ganesha_wait" -lt 300; do
                if ! kill -0 "$ganesha_pid" 2>/dev/null; then
                    echo "KOOV: --- last 40 log lines ---" >&2
                    test ! -f "$lane_root/server/ganesha.log" || \
                        tail -n 40 "$lane_root/server/ganesha.log" >&2
                    echo "KOOV: --- markers ---" >&2
                    if grep -q "NFS EXIT" "$lane_root/server/ganesha.log" 2>/dev/null; then
                        echo "KOOV: graceful-exit marker PRESENT" >&2
                    else
                        echo "KOOV: graceful-exit marker ABSENT" >&2
                    fi
                    echo "KOOV: --- summary (last so tail -80 cannot drop it) ---" >&2
                    echo "KOOV: lane ganesha.nfsd exited after $ganesha_wait checks" >&2
                    echo "KOOV: process=$ganesha_pid" >&2
                    echo "KOOV: netns_pids=$(ip netns pids "$server_ns" 2>/dev/null | wc -l)" >&2
                    echo "KOOV: netns_pid_list=$(ip netns pids "$server_ns" 2>/dev/null | tr "\n" " ")" >&2
                    exit 1
                fi
                # Ganesha binds ":::PORT" (Bind_sockets_V6, v6disabled = 0), so
                # its listener appears ONLY in /proc/net/tcp6.  "0+:[0]+"
                # accepts both the 8-digit IPv4 and 32-digit IPv6 remote
                # address fields; an ESTABLISHED row or another port does not
                # match.
                if grep -qE ":$ganesha_hex 0+:[0]+ 0A " \
                        /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
                    ganesha_listening=1
                    break
                fi
                ganesha_wait=$((ganesha_wait + 1))
                sleep 0.1
            done
            if test "$ganesha_listening" -ne 1; then
                echo "KOOV: --- port state ---" >&2
                grep -E ":$ganesha_hex " /proc/net/tcp /proc/net/tcp6 >&2 || true
                echo "KOOV: --- last 40 log lines ---" >&2
                test ! -f "$lane_root/server/ganesha.log" || \
                    tail -n 40 "$lane_root/server/ganesha.log" >&2
                echo "KOOV: --- summary ---" >&2
                echo "KOOV: alive (pid $ganesha_pid) but not listening on $ganesha_port" >&2
                exit 1
            fi
            # The foreground process is this lane daemon, not a peer lane.
            printf "%s\n" "$ganesha_pid" > "$lane_root/server/ganesha.pid"
            touch "$lane_root/server/ganesha.ready"
        fi
        if [ "$server_impl" = both ]; then
            command -v nfs-proxy >/dev/null 2>&1 || {
                echo "KOOV: guest relay not on PATH" >&2
                exit 1
            }
            nfs-proxy "10.89.$lane.2" "10.89.$lane.6" \
                "10.89.$lane.1:$server_port" "10.89.$lane.5:$server_port" \
                "10.89.$lane.1:$knfsd_port" "10.89.$lane.5:$ganesha_port" \
                --control "$executor_root/proc-$lane/control/arm.sock" \
                --delta-dir "$lane_root/server/deltas" \
                > "$lane_root/server/proxy.log" 2>&1 &
            proxy_pid=$!
            printf "%s\n" "$proxy_pid" > "$lane_root/server/proxy.pid"
            proxy_wait=0
            while ! grep -q "^relay ready:" "$lane_root/server/proxy.log"; do
                if ! kill -0 "$proxy_pid" 2>/dev/null || \
                    test "$proxy_wait" -ge 100; then
                    echo "KOOV: relay failed to bind both destinations" >&2
                    cat "$lane_root/server/proxy.log" >&2
                    exit 1
                fi
                proxy_wait=$((proxy_wait + 1))
                sleep 0.1
            done
        fi
        touch "$lane_root/server.ready"
        exec sleep 86400
    ' sh "$root" "$setup_lane_id" "10.89.$setup_lane_id.0/29" \
        >"$setup_lane_root/server.log" 2>&1 &
    setup_server_pid=$!
    printf '%s\n' "$setup_server_pid" > "$setup_lane_root/server.pid"
    wait_ready "$setup_lane_root/server.ready" "$setup_server_pid" \
        "$setup_lane_root/server.log"
    kill -0 "$setup_server_pid"

    ip netns exec "$setup_client0_ns" ping -c 1 -W 2 \
        "$setup_server0_ip" >/dev/null
    ip netns exec "$setup_client1_ns" ping -c 1 -W 2 \
        "$setup_server1_ip" >/dev/null
    if [ "$server_impl" = both ]; then
        ip netns exec "$setup_client0_ns" ping -c 1 -W 2 \
            "$setup_server1_ip" >/dev/null
        ip netns exec "$setup_client1_ns" ping -c 1 -W 2 \
            "$setup_server0_ip" >/dev/null
    fi
    setup_client0_backend=$server_impl
    setup_client1_backend=$server_impl
    if [ "$server_impl" = both ]; then
        setup_client0_backend=knfsd
        setup_client1_backend=ganesha
    fi
    setup_client "$setup_lane_id" 0 "$setup_client0_ns" "$setup_server0_ip" "$server_port" "$setup_client0_backend"
    setup_client "$setup_lane_id" 1 "$setup_client1_ns" "$setup_server1_ip" "$server_port" "$setup_client1_backend"
    if [ "$server_impl" = both ]; then
        setup_cross_mount "$setup_lane_id" 0 "$setup_client0_ns" \
            ganesha "$setup_server1_ip"
        setup_cross_mount "$setup_lane_id" 1 "$setup_client1_ns" \
            knfsd "$setup_server0_ip"
    fi

    # A fixed fuzzer process N enters only lane N's primary client mount
    # namespace.  Its peer alias preserves the second client for
    # cross-client state, locking, callback, and race workloads.
    ln -s "lane$setup_lane_id/client0" "$root/proc$setup_lane_id"
    ln -s "lane$setup_lane_id/client1" "$root/proc$setup_lane_id-peer"
    ln -s "lane$setup_lane_id/client0.pid" "$root/proc$setup_lane_id.pid"
    ln -s "lane$setup_lane_id/client1.pid" "$root/proc$setup_lane_id-peer.pid"
    ln -s client0.pid "$setup_lane_root/client.pid"
    ln -s client0/mnt "$setup_lane_root/mnt"
}

expose_lane_to_executor()
{
    expose_lane=$1
    expose_lane_root=$root/lane$expose_lane
    expose_source=$executor_root/proc-$expose_lane

    mkdir -p "$expose_source/client0" "$expose_source/client1"
    # Import both clients' NFS mount trees into one process-specific source
    # tree without sharing either client's otherwise-private mount namespace.
    # The executor bind-mounts only this selected subtree into its sandbox.
    mount --bind "$expose_lane_root/client0/mnt" "$expose_source/client0"
    expose_peer_mount=$expose_lane_root/client1/mnt
    if [ "$server_impl" = both ]; then
        expose_peer_mount=$expose_lane_root/client1/knfsd
    fi
    mount --bind "$expose_peer_mount" "$expose_source/client1"
    if [ "$server_impl" = both ]; then
        for expose_client in 0 1; do
            for expose_backend in knfsd ganesha; do
                mkdir "$expose_source/client$expose_client-$expose_backend"
                if [ "$expose_client:$expose_backend" = 0:knfsd ] || \
                   [ "$expose_client:$expose_backend" = 1:ganesha ]; then
                    expose_mount="$expose_lane_root/client$expose_client/mnt"
                else
                    expose_mount="$expose_lane_root/client$expose_client/$expose_backend"
                fi
                mount --bind "$expose_mount" \
                    "$expose_source/client$expose_client-$expose_backend"
            done
        done
        test -S "$expose_source/control/arm.sock"
    fi
    touch "$expose_source/.client0_netns" "$expose_source/.client1_netns"
    mount --bind "/run/netns/$(lane_client_ns "$expose_lane" 0)" \
        "$expose_source/.client0_netns"
    mount --bind "/run/netns/$(lane_client_ns "$expose_lane" 1)" \
        "$expose_source/.client1_netns"
    printf '%s\n' "$expose_lane" > "$expose_source/.lane_id"
    # Protected bootstrap metadata is consumed before the executor chroot is
    # entered.  Only client0/client1 mount trees are imported into /nfs-lane.
    cat "$expose_lane_root/client0.pid" > "$expose_source/.client0_pid"
    cat "$expose_lane_root/client1.pid" > "$expose_source/.client1_pid"
    printf '10.89.%s.1\n' "$expose_lane" > "$expose_source/.server0_ipv4"
    printf '10.89.%s.5\n' "$expose_lane" > "$expose_source/.server1_ipv4"
    chmod 0444 "$expose_source/.lane_id" "$expose_source/.client0_pid" \
        "$expose_source/.client1_pid" "$expose_source/.server0_ipv4" \
        "$expose_source/.server1_ipv4"
}

cleanup_fixture()
{
    if test -e "$root/relay.cleanup.trace"; then
        echo "KOOV cleanup trace: enter" >&2
    fi
    cleanup_count=4
    if test -s "$root/fixture.count"; then
        cleanup_saved_count=$(cat "$root/fixture.count")
        if valid_count "$cleanup_saved_count"; then
            cleanup_count=$cleanup_saved_count
        fi
    fi
    cleanup_mount_leaks=0
    cleanup_namespace_leaks=0
    cleanup_nfsd_leaks=0
    cleanup_veth_leaks=0
    cleanup_domain_retire_failures=0
    cleanup_source_tree_leaks=0
	cleanup_active_executor_mounts=0
    cleanup_lane=0

	# The caller must quiesce executors before lane teardown.  A live private
	# /nfs-lane bind can keep the NFS superblock/netns alive after the source
	# tree is unmounted, so never report a clean teardown in that state.
	for cleanup_proc in /proc/[0-9]*; do
		cleanup_pid=${cleanup_proc#/proc/}
		if nsenter -t "$cleanup_pid" -m \
			--root="/proc/$cleanup_pid/root" --wd=/ -- \
			test -r /nfs-lane/.lane_id 2>/dev/null; then
			cleanup_active_executor_mounts=$((cleanup_active_executor_mounts + 1))
		fi
	done
	if test "$cleanup_active_executor_mounts" -ne 0; then
		echo "refusing lane cleanup with $cleanup_active_executor_mounts active executor mount namespaces" >&2
		return 1
	fi

    if test -L "$executor_root" || \
        { test -e "$executor_root" && \
          { test ! -f "$executor_root/.frozen_phase9_fixture" || \
            test "$(cat "$executor_root/.frozen_phase9_fixture")" != "$root"; }; }; then
        printf '{"lane_count":%s,"mount_leaks":0,"namespace_leaks":0,"nfsd_resource_leaks":0,"veth_leaks":0,"domain_retire_failures":0,"source_tree_leaks":1}\n' \
            "$cleanup_count"
        return 1
    fi
    if test -d "$executor_root"; then
        while test "$cleanup_lane" -lt "$cleanup_count"; do
            cleanup_source=$executor_root/proc-$cleanup_lane
            for cleanup_netns in \
                "$cleanup_source/.client0_netns" \
                "$cleanup_source/.client1_netns"; do
                timeout 30s umount "$cleanup_netns" 2>/dev/null || true
                if mountpoint -q "$cleanup_netns" 2>/dev/null; then
                    cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                fi
            done
            for cleanup_client_mount in \
                "$cleanup_source/client0-knfsd" \
                "$cleanup_source/client0-ganesha" \
                "$cleanup_source/client1-knfsd" \
                "$cleanup_source/client1-ganesha" \
                "$cleanup_source/client0" "$cleanup_source/client1"; do
                if nfs_mount_exists "$cleanup_client_mount"; then
                    timeout 30s umount "$cleanup_client_mount" 2>/dev/null || true
                    if nfs_mount_exists "$cleanup_client_mount"; then
                        cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                    fi
                fi
            done
            cleanup_lane=$((cleanup_lane + 1))
        done
    fi
    cleanup_lane=0

    while test "$cleanup_lane" -lt "$cleanup_count"; do
        cleanup_lane_root=$root/lane$cleanup_lane
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: cross mounts lane=$cleanup_lane" >&2
        fi
        for cleanup_cross_mount in \
            "$cleanup_lane_root/client0/ganesha" \
            "$cleanup_lane_root/client1/knfsd"; do
            if nfs_mount_exists "$cleanup_cross_mount"; then
                if test -e "$root/relay.cleanup.trace"; then
                    echo "KOOV cleanup trace: umount $cleanup_cross_mount" >&2
                fi
                timeout 30s umount "$cleanup_cross_mount" 2>/dev/null || true
                if nfs_mount_exists "$cleanup_cross_mount"; then
                    cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                fi
            fi
        done
        cleanup_client=0
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: primary mounts lane=$cleanup_lane" >&2
        fi
        while test "$cleanup_client" -lt 2; do
            cleanup_mount=$cleanup_lane_root/client$cleanup_client/mnt
            if nfs_mount_exists "$cleanup_mount"; then
                if test -e "$root/relay.cleanup.trace"; then
                    echo "KOOV cleanup trace: umount $cleanup_mount" >&2
                fi
                timeout 30s umount "$cleanup_mount" 2>/dev/null || true
                if nfs_mount_exists "$cleanup_mount"; then
                    cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                fi
            fi
            cleanup_client=$((cleanup_client + 1))
        done

        if test "$cleanup_mount_leaks" -ne 0; then
            echo "KOOV: NFS mounts still present; refusing to traverse $root" >&2
            return 1
        fi

        cleanup_server_ns=$(lane_server_ns "$cleanup_lane")
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: server resources lane=$cleanup_lane" >&2
        fi
        if test -s "$cleanup_lane_root/server.pid"; then
            cleanup_server_pid=$(cat "$cleanup_lane_root/server.pid")
            if pid_in_named_netns "$cleanup_server_pid" "$cleanup_server_ns"; then
                timeout 30s nsenter -t "$cleanup_server_pid" -m -n -- sh -c \
                    'test ! -e /proc/fs/nfsd/threads || printf "0\n" > /proc/fs/nfsd/threads; exportfs -au 2>/dev/null || true' \
                    2>/dev/null || cleanup_nfsd_leaks=$((cleanup_nfsd_leaks + 1))
                # KOOV: only look for leaked nfsd threads if there IS a kernel
                # NFS server.  cleanup_fixture read /proc/fs/nfsd/threads and
                # counted a leak for anything that is not the literal 0; in
                # ganesha mode that path does not exist, the read failed, the
                # fallback printed "invalid", and every Ganesha lane was reported
                # as leaking nfsd resources.  A kernel NFS server that is not
                # there cannot leak threads.  Same class of knfsd-only
                # assumption as the runner's server_threads gate.
                cleanup_nfsd_present=$(nsenter -t "$cleanup_server_pid" -m -n -- \
                    test -e /proc/fs/nfsd/threads && echo 1 || echo 0)
                if test "$cleanup_nfsd_present" = 1; then
                    cleanup_threads=$(nsenter -t "$cleanup_server_pid" -m -n -- \
                        cat /proc/fs/nfsd/threads 2>/dev/null || printf 'invalid\n')
                    case "$cleanup_threads" in
                        0) ;;
                        *) cleanup_nfsd_leaks=$((cleanup_nfsd_leaks + 1)) ;;
                    esac
                fi
            elif namespace_exists "$cleanup_server_ns"; then
                cleanup_nfsd_leaks=$((cleanup_nfsd_leaks + 1))
            fi
        fi

        cleanup_client0_ns=$(lane_client_ns "$cleanup_lane" 0)
        cleanup_client1_ns=$(lane_client_ns "$cleanup_lane" 1)
        if test -s "$cleanup_lane_root/lane_epoch"; then
            cleanup_epoch=$(cat "$cleanup_lane_root/lane_epoch")
            case "$cleanup_epoch" in
                ''|*[!0-9]*) cleanup_domain_retire_failures=$((cleanup_domain_retire_failures + 1)) ;;
                *)
                    if ! namespace_exists "$cleanup_server_ns" || \
                        ! in_netns_with_host_mounts "$cleanup_server_ns" sh -c \
                        'printf "retire %s %s\n" "$1" "$2" > "$3"' sh \
                        "$cleanup_lane" "$cleanup_epoch" "$domain_control" || \
                        test "$(in_netns_with_host_mounts "$cleanup_server_ns" \
                            cat "$domain_state" 2>/dev/null || true)" != \
                            "lane_id $cleanup_lane lane_epoch $cleanup_epoch active 0"; then
                        cleanup_domain_retire_failures=$((cleanup_domain_retire_failures + 1))
                    fi
                    ;;
            esac
        fi

        stop_namespace "$cleanup_client0_ns" || \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: client0 stopped lane=$cleanup_lane" >&2
        fi
        stop_namespace "$cleanup_client1_ns" || \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: client1 stopped lane=$cleanup_lane" >&2
        fi
        stop_namespace "$cleanup_server_ns" || \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        if test -e "$root/relay.cleanup.trace"; then
            echo "KOOV cleanup trace: server stopped lane=$cleanup_lane" >&2
        fi
        namespace_exists "$cleanup_client0_ns" && \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        namespace_exists "$cleanup_client1_ns" && \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        namespace_exists "$cleanup_server_ns" && \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        for cleanup_link in \
            "$(lane_link "$cleanup_lane" c 0)" \
            "$(lane_link "$cleanup_lane" s 0)" \
            "$(lane_link "$cleanup_lane" c 1)" \
            "$(lane_link "$cleanup_lane" s 1)"; do
            if ip link show "$cleanup_link" >/dev/null 2>&1; then
                cleanup_veth_leaks=$((cleanup_veth_leaks + 1))
            fi
        done
        cleanup_lane=$((cleanup_lane + 1))
    done

    if test "$cleanup_source_tree_leaks" -eq 0 && \
        test -f "$executor_root/.frozen_phase9_fixture"; then
        cleanup_lane=0
        while test "$cleanup_lane" -lt "$cleanup_count"; do
            cleanup_source=$executor_root/proc-$cleanup_lane
            rm -f "$cleanup_source/.lane_id" \
                "$cleanup_source/.client0_pid" "$cleanup_source/.client1_pid" \
                "$cleanup_source/.client0_netns" "$cleanup_source/.client1_netns" \
                "$cleanup_source/.server0_ipv4" "$cleanup_source/.server1_ipv4"
            rm -f "$cleanup_source/control/arm.sock"
            rmdir "$cleanup_source/control" 2>/dev/null || true
            rmdir "$cleanup_source/client0-knfsd" \
                "$cleanup_source/client0-ganesha" \
                "$cleanup_source/client1-knfsd" \
                "$cleanup_source/client1-ganesha" 2>/dev/null || true
            rmdir "$cleanup_source/client0" "$cleanup_source/client1" \
                "$cleanup_source" 2>/dev/null || cleanup_source_tree_leaks=1
            cleanup_lane=$((cleanup_lane + 1))
        done
        rm -f "$executor_root/enabled" "$executor_root/.lane_count" \
            "$executor_root/.frozen_phase9_fixture"
        rmdir "$executor_root" 2>/dev/null || cleanup_source_tree_leaks=1
    fi
    if test -e "$root/relay.cleanup.trace"; then
        echo "KOOV cleanup trace: rm root=$root" >&2
    fi
    rm -rf "$root"
    printf '{"lane_count":%s,"mount_leaks":%s,"namespace_leaks":%s,"nfsd_resource_leaks":%s,"veth_leaks":%s,"domain_retire_failures":%s,"source_tree_leaks":%s,"active_executor_mounts":%s}\n' \
        "$cleanup_count" "$cleanup_mount_leaks" "$cleanup_namespace_leaks" \
        "$cleanup_nfsd_leaks" "$cleanup_veth_leaks" \
        "$cleanup_domain_retire_failures" "$cleanup_source_tree_leaks" \
		"$cleanup_active_executor_mounts"
    test "$cleanup_mount_leaks" -eq 0
    test "$cleanup_namespace_leaks" -eq 0
    test "$cleanup_nfsd_leaks" -eq 0
    test "$cleanup_veth_leaks" -eq 0
    test "$cleanup_domain_retire_failures" -eq 0
    test "$cleanup_source_tree_leaks" -eq 0
	test "$cleanup_active_executor_mounts" -eq 0
}

status_fixture()
{
    if test -e "$root/relay.status.trace"; then
        set -x
    fi
    test -s "$root/fixture.count"
    status_count=$(cat "$root/fixture.count")
    valid_count "$status_count"
    status_version=$(cat "$root/fixture.version")
    case "$status_version" in 3|4.0|4.1|4.2) ;; *) return 1 ;; esac
    status_mount_type=nfs4
    status_mount_version=$status_version
    status_minor_json=${status_version#4.}
    if [ "$status_version" = 3 ]; then
        status_mount_type=nfs
        status_minor_json=null
    fi
    test "$(cat /sys/module/nfs/parameters/localio_enabled)" = N
    test "$(cat "$executor_root/enabled")" -eq 1
    test "$(cat "$executor_root/.lane_count")" -eq "$status_count"
    test "$(cat "$executor_root/.frozen_phase9_fixture")" = "$root"
    printf '{"lane_count":%s,"nfs_version":"%s","nfs_minor":%s,"localio":"N","lanes":[' \
        "$status_count" "$status_version" "$status_minor_json"
    status_lane=0
    status_previous_epoch=0
    while test "$status_lane" -lt "$status_count"; do
        status_lane_root=$root/lane$status_lane
        status_server_ns=$(lane_server_ns "$status_lane")
        status_client0_ns=$(lane_client_ns "$status_lane" 0)
        status_client1_ns=$(lane_client_ns "$status_lane" 1)
        status_epoch=$(cat "$status_lane_root/lane_epoch")
        case "$status_epoch" in
            ''|*[!0-9]*) return 1 ;;
        esac
        test "$status_epoch" -gt 0
        test "$status_epoch" -gt "$status_previous_epoch"

        status_server_pid=$(cat "$status_lane_root/server.pid")
        status_client0_pid=$(cat "$status_lane_root/client0.pid")
        status_client1_pid=$(cat "$status_lane_root/client1.pid")
        namespace_exists "$status_server_ns"
        namespace_exists "$status_client0_ns"
        namespace_exists "$status_client1_ns"
        pid_in_named_netns "$status_server_pid" "$status_server_ns"
        pid_in_named_netns "$status_client0_pid" "$status_client0_ns"
        pid_in_named_netns "$status_client1_pid" "$status_client1_ns"

        for status_client in 0 1; do
            status_pid=$(cat "$status_lane_root/client$status_client.pid")
            nsenter -t "$status_pid" -m -n -- grep -Eq \
                " $status_lane_root/client$status_client/mnt $status_mount_type .*vers=$status_mount_version.*proto=tcp" \
                /proc/mounts
        done
        test -L "$root/proc$status_lane"
        test -L "$root/proc$status_lane-peer"
        test "$(cat "$root/proc$status_lane.pid")" -eq "$status_client0_pid"
        test "$(cat "$root/proc$status_lane-peer.pid")" -eq "$status_client1_pid"

        status_expected_domain="lane_id $status_lane lane_epoch $status_epoch active 1"
        test "$(in_netns_with_host_mounts "$status_server_ns" cat "$domain_state")" = \
            "$status_expected_domain"
        test "$(in_netns_with_host_mounts "$status_client0_ns" cat "$domain_state")" = \
            "$status_expected_domain"
        test "$(in_netns_with_host_mounts "$status_client1_ns" cat "$domain_state")" = \
            "$status_expected_domain"

        # KOOV: the nfsd gates are knfsd-specific, and the client-facing
        # port is no longer hardcoded to 2049.
        status_port_hex=$(printf "%04X" "$server_port")
        status_threads=0
        if [ "$server_impl" != ganesha ]; then
            status_threads=$(nsenter -t "$status_server_pid" -m -n -- \
                cat /proc/fs/nfsd/threads)
            test "$status_threads" -ge 2
        fi
        # Both families: a client of a dual-stack IPv6 listener gets an
        # AF_INET6 socket, so its ESTABLISHED row lives in
        # /proc/net/tcp6 even when the peer address is IPv4.  Summing both
        # tables is a no-op for knfsd (v4 only) and is what makes the
        # count meaningful for ganesha.
        status_connections=$(nsenter -t "$status_server_pid" -m -n -- awk \
            -v p="$status_port_hex" \
            '$2 ~ ":"p"$" && $4 == "01" { count++ } END { print count + 0 }' \
            /proc/net/tcp /proc/net/tcp6)
        test "$status_connections" -ge 2
        # KOOV: Ganesha liveness is an explicit gate.  A Ganesha that died
        # quietly would otherwise be recorded as "no bugs found", which is
        # the false-negative channel this axis is most exposed to.
        status_ganesha_live=0
        status_ganesha_listen=0
        status_ganesha_backing=
        status_ganesha_backing_options=
        if [ "$server_impl" = ganesha ] || [ "$server_impl" = both ]; then
            status_ganesha_pid=$(cat "$status_lane_root/server/ganesha.pid")
            kill -0 "$status_ganesha_pid"
            test -f "$status_lane_root/server/ganesha.ready"
            status_ganesha_live=1
            status_ganesha_hex=$(printf "%04X" "$ganesha_port")
            # Ganesha binds ":::PORT" (Bind_sockets_V6, v6disabled = 0),
            # so its listener is in /proc/net/tcp6 and NOT in
            # /proc/net/tcp.
            status_ganesha_listen=$(nsenter -t "$status_server_pid" -m -n -- awk \
                -v p="$status_ganesha_hex" \
                '$2 ~ ":"p"$" && $4 == "0A" { n++ } END { print n + 0 }' \
                /proc/net/tcp /proc/net/tcp6)
            test "$status_ganesha_listen" -ge 1
            status_ganesha_backing=$(nsenter -t "$status_server_pid" -m -n -- \
                findmnt -n -o SOURCE \
                -- "$status_lane_root/server/export-ganesha")
            case "$status_ganesha_backing" in
                /dev/loop*) ;;
                *) echo "KOOV: Ganesha backing is not a loop device" >&2
                   exit 1 ;;
            esac
            test "$(nsenter -t "$status_server_pid" -m -n -- \
                findmnt -n -o FSTYPE -- \
                "$status_lane_root/server/export-ganesha")" = ext4
            status_ganesha_bytes=$(stat -c %s \
                "$status_lane_root/server/ganesha.ext4")
            test "$status_ganesha_bytes" -gt 0
            test "$(blockdev --getsize64 "$status_ganesha_backing")" -eq \
                "$status_ganesha_bytes"
            status_ganesha_backing_options=$(nsenter -t "$status_server_pid" \
                -m -n -- findmnt -n -o OPTIONS \
                -- "$status_lane_root/server/export-ganesha")
        fi
        if [ "$server_impl" = both ]; then
            status_relay_pid=$(cat "$status_lane_root/server/proxy.pid")
            pid_in_named_netns "$status_relay_pid" "$status_server_ns"
            test "$status_connections" -ge 4
            nsenter -t "$status_client0_pid" -m -n -- grep -Eq \
                " $status_lane_root/client0/ganesha $status_mount_type .*vers=$status_mount_version.*proto=tcp" \
                /proc/mounts
            nsenter -t "$status_client1_pid" -m -n -- grep -Eq \
                " $status_lane_root/client1/knfsd $status_mount_type .*vers=$status_mount_version.*proto=tcp" \
                /proc/mounts
            status_knfsd_source=10.89.$status_lane.1:/
            status_ganesha_source=10.89.$status_lane.5:/
            if [ "$status_version" = 3 ]; then
                status_knfsd_source=10.89.$status_lane.1:$status_lane_root/server/export
                status_ganesha_source=10.89.$status_lane.5:$status_lane_root/server/export-ganesha
            fi
            test "$(findmnt -n -o SOURCE -- "$status_lane_root/client0/ganesha")" = \
                "$status_ganesha_source"
            test "$(findmnt -n -o SOURCE -- "$status_lane_root/client1/knfsd")" = \
                "$status_knfsd_source"
        fi
        status_backing_type=$(nsenter -t "$status_server_pid" -m -n -- \
            findmnt -n -o FSTYPE -- "$status_lane_root/server/export")
        status_backing_source=$(nsenter -t "$status_server_pid" -m -n -- \
            findmnt -n -o SOURCE -- "$status_lane_root/server/export")
        test "$status_backing_type" = tmpfs
        test "$status_backing_source" = frozen-phase9-lane$status_lane
        # KOOV: the per-lane tmpfs MUST be size-bounded.  Unbounded, a runaway
        # program exhausts guest RAM and the OOM kill is indistinguishable
        # from a kernel bug -- the measurement channel dies silently.
        status_backing_options=$(nsenter -t "$status_server_pid" -m -n -- \
            findmnt -n -o OPTIONS -- "$status_lane_root/server/export")
        case "$status_backing_options" in
            *size=*) ;;
            *) echo "KOOV: lane tmpfs is not size-bounded (OPTIONS=$status_backing_options)" >&2
               exit 1 ;;
        esac

        status_client0_identifier=$(cat "$status_lane_root/client0.identifier")
        status_client1_identifier=$(cat "$status_lane_root/client1.identifier")
        test "$status_client0_identifier" = \
            frozen-phase9-lane${status_lane}-client0
        test "$status_client1_identifier" = \
            frozen-phase9-lane${status_lane}-client1
        test "$status_client0_identifier" != "$status_client1_identifier"
        status_source=$executor_root/proc-$status_lane
        test "$(cat "$status_source/.lane_id")" -eq "$status_lane"
        status_source_entries=$(find "$status_source" -mindepth 1 \
            -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
        if [ "$server_impl" = both ]; then
            test "$status_source_entries" = "$(printf '.client0_netns\n.client0_pid\n.client1_netns\n.client1_pid\n.lane_id\n.server0_ipv4\n.server1_ipv4\nclient0\nclient0-ganesha\nclient0-knfsd\nclient1\nclient1-ganesha\nclient1-knfsd\ncontrol\n')"
            test -S "$status_source/control/arm.sock"
            for status_bind in client0-knfsd client0-ganesha \
                client1-knfsd client1-ganesha; do
                nfs_mount_exists "$status_source/$status_bind"
            done
            test "$(findmnt -n -o SOURCE -- "$status_source/client0-knfsd")" = "$status_knfsd_source"
            test "$(findmnt -n -o SOURCE -- "$status_source/client1-knfsd")" = "$status_knfsd_source"
            test "$(findmnt -n -o SOURCE -- "$status_source/client0-ganesha")" = "$status_ganesha_source"
            test "$(findmnt -n -o SOURCE -- "$status_source/client1-ganesha")" = "$status_ganesha_source"
        else
            test "$status_source_entries" = "$(printf '.client0_netns\n.client0_pid\n.client1_netns\n.client1_pid\n.lane_id\n.server0_ipv4\n.server1_ipv4\nclient0\nclient1\n')"
        fi
        mountpoint -q "$status_source/.client0_netns"
        mountpoint -q "$status_source/.client1_netns"
        test "$(cat "$status_source/.client0_pid")" -eq "$status_client0_pid"
        test "$(cat "$status_source/.client1_pid")" -eq "$status_client1_pid"
        test "$(cat "$status_source/.server0_ipv4")" = "10.89.$status_lane.1"
        test "$(cat "$status_source/.server1_ipv4")" = "10.89.$status_lane.5"
        nfs_mount_exists "$status_source/client0"
        nfs_mount_exists "$status_source/client1"
        test "$(findmnt -n -o FSTYPE -- "$status_source/client0")" = "$status_mount_type"
        test "$(findmnt -n -o FSTYPE -- "$status_source/client1")" = "$status_mount_type"
        status_client0_source=10.89.$status_lane.1:/
        status_client1_source=10.89.$status_lane.5:/
        if [ "$server_impl" = both ]; then
            status_client1_source=$status_knfsd_source
        elif [ "$status_version" = 3 ]; then
            status_export=export
            if [ "$server_impl" = ganesha ]; then
                status_export=export-ganesha
            fi
            status_client0_source=10.89.$status_lane.1:$status_lane_root/server/$status_export
            status_client1_source=10.89.$status_lane.5:$status_lane_root/server/$status_export
        fi
        if [ "$server_impl" = both ]; then
            status_client0_source=$status_knfsd_source
        fi
        test "$(findmnt -n -o SOURCE -- "$status_source/client0")" = "$status_client0_source"
        test "$(findmnt -n -o SOURCE -- "$status_source/client1")" = "$status_client1_source"

        test "$status_lane" -eq 0 || printf ','
        printf '{"lane_id":%s,"lane_epoch":%s,"proc":%s,"server_namespace":"%s","client0_namespace":"%s","client1_namespace":"%s","server0_ip":"10.89.%s.1","client0_ip":"10.89.%s.2","server1_ip":"10.89.%s.5","client1_ip":"10.89.%s.6","backing_root":"%s/lane%s/server/export","backing_source":"%s","proc_pid":%s,"proc_mount":"%s/proc%s/mnt","peer_pid":%s,"peer_mount":"%s/proc%s-peer/mnt","source_root":"%s/proc-%s","source_client0":"%s/proc-%s/client0","source_client1":"%s/proc-%s/client1","client0_identifier":"%s","client1_identifier":"%s","server_threads":%s,"tcp_connections":%s,"server_port":%s,"ganesha_live":%s,"ganesha_listen":%s,"ganesha_backing_source":"%s","backing_options":"%s","ganesha_backing_options":"%s"}' \
            "$status_lane" "$status_epoch" "$status_lane" \
            "$status_server_ns" "$status_client0_ns" "$status_client1_ns" \
            "$status_lane" "$status_lane" "$status_lane" "$status_lane" \
            "$root" "$status_lane" "$status_backing_source" \
            "$status_client0_pid" "$root" "$status_lane" \
            "$status_client1_pid" "$root" "$status_lane" \
            "$executor_root" "$status_lane" \
            "$executor_root" "$status_lane" \
            "$executor_root" "$status_lane" \
            "$status_client0_identifier" "$status_client1_identifier" \
            "$status_threads" "$status_connections" \
            "$server_port" "$status_ganesha_live" "$status_ganesha_listen" \
            "$status_ganesha_backing" "$status_backing_options" \
            "$status_ganesha_backing_options"
        status_previous_epoch=$status_epoch
        status_lane=$((status_lane + 1))
    done
    printf ']}\n'
    if test -e "$root/relay.status.trace"; then
        set +x
    fi
}

case "$action" in
cleanup)
    cleanup_fixture
    ;;
status)
    status_fixture
    ;;
setup)
    requested_count=${3:?setup requires a lane/proc count: 1, 2, or 4}
    valid_count "$requested_count" || {
        echo "Phase 9 lane/proc count must be 1, 2, or 4" >&2
        exit 2
    }
    cleanup_fixture >/dev/null
    trap 'rc=$?; trap - EXIT; if test "$rc" -ne 0; then
        for failed_log in "$root"/lane*/server.log; do
            test ! -f "$failed_log" || tail -n 80 "$failed_log" >&2
        done
        cleanup_fixture >/dev/null || true
    fi; exit "$rc"' EXIT
    mkdir -p "$root"
    printf '%s\n' "$requested_count" > "$root/fixture.count"
    printf '%s\n' "$nfs_version" > "$root/fixture.version"
    if test -e "$executor_root" || test -L "$executor_root"; then
        echo "$executor_root is already owned by another fixture" >&2
        exit 1
    fi
    mkdir -m 0755 "$executor_root"
    if ! printf '%s\n' "$root" > "$executor_root/.frozen_phase9_fixture"; then
        rm -f "$executor_root/.frozen_phase9_fixture"
        rmdir "$executor_root" 2>/dev/null || true
        exit 1
    fi
    printf '%s\n' "$requested_count" > "$executor_root/.lane_count"
    setup_index=0
    while test "$setup_index" -lt "$requested_count"; do
        setup_lane "$setup_index"
        expose_lane_to_executor "$setup_index"
        setup_index=$((setup_index + 1))
    done
    printf '1\n' > "$executor_root/enabled"
    status_fixture
    trap - EXIT
    ;;
*)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
