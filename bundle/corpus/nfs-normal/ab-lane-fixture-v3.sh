#!/bin/sh
# B04 NFSv3 lane fixture (inline; attribution adaptation).
#
# NFSv3 is load-bearing for deterministic svc_defer re-entry: unlike NFSv4,
# its filehandle decode does not clear RQ_USEDEFERRAL before nfsd.fh lookup.
#
# INLINE form is load-bearing: the guest exhausts fork capacity when a thin
# wrapper forks /opt/frozen-phase9/lane.sh during the boot-fixture retirement
# window ("Cannot fork" / rc=124 in fixture-setup).  Like the AB fixture
# (tools/ab-lane-fixture.sh), this file IS the lane script: prelude first,
# then the original lane.sh body verbatim below (byte-identical to the baked
# /opt/frozen-phase9/lane.sh which the image baker installs).
set -eu
action=${1:-}
case "$action" in
    setup)
        systemctl stop frozen-phase9-fixture.service >/dev/null 2>&1 || \
            NFS_MINOR_VERSION=${NFS_MINOR_VERSION:-1} \
                /opt/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager >/dev/null 2>&1 || true
        ;;
esac
NFS_MINOR_VERSION=3
export NFS_MINOR_VERSION

# ==== original frozen_phase9_lane.sh body (verbatim) ====
#!/bin/sh
# Disposable-VM Phase 9 multi-lane fixture. Never run this on the host.
set -eu

action=${1:?usage: frozen_phase9_lane.sh setup ROOT 1|2|4 | status ROOT | cleanup ROOT}
root=${2:?usage: frozen_phase9_lane.sh setup ROOT 1|2|4 | status ROOT | cleanup ROOT}

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
nfs_minor_version=${NFS_MINOR_VERSION:-1}
case "$nfs_minor_version" in
    3) ;;
    *) echo "B04 fixture requires NFS version 3" >&2; exit 2 ;;
esac

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
    client_minor=$5
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
    nsenter --net="/run/netns/$client_ns" -- \
        mount.nfs -o "vers=3,proto=tcp,mountproto=tcp,port=2049,mountport=20048,sec=sys,actimeo=0,lookupcache=none,nosharecache" \
        "$client_server_ip:$client_root/server/export" "$client_mount"
    grep -F " $client_mount nfs " /proc/mounts > \
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

setup_lane()
{
    setup_lane_id=$1
    setup_lane_root=$root/lane$setup_lane_id
    setup_server_ns=$(lane_server_ns "$setup_lane_id")
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
        "$setup_lane_root/server/state/nfs" \
        "$setup_lane_root/server/state/rpcbind" \
        "$setup_lane_root/client0/mnt" "$setup_lane_root/client1/mnt"

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
        mount --bind "$lane_root/server/state/rpcbind" /run
        mkdir -p /run/rpcbind
        mkdir -p /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery \
            /var/lib/nfs/nfsdcld
        touch /var/lib/nfs/etab /var/lib/nfs/rmtab
        mount -t tmpfs -o mode=0755 "frozen-phase9-lane$lane" \
            "$lane_root/server/export"
        mkdir -p "$lane_root/server/export/shared"
        printf "frozen Phase 9 lane %s fixture\n" "$lane" > \
            "$lane_root/server/export/shared/fixture"
        # NFSv3/lockd need a responsive rpcbind in this lane before threads
        # start. Its socket and PID paths must remain inside the private /run.
        if getent passwd _rpc > "$lane_root/server/rpcbind-nss.log"; then
            echo "_rpc_rc=0" >> "$lane_root/server/rpcbind-nss.log"
        else
            echo "_rpc_rc=$?" >> "$lane_root/server/rpcbind-nss.log"
        fi
        getent passwd daemon > "$lane_root/server/rpcbind-run-user"
        rpcbind -d -s -f >"$lane_root/server/rpcbind.log" 2>&1 &
        rpcbind_pid=$!
        printf "%s\n" "$rpcbind_pid" > "$lane_root/server/rpcbind.pid"
        rpcbind_ready=0
        rpcbind_probe=0
        while test "$rpcbind_probe" -lt 200; do
            if rpcinfo -n 111 -t 127.0.0.1 100000 4 >/dev/null 2>&1; then
                rpcbind_ready=1
                break
            fi
            if ! kill -0 "$rpcbind_pid" 2>/dev/null; then
                echo "rpcbind exited before protocol readiness" >&2
                if wait "$rpcbind_pid"; then
                    echo "rpcbind exit status 0" >&2
                else
                    echo "rpcbind exit status $?" >&2
                fi
                cat "$lane_root/server/rpcbind.log" >&2
                exit 1
            fi
            rpcbind_probe=$((rpcbind_probe + 1))
            sleep 0.05
        done
        if test "$rpcbind_ready" -ne 1; then
            echo "rpcbind did not answer RPCB v4 over lane-local TCP/111" >&2
            cat "$lane_root/server/rpcbind.log" >&2
            exit 1
        fi
        rpcinfo -p 127.0.0.1 > "$lane_root/server/rpcbind.ready"
        {
            printf "shell_net="; readlink /proc/self/ns/net
            printf "rpcbind_net="; readlink "/proc/$rpcbind_pid/ns/net"
            printf "init_net="; readlink /proc/1/ns/net
        } > "$lane_root/server/netns-identities.txt"
        test "$(stat -Lc "%d:%i" /proc/self/ns/net)" = \
            "$(stat -Lc "%d:%i" "/proc/$rpcbind_pid/ns/net")"
        mount -t nfsd nfsd /proc/fs/nfsd
        mountpoint -q /var/lib/nfs/rpc_pipefs || \
            mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs
        snapshot_nfsd()
        {
            {
                printf "stage=%s\n" "$1"
                cat /proc/fs/nfsd/versions
                cat /proc/fs/nfsd/portlist
                cat /proc/fs/nfsd/threads
                grep ":0801 " /proc/net/tcp /proc/net/tcp6 || true
            } > "$lane_root/server/nfsd-$1.txt"
        }
        printf "%s\n" "-2 +3 -4" > /proc/fs/nfsd/versions
        snapshot_nfsd after-versions
        printf "10\n" > /proc/fs/nfsd/nfsv4leasetime
        printf "10\n" > /proc/fs/nfsd/nfsv4gracetime
        exportfs -i -o rw,sync,insecure,no_subtree_check,no_root_squash,fsid=0 \
            "$export_network:$lane_root/server/export"
        rpc.mountd --no-nfs-version 2 --no-nfs-version 4 --no-udp --port 20048
        nfsdcld
        printf "tcp 2049\n" > /proc/fs/nfsd/portlist
        snapshot_nfsd after-portlist
        printf "4\n" > /proc/fs/nfsd/threads
        snapshot_nfsd after-threads
        if ! rpcinfo -n 2049 -t 127.0.0.1 100003 3 \
                > "$lane_root/server/nfs3-null.stdout" \
                2> "$lane_root/server/nfs3-null.stderr"; then
            echo "NFSv3 direct NULL failed; retained control snapshots:" >&2
            for stage in after-versions after-portlist after-threads; do
                cat "$lane_root/server/nfsd-$stage.txt" >&2
            done
            cat "$lane_root/server/netns-identities.txt" >&2
            cat "$lane_root/server/nfs3-null.stderr" >&2
            exit 1
        fi
        rpcinfo -n 20048 -t 127.0.0.1 100005 3 >/dev/null
        rpcinfo -p 127.0.0.1 > "$lane_root/server/rpc-programs.ready"
        grep -Eq "^[[:space:]]*100003[[:space:]]+3[[:space:]]+tcp[[:space:]]+2049([[:space:]]|$)" \
            "$lane_root/server/rpc-programs.ready"
        grep -Eq "^[[:space:]]*100005[[:space:]]+3[[:space:]]+tcp[[:space:]]+20048([[:space:]]|$)" \
            "$lane_root/server/rpc-programs.ready"
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
    setup_client "$setup_lane_id" 0 "$setup_client0_ns" "$setup_server0_ip" "$nfs_minor_version"
    setup_client "$setup_lane_id" 1 "$setup_client1_ns" "$setup_server1_ip" "$nfs_minor_version"

    # A fixed fuzzer process N enters only lane N's primary client mount
    # namespace.  Its peer alias preserves the second Phase 1 client for
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
    mount --bind "$expose_lane_root/client1/mnt" "$expose_source/client1"
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
                "$cleanup_source/client0" "$cleanup_source/client1"; do
                timeout 30s umount "$cleanup_client_mount" 2>/dev/null || true
                if mountpoint -q "$cleanup_client_mount" 2>/dev/null; then
                    cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                fi
            done
            cleanup_lane=$((cleanup_lane + 1))
        done
    fi
    cleanup_lane=0

    while test "$cleanup_lane" -lt "$cleanup_count"; do
        cleanup_lane_root=$root/lane$cleanup_lane
        cleanup_client=0
        while test "$cleanup_client" -lt 2; do
            cleanup_mount=$cleanup_lane_root/client$cleanup_client/mnt
            if mountpoint -q "$cleanup_mount" 2>/dev/null; then
                timeout 30s umount "$cleanup_mount" 2>/dev/null || true
                if mountpoint -q "$cleanup_mount" 2>/dev/null; then
                    cleanup_mount_leaks=$((cleanup_mount_leaks + 1))
                fi
            fi
            cleanup_client=$((cleanup_client + 1))
        done

        cleanup_server_ns=$(lane_server_ns "$cleanup_lane")
        if test -s "$cleanup_lane_root/server.pid"; then
            cleanup_server_pid=$(cat "$cleanup_lane_root/server.pid")
            if pid_in_named_netns "$cleanup_server_pid" "$cleanup_server_ns"; then
                timeout 30s nsenter -t "$cleanup_server_pid" -m -n -- sh -c \
                    'test ! -e /proc/fs/nfsd/threads || printf "0\n" > /proc/fs/nfsd/threads; exportfs -au 2>/dev/null || true' \
                    2>/dev/null || cleanup_nfsd_leaks=$((cleanup_nfsd_leaks + 1))
                cleanup_threads=$(nsenter -t "$cleanup_server_pid" -m -n -- \
                    cat /proc/fs/nfsd/threads 2>/dev/null || printf 'invalid\n')
                case "$cleanup_threads" in
                    0) ;;
                    *) cleanup_nfsd_leaks=$((cleanup_nfsd_leaks + 1)) ;;
                esac
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
        stop_namespace "$cleanup_client1_ns" || \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
        stop_namespace "$cleanup_server_ns" || \
            cleanup_namespace_leaks=$((cleanup_namespace_leaks + 1))
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
            rmdir "$cleanup_source/client0" "$cleanup_source/client1" \
                "$cleanup_source" 2>/dev/null || cleanup_source_tree_leaks=1
            cleanup_lane=$((cleanup_lane + 1))
        done
        rm -f "$executor_root/enabled" "$executor_root/.lane_count" \
            "$executor_root/.frozen_phase9_fixture"
        rmdir "$executor_root" 2>/dev/null || cleanup_source_tree_leaks=1
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
    test -s "$root/fixture.count"
    status_count=$(cat "$root/fixture.count")
    valid_count "$status_count"
    status_minor=$(cat "$root/fixture.minor")
    case "$status_minor" in 1|2) ;; *) return 1 ;; esac
    test "$(cat /sys/module/nfs/parameters/localio_enabled)" = N
    test "$(cat "$executor_root/enabled")" -eq 1
    test "$(cat "$executor_root/.lane_count")" -eq "$status_count"
    test "$(cat "$executor_root/.frozen_phase9_fixture")" = "$root"
    printf '{"lane_count":%s,"nfs_minor":%s,"localio":"N","lanes":[' \
        "$status_count" "$status_minor"
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
            nsenter -t "$status_pid" -m -n -- mountpoint -q \
                "$status_lane_root/client$status_client/mnt"
            nsenter -t "$status_pid" -m -n -- grep -Eq \
                " $status_lane_root/client$status_client/mnt nfs .*vers=3.*proto=tcp" \
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

        status_threads=$(nsenter -t "$status_server_pid" -m -n -- \
            cat /proc/fs/nfsd/threads)
        test "$status_threads" -ge 2
        status_versions=$(nsenter -t "$status_server_pid" -m -n -- \
            cat /proc/fs/nfsd/versions)
        printf '%s\n' "$status_versions" | grep -Eq '(^| )\\+3( |$)'
        ! printf '%s\n' "$status_versions" | grep -Eq '(^| )\\+4( |$)'
        nsenter -t "$status_server_pid" -m -n -- \
            test -w /proc/net/rpc/nfsd.fh/flush
        status_connections=$(nsenter -t "$status_server_pid" -m -n -- awk \
            '$2 ~ /:0801$/ && $4 == "01" { count++ } END { print count + 0 }' \
            /proc/net/tcp)
        test "$status_connections" -ge 2
        status_backing_type=$(nsenter -t "$status_server_pid" -m -n -- \
            findmnt -n -o FSTYPE -- "$status_lane_root/server/export")
        status_backing_source=$(nsenter -t "$status_server_pid" -m -n -- \
            findmnt -n -o SOURCE -- "$status_lane_root/server/export")
        test "$status_backing_type" = tmpfs
        test "$status_backing_source" = frozen-phase9-lane$status_lane

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
        test "$status_source_entries" = "$(printf '.client0_netns\n.client0_pid\n.client1_netns\n.client1_pid\n.lane_id\n.server0_ipv4\n.server1_ipv4\nclient0\nclient1\n')"
        mountpoint -q "$status_source/.client0_netns"
        mountpoint -q "$status_source/.client1_netns"
        test "$(cat "$status_source/.client0_pid")" -eq "$status_client0_pid"
        test "$(cat "$status_source/.client1_pid")" -eq "$status_client1_pid"
        test "$(cat "$status_source/.server0_ipv4")" = "10.89.$status_lane.1"
        test "$(cat "$status_source/.server1_ipv4")" = "10.89.$status_lane.5"
        mountpoint -q "$status_source/client0"
        mountpoint -q "$status_source/client1"
        test "$(findmnt -n -o FSTYPE -- "$status_source/client0")" = nfs
        test "$(findmnt -n -o FSTYPE -- "$status_source/client1")" = nfs
        test "$(findmnt -n -o SOURCE -- "$status_source/client0")" = \
            "10.89.$status_lane.1:$root/lane$status_lane/server/export"
        test "$(findmnt -n -o SOURCE -- "$status_source/client1")" = \
            "10.89.$status_lane.5:$root/lane$status_lane/server/export"

        test "$status_lane" -eq 0 || printf ','
        printf '{"lane_id":%s,"lane_epoch":%s,"proc":%s,"server_namespace":"%s","client0_namespace":"%s","client1_namespace":"%s","server0_ip":"10.89.%s.1","client0_ip":"10.89.%s.2","server1_ip":"10.89.%s.5","client1_ip":"10.89.%s.6","backing_root":"%s/lane%s/server/export","backing_source":"%s","proc_pid":%s,"proc_mount":"%s/proc%s/mnt","peer_pid":%s,"peer_mount":"%s/proc%s-peer/mnt","source_root":"%s/proc-%s","source_client0":"%s/proc-%s/client0","source_client1":"%s/proc-%s/client1","client0_identifier":"%s","client1_identifier":"%s","server_threads":%s,"tcp_connections":%s}' \
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
            "$status_threads" "$status_connections"
        status_previous_epoch=$status_epoch
        status_lane=$((status_lane + 1))
    done
    printf ']}\n'
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
    trap 'rc=$?; trap - EXIT; if test "$rc" -ne 0; then cleanup_fixture >/dev/null || true; fi; exit "$rc"' EXIT
    mkdir -p "$root"
    printf '%s\n' "$requested_count" > "$root/fixture.count"
    printf '%s\n' "$nfs_minor_version" > "$root/fixture.minor"
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
