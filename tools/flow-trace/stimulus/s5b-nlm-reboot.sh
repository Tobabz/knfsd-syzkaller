#!/bin/sh
# S5b: NLM reclaim after a peer-reboot notification, recorded by capture.py.
# Needs: ROOT (fixture root), NFS_VERSION=3.
#
# Same setup as s5-nlm-lock.sh (loopback mount with locks in the lane 0 server
# keeper namespaces). A client task holds a lock; then rpc.statd is restarted
# WITHOUT --no-notify, so its sm-notify helper sends SM_NOTIFY to the hosts it
# monitored. lockd then runs nlm_host_rebooted and starts the reclaimer kthread.
set -eu
: "${ROOT:?}" "${NFS_VERSION:?}"
test "$NFS_VERSION" = 3 || { echo "S5-NOTE needs NFSv3"; exit 1; }
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
keeper=$(cat "$ROOT/lane0/server.pid")
export_dir=$ROOT/lane0/server/export
mnt=/mnt/flow-nlm
say() { echo "S5-STEP $1 $(cut -d' ' -f1 /proc/uptime)"; }
in_server() { nsenter -t "$keeper" -m -n -- "$@"; }

say start-statd
in_server mkdir -p /var/lib/nfs/sm /var/lib/nfs/sm.bak
in_server sh -c 'grep -q "$(hostname)" /etc/hosts || echo "127.0.0.1 $(hostname)" >> /etc/hosts'
in_server sh -c "rpc.statd --no-notify -F -d -p 32765 -o 32766 > /var/lib/nfs/statd.log 2>&1 &"
sleep 2
say export-loopback
in_server exportfs -i -o rw,sync,insecure,no_subtree_check,no_root_squash,fsid=0 "127.0.0.1:$export_dir"
say mount-with-locks
in_server mkdir -p "$mnt"
in_server mount.nfs \
    -o "vers=3,proto=tcp,port=20490,mountproto=tcp,mountport=20048,sec=sys,actimeo=0,lookupcache=none,nosharecache" \
    "127.0.0.1:$export_dir" "$mnt"
in_server sh -c "echo nlm-test > $mnt/shared/.flow-s5b-lock; sync"

say wait-lockd-grace
i=0
while [ "$(grep -c ' grace_end:' /sys/kernel/tracing/trace)" -lt 4 ] && [ $i -lt 120 ]; do
    sleep 1
    i=$((i + 1))
done
echo "S5-GRACE-WAIT-SECONDS $i"

say hold-lock
in_server flock -x "$mnt/shared/.flow-s5b-lock" -c 'echo S5-HELD; sleep 14; echo S5-RELEASING' &
holder=$!
sleep 2
in_server sh -c "ls /var/lib/nfs/sm /var/lib/nfs/sm.bak; pgrep -a rpc.statd"

say restart-statd-with-notify
# statd runs /sbin/sm-notify by absolute path; the lane image keeps it under the deps prefix.
[ -e /sbin/sm-notify ] || ln -s $deps/sbin/sm-notify /sbin/sm-notify
in_server pkill rpc.statd || true
sleep 1
# Start statd first and let it register. sm-notify run from a freshly started
# statd asks rpcbind before statd has registered and then waits 120 s to retry.
in_server sh -c "rpc.statd --no-notify -F -d -p 32765 -o 32766 >> /var/lib/nfs/statd.log 2>&1 &"
sleep 2
in_server sh -c "sm-notify -d -f -p 32766 > /var/lib/nfs/sm-notify.log 2>&1; tail -8 /var/lib/nfs/sm-notify.log" || true
sleep 3
in_server sh -c "tail -6 /var/lib/nfs/statd.log; ls /var/lib/nfs/sm /var/lib/nfs/sm.bak" || true
wait $holder || true

say unmount
in_server rm -f "$mnt/shared/.flow-s5b-lock"
in_server umount "$mnt" || echo "S5-NOTE umount failed"
say done
