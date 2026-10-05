#!/bin/sh
# S4: provoke state lifetime and cleanup work on lane 0 and record it.
# Needs: ROOT (fixture root), NFS_VERSION (4.0, 4.1 or 4.2). Run by capture.py.
# Steps (each prints a marker line so the trace can be aligned with the log):
#   1. create and close files on client0 (filecache entries, then GC)
#   2. flush the server's export caches (cache upcall to rpc.mountd, svc_revisit)
#   3. drop page/slab caches (shrinkers)
#   4. cut client1's link for longer than the lease (10 s) (laundromat, state expiry)
#   5. restore the link and access the mount again (client state manager recovery)
set -eu
: "${ROOT:?}" "${NFS_VERSION:?}"
mnt=$ROOT/lane0/client0/mnt
peer=$ROOT/lane0/client1/mnt
srv_ns=f9l0s
c1_ns=f9l0c1

say() { echo "S4-STEP $1 $(cut -d' ' -f1 /proc/uptime)"; }

say create-files
i=0
while [ $i -lt 8 ]; do
    echo "flow-s4 $i" > "$mnt/shared/.flow-s4-$i"
    i=$((i + 1))
done
sync
cat "$mnt"/shared/.flow-s4-* > /dev/null
rm -f "$mnt"/shared/.flow-s4-*
sleep 3

say flush-export-caches
# /proc/net follows the opener's network namespace, so writing from inside the
# server namespace flushes the lane's caches.
now=$(date +%s)
for f in auth.unix.ip auth.unix.gid nfsd.export nfsd.fh; do
    nsenter --net=/run/netns/$srv_ns -- sh -c "echo $((now + 1)) > /proc/net/rpc/$f/flush" || true
done
sleep 2
ls "$mnt/shared" > /dev/null
ls "$peer/shared" > /dev/null

say drop-caches
echo 3 > /proc/sys/vm/drop_caches
sleep 3

say link-down
dev=$(ip -n $c1_ns -o link show | awk -F': ' '$2 ~ /^f9/ {sub(/@.*/, "", $2); print $2; exit}')
test -n "$dev"
ip -n $c1_ns link set "$dev" down
sleep 25

say link-up
ip -n $c1_ns link set "$dev" up
sleep 2
timeout 60 ls "$peer/shared" > /dev/null || echo "S4-NOTE peer access failed after link-up"
timeout 60 sh -c "echo after-recovery > $peer/shared/.flow-s4-recovered && sync && rm -f $peer/shared/.flow-s4-recovered" \
    || echo "S4-NOTE peer write failed after link-up"
sleep 3
say done
