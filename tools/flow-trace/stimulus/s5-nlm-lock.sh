#!/bin/sh
# S5: NFSv3 byte-range lock conflict over NLM on lane 0, recorded by capture.py.
# Needs: ROOT (fixture root), NFS_VERSION=3.
#
# The lane client mounts use nolock, and the lane has no rpc.statd. This script
# leaves the lane mounts alone. Everything below runs inside the lane 0 server
# keeper namespaces (private /run and /var/lib/nfs, lane 0 network namespace):
#   1. start rpc.statd
#   2. export the lane 0 tree to 127.0.0.1
#   3. mount it over loopback WITHOUT nolock
#   4. two processes lock the same file; the second one blocks (NLM_BLOCKED)
#      until the first one releases (GRANTED_MSG callback from the lockd thread)
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
in_server sh -c "cat /var/lib/nfs/statd.log; pgrep -a rpc.statd" || true
in_server rpcinfo -p 127.0.0.1 | grep -E "status|nlockmgr" || echo "S5-NOTE no statd/nlockmgr in rpcbind"

say export-loopback
in_server exportfs -i -o rw,sync,insecure,no_subtree_check,no_root_squash,fsid=0 "127.0.0.1:$export_dir"

say mount-with-locks
in_server mkdir -p "$mnt"
in_server mount.nfs \
    -o "vers=3,proto=tcp,port=20490,mountproto=tcp,mountport=20048,sec=sys,actimeo=0,lookupcache=none,nosharecache" \
    "127.0.0.1:$export_dir" "$mnt"
in_server sh -c "grep -F ' $mnt ' /proc/mounts | head -1 | cut -c1-200"
in_server sh -c "echo nlm-test > $mnt/shared/.flow-s5-lock; sync"

say wait-lockd-grace
# New NLM locks are refused while the lockd grace period runs (about 50 s after
# the lane starts); the client retries about every 5 s. Wait for all four grace
# timers (one per lane) in the trace buffer, at most 120 s.
i=0
while [ "$(grep -c ' grace_end:' /sys/kernel/tracing/trace)" -lt 4 ] && [ $i -lt 120 ]; do
    sleep 1
    i=$((i + 1))
done
echo "S5-GRACE-WAIT-SECONDS $i"

say lock-conflict
# The holder is a local task on the server side: it takes a POSIX lock on the
# exported file itself. The NFS client's flock() becomes an NLM LOCK request, so
# the server must answer NLM_BLOCKED. When the holder exits, the VFS calls the
# lock manager (lm_notify), which grants the lock with a GRANTED_MSG callback.
# (Two NFS clients on one mount would race: the client holds the conflict locally.)
cat > /tmp/plock.c <<'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv)
{
	struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
	int fd = open(argv[1], O_RDWR);
	if (fd < 0 || fcntl(fd, F_SETLKW, &fl) < 0) {
		perror("plock");
		return 1;
	}
	printf("S5-HOLDER-LOCKED\n");
	fflush(stdout);
	sleep(atoi(argv[2]));
	printf("S5-HOLDER-RELEASING\n");
	return 0;
}
EOF
gcc -O1 -o /tmp/plock /tmp/plock.c
cp /tmp/plock "$ROOT/plock"
in_server "$ROOT/plock" "$export_dir/shared/.flow-s5-lock" 4 &
holder=$!
sleep 1
# waiter: blocks until the holder releases (NLM_BLOCKED, then GRANTED_MSG)
start=$(cut -d' ' -f1 /proc/uptime)
in_server flock -x "$mnt/shared/.flow-s5-lock" -c 'echo S5-WAITER-LOCKED' &
waiter=$!
wait $holder || true
wait $waiter || true
end=$(cut -d' ' -f1 /proc/uptime)
echo "S5-WAITED $start $end"

say unmount
in_server rm -f "$mnt/shared/.flow-s5-lock"
in_server umount "$mnt"
say done
