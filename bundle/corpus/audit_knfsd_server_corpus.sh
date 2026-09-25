#!/bin/sh
set -eu

if test "$#" -ne 1; then
	echo "usage: $0 CORPUS.db" >&2
	exit 2
fi

corpus=$1
syz_db=/home/fuzzer/tools/syzkaller-frozen-attribution/bin/syz-db
test -s "$corpus"

audit_dir=$(mktemp -d /tmp/knfsd-server-audit.XXXXXX)
"$syz_db" unpack "$corpus" "$audit_dir" >/dev/null

programs=0
lane_programs=0
both_clients=0
errors=0

for program in "$audit_dir"/*; do
	test -f "$program" || continue
	programs=$((programs + 1))

	if ! rg -q 'open\$dir\(.*nfs-lane/client[01]' "$program"; then
		echo "anchorless program: $program" >&2
		errors=$((errors + 1))
		continue
	fi
	lane_programs=$((lane_programs + 1))

	if ! rg -q '(^| = )(openat|creat|read|pread64|readv|write|pwrite64|writev|lseek|readahead|flock|fcntl\$(lock|setlease)|fsync|fdatasync|syncfs|sync_file_range|fallocate|copy_file_range|splice|mmap|msync|getdents64|statx|statfs|fstatfs|mkdir|mknod|rmdir|unlink|rename|link|symlink|readlink|chmod|fchmod|chown|fchown|utime|utimes|utimensat|truncate|ftruncate|setxattr|fsetxattr|getxattr|fgetxattr|listxattr|flistxattr|removexattr|fremovexattr)[^a-zA-Z0-9_]*\(' "$program"; then
		echo "no NFS workload operation: $program" >&2
		errors=$((errors + 1))
	fi

	if rg -q 'nfs-lane/\.lane_id|\.phase9-executor|\.phase9-peer|\.remote-kcov-ab' "$program"; then
		echo "fixture/marker path leaked into corpus: $program" >&2
		errors=$((errors + 1))
	fi

	if rg -q 'nfs-lane/client0' "$program" && rg -q 'nfs-lane/client1' "$program"; then
		both_clients=$((both_clients + 1))
	fi
done

if test "$programs" -eq 0; then
	echo "empty corpus: $corpus" >&2
	exit 1
fi

printf 'corpus=%s\nprograms=%s\nlane_anchored=%s\nboth_clients=%s\nerrors=%s\naudit_dir=%s\n' \
	"$corpus" "$programs" "$lane_programs" "$both_clients" "$errors" "$audit_dir"

test "$errors" -eq 0
