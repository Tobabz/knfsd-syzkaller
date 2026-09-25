#!/bin/sh
set -eu

if test "$#" -ne 2; then
	echo "usage: $0 SOURCE_CORPUS.db OUTPUT_CORPUS.db" >&2
	exit 2
fi

source_db=$1
output_db=$2
repo=/home/fuzzer/fuzz/knfsd-fuzz
syz_db=/home/fuzzer/tools/syzkaller-frozen-attribution/bin/syz-db
audit=$repo/scripts/audit_knfsd_server_corpus.sh

test -f "$source_db"
test ! -e "$output_db"

build_dir=$(mktemp -d /tmp/knfsd-server-corpus.XXXXXX)
mkdir "$build_dir/unpacked" "$build_dir/selected"
"$syz_db" unpack "$source_db" "$build_dir/unpacked" >"$build_dir/unpack.log"

for program in "$build_dir"/unpacked/*; do
	test -f "$program" || continue
	# Coverage focus alone is not a sufficient corpus predicate: executor lane
	# setup can produce stable fs/nfsd coverage while corpus minimization removes
	# the actual NFS calls.  Keep only programs that retain both the lane anchor
	# and an operation capable of issuing an NFS request.
	if rg -q 'open\$dir\(.*nfs-lane/client[01]' "$program" &&
	   rg -q '(^| = )(openat|creat|read|pread64|readv|write|pwrite64|writev|lseek|readahead|flock|fcntl\$(lock|setlease)|fsync|fdatasync|syncfs|sync_file_range|fallocate|copy_file_range|splice|mmap|msync|getdents64|statx|statfs|fstatfs|mkdir|mknod|rmdir|unlink|rename|link|symlink|readlink|chmod|fchmod|chown|fchown|utime|utimes|utimensat|truncate|ftruncate|setxattr|fsetxattr|getxattr|fgetxattr|listxattr|flistxattr|removexattr|fremovexattr)[^a-zA-Z0-9_]*\(' "$program" &&
	   ! rg -q 'nfs-lane/\.lane_id|\.phase9-executor|\.phase9-peer|\.remote-kcov-ab' "$program"; then
		cp "$program" "$build_dir/selected/"
	fi
done

"$syz_db" pack "$build_dir/selected" "$output_db"
seed_db=$build_dir/seeds.db
"$syz_db" pack "$repo/corpus/knfsd-server-seeds" "$seed_db"
"$syz_db" merge "$output_db" "$seed_db"
"$audit" "$output_db"

printf 'candidate_build_dir=%s\n' "$build_dir"
printf 'candidate_programs=%s\n' "$(find "$build_dir/selected" -maxdepth 1 -type f | wc -l)"
sha256sum "$source_db" "$output_db"
