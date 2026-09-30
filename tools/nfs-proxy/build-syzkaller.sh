#!/usr/bin/env bash
# Apply the final bundle patch to an already-forward-ported syzkaller tree.
# The original series entries, scripts and dependency archive are unchanged.
set -euo pipefail
tools=$(cd "$(dirname "$0")" && pwd)
repo=${KOOV_WORK_ROOT:-$(cd "$tools/../.." && pwd)}
syz=${KOOV_SYZ_TARGET:-$repo/env/syzkaller}
patch_dir=${KOOV_BUNDLE_DIR:-$repo/bundle}/patches/syzkaller
patch=$patch_dir/0017-executor-route-four-nfs-pairs-and-arm-scoped-proxy.patch
test -f "$syz/sys/linux/fs_nfs_fuzz.txt"
if git -C "$syz" apply --reverse --check "$patch"; then
    echo "syzkaller four-route overlay already applied: $syz"
else
    git -C "$syz" apply --check "$patch"
    git -C "$syz" apply "$patch"
fi
make -C "$syz" executor execprog
echo "syzkaller four-route executor and execprog ready: $syz/bin/linux_amd64"
