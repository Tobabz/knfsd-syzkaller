#!/usr/bin/env bash
# Guest 2-client x 2-backend NFSv4 relay smoke, with Ganesha ASan enabled.
set -euo pipefail
tools=$(cd "$(dirname "$0")" && pwd)
repo=${KOOV_WORK_ROOT:-$(cd "$tools/../.." && pwd)}
env_dir=${KOOV_ENV_DIR:-$repo/env}
VARIANT="${KOOV_VARIANT:-kasan}"
bundle=${KOOV_BUNDLE_DIR:-$repo/bundle}
deps=${KOOV_GANESHA_DEPS:-$bundle/src/guest-deps-ganesha-asan.tar.gz}
proxy=${KOOV_NFS_PROXY_GUEST:-$bundle/src/nfs-proxy-control-guest}
out=${KOOV_EVIDENCE_DIR:-$repo/evidence/ganesha-asan-relay}
key=${KOOV_SSH_KEY:-$repo/artifacts/bookworm.id_rsa}
opts=${KOOV_GANESHA_ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=stderr}
for file in "$deps" "$proxy" "$key"; do
    [ -s "$file" ] || { echo "missing guest input: $file" >&2; exit 2; }
done
syz_flags=()
if [ -n "${KOOV_SYZ_FOUR_WORKLOAD:-}" ]; then
    syz_flags=(--syz-executor "${KOOV_SYZ_EXECUTOR:-$env_dir/syzkaller/bin/linux_amd64/syz-executor}"
               --syz-execprog "${KOOV_SYZ_EXECPROG:-$env_dir/syzkaller/bin/linux_amd64/syz-execprog}"
               --workload "$KOOV_SYZ_FOUR_WORKLOAD")
    if grep -q syz_arm_nfs_proxy "$KOOV_SYZ_FOUR_WORKLOAD"; then
        probe=${KOOV_NFS_PROXY_REPLAY_PROBE:-$bundle/src/nfs-proxy-replay-probe}
        if [ ! -s "$probe" ]; then
            cc -std=c11 -O2 -static -Wall -Wextra -Werror \
                "$tools/test/guest-delta-replay.c" -o "$probe"
        fi
        syz_flags+=(--replay-probe "$probe")
    fi
fi
python3 "$tools/run-ganesha-asan-relay-smoke.py" \
    --kernel "$env_dir/images/$VARIANT/bzImage" \
    --image "$env_dir/images/bookworm-kcov-fresh-v1.raw" \
    --ssh-key "$key" --deps-tar "$deps" --proxy-binary "$proxy" \
    --lane-fixture "$tools/../ganesha-lane.sh" \
    --four-mount-script "$tools/test/guest-four-mounts.sh" \
    --output "$out" --asan-options "$opts" --cpus 4 --memory 6144 \
    "${syz_flags[@]}"
echo "ASan Ganesha four-route guest evidence: $out"
