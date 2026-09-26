#!/usr/bin/env bash
# Guest 2-client x 2-backend NFSv4 relay smoke, with Ganesha ASan enabled.
set -euo pipefail
tools=$(cd "$(dirname "$0")" && pwd)
repo=${KOOV_WORK_ROOT:-$(cd "$tools/../.." && pwd)}
env_dir=${KOOV_ENV_DIR:-$repo/env}
bundle=${KOOV_BUNDLE_DIR:-$repo/bundle}
deps=${KOOV_GANESHA_DEPS:-$bundle/src/guest-deps-ganesha-asan.tar.gz}
proxy=${KOOV_NFS_PROXY_GUEST:-$bundle/src/nfs-proxy-guest}
out=${KOOV_EVIDENCE_DIR:-$repo/evidence/ganesha-asan-relay}
key=${KOOV_SSH_KEY:-$repo/artifacts/bookworm.id_rsa}
opts=${KOOV_GANESHA_ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=stderr}
for file in "$deps" "$proxy" "$key"; do
    [ -s "$file" ] || { echo "missing guest input: $file" >&2; exit 2; }
done
python3 "$tools/run-ganesha-asan-relay-smoke.py" \
    --kernel "$env_dir/linux/arch/x86/boot/bzImage" \
    --image "$env_dir/bookworm-kcov-fresh-v1.raw" \
    --ssh-key "$key" --deps-tar "$deps" --proxy-binary "$proxy" \
    --lane-fixture "$tools/../ganesha-lane.sh" \
    --four-mount-script "$tools/test/guest-four-mounts.sh" \
    --output "$out" --asan-options "$opts" --cpus 4 --memory 6144
echo "ASan Ganesha four-route guest evidence: $out"
