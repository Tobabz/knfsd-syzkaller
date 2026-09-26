#!/usr/bin/env bash
# Formal four-route ASan relay arm OFF/ON comparison on fresh snapshot VMs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=${KOOV_WORK_ROOT:-$(cd "$here/../.." && pwd)}
env_dir=${KOOV_ENV_DIR:-$repo/env}
bundle=${KOOV_BUNDLE_DIR:-$repo/bundle}
bash "$repo/tools/convert-ab-image.sh"
python3 "$here/run-ganesha-asan-relay-ab.py" \
    --kernel "$env_dir/linux/arch/x86/boot/bzImage" \
    --image "$env_dir/bookworm-kcov-fresh-v1.raw" \
    --ssh-key "${KOOV_SSH_KEY:-$repo/artifacts/bookworm.id_rsa}" \
    --deps-tar "${KOOV_GANESHA_DEPS:-$bundle/src/guest-deps-ganesha-asan.tar.gz}" \
    --proxy-binary "${KOOV_NFS_PROXY_GUEST:-$bundle/src/nfs-proxy-control-guest}" \
    --syz-executor "${KOOV_SYZ_EXECUTOR:-$env_dir/syzkaller/bin/linux_amd64/syz-executor}" \
    --syz-execprog "${KOOV_SYZ_EXECPROG:-$env_dir/syzkaller/bin/linux_amd64/syz-execprog}" \
    --asan-options "${KOOV_GANESHA_ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=stderr}" \
    --output "${KOOV_EVIDENCE_DIR:-$repo/evidence/ganesha-asan-relay-ab}" \
    --executions 30 --trials 2
