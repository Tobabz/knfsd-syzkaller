#!/usr/bin/env bash
# Small guest gate for the separately built AddressSanitizer Ganesha daemon.
# This is a Ganesha ASan functional smoke, not the formal 30x2 AB experiment.
set -euo pipefail

tools=$(cd "$(dirname "$0")" && pwd)
repo=${KOOV_WORK_ROOT:-$(dirname "$tools")}
env_dir=${KOOV_ENV_DIR:-$repo/env}
VARIANT="${KOOV_VARIANT:-kasan}"
bundle=${KOOV_BUNDLE_DIR:-$repo/bundle}
deps=${KOOV_GANESHA_DEPS:-$bundle/src/guest-deps-ganesha-asan.tar.gz}
out=${KOOV_EVIDENCE_DIR:-$repo/evidence/ganesha-asan-smoke}
key=${KOOV_SSH_KEY:-$repo/artifacts/bookworm.id_rsa}
asan_opts=${KOOV_GANESHA_ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=stderr}

[ -s "$deps" ] || { echo "missing ASan deps: $deps" >&2; exit 2; }
[ -s "$key" ] || { echo "missing SSH key: $key" >&2; exit 2; }
python3 "$tools/run-ganesha-asan-smoke.py" \
    --kernel "$env_dir/images/$VARIANT/bzImage" \
    --image "$env_dir/images/bookworm-kcov-fresh-v1.raw" \
    --ssh-key "$key" --deps-tar "$deps" \
    --syz-executor "$env_dir/syzkaller/bin/linux_amd64/syz-executor" \
    --syz-execprog "$env_dir/syzkaller/bin/linux_amd64/syz-execprog" \
    --lane-fixture "$tools/ganesha-lane.sh" \
    --workload "$tools/nfs_remote_kcov_ganesha_v41_workload.prog" \
    --output "$out" --asan-options "$asan_opts" \
    --executions 2 --cpus 4 --memory 6144 \
    --boot-timeout 180 --trial-timeout 300
echo "ASan Ganesha guest smoke complete: $out"
