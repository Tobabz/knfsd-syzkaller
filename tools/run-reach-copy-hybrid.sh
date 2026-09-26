#!/usr/bin/env bash
# S4 reach corpus DISCRIMINATOR: hybrid sync+async COPY in ONE program (19
# calls).  Same fresh-VM deterministic Remote KCOV OFF/ON pipeline as
# run-reach-copy-offload.sh, same kernel/image/tools.  The only difference is
# the workload: the program performs a synchronous COPY (1MiB source, clamped
# count <= 2*rsize) followed by an asynchronous COPY (ftruncate'd 16MiB source,
# clamped count 16MiB > 2*rsize).
#
# Question being discriminated (v2 = async-only gave ON extra=0):
#   - if ON extra > 0 and sync server sentinels present but async sentinels
#     (nfsd4_do_async_copy, sunrpc_fuzz_saved_work_start/stop) absent -> the
#     async COPY hop is NOT attributed (real finding, honest boundary);
#   - if ON extra > 0 and async sentinels present -> async hop attributed; v2's
#     zero was infra/flake, re-run v2 to confirm PASS;
#   - if ON extra = 0 even with a sync COPY in the program -> channel itself did
#     not engage in this run (infra), run the v1 sync-only control to check.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence}"

# Hybrid program: 19 syscalls, no lock-conflict call.
export KOOV_EXPECTED_CALLS="${KOOV_EXPECTED_CALLS:-19}"
export KOOV_CONFLICT_CALL="${KOOV_CONFLICT_CALL:--1}"
CORPUS="$HF/corpus/reach-copy-offload"

SYZ_BIN_FLAG=""
if [ -n "${KOOV_SYZ_BIN:-}" ]; then
	SYZ_BIN_FLAG="--syz-bin $KOOV_SYZ_BIN"
else
	SYZ_BIN_FLAG="--syz-executor $KC/syzkaller/bin/linux_amd64/syz-executor --syz-execprog $KC/syzkaller/bin/linux_amd64/syz-execprog"
fi
python3 "$TOOLS/run-reach-adapted.py" \
	--kernel "$KC/linux/arch/x86/boot/bzImage" \
	--image "$KC/bookworm-kcov-fresh-v1.raw" \
	--ssh-key "${KOOV_SSH_KEY:-$HF/src/bookworm.id_rsa}" \
	--deps-tar "$HF/src/guest-deps.tar.gz" \
	--vmlinux "$KC/linux/vmlinux" \
	${SYZ_BIN_FLAG} \
	--lane-fixture "$TOOLS/ab-lane-fixture-v42.sh" \
	--workload "$CORPUS/reach-copy-offload-hybrid.prog" \
	--output "$OUT" \
	--mode both \
	--trials 2 \
	--executions 10 \
	--procs 2 \
	--cpus 4 \
	--memory 4096 \
	--boot-timeout 180 \
	--trial-timeout 900
echo "S4 hybrid discriminator run complete: $OUT"
echo "next: analyze-ab.sh then tools/reach-assert.py --results $OUT --vmlinux $KC/linux/vmlinux"