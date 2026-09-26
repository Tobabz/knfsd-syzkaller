#!/usr/bin/env bash
# S4 discriminator CONTROL: rerun the v1 SYNC-ONLY corpus (prog sha
# 02010f0f..., 10 calls) in the SAME environment/infra as the v2 async run
# (evidence3) and the hybrid run (evidence4).  The only thing that changes vs
# the earlier successful v1 evidence2 run is the fresh VM boot instance.
#
# Discriminates between:
#   - workload-class effect: async COPY presence zeroes ON extra even when the
#     same run contains a synchronous COPY (hybrid result 0) -> real finding
#     that the async offload hop kills session attribution for the whole
#     execution.  Then v1 rerun must reproduce extra=10 (channel alive).
#   - infra/timing effect: remote channel simply not attaching on the current
#     boot queue.  Then v1 rerun also yields extra=0 and v1 evidence2 (extra=10)
#     is the outlier baseline; the earlier v1/v2/hybrid comparison collapses to
#     an infra question and evidence3's zero needs no corpus explanation.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="$(dirname "$TOOLS")"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence}"

export KOOV_EXPECTED_CALLS="${KOOV_EXPECTED_CALLS:-10}"
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
	--workload "$CORPUS/reach-copy-offload-v1.prog" \
	--output "$OUT" \
	--mode both \
	--trials 2 \
	--executions 10 \
	--procs 2 \
	--cpus 4 \
	--memory 4096 \
	--boot-timeout 180 \
	--trial-timeout 900
echo "S4 v1 sync-only CONTROL run complete: $OUT"