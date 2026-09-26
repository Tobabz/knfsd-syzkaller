#!/usr/bin/env bash
# S4 reach corpus: NFSv4.2 async COPY offload -- thread-hop attribution.
# Same fresh-VM deterministic Remote KCOV OFF/ON pipeline as run-ab.sh, but
# with the reach-copy-offload corpus prog, the v4.2 lane fixture and fewer
# repetitions (determinism, not breadth, is the point of a reach corpus).
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence}"

# Reach corpus: 10 syscalls, no lock-conflict call.  The shared
# run_ab_adapted.py hardcodes AB-corpus validation (34 calls, conflict 14);
# run-reach-adapted.py makes them env-overridable.  Defaults below keep
# reach validation correct; unset AB compatibility is unchanged.
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
	--workload "$CORPUS/reach-copy-offload.prog" \
	--output "$OUT" \
	--mode both \
	--trials 2 \
	--executions 10 \
	--procs 2 \
	--cpus 4 \
	--memory 4096 \
	--boot-timeout 180 \
	--trial-timeout 900
echo "S4 reach corpus run complete: $OUT"
echo "next: analyze-ab.sh then tools/reach-assert.py --results $OUT --vmlinux $KC/linux/vmlinux"