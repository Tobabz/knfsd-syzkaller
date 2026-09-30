#!/usr/bin/env bash
# tools/ganesha-lane-parity.sh -- prove tools/ganesha-lane.sh is behaviourally
# identical to tools/ab-lane-fixture.sh (and to the baked lane.sh) on the
# default SERVER_IMPL=knfsd path.
#
# Same runner, same corpus, same image as tools/run-ab.sh.  The ONLY
# difference is --lane-fixture.  If this passes, the 10 KOOV edits are
# inert on the knfsd path and the tmpfs size= bound is the sole behaviour
# change (observable as the tmpfs size, nothing else).
#
# Minimised on purpose: --mode off (one group), --trials 1, --executions 2,
# --procs 1.  This is a fixture regression gate, not an experiment -- the
# real numbers come from run-ab.sh.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence/ganesha-lane-parity}"

SYZ_BIN_FLAG=""
if [ -n "${KOOV_SYZ_BIN:-}" ]; then
	SYZ_BIN_FLAG="--syz-bin $KOOV_SYZ_BIN"
else
	SYZ_BIN_FLAG="--syz-executor $KC/syzkaller/bin/linux_amd64/syz-executor --syz-execprog $KC/syzkaller/bin/linux_amd64/syz-execprog"
fi

python3 "$TOOLS/run_ab_adapted.py" \
	--kernel "$KC/linux/arch/x86/boot/bzImage" \
	--image "$KC/bookworm-kcov-fresh-v1.raw" \
	--ssh-key "${KOOV_SSH_KEY:-$HF/src/bookworm.id_rsa}" \
	--deps-tar "$HF/src/guest-deps.tar.gz" \
	--vmlinux "$KC/linux/vmlinux" \
	${SYZ_BIN_FLAG} \
	--lane-fixture "$TOOLS/ganesha-lane.sh" \
	--workload "$TOOLS/nfs_remote_kcov_ab_workload_markerhidden.prog" \
	--output "$OUT" \
	--mode off \
	--trials 1 \
	--executions 2 \
	--sample-every 1 \
	--procs 1 \
	--cpus 4 \
	--memory 4096 \
	--boot-timeout 180 \
	--trial-timeout 300
echo "ganesha-lane parity dry-run complete: $OUT"
