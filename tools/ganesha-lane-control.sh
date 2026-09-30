#!/usr/bin/env bash
# Control run: identical to tools/ganesha-lane-parity.sh except the fixture is
# the pre-existing tools/ab-lane-fixture.sh.  Any failure here is a property of
# the dry-run configuration (procs=1 / mode=off / executions=2), not of the
# KOOV edits in tools/ganesha-lane.sh.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
VARIANT="${KOOV_VARIANT:-kasan}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence/ganesha-lane-control}"

python3 "$TOOLS/run_ab_adapted.py" \
	--kernel "$KC/images/$VARIANT/bzImage" \
	--image "$KC/images/bookworm-kcov-fresh-v1.raw" \
	--ssh-key "${KOOV_SSH_KEY:-$HF/src/bookworm.id_rsa}" \
	--deps-tar "$HF/src/guest-deps.tar.gz" \
	--vmlinux "$KC/images/$VARIANT/vmlinux" \
	--syz-executor "$KC/syzkaller/bin/linux_amd64/syz-executor" \
	--syz-execprog "$KC/syzkaller/bin/linux_amd64/syz-execprog" \
	--lane-fixture "$TOOLS/ab-lane-fixture.sh" \
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
echo "lane control dry-run complete: $OUT"
