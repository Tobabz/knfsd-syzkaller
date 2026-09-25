#!/usr/bin/env bash
# T1/T2/T3/T4/T5/T6 evidence: deterministic Remote KCOV OFF/ON A/B trials
# on fresh -snapshot VMs with the fixed 34-call lane workload.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence}"

# Marker-hidden lane layout adaptation: the pinned executor (patch 0014,
# "hide fixed lane marker") exposes only client0/client1 mounts at /nfs-lane;
# the checked-in workload's marker read (call 0) and the runner's BIND_RE
# predate that change.  tools/ holds the adapted workload + runner copy.
# 외부 syz 빌드 루트(KOOV_SYZ_BIN)가 있으면 --syz-bin으로 전달해
# env/ 기본 빌드 대신 외부 바이너리를 소비; 없으면 env/ 빌드 기본값.
SYZ_BIN_FLAG=""
if [ -n "${KOOV_SYZ_BIN:-}" ]; then
	SYZ_BIN_FLAG="--syz-bin $KOOV_SYZ_BIN"
else
	SYZ_BIN_FLAG="--syz-executor $KC/syzkaller/bin/linux_amd64/syz-executor --syz-execprog $KC/syzkaller/bin/linux_amd64/syz-execprog"
fi
python3 "$TOOLS/run_ab_adapted.py" \
	--kernel "$KC/linux/arch/x86/boot/bzImage" \
	--image "$KC/bookworm-kcov-fresh-v1.raw" \
	--ssh-key "$HF/src/bookworm.id_rsa" \
	--deps-tar "$HF/src/guest-deps.tar.gz" \
	--vmlinux "$KC/linux/vmlinux" \
	${SYZ_BIN_FLAG} \
	--lane-fixture "$TOOLS/ab-lane-fixture.sh" \
	--workload "$TOOLS/nfs_remote_kcov_ab_workload_markerhidden.prog" \
	--output "$OUT" \
	--mode both \
	--trials 2 \
	--executions 30 \
	--procs 2 \
	--cpus 4 \
	--memory 4096 \
	--boot-timeout 180 \
	--trial-timeout 900
echo "AB experiment complete: $OUT"