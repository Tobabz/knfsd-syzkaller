#!/usr/bin/env bash
# tools/ganesha-lane-run.sh — first real Ganesha validation.
#
# The workload is tools/nfs_remote_kcov_ganesha_v41_workload.prog, not the AB
# corpus: the two servers genuinely differ on creating an entry directly in
# the NFSv4 pseudo root (knfsd 0, Ganesha EROFS), so the marker file is
# created under the export's "shared" subdirectory instead.  The call
# count and indices are unchanged, so the errno contract is untouched.
#
# MODE (default "on") selects the group; override with KOOV_GANESHA_MODE.
# A previous note here blamed the nfsd_rpc_positive / ordinal_mismatch_zero
# failures on running "off".  That was wrong.  They failed for real, and because
# a failing trial aborts the run, "both" never reached the ON group at all --
# remote_on/ was empty.  The real signal is ordinal_mismatch=153 with
# connection_pair_miss=0 inside an OFF group: the remote KCOV attribution
# expects kernel-server sections, and a userspace server does not produce them.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
VARIANT="${KOOV_VARIANT:-kasan}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence/ganesha-lane-run}"

DEPS="${KOOV_GANESHA_DEPS:-$HF/src/guest-deps-ganesha.tar.gz}"
[ -s "$DEPS" ] || { echo "missing $DEPS -- run the packer first" >&2; exit 2; }
ASAN_ENV=()
if [ -n "${KOOV_GANESHA_ASAN_OPTIONS:-}" ]; then
	ASAN_ENV=(--fixture-env "KOOV_GANESHA_ASAN_OPTIONS=$KOOV_GANESHA_ASAN_OPTIONS")
fi

python3 "$TOOLS/run_ab_adapted.py" \
	--kernel "$KC/images/$VARIANT/bzImage" \
	--image "$KC/images/bookworm-kcov-fresh-v1.raw" \
	--ssh-key "${KOOV_SSH_KEY:-$HF/src/bookworm.id_rsa}" \
	--deps-tar "$DEPS" \
	--vmlinux "$KC/images/$VARIANT/vmlinux" \
	--phase9-runner "$TOOLS/run_frozen_phase9_vm_ganesha.py" \
	--syz-executor "$KC/syzkaller/bin/linux_amd64/syz-executor" \
	--syz-execprog "$KC/syzkaller/bin/linux_amd64/syz-execprog" \
	--lane-fixture "$TOOLS/ganesha-lane.sh" \
	--fixture-env SERVER_IMPL=ganesha \
	--fixture-env SERVER_PORT=2049 \
	--fixture-env NFS_MINOR_VERSION=1 \
	--fixture-env KOOV_TMPFS_SIZE=256m \
	--fixture-env KOOV_GANESHA_DEBUG="${KOOV_GANESHA_DEBUG:-NIV_DEBUG}" \
	"${ASAN_ENV[@]}" \
	--workload "$TOOLS/nfs_remote_kcov_ganesha_v41_workload.prog" \
	--output "$OUT" \
	--mode "${KOOV_GANESHA_MODE:-on}" \
	--trials 1 \
	--executions 2 \
	--sample-every 1 \
	--procs 1 \
	--cpus 4 \
	--memory "${KOOV_GANESHA_MEMORY_MIB:-4096}" \
	--boot-timeout 180 \
	--trial-timeout 300
echo "ganesha lane run complete: $OUT"
