#!/usr/bin/env bash
# T7 evidence: symbolize OFF/ON raw PCs, coverage-set analysis and report
# (handler gate per NFS operation), plus performance metrics (T9).
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
HF="${KOOV_BUNDLE_DIR:-$WORK_ROOT/bundle}"
OUT="${KOOV_EVIDENCE_DIR:-$WORK_ROOT/evidence}"
cd "$TOOLS" && python3 "$TOOLS/analyze_ab_adapted.py" \
	--results "$OUT" \
	--vmlinux "$KC/linux/vmlinux"
echo "analysis complete; see $OUT/"