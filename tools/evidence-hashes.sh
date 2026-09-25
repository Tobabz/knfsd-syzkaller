#!/usr/bin/env bash
# Record sha256 of key evidence artifacts for the handoff report.
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
EVIDENCE="$WORK_ROOT/evidence"
declare -a files=(
  "$EVIDENCE/experiment_manifest.json"
  "$EVIDENCE/nfs_remote_kcov_on_off_coverage_report.md"
  "$EVIDENCE/analysis_summary.json"
  "$EVIDENCE/coverage_sets/fs_nfsd_on_only_ranked.csv"
)
for f in "${files[@]}"; do
  [ -f "$f" ] && sha256sum "$f" | sed "s|  $WORK_ROOT|  |" || echo "MISSING: $f"
done
echo "--- prep adaptations ---"
sha256sum "$TOOLS/ab-lane-fixture.sh" \
  "$TOOLS/nfs_remote_kcov_ab_workload_markerhidden.prog" \
  "$TOOLS/run_ab_adapted.py" | sed "s|  $WORK_ROOT|  |"