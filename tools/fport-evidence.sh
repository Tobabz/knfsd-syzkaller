#!/usr/bin/env bash
# tools/fport-evidence.sh - record SHA256 of the forward-port tooling artifacts.
set -eu
PREP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_ROOT=${KOOV_WORK_ROOT:-$(CDPATH= cd -- "$PREP/.." && pwd)}
OUT=$WORK_ROOT/report/evidence-forward-port.sha256
cd "$PREP"
{
  echo "# forward-port configuration artifacts ($(date -Is))"
  sha256sum \
    fport-patch-hygiene.py \
    fport-patch-risk.py \
    fport-apply.sh \
    fport-variant.sh \
    fport-design-gate.sh \
    fport-pipeline.sh \
    portability-check.sh \
    rename-scripts.py \
    check-rename-leftovers.sh \
    bootstrap-kcov-env.py \
    README.md
  cd "$WORK_ROOT/report" && sha256sum patch-forward-compat.md design-spec.md script-rename-map.md
} | tee "$OUT"
echo
echo "recorded: $OUT"