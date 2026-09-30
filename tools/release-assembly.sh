#!/bin/bash
# tools/release-assembly.sh - assemble a minimal forward-port bundle snapshot.
# SHA256 verification was removed; this now simply archives the committed bundle.
set -eu

WORK_ROOT=${KOOV_WORK_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
BUNDLE="$WORK_ROOT/bundle"
DIST="$WORK_ROOT/dist"
STAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$DIST/knfsd-syzkaller-forward-port-${STAMP}.tar.gz"

mkdir -p "$DIST"

echo "=== Assemble bundle snapshot ==="
tar czf "$ARCHIVE" -C "$BUNDLE"     README-HANDOFF.md     src/guest-deps.tar.gz     patches/kernel     patches/syzkaller     patches/kernel.config     ab-runner     baker     corpus

echo "Archive: $ARCHIVE"
ls -lh "$ARCHIVE"
