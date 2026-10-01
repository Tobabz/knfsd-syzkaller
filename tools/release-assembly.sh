#!/bin/bash
# tools/release-assembly.sh - assemble a minimal forward-port bundle snapshot.
# SHA256 verification was removed; this archives the current bundle inputs.
set -eu

WORK_ROOT=${KOOV_WORK_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
BUNDLE="$WORK_ROOT/bundle"
DIST="$WORK_ROOT/dist"
STAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$DIST/knfsd-syzkaller-forward-port-${STAMP}.tar.gz"

mkdir -p "$DIST"

echo "=== Assemble bundle snapshot ==="
tar czf "$ARCHIVE" --exclude=__pycache__ --exclude='*.pyc' -C "$BUNDLE" \
    README-HANDOFF.md src/guest-deps-lane.tar.gz patches/kernel \
    patches/syzkaller patches/kernel.config lane baker corpus

echo "Archive: $ARCHIVE"
ls -lh "$ARCHIVE"
