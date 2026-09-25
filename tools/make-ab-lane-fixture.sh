#!/usr/bin/env bash
# Generate the AB disposable-VM lane fixture wrapper:
#   - on "setup", first retire the boot-time manager fixture
#     (/tmp/frozen-phase9.manager owner of /syz-nfs-lanes), because lane.sh
#     is single-tenant (setup's pre-clean refuses a foreign owner root)
#   - then run the original frozen_phase9_lane.sh body verbatim
# The wrapper is passed to run_nfs_remote_kcov_ab.py via --lane-fixture.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
ABRUN="$WORK_ROOT/bundle/ab-runner"
OUT="${KOOV_OUT:-$TOOLS/ab-lane-fixture.sh}"

cat > "$OUT" <<'PRELUDE'
#!/bin/sh
# AB disposable-VM lane fixture wrapper (porting adaptation).
# The baked manager image auto-starts frozen-phase9-fixture.service, which
# owns /syz-nfs-lanes for /tmp/frozen-phase9.manager (single-tenant guard).
# The AB runner allocates its own trial root, so retire the boot fixture
# first, then behave exactly like the original lane.sh body below.
set -eu
action=${1:-}
case "$action" in
    setup)
        systemctl stop frozen-phase9-fixture.service >/dev/null 2>&1 || \
            NFS_MINOR_VERSION=${NFS_MINOR_VERSION:-1} \
                /opt/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager >/dev/null 2>&1 || true
        ;;
esac
# ==== original frozen_phase9_lane.sh body (verbatim) ====
PRELUDE

cat "$ABRUN/frozen_phase9_lane.sh" >> "$OUT"
chmod 0755 "$OUT"
echo "wrote $OUT"
wc -l "$OUT"