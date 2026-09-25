#!/usr/bin/env bash
# The A/B runner's phase1 VM hardcodes -drive format=raw, so the baked
# qcow2 (manager-facing) gets a raw twin used only by the A/B runner.
set -eu
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
KC="${KOOV_ENV_DIR:-$WORK_ROOT/env}"
RAW="$KC/bookworm-kcov-fresh-v1.raw"
QCOW="$KC/bookworm-kcov-fresh-v1.qcow2"
if [ ! -s "$RAW" ]; then
	qemu-img convert -f qcow2 -O raw "$QCOW" "$RAW"
fi
qemu-img info "$RAW" | head -n 4