#!/bin/bash
# temp check: remaining hardcoded paths + syntax + portability (reuse run from /tmp)
set -u
echo "=== 1. remaining hardcoded /home/idealinsane in prep scripts (should be none / comments only) ==="
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
grep -rn 'home/idealinsane' "$TOOLS/" 2>/dev/null || echo "(none)"
echo
echo "=== 2. bash -n syntax for all tools/*.sh ==="
# tools/*.sh는 전부 #!/usr/bin/env bash (BASH_SOURCE 사용) — bash -n으로 정합 검사.
# (dash sh -n은 bash 전용 구문(배열·process substitution)에서 오탐 — 2026-09-26)
for f in "$TOOLS"/*.sh; do
    bash -n "$f" && echo "OK  $(basename "$f")" || echo "FAIL $(basename "$f")"
done
echo
echo "=== 3. portability: run pipeline reuse from /tmp (derived paths, not CWD) ==="
cd /tmp
bash "$TOOLS/fport-pipeline.sh" --mode reuse > /tmp/portability-reuse.log 2>&1
rc=$?
echo "exit=$rc"
tail -25 /tmp/portability-reuse.log
echo
echo "=== 4. design-gate standalone -v ==="
bash "$TOOLS/fport-design-gate.sh" -v | tail -20