#!/usr/bin/env bash
# Verify no numbered script references remain after the rename (tools/ + report/ only).
set -u
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
cd "$WORK_ROOT"
grep -rn -E '(10[0-6]|11[0-5]|12[0-3]|13[0-4])-[a-z]|/tmp/11[0-9]-|\[1[0-3][0-9]\]|[(（]1[0-3][0-9][)）]' \
    prep report 2>/dev/null \
    | grep -v 'script-rename-map.md' \
    | grep -v '__pycache__' \
    | grep -v 'evidence-forward-port.sha256'
rc=$?
if [ "$rc" -eq 1 ]; then
    echo "OK: no numbered script references remain"
    exit 0
fi
echo "LEFT OVER (above)"; exit "$rc"