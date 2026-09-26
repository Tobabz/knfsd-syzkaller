#!/bin/sh
# tools/lane-quote-lint.sh -- guard the Phase 9 lane fixtures against the two
# failure modes that `sh -n` on the fixture CANNOT see.
#
# WHY THIS EXISTS
#
# The lane's server block is passed as ONE single-quoted argument:
#
#     ip netns exec ... unshare --mount --propagation private sh -c '
#         ... many lines, including comments ...
#     ' sh "$root" "$lane" "10.89.$lane.0/29"
#
# Everything between those quotes is a STRING LITERAL as far as the outer file
# is concerned.  `sh -n` and `dash -n` on the fixture therefore never parse it:
# the entire server-side script -- the part that actually mounts filesystems
# and starts daemons -- is unvalidated until a guest runs it.  Two distinct
# defects lived in that blind spot, each of which cost a guest boot cycle to
# find:
#
#   1. An apostrophe in a COMMENT closed the quoted string early.  The rest was
#      re-parsed as shell code by the outer shell, and `sh -n` passed.  In the
#      guest it surfaced as "side: 3: 1: parameter not set" (rc=2, dash).
#   2. A stray `fi` left behind by an edit sat inside the same string.  The
#      outer file was still syntactically valid, `sh -n` passed, and the guest
#      died with 'Syntax error: "fi" unexpected (expecting "done")' before the
#      server ever started.
#
# So the lint does three things, all scoped to the extracted region:
#
#   1. no apostrophe may appear in the region (it would end the string);
#   2. the region must parse as shell under `sh -n` AND `dash -n`;
#   3. the region must be non-trivial, so a failed extraction cannot make the
#      whole lint vacuously pass.
#
# The region is unambiguous to extract precisely because of check 1: with no
# apostrophe inside, the first line ending in `sh -c '` and the first following
# line matching ^[ \t]*' sh  are the true delimiters.
#
# Usage: tools/lane-quote-lint.sh <fixture.sh> [reference.sh]
set -eu

fixture=${1:?usage: lane-quote-lint.sh FIXTURE [REFERENCE]}
reference=${2:-"$(dirname "$0")/../bundle/ab-runner/frozen_phase9_lane.sh"}

for f in "$fixture" "$reference"; do
    if [ ! -r "$f" ]; then
        echo "lane-quote-lint: cannot read $f" >&2
        exit 2
    fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

extract() {
    awk '
        /sh -c .$/ && /sh -c '"'"'$/ { inside = 1; next }
        inside && /^[ \t]*'"'"' sh / { inside = 0; next }
        inside { print }
    ' "$1"
}

extract "$fixture" > "$work/region"
extract "$reference" > "$work/reference"

status=0
region_lines=$(wc -l < "$work/region")

# --- 3. the extraction must be non-trivial, or the rest is vacuous ---------
if [ "$region_lines" -lt 20 ]; then
    echo "FAIL: located only $region_lines lines of the sh -c region in $fixture" >&2
    echo "      the opener/closer pattern did not match, so checks 1-2 are void" >&2
    status=1
fi

# --- 1. no apostrophe inside the region ------------------------------------
if grep -n "'" "$work/region" > "$work/hits" 2>/dev/null; then
    echo "FAIL: apostrophe(s) inside the sh -c region of $fixture:" >&2
    sed 's/^/      /' "$work/hits" >&2
    echo "      each one closes the quoted string early; reword, do not escape" >&2
    status=1
fi

# --- 2. the region must actually parse as shell ---------------------------
# The whole point: the outer file parses as a string, so this is the ONLY
# syntax check the server-side script ever gets before a guest runs it.
for shell in sh dash; do
    if command -v "$shell" >/dev/null 2>&1; then
        if "$shell" -n "$work/region" 2> "$work/err"; then
            echo "  region parses under: $shell -n"
        else
            echo "FAIL: the sh -c region does not parse under $shell -n:" >&2
            sed 's/^/      /' "$work/err" >&2
            status=1
        fi
    fi
done

if [ "$status" -eq 0 ]; then
    echo "PASS: $fixture sh -c region is quote-clean and parses ($region_lines lines)"
fi
exit "$status"
