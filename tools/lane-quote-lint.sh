#!/bin/sh
# tools/lane-quote-lint.sh -- guard against the quoting trap in the Phase 9
# lane fixtures.
#
# The server-side block of bundle/ab-runner/frozen_phase9_lane.sh is passed as
# a SINGLE-QUOTED argument:
#
#     ip netns exec ... unshare --mount --propagation private sh -c '
#         ...many lines, including comments...
#     ' sh "$root" "$lane" "10.89.$lane.0/29"
#
# `sh -n' accepts the file happily, so a stray apostrophe inside that block --
# including one in a COMMENT -- silently closes the string early.  Everything
# after it is re-parsed as shell code by the outer shell, and the failure only
# appears in the guest, far from the edit.  Observed on 2026-09-26: the
# comment "the secondary's side effects" produced
#
#     side: 3: 1: parameter not set          (rc=2, dash)
#
# because the word `side` ended up as the sh -c name argument of an unrelated
# command.  Cost: one VM boot cycle to localise, because no local syntax check
# sees it.
#
# This lint makes the trap a build-time failure:
#
#   1. the sh -c '...' region must contain no apostrophe at all
#   2. that region's apostrophe count must equal the pristine original's
#      (the original is the reference: it is known-good)
#
# Usage: tools/lane-quote-lint.sh <fixture.sh> [reference.sh]
set -eu

fixture=${1:?usage: lane-quote-lint.sh FIXTURE [REFERENCE]}
reference=${2:-"$(dirname "$0")/../bundle/ab-runner/frozen_phase9_lane.sh"}

if [ ! -r "$fixture" ]; then
    echo "lane-quote-lint: cannot read $fixture" >&2
    exit 2
fi
if [ ! -r "$reference" ]; then
    echo "lane-quote-lint: cannot read reference $reference" >&2
    exit 2
fi

# Extract the region between the opening "sh -c '" and its closing "' sh".
extract() {
    awk '
        # Opener must END with sh -c + quote: the bare `sh -c \` continuation
        # lines in setup_client must not match.
        /sh -c .$/ && /sh -c '"'"'$/ { inside = 1; next }
        inside && /^[ \t]*'"'"' sh / { inside = 0; next }
        inside { print }
    ' "$1"
}

extract "$fixture" > /tmp/lane-quote-lint.fixture.$$
extract "$reference" > /tmp/lane-quote-lint.reference.$$

status=0

region_lines=$(wc -l < /tmp/lane-quote-lint.fixture.$$)
if [ "$region_lines" -lt 20 ]; then
    echo "FAIL: located only $region_lines lines of the sh -c region in $fixture" >&2
    echo "      (the opener/closer pattern did not match; the lint is not effective)" >&2
    status=1
fi

# 1. no apostrophe may appear inside the region
if grep -n "'" /tmp/lane-quote-lint.fixture.$$ > /tmp/lane-quote-lint.hits.$$; then
    echo "FAIL: apostrophe(s) inside the sh -c '...' region of $fixture:" >&2
    sed 's/^/      /' /tmp/lane-quote-lint.hits.$$ >&2
    echo "      Each one closes the quoted string early.  Remove the apostrophe" >&2
    echo "      (reword the comment) -- do not escape it." >&2
    status=1
fi

# 2. apostrophe count must match the known-good reference exactly
fixture_ticks=$(tr -cd "'" < /tmp/lane-quote-lint.fixture.$$ | wc -c)
reference_ticks=$(tr -cd "'" < /tmp/lane-quote-lint.reference.$$ | wc -c)
if [ "$fixture_ticks" -ne "$reference_ticks" ]; then
    echo "FAIL: $fixture_ticks apostrophe(s) in the region, reference has $reference_ticks" >&2
    status=1
fi

rm -f /tmp/lane-quote-lint.fixture.$$ /tmp/lane-quote-lint.reference.$$ \
      /tmp/lane-quote-lint.hits.$$

if [ "$status" -eq 0 ]; then
    echo "PASS: $fixture sh -c region is quote-clean ($region_lines lines, 0 apostrophes)"
fi
exit "$status"
