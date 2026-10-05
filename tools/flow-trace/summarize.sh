#!/bin/sh
# Judge every scenario against its trace and save the results next to the traces.
# Usage: summarize.sh RUN_DIR
# Each line below pairs a scenario file with the run that records its stimulus,
# plus the negative control run for that scenario.
set -u
here=$(cd "$(dirname "$0")" && pwd)
run=${1:?usage: summarize.sh RUN_DIR}
out=$run/judgement
mkdir -p "$out"

judge() { # scenario-file trace-name label [extra args]
    scen=$1
    trace=$2
    label=$3
    shift 3
    echo "### $label: $(basename "$scen") on $trace" >>"$out/summary.txt"
    python3 "$here/handoffs.py" "$run/$trace/trace.txt.gz" "$here/scenarios/$scen" \
        --json "$out/$label.json" "$@" >>"$out/summary.txt" 2>&1
    echo "(exit $?)" >>"$out/summary.txt"
    echo >>"$out/summary.txt"
}

: >"$out/summary.txt"
judge s1-v3-basic-io.json            s1-v3-basic       s1
judge s1-v3-basic-io.json            ctl-v41-basic     s1-control-no-restart --control
judge s1-v3-basic-io.json            s4b-v41-grace     s1-on-v41-restart --only S1-09,S1-10
judge s2-v40-delegation-recall.json  s2-v40-deleg      s2
judge s2-v40-delegation-recall.json  s1-v3-basic       s2-control-v3 --control
judge s2-v40-delegation-recall.json  s3b-v41-deleg     s2-on-v41 --only S2-02,S2-03,S2-04,S2-05,S2-06,S2-07,S2-12,S2-13
judge s3-v42-async-copy.json         s3-v42-copy       s3
judge s3-v42-async-copy.json         s1-v3-basic       s3-control-v3 --control
judge s3-v42-async-copy.json         ctl-v41-basic     s3-control-v41 --control
judge s3b-v41-delegation-recall-bc.json s3b-v41-deleg  s3b
judge s3b-v41-delegation-recall-bc.json s1-v3-basic    s3b-control-v3 --control
judge s3b-v41-delegation-recall-bc.json s2-v40-deleg   s3b-on-v40 --only S3b-05,S3b-06,S3b-10
judge s4-v41-state-lifetime.json     s4-v41-state      s4
judge s4-v41-state-lifetime.json     s4b-v41-grace     s4b
judge s4-v41-state-lifetime.json     ctl-v41-basic     s4-control --control
judge s4-v41-state-lifetime.json     s1-v3-basic       s4-on-v3

python3 "$here/subjects.py" \
    ctl-v41-basic="$run/ctl-v41-basic/trace.txt.gz" \
    s1-v3="$run/s1-v3-basic/trace.txt.gz" \
    s2-v40="$run/s2-v40-deleg/trace.txt.gz" \
    s3-v42="$run/s3-v42-copy/trace.txt.gz" \
    s3b-v41="$run/s3b-v41-deleg/trace.txt.gz" \
    s4-v41="$run/s4-v41-state/trace.txt.gz" \
    s4b-v41="$run/s4b-v41-grace/trace.txt.gz" \
    --json "$out/subjects.json" >"$out/subjects.txt" 2>&1
echo "saved: $out/summary.txt $out/subjects.txt"
