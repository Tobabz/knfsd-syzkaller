#!/bin/sh
# tools/fport-pipeline.sh - forward-port automation pipeline.
# DESIGN (report/design-spec.md R1,R2,R4,R5) is the terminal authority.
# Exit: 0=HOLDS 1=fail 2=preconditions-unmet 10=apply-fail 20=env-fail
set -u

PREP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_ROOT=${KOOV_WORK_ROOT:-$(CDPATH= cd -- "$PREP/.." && pwd)}
RUNS=${PORT_RUNS:-$WORK_ROOT/runs}
BUNDLE=${KOOV_BUNDLE:-$WORK_ROOT/bundle/patches}
MANIFEST_JSON=${KOOV_MANIFEST:-$WORK_ROOT/env/manifest.json}

MODE=reuse
KIND=kernel
TARGET=$WORK_ROOT/env/linux
NEW_BASE=""
PHASES=all
CHECKPOINT=1

while test "$#" -gt 0; do
    case "$1" in
    --mode)    MODE=$2; shift 2 ;;
    --kind)    KIND=$2; shift 2 ;;
    --target)  TARGET=$2; shift 2 ;;
    --new-base) NEW_BASE=$2; shift 2 ;;
    --phases)  PHASES=$2; shift 2 ;;
    --no-checkpoint) CHECKPOINT=0; shift ;;
    --help|-h) sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 20 ;;
    esac
done

case "$KIND" in
kernel)       sub=kernel;               expected_base=93f51579e7df248780214094418f205253383cc5 ;;
syzkaller)    sub=syzkaller;            expected_base=801f0966669a37e048adabf9e5f38ce52825ea82 ;;
*) echo "unknown kind: $KIND" >&2; exit 20 ;;
esac

has_phase() { test "$PHASES" = all || echo ",$PHASES," | grep -q ",$1,"; }
stamp=$(date +%Y%m%d-%H%M%S)
run_dir=$RUNS/port-$KIND-$stamp
mkdir -p "$run_dir"
MF="$run_dir/manifest.env"   # flat record
exec 3> "$MF"
rec() { echo "$1=$2" >&3; echo "[$1] $2"; }

STATUS=PASS   # running verdict
STEP_FAIL=""

run_phase() {
    name=$1; desc=$2; shift 2
    has_phase "$name" || { rec "phase_$name" "skipped"; return 0; }
    echo
    echo "########## phase:$name  $desc ##########"
    # NOTE: run in the CURRENT shell (not a subshell) so phase state
    # (variables, status) propagates; capture output via file redirect.
    logf="$run_dir/phase-$name.log"
    "$@" > "$logf" 2>&1
    rc=$?
    if test "$rc" -eq 0; then
        rec "phase_$name" "pass"
        sed 's/^/    /' "$logf" | tail -25
        return 0
    fi
    rec "phase_$name" "fail(rc=$rc)"
    sed 's/^/    /' "$logf" | tail -30
    STATUS=FAIL
    STEP_FAIL=$name
    return "$rc"
}

# ---------------- P0 provision ----------------
p0() {
    for c in git python3 sha256sum qemu-img; do
        command -v "$c" >/dev/null || { echo "missing tool: $c"; return 1; }
    done
    test -d "$TARGET/.git" || { echo "target not a git repo: $TARGET"; return 1; }
    test -f "$MANIFEST_JSON" || { echo "bootstrap manifest missing (need provision first)"; return 1; }
    if test "$MODE" = reuse; then
        for e in "$WORK_ROOT/evidence/analysis_summary.json" \
                 "$WORK_ROOT/evidence/coverage_sets/fs_nfsd_on_only_ranked.csv"; do
            test -f "$e" || { echo "reuse evidence missing: $e"; return 1; }
        done
    fi
    echo "env OK (mode=$MODE kind=$KIND target=$TARGET)"
}

# ---------------- P1 detect ----------------
# Sentinel: a file the series adds that can never exist in mainline.
# Content-based and commit-independent: presence == series applied. This is the
# binary "already applied?" gate for skip/mutate; per-patch diagnostics belong
# to the apply machinery (P3 / fport-apply.sh), not here.
sentinel_for() {
    case "$1" in
        kernel)      echo net/sunrpc/fuzz.c ;;
        syzkaller)   echo sys/linux/fs_nfs_fuzz.txt ;;
        *)           echo "" ;;
    esac
}

p1() {
    actual=$(git -C "$TARGET" rev-parse HEAD)
    rec "actual_base" "$actual"
    rec "expected_base" "$expected_base"
    if test "$actual" = "$expected_base"; then rec "drift" "none"; else rec "drift" "yes"; fi
    s=$(sentinel_for "$KIND")
    if test -n "$s" && test -f "$TARGET/$s"; then
        APP_STATE=yes
    else
        APP_STATE=no
    fi
    rec "applied" "$APP_STATE (sentinel=$s)"
}

# ---------------- P2 variant ----------------
p2() {
    if test -n "$NEW_BASE"; then
        rec "variant" "rebasing $KIND onto $NEW_BASE"
        "$PREP/fport-variant.sh" "$KIND" "$TARGET" "$NEW_BASE" || return $?
    else
        rec "variant" "none (no --new-base trigger)"
    fi
}

# ---------------- P3 apply ----------------
p3() {
    if test "${APP_STATE:-}" = yes; then
        rec "apply" "already-applied (sentinel); skip"
        return 0
    fi
    if test "$MODE" = reuse; then
        echo "reuse mode: series not applied here - refusing to mutate validated tree."
        echo "run with --mode full in a fresh environment (or --new-base for a real rc port)."
        return 10
    fi
    "$PREP/fport-apply.sh" "$KIND" "$TARGET" || return $?
    if test "$CHECKPOINT" -eq 1; then
        echo "== human checkpoint: if apply failed above, regenerate the patch"
        echo "   from the design-intent record,"
        echo "   update the bundle, then re-run this pipeline (resumes at P3). =="
    fi
}

# ---------------- P4 build-check ----------------
p4() {
    local variant found=0
    for variant in kasan kcsan; do
        test -d "$WORK_ROOT/env/images/$variant" || continue
        test -f "$WORK_ROOT/env/images/$variant/bzImage" || { echo "$variant bzImage missing"; return 1; }
        test -f "$WORK_ROOT/env/images/$variant/vmlinux" || { echo "$variant vmlinux missing"; return 1; }
        echo "$variant vmlinux=$(sha256sum "$WORK_ROOT/env/images/$variant/vmlinux" | cut -c1-12).."
        found=1
    done
    test "$found" = 1 || { echo "no kernel variant under env/images"; return 1; }
    test -f "$WORK_ROOT/env/images/bookworm-kcov-fresh-v1.qcow2" || { echo "qcow2 missing"; return 1; }
    echo "qcow2=$(sha256sum "$WORK_ROOT/env/images/bookworm-kcov-fresh-v1.qcow2" | cut -c1-12).."
    if test "$MODE" = full; then echo "(full mode: rebuild/bake happens in bootstrap provision)"; fi
}

# ---------------- P5 gates ----------------
p5() {
    "$PREP/fport-design-gate.sh" -v || return $?
}

# ---------------- P6 evidence ----------------
p6() {
    if test "$MODE" = reuse; then
        echo "reuse mode: general-corpus AB evidence already on disk; gates (P5) consumed it."
        rec "evidence" "reused (general corpus)"
        return 0
    fi
    echo "full mode evidence chain (general NFS corpus, no crash-reproduction step):"
    echo "  tools/run-ab.sh -> tools/analyze-ab.sh  (일반 코퍼스 AB, 크래시 재현 단계 미포함)"
    "$PREP/run-ab.sh" || return $?
    "$PREP/analyze-ab.sh" || return $?
    rec "evidence" "generated (general corpus)"
}

# ---------------- P7 report ----------------
p7() {
    rec "verdict" "$STATUS"
    rec "run_dir" "$run_dir"
    python3 - "$MF" "$run_dir" <<'PYEOF'
import sys, pathlib
kv = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line or "=" not in line: continue
    k, v = line.split("=", 1)
    kv[k] = v
md = pathlib.Path(sys.argv[2]) / "port-run.md"
lines = ["# Port pipeline run", "", "| key | value |", "| --- | --- |"]
for k in sorted(kv):
    lines.append("| %s | %s |" % (k, kv[k]))
md.write_text("\n".join(lines) + "\n")
print("report: %s" % md)
PYEOF
}

# ---------------- run phases ----------------
run_phase p0    "provision/env-check"   p0 || exit 20
run_phase p1    "detect base/applied"   p1 || { rec "verdict" FAIL; exit 1; }
run_phase p2    "variant record"        p2 || { rec "verdict" FAIL; exit 1; }
run_phase p3    "apply series"          p3 || exit 10
run_phase p4    "build artifact check"  p4 || exit 20
run_phase p5    "design gates R1,R2,R4,R5"   p5 || STATUS=FAIL
run_phase p6    "fuzz evidence"         p6 || STATUS=FAIL
final=$STATUS
run_phase p7    "report"                p7
rec "status" "$final"

case "$final" in
PASS) echo; echo ">>> PIPELINE RESULT: DESIGN HOLDS on $TARGET (all phases pass)"; exit 0 ;;
*)    echo; echo ">>> PIPELINE RESULT: FAILED at $STEP_FAIL (see $run_dir)"; exit 1 ;;
esac
