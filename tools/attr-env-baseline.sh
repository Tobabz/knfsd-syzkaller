#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL=/home/idealinsane/kcsan-env-0012/linux/arch/x86/boot/bzImage
VMLINUX=/home/idealinsane/kcsan-env-0012/linux/vmlinux
IMAGE=/home/idealinsane/kcsan-env-0012/bookworm-kcov-fresh-v1.raw
DEPS="$ROOT/bundle/src/guest-deps.tar.gz"
SYZ_EXECPROG=/home/idealinsane/kcsan-env-0012/syzkaller/bin/linux_amd64/syz-execprog
SYZ_EXECUTOR=/home/idealinsane/kcsan-env-0012/syzkaller/bin/linux_amd64/syz-executor
SSH_KEY="$ROOT/artifacts/bookworm.id_rsa"
if [[ ! -f "$SSH_KEY" ]]; then
    SSH_KEY=/home/idealinsane/knfsd-syzkaller-fresh/artifacts/bookworm.id_rsa
fi
REPORT="$ROOT/report/attr-env-baseline.json"
GATE8_OUT=/home/idealinsane/attr-scenario-evidence/_baseline-gate8
REACH_OUT=/home/idealinsane/attr-scenario-evidence/_baseline-reach
REPORT_ONLY=0

usage() {
    cat <<EOF
usage: $0 [--kernel PATH] [--vmlinux PATH] [--image PATH] [--deps-tar PATH]
          [--syz-execprog PATH] [--syz-executor PATH] [--ssh-key PATH]
          [--report PATH] [--gate8-output PATH] [--reach-output PATH]
          [--report-only]
EOF
}

while (($#)); do
    case "$1" in
        --kernel) KERNEL=$2; shift 2 ;;
        --vmlinux) VMLINUX=$2; shift 2 ;;
        --image) IMAGE=$2; shift 2 ;;
        --deps-tar) DEPS=$2; shift 2 ;;
        --syz-execprog) SYZ_EXECPROG=$2; shift 2 ;;
        --syz-executor) SYZ_EXECUTOR=$2; shift 2 ;;
        --ssh-key) SSH_KEY=$2; shift 2 ;;
        --report) REPORT=$2; shift 2 ;;
        --gate8-output) GATE8_OUT=$2; shift 2 ;;
        --reach-output) REACH_OUT=$2; shift 2 ;;
        --report-only) REPORT_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

declare -a INPUT_NAMES=(kernel vmlinux image deps_tar syz_execprog syz_executor ssh_key)
declare -a INPUT_PATHS=("$KERNEL" "$VMLINUX" "$IMAGE" "$DEPS" "$SYZ_EXECPROG" "$SYZ_EXECUTOR" "$SSH_KEY")
for i in "${!INPUT_NAMES[@]}"; do
    if [[ ! -s "${INPUT_PATHS[$i]}" ]]; then
        echo "error: missing or empty ${INPUT_NAMES[$i]} input: ${INPUT_PATHS[$i]}" >&2
        exit 2
    fi
done

for path in \
    "$ROOT/bundle/ab-runner/run_frozen_phase8_vm.py" \
    "$ROOT/tools/ab-lane-fixture-gate8.sh" \
    "$ROOT/tools/run-reach-adapted-window.py" \
    "$ROOT/tools/ab-lane-fixture-v42.sh" \
    "$ROOT/tools/reach-assert.py" \
    "$ROOT/bundle/corpus/reach-copy-offload/reach-copy-offload-x2.prog" \
    "$ROOT/bundle/corpus/reach-copy-offload/manifest.json"; do
    if [[ ! -s "$path" ]]; then
        echo "error: missing or empty runner input: $path" >&2
        exit 2
    fi
done
TMP=$(mktemp -d "${TMPDIR:-/tmp}/attr-env-baseline.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

if (( REPORT_ONLY )); then
    for path in "$GATE8_OUT/phase8-evidence.json" \
                "$REACH_OUT/experiment_manifest.json" \
                "$REACH_OUT/reach_verdict_reach-copy-offload.json"; do
        if [[ ! -s "$path" ]]; then
            echo "error: missing or empty verified evidence: $path" >&2
            exit 2
        fi
    done
    image_sha_before=$(sha256sum "$IMAGE" | awk '{print $1}')
    image_sha_after=$image_sha_before
else
    for path in "$GATE8_OUT" "$REACH_OUT"; do
        if [[ -e "$path" || -L "$path" ]]; then
            echo "error: evidence output already exists: $path" >&2
            exit 2
        fi
    done
    mkdir -p "$(dirname "$GATE8_OUT")" "$(dirname "$REACH_OUT")"
    image_sha_before=$(sha256sum "$IMAGE" | awk '{print $1}')

is_ssh_timeout() {
    local evidence=$1 log=$2
    grep -Fqi "timed out waiting for guest SSH" "$log" && return 0
    [[ -f "$evidence" ]] && grep -Fqi "timed out waiting for guest SSH" "$evidence"
}

run_gate8() {
    local boot_timeout=$1 log=$2
    python3 "$ROOT/bundle/ab-runner/run_frozen_phase8_vm.py" \
        --kernel "$KERNEL" --image "$IMAGE" --ssh-key "$SSH_KEY" \
        --deps-tar "$DEPS" --output "$GATE8_OUT" \
        --lane-script "$ROOT/tools/ab-lane-fixture-gate8.sh" \
        --boot-timeout "$boot_timeout" >"$log" 2>&1
}

gate_log1="$TMP/gate8-attempt-1.log"
if ! run_gate8 180 "$gate_log1"; then
    if is_ssh_timeout "$GATE8_OUT/phase8-evidence.json" "$gate_log1"; then
        rm -rf "$GATE8_OUT"
        gate_log2="$TMP/gate8-attempt-2.log"
        if ! run_gate8 360 "$gate_log2"; then
            mkdir -p "$GATE8_OUT"
            cp "$gate_log1" "$GATE8_OUT/host-attempt-1.log"
            cp "$gate_log2" "$GATE8_OUT/host-attempt-2.log"
            cat "$gate_log2" >&2
            exit 1
        fi
        cp "$gate_log1" "$GATE8_OUT/host-attempt-1.log"
        cp "$gate_log2" "$GATE8_OUT/host-attempt-2.log"
    else
        cp "$gate_log1" "$GATE8_OUT/host-attempt-1.log"
        cat "$gate_log1" >&2
        exit 1
    fi
else
    cp "$gate_log1" "$GATE8_OUT/host-attempt-1.log"
fi

run_reach() {
    local boot_timeout=$1 log=$2
    KOOV_EXPECTED_CALLS=11 KOOV_CONFLICT_CALL=-1 python3 "$ROOT/tools/run-reach-adapted-window.py" \
        --kernel "$KERNEL" --image "$IMAGE" --ssh-key "$SSH_KEY" \
        --deps-tar "$DEPS" --vmlinux "$VMLINUX" --output "$REACH_OUT" \
        --lane-fixture "$ROOT/tools/ab-lane-fixture-v42.sh" \
        --workload "$ROOT/bundle/corpus/reach-copy-offload/reach-copy-offload-x2.prog" \
        --syz-execprog "$SYZ_EXECPROG" --syz-executor "$SYZ_EXECUTOR" \
        --mode both --trials 1 --executions 10 --procs 2 \
        --boot-timeout "$boot_timeout" >"$log" 2>&1
}

reach_log1="$TMP/reach-attempt-1.log"
if ! run_reach 180 "$reach_log1"; then
    if is_ssh_timeout "$REACH_OUT/experiment_manifest.json" "$reach_log1"; then
        rm -rf "$REACH_OUT"
        reach_log2="$TMP/reach-attempt-2.log"
        if ! run_reach 360 "$reach_log2"; then
            mkdir -p "$REACH_OUT"
            cp "$reach_log1" "$REACH_OUT/host-attempt-1.log"
            cp "$reach_log2" "$REACH_OUT/host-attempt-2.log"
            cat "$reach_log2" >&2
            exit 1
        fi
        cp "$reach_log1" "$REACH_OUT/host-attempt-1.log"
        cp "$reach_log2" "$REACH_OUT/host-attempt-2.log"
    else
        cp "$reach_log1" "$REACH_OUT/host-attempt-1.log"
        cat "$reach_log1" >&2
        exit 1
    fi
else
    cp "$reach_log1" "$REACH_OUT/host-attempt-1.log"
fi

python3 "$ROOT/tools/analyze_ab_adapted.py" \
    --results "$REACH_OUT" --vmlinux "$VMLINUX" \
    >"$REACH_OUT/analyze.log" 2>&1
python3 "$ROOT/tools/reach-assert.py" \
    --results "$REACH_OUT" --vmlinux "$VMLINUX" \
    --manifest "$ROOT/bundle/corpus/reach-copy-offload/manifest.json" \
    >"$REACH_OUT/reach-assert.log" 2>&1 || {
        cat "$REACH_OUT/reach-assert.log" >&2
        exit 1
    }

image_sha_after=$(sha256sum "$IMAGE" | awk '{print $1}')
if [[ "$image_sha_after" != "$image_sha_before" ]]; then
    echo "error: base image SHA-256 changed: $image_sha_before -> $image_sha_after" >&2
    exit 1
fi
fi

mkdir -p "$(dirname "$REPORT")"
REPORT_TMP="$TMP/attr-env-baseline.json"
export KERNEL VMLINUX IMAGE DEPS SYZ_EXECPROG SYZ_EXECUTOR
export GATE8_OUT REACH_OUT REPORT REPORT_TMP image_sha_before image_sha_after
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

paths = {"kernel": os.environ["KERNEL"], "vmlinux": os.environ["VMLINUX"],
         "image": os.environ["IMAGE"], "deps_tar": os.environ["DEPS"],
         "syz_execprog": os.environ["SYZ_EXECPROG"],
         "syz_executor": os.environ["SYZ_EXECUTOR"]}
gate8_out = Path(os.environ["GATE8_OUT"])
reach_out = Path(os.environ["REACH_OUT"])
report_path = Path(os.environ["REPORT"])
baseline = {name: {"path": path, "sha256": digest(path)} for name, path in paths.items()}
named = [
    ("gate8-baked", "/home/idealinsane/frozen-gate8-baked-evidence12", "phase8-evidence.json"),
    ("gate8-dedup16k", "/home/idealinsane/frozen-gate8-dedup16k-evidence10", "phase8-evidence.json"),
    ("gate8-s3", "/home/idealinsane/frozen-gate8-s3-evidence4", "phase8-evidence.json"),
    ("reach-async-x2", "/home/idealinsane/reach-baked-async-x2-review", "experiment_manifest.json"),
    ("gate9-run13", "/home/idealinsane/projects/knfsd-fuzz/artifacts/frozen-phase9-gate-2026-09-17-run13", "phase9-evidence.json"),
]
existing = []
for name, directory, filename in named:
    meta = Path(directory) / filename
    item = {"name": name, "path": directory, "metadata": str(meta), "sha_match": False}
    if not Path(directory).is_dir():
        item["reason"] = "evidence directory missing"
    elif not meta.is_file():
        item["reason"] = "input metadata missing"
    else:
        try:
            inputs = json.loads(meta.read_text()).get("inputs", {})
            compared, mismatches = {}, []
            for key in baseline:
                value = inputs.get(key)
                if isinstance(value, dict) and value.get("sha256"):
                    actual, expected = value["sha256"], baseline[key]["sha256"]
                    compared[key] = {"evidence": actual, "baseline": expected,
                                     "match": actual == expected}
                    if actual != expected:
                        mismatches.append(key)
            item["compared_inputs"] = compared
            required = ("kernel", "vmlinux", "image")
            missing = [key for key in required if key not in compared]
            reasons = []
            if missing:
                reasons.append("missing required provenance SHA-256: " + ", ".join(missing))
            if mismatches:
                reasons.append("SHA-256 mismatch: " + ", ".join(mismatches))
            if reasons:
                item["reason"] = "; ".join(reasons)
            else:
                item["sha_match"] = True
                item["reason"] = "required kernel, vmlinux, and image SHA-256 values match"
        except (OSError, ValueError) as error:
            item["reason"] = f"unreadable input metadata: {error}"
    existing.append(item)

gate = json.loads((gate8_out / "phase8-evidence.json").read_text())["gate"]["status"]
reach_manifest = json.loads((reach_out / "experiment_manifest.json").read_text())
reach_verdict_path = reach_out / "reach_verdict_reach-copy-offload.json"
reach_assertion = json.loads(reach_verdict_path.read_text())["overall"]
if gate != "pass" or reach_manifest.get("status") != "collected" or reach_assertion != "PASS":
    raise SystemExit("verified current evidence is not PASS")

history = []
if report_path.is_file():
    previous_reach = json.loads(report_path.read_text()).get("reach", {})
    history.extend(previous_reach.get("history", []))
    if previous_reach.get("assertion") not in (None, "PASS"):
        history.append({
            "assertion": previous_reach["assertion"],
            "failure": previous_reach.get("failure"),
            "runner_status": previous_reach.get("runner_status"),
            "superseded_by": str(reach_verdict_path),
        })
deduped_history = []
for entry in history:
    if entry not in deduped_history:
        deduped_history.append(entry)

report = {"schema": 1, "inputs": baseline, "existing_evidence": existing,
          "gate8": {"output": str(gate8_out), "status": gate},
          "reach": {"output": str(reach_out),
                    "runner_status": reach_manifest["status"],
                    "assertion": reach_assertion,
                    "verdict": str(reach_verdict_path),
                    "history": deduped_history},
          "image_sha256_before": os.environ["image_sha_before"],
          "image_sha256_after": os.environ["image_sha_after"],
          "image_unchanged": os.environ["image_sha_before"] == os.environ["image_sha_after"]}
Path(os.environ["REPORT_TMP"]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
mv "$REPORT_TMP" "$REPORT"
printf "baseline PASS: %s\n" "$REPORT"
