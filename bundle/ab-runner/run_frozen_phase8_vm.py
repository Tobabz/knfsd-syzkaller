#!/usr/bin/env python3
"""Run Frozen Baseline Gate 8 with real svc replay and NFSv4.2 async COPY."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time


SCHEMA_VERSION = 1
REMOTE_DRIVER = "/opt/frozen-phase8"
PHASE3_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
PHASE3_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
PHASE4_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase4_stats"
PHASE4_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase4_control"
PHASE4_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase4_state"
PHASE5_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase5_stats"
PHASE5_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase5_control"
PHASE5_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase5_state"
PHASE6_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase6_stats"
PHASE6_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase6_control"
PHASE6_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase6_state"
PHASE8_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase8_stats"
PHASE8_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase8_control"

REQUIRED_COUNTERS = {
    "deferred_child_created", "deferred_child_rejected",
    "deferred_restored", "deferred_redeferred", "deferred_grant_ok",
    "deferred_owner_none", "deferred_start_ok",
    "deferred_start_incomplete", "deferred_start_nested",
    "deferred_completed", "deferred_dropped",
    "deferred_abort_before_grant",
    "deferred_pause_after_grant_entered",
    "deferred_pause_after_grant_released",
    "deferred_pause_after_grant_timed_out", "deferred_direct_active",
    "async_child_created", "async_child_rejected", "async_grant_ok",
    "async_owner_none", "async_start_ok", "async_start_incomplete",
    "async_start_nested", "async_completed", "async_dropped",
    "async_abort_before_grant", "async_pause_after_grant_entered",
    "async_pause_after_grant_released",
    "async_pause_after_grant_timed_out", "async_direct_active",
    "saved_work_double_attach", "live_saved_work",
    "abort_next_deferred_armed", "abort_next_async_armed",
    "pause_next_deferred_armed", "pause_next_async_armed",
}

PHASE8_ZERO_FINAL = {
    "live_saved_work", "abort_next_deferred_armed",
    "abort_next_async_armed", "pause_next_deferred_armed",
    "pause_next_async_armed", "deferred_direct_active",
    "async_direct_active", "saved_work_double_attach",
    "deferred_start_nested", "async_start_nested",
    "deferred_pause_after_grant_timed_out",
    "async_pause_after_grant_timed_out",
}

FATAL_KERNEL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:|refcount_t:)",
    re.IGNORECASE,
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load helper module: %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_evidence(output, evidence):
    temporary = output / ".phase8-evidence.json.tmp"
    final = output / "phase8-evidence.json"
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, final)


def parse_stats(text):
    values = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.replace("=", " ", 1).split()
        if len(fields) != 2 or not re.fullmatch(r"[a-z][a-z0-9_]*", fields[0]):
            raise ValueError("invalid Phase 8 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 8 counter: " + fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer Phase 8 counter: " + fields[0]) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 8 counter: " + fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing Phase 8 counters: " + ", ".join(missing))
    return values


def snapshot(vm, stage):
    return parse_stats(vm.guest(stage, "cat " + PHASE8_STATS, timeout=20).stdout)


def delta(before, after, name):
    value = after[name] - before[name]
    if value < 0:
        raise ValueError("counter regressed: " + name)
    return value


def json_object(text, context):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(context + " emitted invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(context + " JSON is not an object")
    return value


def validate_probe(value, scenario):
    normal = scenario.endswith("normal")
    async_copy = scenario.startswith("async-")
    if (value.get("status") != "pass" or value.get("scenario") != scenario or
            int(value.get("generation", 0)) <= 0 or
            int(value.get("local_entries", 0)) <= 0 or
            int(value.get("operation_bytes", 0)) <= 0):
        raise ValueError("Phase 8 probe failed contract: " + scenario)
    if (int(value.get("remote_entries", 0)) > 0) != normal:
        raise ValueError("Phase 8 remote publication mismatch: " + scenario)
    if async_copy and (
            int(value.get("operation_bytes", 0)) != 4 << 20 or
            int(value.get("content_hash", 0)) == 0 or
            value.get("content_hash") != value.get("expected_hash")):
        raise ValueError("Phase 8 async COPY content mismatch: " + scenario)
    return value


def run_probe(vm, scenario):
    identity = "%s/sync/%s.id" % (vm.lane_root, scenario)
    command = (
        "set -eu; pid=$(cat %s/client0.pid); exec timeout 150s "
        "nsenter -t \"$pid\" -m -n -- %s/phase8-probe %s %s/client0/mnt %s"
        % (shlex.quote(vm.lane_root), REMOTE_DRIVER, shlex.quote(scenario),
           shlex.quote(vm.lane_root), shlex.quote(identity))
    )
    result = vm.guest("phase8-probe-" + scenario, command, timeout=165)
    return validate_probe(json_object(result.stdout, scenario), scenario)


def stop_mountd_and_flush(vm, scenario):
    root = shlex.quote(vm.lane_root)
    command = """set -eu
server=$(cat %s/server.pid)
mountd=$(nsenter -t "$server" -m -n -- pgrep -xo rpc.mountd)
test -n "$mountd"
kill -STOP "$mountd"
i=0
while ! awk '$1 == "State:" && $2 ~ /^T/ { found=1 } END { exit !found }' "/proc/$mountd/status"; do
    i=$((i + 1))
    test "$i" -lt 100
    sleep 0.01
done
nsenter -t "$server" -m -n -- sh -c '
    set -eu
    test -w /proc/net/rpc/auth.unix.ip/flush
    test -w /proc/net/rpc/nfsd.export/flush
    printf "1\n" > /proc/net/rpc/auth.unix.ip/flush
    printf "1\n" > /proc/net/rpc/nfsd.export/flush
'
printf '%%s\n' "$mountd"
""" % root
    result = vm.guest("deferred-stop-flush-" + scenario, command, timeout=30)
    text = result.stdout.strip()
    if not text.isdigit() or int(text) <= 1:
        raise ValueError("invalid rpc.mountd PID: %r" % text)
    return int(text)


def resume_mountd(vm, scenario, mountd):
    vm.guest(
        "deferred-resume-mountd-" + scenario,
        "kill -CONT %d; test -e /proc/%d/status" % (mountd, mountd),
        timeout=20,
    )


def start_background_probe(vm, scenario):
    stem = "%s/sync/%s" % (vm.lane_root, scenario)
    stdout = stem + ".stdout"
    stderr = stem + ".stderr"
    rc_path = stem + ".rc"
    identity = stem + ".id"
    client_pid = "%s/client0.pid" % vm.lane_root
    mount = "%s/client0/mnt" % vm.lane_root
    probe = (
        "timeout 150s nsenter -t $(cat %s) -m -n -- %s/phase8-probe %s %s %s"
        % (shlex.quote(client_pid), REMOTE_DRIVER, shlex.quote(scenario),
           shlex.quote(mount), shlex.quote(identity))
    )
    inner = (
        "set +e; %s >%s 2>%s; value=$?; printf '%%s\\n' \"$value\" >%s"
        % (probe, shlex.quote(stdout), shlex.quote(stderr), shlex.quote(rc_path))
    )
    command = (
        "rm -f %s %s %s %s; setsid sh -c %s </dev/null >/dev/null 2>&1 & "
        "printf '%%s\\n' \"$!\""
        % (shlex.quote(stdout), shlex.quote(stderr), shlex.quote(rc_path),
           shlex.quote(identity), shlex.quote(inner))
    )
    result = vm.guest("deferred-start-probe-" + scenario, command, timeout=20)
    pid = result.stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise ValueError("invalid background probe PID: %r" % pid)
    return {"pid": int(pid), "stdout": stdout, "stderr": stderr,
            "rc": rc_path, "identity": identity}


def wait_counter_after(vm, baseline, name, scenario, timeout=45):
    deadline = time.monotonic() + timeout
    latest = baseline
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        latest = snapshot(vm, "deferred-wait-%s-%02d" % (scenario, attempt))
        if latest[name] > baseline[name] and latest["live_saved_work"] > 0:
            return latest
        time.sleep(0.5)
    raise ValueError("deferred request did not save work: %s" % scenario)


def finish_background_probe(vm, scenario, background):
    command = """set -eu
i=0
while ! test -s %s; do
    i=$((i + 1))
    test "$i" -lt 180
    sleep 1
done
cat %s
""" % (shlex.quote(background["rc"]), shlex.quote(background["rc"]))
    result = vm.guest("deferred-wait-probe-" + scenario, command, timeout=190)
    rc_text = result.stdout.strip()
    if not re.fullmatch(r"[0-9]+", rc_text):
        raise ValueError("invalid background probe status: %r" % rc_text)
    output = vm.guest(
        "deferred-read-probe-" + scenario,
        "cat " + shlex.quote(background["stdout"]), timeout=20,
    ).stdout
    stderr = vm.guest(
        "deferred-read-stderr-" + scenario,
        "cat " + shlex.quote(background["stderr"]), timeout=20,
        check=False,
    ).stdout
    if int(rc_text):
        raise ValueError("background probe %s failed rc=%s: %s" %
                         (scenario, rc_text, stderr.strip()))
    vm.guest(
        "deferred-clean-probe-" + scenario,
        "rm -f %s %s %s %s" % tuple(
            shlex.quote(background[name])
            for name in ("stdout", "stderr", "rc", "identity")
        ), timeout=20,
    )
    return validate_probe(json_object(output, scenario), scenario)


def run_deferred_probe(vm, scenario, before):
    mountd = stop_mountd_and_flush(vm, scenario)
    background = None
    resumed = False
    try:
        background = start_background_probe(vm, scenario)
        blocked = wait_counter_after(
            vm, before, "deferred_child_created", scenario
        )
        expected_armed = {
            "deferred-abort-before-grant": "abort_next_deferred_armed",
            "deferred-abort-after-grant": "pause_next_deferred_armed",
        }.get(scenario)
        if expected_armed and blocked[expected_armed] != 1:
            raise ValueError("deferred fault was not armed: " + scenario)
        resume_mountd(vm, scenario, mountd)
        resumed = True
        value = finish_background_probe(vm, scenario, background)
        return value, blocked
    finally:
        if not resumed:
            vm.guest("deferred-emergency-resume-" + scenario,
                     "kill -CONT %d" % mountd, timeout=20, check=False)


def resources(vm, phase4, phase5, phase6, stage):
    return {
        "phase8": snapshot(vm, stage + "-phase8"),
        "phase4": {
            "stats": phase4.parse_stats(vm.guest(
                stage + "-phase4-stats", "cat " + PHASE4_STATS,
                timeout=20).stdout),
            "state": vm.guest(stage + "-phase4-state",
                              "cat " + PHASE4_STATE, timeout=20).stdout,
        },
        "phase5": {
            "stats": phase5.parse_stats(vm.guest(
                stage + "-phase5-stats", "cat " + PHASE5_STATS,
                timeout=20).stdout),
            "state": phase5.parse_state(vm.guest(
                stage + "-phase5-state", "cat " + PHASE5_STATE,
                timeout=20).stdout),
        },
        "phase6": {
            "stats": phase6.parse_stats(vm.guest(
                stage + "-phase6-stats", "cat " + PHASE6_STATS,
                timeout=20).stdout),
            "state": phase6.parse_state(vm.guest(
                stage + "-phase6-state", "cat " + PHASE6_STATE,
                timeout=20).stdout),
        },
    }


def resources_drained(value):
    phase8 = value["phase8"]
    phase4 = value["phase4"]
    phase5 = value["phase5"]
    phase6 = value["phase6"]
    return (
        all(phase8[name] == 0 for name in (
            "live_saved_work", "abort_next_deferred_armed",
            "abort_next_async_armed", "pause_next_deferred_armed",
            "pause_next_async_armed")) and
        phase4["stats"]["outstanding_tokens"] == 0 and
        phase4["stats"]["object_refs"] == 0 and
        not phase4["state"].strip() and
        not phase5["state"]["generations"] and
        all(number == 0 for number in phase5["state"]["live"].values()) and
        not phase6["state"]["generations"] and
        all(number == 0 for number in phase6["state"]["live"].values())
    )


def wait_drained(vm, phase4, phase5, phase6, scenario, timeout=30):
    deadline = time.monotonic() + timeout
    attempt = 0
    latest = None
    while time.monotonic() < deadline:
        attempt += 1
        latest = resources(vm, phase4, phase5, phase6,
                           "drain-%s-%02d" % (scenario, attempt))
        if resources_drained(latest):
            return latest
        time.sleep(1)
    raise ValueError("Phase 8 resources did not drain after %s: %r" %
                     (scenario, latest))


def scenario_delta(snapshots, scenario, name):
    return delta(snapshots[scenario]["before"],
                 snapshots[scenario]["after"], name)


def no_family_delta(snapshots, scenario, prefix):
    return all(
        scenario_delta(snapshots, scenario, name) == 0
        for name in REQUIRED_COUNTERS if name.startswith(prefix)
        and not name.endswith("_armed")
    )


def validate_gate(snapshots, probes, drains, final_resources,
                  mount_contract, connections):
    checks = {}

    checks["isolated_lane_is_nfsv42"] = (
        len(mount_contract) == 2 and
        all("vers=4.2" in item for item in mount_contract))
    for scenario in probes:
        checks[scenario + "_probe_contract"] = (
            probes[scenario]["status"] == "pass" and
            probes[scenario]["local_entries"] > 0 and
            ((probes[scenario]["remote_entries"] > 0) ==
             scenario.endswith("normal")))
        checks[scenario + "_exact_drain"] = resources_drained(drains[scenario])

    scenario = "deferred-normal"
    created = scenario_delta(snapshots, scenario, "deferred_child_created")
    checks["real_deferred_replay_completed"] = (
        created >= 1 and
        scenario_delta(snapshots, scenario, "deferred_restored") == created and
        scenario_delta(snapshots, scenario, "deferred_grant_ok") == created and
        scenario_delta(snapshots, scenario, "deferred_start_ok") == created and
        scenario_delta(snapshots, scenario, "deferred_completed") == created and
        all(scenario_delta(snapshots, scenario, name) == 0 for name in (
            "deferred_owner_none", "deferred_start_incomplete",
            "deferred_start_nested", "deferred_dropped",
            "deferred_abort_before_grant",
            "deferred_pause_after_grant_entered")))
    checks["deferred_normal_not_async"] = no_family_delta(
        snapshots, scenario, "async_")

    scenario = "deferred-abort-before-grant"
    checks["deferred_abort_before_grant_ownerless"] = (
        scenario_delta(snapshots, scenario, "deferred_child_created") == 1 and
        scenario_delta(snapshots, scenario, "deferred_restored") == 1 and
        scenario_delta(snapshots, scenario,
                       "deferred_abort_before_grant") == 1 and
        scenario_delta(snapshots, scenario, "deferred_owner_none") == 1 and
        scenario_delta(snapshots, scenario, "deferred_dropped") == 1 and
        all(scenario_delta(snapshots, scenario, name) == 0 for name in (
            "deferred_grant_ok", "deferred_start_ok",
            "deferred_start_incomplete", "deferred_completed")))

    scenario = "deferred-abort-after-grant"
    checks["deferred_abort_after_start_granted"] = (
        scenario_delta(snapshots, scenario, "deferred_child_created") == 1 and
        scenario_delta(snapshots, scenario, "deferred_restored") == 1 and
        scenario_delta(snapshots, scenario, "deferred_grant_ok") == 1 and
        scenario_delta(snapshots, scenario,
                       "deferred_pause_after_grant_entered") == 1 and
        scenario_delta(snapshots, scenario,
                       "deferred_pause_after_grant_released") == 1 and
        scenario_delta(snapshots, scenario,
                       "deferred_pause_after_grant_timed_out") == 0 and
        scenario_delta(snapshots, scenario, "deferred_start_ok") == 1 and
        scenario_delta(snapshots, scenario, "deferred_completed") == 1 and
        scenario_delta(snapshots, scenario,
                       "deferred_start_incomplete") == 0 and
        scenario_delta(snapshots, scenario, "deferred_owner_none") == 0 and
        scenario_delta(snapshots, scenario, "deferred_dropped") == 0)

    scenario = "async-normal"
    checks["nfsv42_async_copy_start_granted"] = (
        scenario_delta(snapshots, scenario, "async_child_created") == 1 and
        scenario_delta(snapshots, scenario, "async_grant_ok") == 1 and
        scenario_delta(snapshots, scenario, "async_start_ok") == 1 and
        scenario_delta(snapshots, scenario, "async_completed") == 1 and
        all(scenario_delta(snapshots, scenario, name) == 0 for name in (
            "async_child_rejected", "async_owner_none",
            "async_start_incomplete", "async_start_nested",
            "async_dropped", "async_abort_before_grant",
            "async_pause_after_grant_entered")))
    checks["async_copy_bytes_verified"] = (
        probes[scenario]["operation_bytes"] == 4 << 20 and
        probes[scenario]["content_hash"] == probes[scenario]["expected_hash"])
    checks["async_normal_not_deferred"] = no_family_delta(
        snapshots, scenario, "deferred_")

    scenario = "async-abort-before-grant"
    checks["async_abort_before_grant_ownerless_copy"] = (
        scenario_delta(snapshots, scenario, "async_child_created") == 1 and
        scenario_delta(snapshots, scenario, "async_abort_before_grant") == 1 and
        scenario_delta(snapshots, scenario, "async_owner_none") == 1 and
        scenario_delta(snapshots, scenario, "async_dropped") == 1 and
        scenario_delta(snapshots, scenario, "async_grant_ok") == 0 and
        scenario_delta(snapshots, scenario, "async_start_ok") == 0 and
        probes[scenario]["content_hash"] == probes[scenario]["expected_hash"])

    scenario = "async-abort-after-grant"
    checks["async_abort_after_start_granted"] = (
        scenario_delta(snapshots, scenario, "async_child_created") == 1 and
        scenario_delta(snapshots, scenario, "async_grant_ok") == 1 and
        scenario_delta(snapshots, scenario,
                       "async_pause_after_grant_entered") == 1 and
        scenario_delta(snapshots, scenario,
                       "async_pause_after_grant_released") == 1 and
        scenario_delta(snapshots, scenario,
                       "async_pause_after_grant_timed_out") == 0 and
        scenario_delta(snapshots, scenario, "async_start_ok") == 1 and
        scenario_delta(snapshots, scenario, "async_completed") == 1 and
        scenario_delta(snapshots, scenario, "async_start_incomplete") == 0 and
        scenario_delta(snapshots, scenario, "async_owner_none") == 0 and
        scenario_delta(snapshots, scenario, "async_dropped") == 0 and
        probes[scenario]["content_hash"] == probes[scenario]["expected_hash"])

    final = final_resources["phase8"]
    checks["phase8_lifecycle_balanced"] = (
        final["deferred_child_created"] ==
        final["deferred_completed"] + final["deferred_dropped"] and
        final["async_child_created"] ==
        final["async_completed"] + final["async_dropped"])
    checks["phase8_invariants_and_controls_clean"] = all(
        final[name] == 0 for name in PHASE8_ZERO_FINAL)
    checks["phase4_exact_drain"] = (
        final_resources["phase4"]["stats"]["outstanding_tokens"] == 0 and
        final_resources["phase4"]["stats"]["object_refs"] == 0 and
        final_resources["phase4"]["stats"]["token_double_complete"] == 0 and
        not final_resources["phase4"]["state"].strip())
    checks["phase5_exact_drain"] = (
        not final_resources["phase5"]["state"]["generations"] and
        all(value == 0 for value in
            final_resources["phase5"]["state"]["live"].values()) and
        final_resources["phase5"]["stats"]["remote_stop_double"] == 0 and
        final_resources["phase5"]["stats"]["grant_order_violation"] == 0 and
        final_resources["phase5"]["stats"]["start_transaction_violation"] == 0)
    checks["phase6_exact_drain"] = (
        not final_resources["phase6"]["state"]["generations"] and
        all(value == 0 for value in
            final_resources["phase6"]["state"]["live"].values()))
    checks["wire_ordinals_aligned"] = (
        bool(connections) and
        all(item["ordinal_mismatch"] == 0 for item in connections))

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 8 checks failed: " + ", ".join(failed))
    return checks


def collect_failure_diagnostics(vm):
    result = {}
    for name, command in {
        "phase8_stats": "cat " + PHASE8_STATS,
        "phase6_stats": "cat " + PHASE6_STATS,
        "phase6_state": "cat " + PHASE6_STATE,
        "phase5_stats": "cat " + PHASE5_STATS,
        "phase5_state": "cat " + PHASE5_STATE,
        "phase4_state": "cat " + PHASE4_STATE,
        "phase4_stats": "cat " + PHASE4_STATS,
        "connections": "cat /sys/kernel/debug/sunrpc_fuzz/phase3_connections",
        "tasks": "ps -eo pid,ppid,etimes,state,wchan:32,args | grep -E 'phase8-probe|rpc.mountd|nsenter|timeout' | grep -v grep || true",
    }.items():
        completed = vm.guest("failure-" + name, command, timeout=20, check=False)
        result[name] = {"returncode": completed.returncode,
                        "stdout": completed.stdout.splitlines(),
                        "stderr": completed.stderr.splitlines()}
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    scripts = Path(__file__).resolve().parent
    parser.add_argument("--phase1-runner", type=Path,
                        default=scripts / "run_frozen_phase1_vm.py")
    parser.add_argument("--phase3-runner", type=Path,
                        default=scripts / "run_frozen_phase3_vm.py")
    parser.add_argument("--phase4-runner", type=Path,
                        default=scripts / "run_frozen_phase4_vm.py")
    parser.add_argument("--phase5-runner", type=Path,
                        default=scripts / "run_frozen_phase5_vm.py")
    parser.add_argument("--phase6-runner", type=Path,
                        default=scripts / "run_frozen_phase6_vm.py")
    parser.add_argument("--lane-script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--bootstrap", type=Path,
                        default=scripts / "frozen_phase3_bootstrap.sh")
    parser.add_argument("--cleanup-hook", type=Path,
                        default=scripts / "frozen_phase3_cleanup.sh")
    parser.add_argument("--probe", type=Path,
                        default=scripts / "frozen_phase8_probe.c")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "phase3_runner", "phase4_runner", "phase5_runner",
                 "phase6_runner", "lane_script", "workload", "bootstrap",
                 "cleanup_hook", "probe"):
        path = getattr(args, name).resolve()
        setattr(args, name, path)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" %
                         (name.replace("_", "-"), path))
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    return args


def main(argv=None):
    args = parse_args(argv)
    phase1 = load_module("frozen_phase1_runner", args.phase1_runner)
    phase3 = load_module("frozen_phase3_runner", args.phase3_runner)
    phase4 = load_module("frozen_phase4_runner", args.phase4_runner)
    phase5 = load_module("frozen_phase5_runner", args.phase5_runner)
    phase6 = load_module("frozen_phase6_runner", args.phase6_runner)
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    phase3.REMOTE_DRIVER = REMOTE_DRIVER
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION, "phase": 8, "status": "running",
        "started_at": timestamp(), "commands": [], "snapshots": {},
        "runtime_probes": {}, "drains": {},
        "gate": {"name": "Gate 8", "status": "running"},
        "observability_contract": {
            "stats": PHASE8_STATS, "control": PHASE8_CONTROL,
            "required_counters": sorted(REQUIRED_COUNTERS),
        },
    }
    write_evidence(args.output, evidence)
    phase1.write_evidence = write_evidence
    vm = None
    base_hash = None
    active_epoch = None
    exit_code = 1
    try:
        phase1.validate_inputs(args, evidence)
        for name in ("phase1_runner", "phase3_runner", "phase4_runner",
                     "phase5_runner", "phase6_runner", "bootstrap",
                     "cleanup_hook", "probe"):
            path = getattr(args, name)
            evidence["inputs"][name] = {
                "path": str(path), "bytes": path.stat().st_size,
                "sha256": phase1.sha256(path),
            }
        source = args.probe.read_text(encoding="utf-8")
        evidence["source_contract"] = {
            "real_copy_file_range": "copy_file_range" in source,
            "async_copy_strictly_large": "COPY_BYTES (4U << 20)" in source,
            "deferred_lookup": "exercise_deferred_lookup" in source,
            "generation_finish_bounded": ".timeout_ms = 5000" in source,
            "pregrant_abort_controls": (
                "abort-next-deferred" in source and
                "abort-next-async" in source),
            "postgrant_pause_controls": (
                "pause-next-deferred-after-grant" in source and
                "pause-next-async-after-grant" in source),
            "content_hash_verification": "expected_hash" in source,
        }
        if not all(evidence["source_contract"].values()):
            raise ValueError("Phase 8 source contract incomplete")
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug; command -v gcc ip nsenter timeout tar sed pgrep setsid sha256sum",
            timeout=30,
        )
        for path in (PHASE3_STATS, PHASE3_CONTROL, PHASE4_STATS,
                     PHASE4_CONTROL, PHASE4_STATE, PHASE5_STATS,
                     PHASE5_CONTROL, PHASE5_STATE, PHASE6_STATS,
                     PHASE6_CONTROL, PHASE6_STATE, PHASE8_STATS,
                     PHASE8_CONTROL):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase8-deps.tar.gz")
        vm.put("copy-lane", args.lane_script,
               "/tmp/frozen-phase8-lane-source.sh")
        vm.put("copy-bootstrap", args.bootstrap,
               "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup", args.cleanup_hook,
               "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-probe", args.probe, "/tmp/frozen-phase8-probe.c")
        vm.guest(
            "install-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase8-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase8-lane-source.sh %s/lane.sh; "
            "sed -i -e 's/vers=4.1,minorversion=1/vers=4.2/' "
            "-e 's/vers=4\\\\\\\\.1/vers=4\\\\\\\\.2/' %s/lane.sh; "
            "install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; "
            "install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; "
            "gcc -O2 -Wall -Wextra -Werror -o %s/phase8-probe "
            "/tmp/frozen-phase8-probe.c"
            % ((REMOTE_DRIVER,) * 6), timeout=90,
        )
        lane_transform = vm.guest(
            "record-v42-lane-transform",
            "set -eu; sha256sum /tmp/frozen-phase8-lane-source.sh %s/lane.sh; "
            "grep -nE 'mount[.]nfs4|vers=4' %s/lane.sh"
            % (REMOTE_DRIVER, REMOTE_DRIVER), timeout=20,
        )
        evidence["lane_transform"] = lane_transform.stdout.splitlines()
        allocated = vm.guest("allocate-lane-root",
                             "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10)
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")
        for control in (PHASE3_CONTROL, PHASE4_CONTROL, PHASE5_CONTROL,
                        PHASE6_CONTROL, PHASE8_CONTROL):
            vm.guest("reset-" + Path(control).stem,
                     "printf 'reset\n' > " + control, timeout=20)

        baseline = snapshot(vm, "phase8-baseline")
        active_epoch, lane_status = phase3.setup_lane(vm)
        lane_epoch = active_epoch
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        mount_lines = vm.guest(
            "record-v42-mounts",
            "cat %s/client0.mount %s/client1.mount" %
            (shlex.quote(vm.lane_root), shlex.quote(vm.lane_root)),
            timeout=20,
        ).stdout.splitlines()
        if (len(mount_lines) != 2 or
                any("vers=4.2" not in line for line in mount_lines)):
            raise ValueError("Phase 8 lane did not negotiate NFSv4.2")
        phase3_before = phase3.parse_counter_file(vm.guest(
            "phase3-before-phase8", "cat " + PHASE3_STATS,
            timeout=20).stdout)

        scenarios = (
            "deferred-normal", "deferred-abort-before-grant",
            "deferred-abort-after-grant", "async-normal",
            "async-abort-before-grant", "async-abort-after-grant",
        )
        snapshots = {}
        probes = {}
        drains = {}
        blocked = {}
        for scenario in scenarios:
            before = snapshot(vm, "before-" + scenario)
            if scenario.startswith("deferred-"):
                probes[scenario], blocked[scenario] = run_deferred_probe(
                    vm, scenario, before)
            else:
                probes[scenario] = run_probe(vm, scenario)
            drains[scenario] = wait_drained(
                vm, phase4, phase5, phase6, scenario)
            after = drains[scenario]["phase8"]
            snapshots[scenario] = {"before": before, "after": after}
            evidence["runtime_probes"][scenario] = probes[scenario]
            evidence["snapshots"][scenario] = snapshots[scenario]
            if scenario in blocked:
                evidence["snapshots"][scenario]["blocked"] = blocked[scenario]
            evidence["drains"][scenario] = drains[scenario]
            write_evidence(args.output, evidence)

        phase3_after, all_connections = phase3.wait_for_ordinal_alignment(
            vm, active_epoch,
            phase3.parse_counter_file(vm.guest(
                "phase3-before-cleanup", "cat " + PHASE3_STATS,
                timeout=20).stdout), require_global=False)
        connections = phase3.paired_connections(all_connections, active_epoch)
        final_resources = resources(vm, phase4, phase5, phase6, "final")
        checks = validate_gate(snapshots, probes, drains, final_resources,
                               mount_lines, connections)
        phase3.cleanup_lane(phase1, vm, active_epoch, strict=True)
        active_epoch = None
        evidence["baseline"] = baseline
        evidence["epoch"] = lane_epoch
        evidence["lane_status"] = lane_status
        evidence["mount_contract"] = mount_lines
        evidence["phase3"] = {
            "before": phase3_before, "after": phase3_after,
            "connections": all_connections,
        }
        evidence["final_resources"] = final_resources
        evidence["gate"] = {"name": "Gate 8", "status": "pass",
                            "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__,
                               "message": str(error)}
        evidence["gate"] = {"name": "Gate 8", "status": "fail"}
        evidence["completed_at"] = timestamp()
        if vm is not None and vm.ready:
            vm.guest("emergency-clear-phase8",
                     "printf 'clear-fault\n' > %s; pkill -CONT -x rpc.mountd || true"
                     % PHASE8_CONTROL, timeout=20, check=False)
            try:
                evidence["failure_diagnostics"] = collect_failure_diagnostics(vm)
            except Exception as diagnostic_error:
                evidence.setdefault("collection_errors", []).append(
                    "failure diagnostics: " + str(diagnostic_error))
        write_evidence(args.output, evidence)
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    evidence["cleanup"] = phase1.cleanup_and_validate(
                        vm, 999, strict=False)
                    active_epoch = None
                    if exit_code == 0 and any(
                            evidence["cleanup"].get(field) != 0 for field in
                            ("cleanup_returncode", "validation_returncode")):
                        raise ValueError("final cleanup validation failed")
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
                        evidence["failure"] = {
                            "type": type(error).__name__, "message": str(error)}
                        exit_code = 1
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30,
                                 check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr, encoding="utf-8",
                    errors="replace")
                if dmesg.returncode or FATAL_KERNEL_RE.search(dmesg.stdout):
                    raise ValueError("fatal kernel diagnostic in Phase 8 VM")
            except Exception as error:
                evidence.setdefault("collection_errors", []).append(str(error))
                if exit_code == 0:
                    evidence["status"] = "fail"
                    evidence["gate"]["status"] = "fail"
                    evidence["failure"] = {
                        "type": type(error).__name__, "message": str(error)}
                    exit_code = 1
        if vm is not None:
            vm.stop()
        if base_hash is not None:
            final_hash = phase1.sha256(args.image)
            evidence["inputs"]["image"]["sha256_after"] = final_hash
            evidence["inputs"]["image"]["unchanged"] = final_hash == base_hash
            if final_hash != base_hash:
                evidence["status"] = "fail"
                evidence["gate"]["status"] = "fail"
                evidence["failure"] = {
                    "type": "GateFailure", "message": "base image changed"}
                exit_code = 1
        write_evidence(args.output, evidence)
    print(json.dumps({"status": evidence["status"],
                      "evidence": str(args.output / "phase8-evidence.json")},
                     sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
