#!/usr/bin/env python3
"""Run Frozen Baseline Gate 7 against real knfsd in a disposable VM."""

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
REMOTE_DRIVER = "/opt/frozen-phase7"
PHASE3_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
PHASE3_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
PHASE4_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase4_stats"
PHASE4_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase4_state"
PHASE5_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase5_state"
PHASE6_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase6_state"
PHASE7_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase7_stats"

REQUIRED_COUNTERS = {
    "raw_socket_enable_ok", "raw_socket_enable_rejected",
    "raw_socket_released", "raw_preconnect_created",
    "raw_preconnect_failed", "raw_cmsg_new", "raw_cmsg_new_final",
    "raw_cmsg_retry", "raw_cmsg_retry_final", "raw_cmsg_cancel",
    "raw_cmsg_rejected", "raw_tag_created", "raw_tag_completed",
    "raw_tag_canceled", "raw_tag_auto_sealed", "raw_tx_full",
    "raw_tx_precommit_rollback", "raw_tx_postcommit_partial",
    "raw_retry_same_cookie", "raw_retry_new_ordinal",
    "raw_tag_collision", "raw_cross_socket_retry_rejected",
    "raw_connection_corrupted", "raw_rx_record", "raw_rx_parse_error",
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
    temporary = output / ".phase7-evidence.json.tmp"
    final = output / "phase7-evidence.json"
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
            raise ValueError("invalid Phase 7 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 7 counter: " + fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer Phase 7 counter: " + fields[0]) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 7 counter: " + fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing Phase 7 counters: " + ", ".join(missing))
    return values


def snapshot(vm, stage):
    return parse_stats(vm.guest(stage, "cat " + PHASE7_STATS, timeout=20).stdout)


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


def run_probe(vm, scenario):
    command = (
        "set -eu; pid=$(cat %s/client0.pid); exec timeout 45s "
        "nsenter -t \"$pid\" -m -n -- %s/phase7-probe %s"
        % (shlex.quote(vm.lane_root), REMOTE_DRIVER, shlex.quote(scenario))
    )
    result = vm.guest("phase7-probe-" + scenario, command, timeout=60)
    value = json_object(result.stdout, scenario)
    if (value.get("status") != "pass" or value.get("scenario") != scenario or
            int(value.get("generation", 0)) <= 0):
        raise ValueError("Phase 7 probe failed contract: " + scenario)
    remote_expected = scenario not in {"partial", "non-opt-in", "unrelated-write"}
    if (int(value.get("remote_entries", 0)) > 0) != remote_expected:
        raise ValueError("Phase 7 remote publication mismatch: " + scenario)
    return value


def scenario_delta(snapshots, scenario, name):
    before, after = snapshots[scenario]
    return delta(before, after, name)


def validate_gate(baseline, snapshots, probes, phase3_before, phase3_after,
                  phase4_before, phase4_after, phase4_state,
                  phase5_state, phase6_state, aligned_connections):
    checks = {}

    checks["only_opt_in_accepts_cmsg"] = (
        probes["non-opt-in"]["expected_failures"] == 1 and
        probes["unrelated-write"]["expected_failures"] == 1 and
        scenario_delta(snapshots, "non-opt-in", "raw_cmsg_new_final") == 0)
    checks["normal_new_final"] = (
        scenario_delta(snapshots, "normal-final", "raw_cmsg_new_final") == 1 and
        scenario_delta(snapshots, "normal-final", "raw_tx_full") == 1 and
        scenario_delta(snapshots, "normal-final", "raw_tag_completed") == 1)
    checks["retry_same_cookie"] = (
        scenario_delta(snapshots, "retry-final", "raw_retry_same_cookie") == 2)
    checks["retry_new_ordinal"] = (
        scenario_delta(snapshots, "retry-final", "raw_retry_new_ordinal") == 2 and
        scenario_delta(snapshots, "retry-final", "raw_tx_full") == 3)
    checks["retry_final_lifecycle"] = (
        scenario_delta(snapshots, "retry-final", "raw_cmsg_retry") == 1 and
        scenario_delta(snapshots, "retry-final", "raw_cmsg_retry_final") == 1 and
        scenario_delta(snapshots, "retry-final", "raw_tag_completed") == 1)
    checks["user_tag_collision"] = (
        probes["collision"]["expected_failures"] == 1 and
        scenario_delta(snapshots, "collision", "raw_tag_collision") == 1 and
        scenario_delta(snapshots, "collision", "raw_cmsg_rejected") >= 1)
    checks["cross_socket_retry_rejected"] = (
        probes["cross-socket"]["expected_failures"] == 1 and
        scenario_delta(snapshots, "cross-socket",
                       "raw_cross_socket_retry_rejected") == 1)
    checks["cancel_lifecycle"] = (
        scenario_delta(snapshots, "cancel", "raw_cmsg_cancel") == 1 and
        scenario_delta(snapshots, "cancel", "raw_tag_canceled") == 1 and
        probes["cancel"]["expected_failures"] == 1)
    checks["new_precommit_full_rollback"] = (
        scenario_delta(snapshots, "rollback-new",
                       "raw_tx_precommit_rollback") == 1 and
        probes["rollback-new"]["sends"] == 1 and
        probes["rollback-new"]["replies"] == 1)
    checks["new_final_precommit_full_rollback"] = (
        scenario_delta(snapshots, "rollback-new-final",
                       "raw_tx_precommit_rollback") == 1 and
        probes["rollback-new-final"]["sends"] == 1 and
        scenario_delta(snapshots, "rollback-new-final",
                       "raw_tag_completed") == 1)
    checks["retry_final_failure_keeps_root_open"] = (
        scenario_delta(snapshots, "rollback-retry-final",
                       "raw_tx_precommit_rollback") == 1 and
        scenario_delta(snapshots, "rollback-retry-final",
                       "raw_cmsg_retry_final") == 2 and
        probes["rollback-retry-final"]["sends"] == 2 and
        probes["rollback-retry-final"]["replies"] == 2)
    checks["partial_send_commits_and_corrupts"] = (
        probes["partial"]["short_sends"] == 1 and
        scenario_delta(snapshots, "partial",
                       "raw_tx_postcommit_partial") == 1 and
        scenario_delta(snapshots, "partial",
                       "raw_connection_corrupted") == 1)
    checks["socket_close_auto_seals"] = (
        scenario_delta(snapshots, "socket-autoseal",
                       "raw_tag_auto_sealed") == 1)
    checks["closing_auto_seals_without_timeout"] = (
        scenario_delta(snapshots, "closing-autoseal",
                       "raw_tag_auto_sealed") == 1 and
        probes["closing-autoseal"]["remote_entries"] > 0)
    checks["preconnect_pairing_created"] = (
        delta(baseline, snapshots["unrelated-write"][1],
              "raw_preconnect_created") >= 13 and
        snapshots["unrelated-write"][1]["raw_preconnect_failed"] == 0)
    checks["raw_sockets_released"] = (
        delta(baseline, snapshots["unrelated-write"][1],
              "raw_socket_released") >= 13)

    checks["wire_records_committed"] = (
        phase3_after["wire_attempt_committed"] >
        phase3_before["wire_attempt_committed"])
    checks["record_marker_commit_observed"] = (
        phase3_after["record_marker_first_byte_commit"] >
        phase3_before["record_marker_first_byte_commit"])
    checks["raw_c2s_ordinals_aligned_except_forced_partial"] = (
        (phase3_after["ordinal_tx_c2s"] - phase3_before["ordinal_tx_c2s"]) -
        (phase3_after["ordinal_rx_c2s"] - phase3_before["ordinal_rx_c2s"]) == 1)
    checks["raw_s2c_reply_ordinals_aligned"] = (
        phase3_after["ordinal_tx_s2c"] - phase3_before["ordinal_tx_s2c"] ==
        phase3_after["ordinal_rx_s2c"] - phase3_before["ordinal_rx_s2c"])
    checks["raw_reply_record_parser_complete"] = (
        delta(baseline, snapshots["unrelated-write"][1], "raw_rx_record") == 15 and
        snapshots["unrelated-write"][1]["raw_rx_parse_error"] == 0)
    checks["precommit_wire_rollback_observed"] = (
        phase3_after["wire_attempt_rolled_back"] -
        phase3_before["wire_attempt_rolled_back"] >= 3)
    checks["postcommit_not_rolled_back"] = (
        phase3_after["wire_attempt_postcommit_incomplete"] -
        phase3_before["wire_attempt_postcommit_incomplete"] == 1 and
        phase3_after["corrupted_connection_closed"] -
        phase3_before["corrupted_connection_closed"] == 1)
    checks["same_lane_pairing_no_epoch_collision"] = (
        phase3_after["lane_epoch_collision"] == 0 and
        phase3_after["lane_epoch_immutable_violation"] == 0 and
        phase3_after["direction_role_mismatch"] == 0)
    checks["live_mount_connections_aligned"] = (
        aligned_connections and
        all(item["ordinal_mismatch"] == 0 for item in aligned_connections))

    checks["root_token_accounting_drained"] = (
        phase4_after["outstanding_tokens"] == 0 and
        phase4_after["object_refs"] == 0 and
        phase4_after["token_double_complete"] ==
        phase4_before["token_double_complete"])
    checks["no_live_generation_state"] = not phase4_state.strip()
    checks["no_live_remote_tickets"] = (
        not phase5_state["generations"] and
        all(value == 0 for value in phase5_state["live"].values()))
    checks["scratch_aggregate_resources_drained"] = (
        not phase6_state["generations"] and
        all(value == 0 for value in phase6_state["live"].values()))
    checks["all_scenarios_published_as_expected"] = all(
        int(value["generation"]) > 0 for value in probes.values())

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 7 checks failed: " + ", ".join(failed))
    return checks


def collect_failure_diagnostics(vm):
    commands = {
        "phase7_stats": "cat " + PHASE7_STATS,
        "phase3_stats": "cat " + PHASE3_STATS,
        "phase4_stats": "cat " + PHASE4_STATS,
        "phase4_state": "cat " + PHASE4_STATE,
        "phase5_state": "cat " + PHASE5_STATE,
        "phase6_state": "cat " + PHASE6_STATE,
        "connections": "cat /sys/kernel/debug/sunrpc_fuzz/phase3_connections",
        "tasks": "ps -eo pid,ppid,etimes,state,wchan:32,args | grep -E 'phase7-probe|nsenter|timeout' | grep -v grep || true",
    }
    result = {}
    for name, command in commands.items():
        completed = vm.guest("failure-" + name, command, timeout=20, check=False)
        result[name] = {"returncode": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr}
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
                        default=scripts / "frozen_phase7_probe.c")
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
        "schema": SCHEMA_VERSION, "phase": 7, "status": "running",
        "started_at": timestamp(), "commands": [], "snapshots": {},
        "runtime_probes": {}, "gate": {"name": "Gate 7", "status": "running"},
        "observability_contract": {"stats": PHASE7_STATS,
                                   "required_counters": sorted(REQUIRED_COUNTERS)},
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
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest("guest-inventory",
                 "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug; command -v gcc ip nsenter timeout tar",
                 timeout=30)
        for path in (PHASE3_STATS, PHASE3_CONTROL, PHASE4_STATS, PHASE4_STATE,
                     PHASE5_STATE, PHASE6_STATE, PHASE7_STATS):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase7-deps.tar.gz")
        vm.put("copy-lane", args.lane_script,
               "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-bootstrap", args.bootstrap,
               "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup", args.cleanup_hook,
               "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-probe", args.probe, "/tmp/frozen-phase7-probe.c")
        vm.guest(
            "install-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase7-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase1-lane.sh %s/lane.sh; "
            "install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; "
            "install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; "
            "gcc -O2 -Wall -Wextra -Werror -o %s/phase7-probe /tmp/frozen-phase7-probe.c"
            % ((REMOTE_DRIVER,) * 5), timeout=90)
        allocated = vm.guest("allocate-lane-root",
                             "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10)
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")
        for control in (PHASE3_CONTROL,
                        "/sys/kernel/debug/sunrpc_fuzz/phase4_control",
                        "/sys/kernel/debug/sunrpc_fuzz/phase5_control",
                        "/sys/kernel/debug/sunrpc_fuzz/phase6_control"):
            vm.guest("reset-" + Path(control).stem,
                     "printf 'reset\n' > " + control, timeout=20)

        baseline = snapshot(vm, "phase7-baseline")
        phase4_before = phase4.parse_stats(
            vm.guest("phase4-baseline", "cat " + PHASE4_STATS,
                     timeout=20).stdout)
        active_epoch, lane_status = phase3.setup_lane(vm)
        lane_epoch = active_epoch
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        phase3_before = phase3.parse_counter_file(
            vm.guest("phase3-before-raw", "cat " + PHASE3_STATS,
                     timeout=20).stdout)

        scenarios = (
            "normal-final", "retry-final", "collision", "cross-socket",
            "cancel", "rollback-new", "rollback-new-final",
            "rollback-retry-final", "partial", "socket-autoseal",
            "closing-autoseal", "non-opt-in", "unrelated-write",
        )
        snapshots = {}
        probes = {}
        for scenario in scenarios:
            before = snapshot(vm, "before-" + scenario)
            probes[scenario] = run_probe(vm, scenario)
            after = snapshot(vm, "after-" + scenario)
            snapshots[scenario] = (before, after)
            evidence["runtime_probes"][scenario] = probes[scenario]
            evidence["snapshots"][scenario] = {"before": before, "after": after}
            write_evidence(args.output, evidence)

        phase3_after, connections = phase3.wait_for_ordinal_alignment(
            vm, active_epoch,
            phase3.parse_counter_file(vm.guest(
                "phase3-before-cleanup", "cat " + PHASE3_STATS,
                timeout=20).stdout), require_global=False)
        aligned_connections = phase3.paired_connections(connections, active_epoch)
        phase4_after = phase4.parse_stats(vm.guest(
            "phase4-final", "cat " + PHASE4_STATS, timeout=20).stdout)
        phase4_state = vm.guest("phase4-state-final", "cat " + PHASE4_STATE,
                                timeout=20).stdout
        phase5_state = phase5.parse_state(vm.guest(
            "phase5-state-final", "cat " + PHASE5_STATE, timeout=20).stdout)
        phase6_state = phase6.parse_state(vm.guest(
            "phase6-state-final", "cat " + PHASE6_STATE, timeout=20).stdout)
        checks = validate_gate(
            baseline, snapshots, probes, phase3_before, phase3_after,
            phase4_before, phase4_after, phase4_state, phase5_state,
            phase6_state, aligned_connections)
        phase3.cleanup_lane(phase1, vm, active_epoch, strict=True)
        active_epoch = None
        evidence["epoch"] = lane_epoch
        evidence["lane_status"] = lane_status
        evidence["phase3"] = {"stats": phase3_after,
                              "connections": connections}
        evidence["phase4"] = {"stats": phase4_after,
                              "state": phase4_state.splitlines()}
        evidence["phase5_state"] = phase5_state
        evidence["phase6_state"] = phase6_state
        evidence["gate"] = {"name": "Gate 7", "status": "pass",
                            "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__,
                               "message": str(error)}
        evidence["gate"] = {"name": "Gate 7", "status": "fail"}
        evidence["completed_at"] = timestamp()
        if vm is not None and vm.ready:
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
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    exit_code = 1
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30,
                                 check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr, encoding="utf-8",
                    errors="replace")
                if dmesg.returncode or FATAL_KERNEL_RE.search(dmesg.stdout):
                    raise ValueError("fatal kernel diagnostic in Phase 7 VM")
            except Exception as error:
                evidence.setdefault("collection_errors", []).append(str(error))
                if exit_code == 0:
                    evidence["status"] = "fail"
                    evidence["gate"]["status"] = "fail"
                    evidence["failure"] = {"type": type(error).__name__,
                                           "message": str(error)}
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
                evidence["failure"] = {"type": "GateFailure",
                                       "message": "base image changed"}
                exit_code = 1
        write_evidence(args.output, evidence)
    print(json.dumps({"status": evidence["status"],
                      "evidence": str(args.output / "phase7-evidence.json")},
                     sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
