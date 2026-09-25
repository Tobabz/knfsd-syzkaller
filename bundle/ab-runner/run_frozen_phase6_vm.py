#!/usr/bin/env python3
"""Run Frozen Baseline Gate 6 with real NFS/KCOV traffic in a disposable VM."""

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
REMOTE_DRIVER = "/opt/frozen-phase6"
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

REQUIRED_COUNTERS = {
    "remote_section_created", "remote_section_completed",
    "remote_section_discarded", "scratch_reserved", "scratch_active",
    "scratch_completed", "scratch_returned", "scratch_in_use",
    "scratch_peak", "scratch_overflow", "scratch_address_collision",
    "scratch_trace_entries", "aggregate_allocated",
    "aggregate_merge_started", "aggregate_merge_completed",
    "aggregate_merge_truncated", "aggregate_merge_overlap",
    "aggregate_entries_merged", "aggregate_direct_trace_write",
    "late_merge_after_refs_zero", "aggregate_committed",
    "aggregate_quarantined", "aggregate_discarded",
    "aggregate_publishing", "aggregate_published",
    "aggregate_publish_suppressed", "aggregate_entries_published",
    "aggregate_reuse_blocked_reader", "aggregate_reuse_while_reader",
    "publisher_read_lease_get", "publisher_read_lease_put",
    "publish_readers", "publish_copy_outside_lock",
    "publish_copy_under_gen_lock", "remote_ref_put_before_scratch_return",
    "result_degrade_after_ref_release", "commit_with_tokens",
    "commit_with_refs", "commit_nonvalid", "commit_bad_state",
    "incomplete_published", "invalid_published", "aborted_published",
    "fault_hold_after_grant_entered", "fault_hold_after_grant_released",
    "fault_scratch_limit", "fault_aggregate_limit",
    "fault_pause_publish_entered", "fault_pause_publish_released",
    "destination_seed_overwritten", "late_generic_remote_append",
    "publish_abort_blocked", "publish_begin_blocked",
    "publish_exit_reset_deferred", "publish_exit_reset_completed",
    "remote_refs", "selftest_runs", "selftest_failures",
    "selftest_exclusive_scratch", "selftest_overflow",
    "selftest_truncation", "selftest_serialized_merge",
    "selftest_result_before_release", "selftest_commit_eligibility",
    "selftest_publish_lease", "selftest_abort_discard",
    "selftest_managed_generation_isolation",
}

ZERO_VIOLATIONS = {
    "scratch_address_collision", "aggregate_merge_overlap",
    "aggregate_direct_trace_write", "late_merge_after_refs_zero",
    "aggregate_reuse_while_reader", "publish_copy_under_gen_lock",
    "remote_ref_put_before_scratch_return",
    "result_degrade_after_ref_release", "commit_with_tokens",
    "commit_with_refs", "commit_nonvalid", "commit_bad_state",
    "incomplete_published", "invalid_published", "aborted_published",
    "late_generic_remote_append",
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
    temporary = output / ".phase6-evidence.json.tmp"
    final = output / "phase6-evidence.json"
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
            raise ValueError("invalid Phase 6 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 6 counter: " + fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer Phase 6 counter: " + fields[0]) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 6 counter: " + fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing required Phase 6 counters: " + ", ".join(missing))
    return values


def parse_state(text):
    live = None
    generations = []
    pool = None
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split()
        if not fields:
            continue
        if (len(fields) == 8 and fields[0] == "live_scratch" and
                fields[2] == "live_sections" and fields[4] == "remote_refs" and
                fields[6] == "publish_readers"):
            if live is not None:
                raise ValueError("duplicate Phase 6 live-resource line")
            try:
                live = {fields[i]: int(fields[i + 1], 0) for i in range(0, 8, 2)}
            except ValueError as error:
                raise ValueError("invalid Phase 6 live-resource value") from error
            continue
        if (len(fields) == 16 and fields[0] == "owner" and
                fields[2] == "generation" and fields[4] == "gen_state" and
                fields[6] == "remote_result" and
                fields[8] == "aggregate_state" and fields[10] == "entries" and
                fields[12] == "remote_refs" and
                fields[14] == "publish_readers"):
            try:
                generations.append({
                    "owner": int(fields[1], 0),
                    "generation": int(fields[3], 0),
                    "gen_state": fields[5], "remote_result": fields[7],
                    "aggregate_state": fields[9],
                    "entries": int(fields[11], 0),
                    "remote_refs": int(fields[13], 0),
                    "publish_readers": int(fields[15], 0),
                })
            except ValueError as error:
                raise ValueError("invalid Phase 6 generation state") from error
            continue
        if fields[0] == "pool" and len(fields) >= 3 and len(fields) % 2 == 1:
            if pool is not None:
                raise ValueError("duplicate Phase 6 pool line")
            try:
                pool = {fields[i]: int(fields[i + 1], 0)
                        for i in range(1, len(fields), 2)}
            except ValueError as error:
                raise ValueError("invalid Phase 6 pool state") from error
            continue
        raise ValueError("invalid Phase 6 state line %d: %r" % (number, raw))
    if live is None or pool is None:
        raise ValueError("missing Phase 6 live/pool state")
    if any(value < 0 for value in live.values()) or any(
            value < 0 for value in pool.values()):
        raise ValueError("negative Phase 6 state value")
    return {"live": live, "generations": generations, "pool": pool}


def snapshot(vm, stage):
    return parse_stats(vm.guest(stage, "cat " + PHASE6_STATS, timeout=20).stdout)


def state_snapshot(vm, stage):
    return parse_state(vm.guest(stage, "cat " + PHASE6_STATE, timeout=20).stdout)


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


def client_command(vm, scenario, count):
    return (
        "set -eu; pid=$(cat %s/client0.pid); exec timeout 180s "
        "nsenter -t \"$pid\" -m -n -- %s/phase6-probe %s %s/client0/mnt %d"
        % (shlex.quote(vm.lane_root), REMOTE_DRIVER, shlex.quote(scenario),
           shlex.quote(vm.lane_root), count)
    )


def run_probe(vm, scenario, count):
    result = vm.guest("phase6-probe-" + scenario,
                      client_command(vm, scenario, count), timeout=210)
    value = json_object(result.stdout, scenario)
    workload_ok = (int(value.get("local_entries", 0)) > 0 or
                   (scenario == "owner-exit-publish" and
                    int(value.get("workload_operations", 0)) > 0))
    if (value.get("status") != "pass" or value.get("scenario") != scenario or
            int(value.get("generation", 0)) <= 0 or not workload_ok):
        raise ValueError("Phase 6 probe failed contract: " + scenario)
    expected = scenario in {"normal", "concurrent", "cmp-normal", "publish-lease"}
    if (int(value.get("remote_entries", 0)) > 0) != expected:
        raise ValueError("Phase 6 KCOV mmap publication mismatch: " + scenario)
    if expected and int(value.get("remote_hash", 0)) == 0:
        raise ValueError("Phase 6 published KCOV hash is zero: " + scenario)
    expected_mode = "CMP" if scenario.startswith("cmp-") else "PC"
    if value.get("trace_mode") != expected_mode:
        raise ValueError("Phase 6 KCOV trace mode mismatch: " + scenario)
    entries = int(value.get("remote_entries", 0))
    words = int(value.get("remote_words", -1))
    if words != entries * (4 if expected_mode == "CMP" else 1):
        raise ValueError("Phase 6 KCOV count/word representation mismatch: " + scenario)
    return value


def drained(state):
    return not state["generations"] and all(value == 0 for value in state["live"].values())


def validate_gate(pre_selftest, baseline, snapshots, probes, states, final, phase3_stats,
                  phase4_stats, phase4_state,
                  phase5_stats, phase5_state):
    checks = {}
    checks["selftest_once"] = delta(pre_selftest, baseline, "selftest_runs") == 1
    checks["selftest_clean"] = baseline["selftest_failures"] == 0
    for name in sorted(name for name in REQUIRED_COUNTERS
                       if name.startswith("selftest_") and
                       name not in {"selftest_runs", "selftest_failures"}):
        checks[name] = delta(pre_selftest, baseline, name) == 1
    # Runtime valid publication, including direct observation of owner KCOV mmap.
    before, after = snapshots["normal"]
    checks["normal_remote_extra_observed"] = (
        probes["normal"]["remote_entries"] > 8 and
        probes["normal"]["remote_hash"] > 0 and
        probes["normal"]["pre_finish_seed_entries"] == 1 and
        probes["normal"]["seed_overwritten"] is True and
        delta(before, after, "destination_seed_overwritten") == 1 and
        delta(before, after, "scratch_trace_entries") > 0 and
        delta(before, after, "aggregate_entries_merged") > 0 and
        delta(before, after, "aggregate_entries_published") > 0)
    checks["normal_scratch_merge_publish"] = (
        delta(before, after, "scratch_reserved") > 0 and
        delta(before, after, "scratch_reserved") ==
        delta(before, after, "scratch_returned") and
        delta(before, after, "aggregate_merge_started") ==
        delta(before, after, "aggregate_merge_completed") and
        delta(before, after, "aggregate_committed") == 1 and
        delta(before, after, "aggregate_publishing") == 1 and
        delta(before, after, "aggregate_published") == 1)

    before, after = snapshots["cmp_normal"]
    checks["cmp_remote_extra_observed"] = (
        probes["cmp-normal"]["trace_mode"] == "CMP" and
        probes["cmp-normal"]["remote_entries"] > 0 and
        probes["cmp-normal"]["remote_words"] ==
        probes["cmp-normal"]["remote_entries"] * 4 and
        probes["cmp-normal"]["remote_hash"] > 0 and
        delta(before, after, "scratch_trace_entries") > 0 and
        delta(before, after, "aggregate_entries_merged") > 0 and
        delta(before, after, "aggregate_entries_published") > 0)
    checks["cmp_scratch_merge_publish"] = (
        delta(before, after, "scratch_reserved") > 0 and
        delta(before, after, "scratch_reserved") ==
        delta(before, after, "scratch_returned") and
        delta(before, after, "aggregate_committed") == 1 and
        delta(before, after, "aggregate_published") == 1)

    before, after = snapshots["concurrent"]
    checks["simultaneous_sections_held"] = (
        probes["concurrent"]["held_remote_refs"] >= 2 and
        probes["concurrent"]["held_scratch"] >= 2 and
        delta(before, after, "fault_hold_after_grant_entered") >= 2 and
        delta(before, after, "fault_hold_after_grant_released") >= 2)
    checks["exclusive_distinct_scratch"] = (
        after["scratch_peak"] >= probes["concurrent"]["held_scratch"] >= 2 and
        after["scratch_address_collision"] == 0 and
        delta(before, after, "aggregate_merge_completed") >= 2 and
        probes["concurrent"]["remote_entries"] > 0)

    for scenario, loss_counter in (
            ("scratch_overflow", "scratch_overflow"),
            ("cmp_overflow", "scratch_overflow"),
            ("merge_truncate", "aggregate_merge_truncated"),
            ("cmp_truncate", "aggregate_merge_truncated")):
        before, after = snapshots[scenario]
        fault_counter = ("fault_scratch_limit" if "overflow" in scenario
                         else "fault_aggregate_limit")
        checks[scenario + "_injected"] = (
            delta(before, after, fault_counter) >= 1 and
            delta(before, after, loss_counter) >= 1 and
            probes[scenario.replace("_", "-")]["remote_entries"] == 0)
        checks[scenario + "_discarded_not_published"] = (
            delta(before, after, "aggregate_quarantined") == 1 and
            delta(before, after, "aggregate_discarded") == 1 and
            delta(before, after, "aggregate_published") == 0 and
            delta(before, after, "aggregate_publish_suppressed") >= 1 and
            after["result_degrade_after_ref_release"] == 0)

    before, after = snapshots["abort"]
    checks["abort_quarantine_discard"] = (
        probes["abort"]["remote_entries"] == 0 and
        delta(before, after, "aggregate_quarantined") == 1 and
        delta(before, after, "aggregate_discarded") == 1 and
        delta(before, after, "aggregate_published") == 0 and
        delta(before, after, "aggregate_publish_suppressed") >= 1)

    before, after = snapshots["publish_lease"]
    checks["publishing_read_lease_runtime"] = (
        probes["publish-lease"]["pre_publish_entries"] == 0 and
        probes["publish-lease"]["remote_entries"] > 8 and
        probes["publish-lease"]["held_publish_readers"] >= 1 and
        probes["publish-lease"]["publish_abort_busy"] is True and
        probes["publish-lease"]["publish_begin_busy"] is True and
        delta(before, after, "fault_pause_publish_entered") == 1 and
        delta(before, after, "fault_pause_publish_released") == 1 and
        delta(before, after, "publish_abort_blocked") == 1 and
        delta(before, after, "publish_begin_blocked") == 1 and
        delta(before, after, "aggregate_reuse_blocked_reader") >= 1)
    checks["publisher_lease_balanced_and_safe"] = (
        delta(before, after, "publisher_read_lease_get") == 1 and
        delta(before, after, "publisher_read_lease_put") == 1 and
        after["aggregate_reuse_while_reader"] == 0 and
        delta(before, after, "publish_copy_outside_lock") == 1 and
        after["publish_copy_under_gen_lock"] == 0)

    before, after = snapshots["owner_exit_publish"]
    checks["owner_exit_during_publishing_runtime"] = (
        probes["owner-exit-publish"]["workload_operations"] > 0 and
        probes["owner-exit-publish"]["remote_entries"] == 0 and
        delta(before, after, "fault_pause_publish_entered") == 1 and
        delta(before, after, "fault_pause_publish_released") == 1 and
        delta(before, after, "publish_exit_reset_deferred") == 1 and
        delta(before, after, "publish_exit_reset_completed") == 1)
    checks["owner_exit_stale_publish_suppressed"] = (
        delta(before, after, "aggregate_publishing") == 1 and
        delta(before, after, "aggregate_published") == 0 and
        delta(before, after, "aggregate_publish_suppressed") >= 1 and
        delta(before, after, "publisher_read_lease_get") == 1 and
        delta(before, after, "publisher_read_lease_put") == 1)

    before, after = snapshots["nested_invalid"]
    checks["nested_invalid_discard"] = (
        probes["nested-invalid"]["remote_entries"] == 0 and
        delta(before, after, "aggregate_quarantined") >= 1 and
        delta(before, after, "aggregate_discarded") >= 1 and
        delta(before, after, "aggregate_published") == 0 and
        delta(before, after, "aggregate_publish_suppressed") >= 1 and
        phase5_stats["nested_same_generation"] >= 1 and
        phase5_stats["remote_result_invalid"] >= 1 and
        phase5_stats["lane_unhealthy"] >= 1)

    checks["every_scenario_drained"] = all(drained(value) for value in states.values())
    checks["sections_terminal"] = (
        final["remote_section_created"] ==
        final["remote_section_completed"] + final["remote_section_discarded"])
    checks["all_scratch_returned"] = (
        final["scratch_reserved"] == final["scratch_returned"] and
        final["scratch_in_use"] == 0)
    checks["all_read_leases_returned"] = (
        final["publisher_read_lease_get"] == final["publisher_read_lease_put"] and
        final["publish_readers"] == 0)
    checks["no_gate6_invariant_violation"] = all(final[name] == 0 for name in ZERO_VIOLATIONS)
    checks["serialized_merge"] = final["aggregate_merge_overlap"] == 0
    checks["no_direct_aggregate_tracing"] = final["aggregate_direct_trace_write"] == 0
    checks["no_late_merge_after_refs_zero"] = final["late_merge_after_refs_zero"] == 0
    checks["commit_exact_conditions"] = all(final[name] == 0 for name in (
        "commit_with_tokens", "commit_with_refs", "commit_nonvalid", "commit_bad_state"))
    checks["no_bad_remote_feedback_published"] = all(final[name] == 0 for name in (
        "incomplete_published", "invalid_published", "aborted_published"))
    checks["phase3_ordinals_clean"] = (
        phase3_stats["ordinal_mismatch"] == 0 and
        phase3_stats["direction_role_mismatch"] == 0 and
        phase3_stats["tcp_retransmit_ordinal_increment"] == 0)
    checks["phase4_resources_clean"] = (
        phase4_stats["outstanding_tokens"] == 0 and
        phase4_stats["object_refs"] == 0 and
        phase4_stats["token_double_complete"] == 0 and not phase4_state.strip())
    checks["phase5_resources_clean"] = (
        phase5_stats["remote_refs"] == 0 and
        phase5_stats["remote_stop_double"] == 0 and
        phase5_stats["grant_order_violation"] == 0 and
        phase5_stats["start_transaction_violation"] == 0 and
        phase5_state["live"] == {"live_tickets": 0,
                                 "live_svc_attachments": 0,
                                 "remote_refs": 0} and
        not phase5_state["generations"])
    checks["phase6_resources_clean"] = drained(states["final"])

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 6 checks failed: " + ", ".join(failed))
    return checks


def collect_failure_diagnostics(vm):
    diagnostics = {}
    for name, command in {
        "phase6_stats": "cat " + PHASE6_STATS,
        "phase6_state": "cat " + PHASE6_STATE,
        "phase5_stats": "cat " + PHASE5_STATS,
        "phase5_state": "cat " + PHASE5_STATE,
        "phase4_stats": "cat " + PHASE4_STATS,
        "phase4_state": "cat " + PHASE4_STATE,
        "phase3_stats": "cat " + PHASE3_STATS,
        "tasks": "ps -eo pid,ppid,etimes,state,wchan:32,args | grep -E 'phase6-probe|nsenter|timeout' | grep -v grep || true",
    }.items():
        result = vm.guest("failure-" + name, command, timeout=20, check=False)
        diagnostics[name] = {"returncode": result.returncode,
                             "stdout": result.stdout.splitlines(),
                             "stderr": result.stderr.splitlines()}
    return diagnostics


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    scripts = Path(__file__).resolve().parent
    parser.add_argument("--phase1-runner", type=Path, default=scripts / "run_frozen_phase1_vm.py")
    parser.add_argument("--phase3-runner", type=Path, default=scripts / "run_frozen_phase3_vm.py")
    parser.add_argument("--phase4-runner", type=Path, default=scripts / "run_frozen_phase4_vm.py")
    parser.add_argument("--phase5-runner", type=Path, default=scripts / "run_frozen_phase5_vm.py")
    parser.add_argument("--lane-script", type=Path, default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path, default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--bootstrap", type=Path, default=scripts / "frozen_phase3_bootstrap.sh")
    parser.add_argument("--cleanup-hook", type=Path, default=scripts / "frozen_phase3_cleanup.sh")
    parser.add_argument("--probe", type=Path, default=scripts / "frozen_phase6_probe.c")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "phase3_runner", "phase4_runner", "phase5_runner", "lane_script",
                 "workload", "bootstrap", "cleanup_hook", "probe"):
        path = getattr(args, name).resolve()
        setattr(args, name, path)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" % (name.replace("_", "-"), path))
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
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    phase3.REMOTE_DRIVER = REMOTE_DRIVER
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION, "phase": 6, "status": "running",
        "started_at": timestamp(), "commands": [], "snapshots": {},
        "runtime_probes": {}, "states": {},
        "gate": {"name": "Gate 6", "status": "running"},
        "observability_contract": {"stats": PHASE6_STATS,
                                   "control": PHASE6_CONTROL,
                                   "state": PHASE6_STATE,
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
                     "phase5_runner", "bootstrap", "cleanup_hook", "probe"):
            path = getattr(args, name)
            evidence["inputs"][name] = {"path": str(path),
                                         "bytes": path.stat().st_size,
                                         "sha256": phase1.sha256(path)}
        source = args.probe.read_text(encoding="utf-8")
        evidence["source_contract"].update({
            "exclusive_scratch_hold": "hold-after-grant" in source,
            "actual_owner_mmap_check": "owner_session.area[0]" in source,
            "overflow_and_truncation": "scratch-limit" in source and "aggregate-limit" in source,
            "pc_and_cmp_remote_modes": "KCOV_TRACE_PC" in source and "KCOV_TRACE_CMP" in source and "KCOV_CMP_WORDS" in source,
            "publish_read_lease_probe": "probe-reuse" in source and "pre_publish_entries" in source,
            "publishing_abort_begin_busy": "generation_abort_expect_busy" in source and "generation_begin_expect_busy" in source,
            "managed_destination_overwrite": "DESTINATION_SEED" in source and "seed_overwritten" in source,
            "abort_after_grant": "generation_abort(owner_session.fd, generation)" in source,
            "nested_invalid": "nested-same" in source,
            "owner_exit_publish_race": "owner_exit_thread" in source and "owner_exit_finisher" in source,
        })
        if not all(evidence["source_contract"].values()):
            raise ValueError("Phase 6 source contract incomplete")
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest("guest-inventory", "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug; command -v gcc ip nsenter timeout tar", timeout=30)
        for path in (PHASE3_STATS, PHASE3_CONTROL, PHASE4_STATS, PHASE4_CONTROL,
                     PHASE4_STATE, PHASE5_STATS, PHASE5_CONTROL, PHASE5_STATE,
                     PHASE6_STATS, PHASE6_CONTROL, PHASE6_STATE):
            vm.guest("interface-" + Path(path).name, "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar, "/tmp/frozen-phase6-deps.tar.gz")
        vm.put("copy-lane", args.lane_script, "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-bootstrap", args.bootstrap, "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup", args.cleanup_hook, "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-probe", args.probe, "/tmp/frozen-phase6-probe.c")
        vm.guest("install-inputs",
                 "set -eu; install -d /opt/kcov-nfs/deps %s; tar -xzf /tmp/frozen-phase6-deps.tar.gz -C /opt/kcov-nfs/deps; install -m 0755 /tmp/frozen-phase1-lane.sh %s/lane.sh; install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; gcc -O2 -Wall -Wextra -Werror -pthread -o %s/phase6-probe /tmp/frozen-phase6-probe.c" % ((REMOTE_DRIVER,) * 5), timeout=90)
        allocated = vm.guest("allocate-lane-root", "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10)
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")
        for control in (PHASE3_CONTROL, PHASE4_CONTROL, PHASE5_CONTROL, PHASE6_CONTROL):
            vm.guest("reset-" + Path(control).stem, "printf 'reset\n' > " + control, timeout=20)
        pre_selftest = snapshot(vm, "phase6-before-selftest")
        vm.guest("phase6-selftest", "printf 'selftest\n' > " + PHASE6_CONTROL, timeout=90)
        baseline = snapshot(vm, "phase6-baseline-after-selftest")
        evidence["snapshots"]["before_selftest"] = pre_selftest
        evidence["snapshots"]["baseline_after_selftest"] = baseline
        active_epoch, lane_status = phase3.setup_lane(vm)
        lane_epoch = active_epoch
        vm.guest("nfs-grace", "sleep 11", timeout=20)

        scenario_counts = {
            "normal": 3, "concurrent": 4, "scratch-overflow": 3,
            "cmp-normal": 3, "cmp-overflow": 3,
            "merge-truncate": 3, "cmp-truncate": 3,
            "abort": 3, "publish-lease": 3,
            "owner-exit-publish": 3,
            "nested-invalid": 2,
        }
        snapshots = {}
        states = {}
        probes = {}
        for scenario, count in scenario_counts.items():
            key = scenario.replace("-", "_")
            before = snapshot(vm, "before-" + scenario)
            probes[scenario] = run_probe(vm, scenario, count)
            after = snapshot(vm, "after-" + scenario)
            state = state_snapshot(vm, "state-after-" + scenario)
            snapshots[key] = (before, after)
            states[key] = state
            evidence["runtime_probes"][scenario] = probes[scenario]
            evidence["snapshots"][key] = {"before": before, "after": after}
            evidence["states"][key] = state
            write_evidence(args.output, evidence)

        final_phase3, connections = phase3.wait_for_ordinal_alignment(
            vm, active_epoch,
            phase3.parse_counter_file(vm.guest("phase3-before-cleanup", "cat " + PHASE3_STATS, timeout=20).stdout),
            require_global=False)
        phase3.cleanup_lane(phase1, vm, active_epoch, strict=True)
        active_epoch = None
        final = snapshot(vm, "phase6-final")
        states["final"] = state_snapshot(vm, "phase6-state-final")
        phase4_stats = phase4.parse_stats(vm.guest("phase4-final", "cat " + PHASE4_STATS, timeout=20).stdout)
        phase4_state = vm.guest("phase4-state-final", "cat " + PHASE4_STATE, timeout=20).stdout
        phase5_stats = phase5.parse_stats(vm.guest("phase5-final", "cat " + PHASE5_STATS, timeout=20).stdout)
        phase5_state = phase5.parse_state(vm.guest("phase5-state-final", "cat " + PHASE5_STATE, timeout=20).stdout)
        checks = validate_gate(pre_selftest, baseline, snapshots, probes, states, final,
                               final_phase3, phase4_stats, phase4_state,
                               phase5_stats, phase5_state)
        evidence["snapshots"]["final"] = final
        evidence["states"]["final"] = states["final"]
        evidence["epoch"] = lane_epoch
        evidence["lane_status"] = lane_status
        evidence["phase3"] = {"stats": final_phase3, "connections": connections}
        evidence["phase4"] = {"stats": phase4_stats, "state": phase4_state.splitlines()}
        evidence["phase5"] = {"stats": phase5_stats, "state": phase5_state}
        evidence["gate"] = {"name": "Gate 6", "status": "pass", "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        evidence["gate"] = {"name": "Gate 6", "status": "fail"}
        evidence["completed_at"] = timestamp()
        if vm is not None and vm.ready:
            try:
                evidence["failure_diagnostics"] = collect_failure_diagnostics(vm)
            except Exception as diagnostic_error:
                evidence.setdefault("collection_errors", []).append("failure diagnostics: " + str(diagnostic_error))
        write_evidence(args.output, evidence)
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    evidence["cleanup"] = phase1.cleanup_and_validate(vm, 999, strict=False)
                    active_epoch = None
                    if exit_code == 0 and any(evidence["cleanup"].get(field) != 0 for field in ("cleanup_returncode", "validation_returncode")):
                        raise ValueError("final idempotent cleanup validation failed")
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        exit_code = 1
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
                (args.output / "dmesg.txt").write_text(dmesg.stdout + dmesg.stderr, encoding="utf-8", errors="replace")
                if exit_code == 0 and (dmesg.returncode or FATAL_KERNEL_RE.search(dmesg.stdout)):
                    raise ValueError("fatal kernel diagnostic in Phase 6 VM")
            except Exception as error:
                evidence.setdefault("collection_errors", []).append(str(error))
                if exit_code == 0:
                    evidence["status"] = "fail"
                    evidence["gate"]["status"] = "fail"
                    evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
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
                evidence["failure"] = {"type": "GateFailure", "message": "base image changed"}
                exit_code = 1
        write_evidence(args.output, evidence)
    print(json.dumps({"status": evidence["status"],
                      "evidence": str(args.output / "phase6-evidence.json")}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
