#!/usr/bin/env python3
"""Run Frozen Baseline Gate 5 with real NFS traffic in a disposable VM."""

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
REMOTE_DRIVER = "/opt/frozen-phase5"
PHASE3_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
PHASE3_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
PHASE4_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase4_stats"
PHASE4_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase4_control"
PHASE4_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase4_state"
PHASE5_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase5_stats"
PHASE5_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase5_control"
PHASE5_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase5_state"

REQUIRED_COUNTERS = {
    "remote_grant_attempt",
    "remote_grant_rejected_generation",
    "remote_grant_rejected_root",
    "remote_grant_rejected_token",
    "mapping_exact_owner_match",
    "mapping_exact_owner_mismatch",
    "remote_ticket_created",
    "remote_ticket_completed",
    "remote_ticket_canceled",
    "remote_start_granted",
    "remote_start_ok",
    "remote_start_incomplete",
    "remote_start_nested",
    "remote_stop",
    "remote_stop_double",
    "remote_scratch_reserved",
    "remote_scratch_returned",
    "remote_target_pinned",
    "remote_target_unpinned",
    "remote_ref_acquired",
    "remote_ref_released",
    "remote_refs",
    "grant_order_violation",
    "start_transaction_violation",
    "stop_without_start",
    "abort_after_grant",
    "start_after_abort_ok",
    "grant_revoked_after_abort",
    "remote_result_valid",
    "remote_result_incomplete",
    "remote_result_invalid",
    "nested_attempted_invalid",
    "nested_incumbent_invalid",
    "nested_incumbent_unknown",
    "nested_same_generation",
    "nested_cross_generation",
    "lane_unhealthy",
    "fault_start_fail",
    "fault_pause_after_grant_entered",
    "fault_pause_after_grant_released",
    "wire_work_attached",
    "wire_work_ownerless",
    "wire_work_terminal",
    "svc_rqst_fuzz_reset",
    "svc_rqst_stale_attachment",
    "svc_rqst_callback_reset",
    "svc_rqst_short_record_reset",
    "nested_incumbent_active_match",
    "nested_without_active_incumbent",
    "nested_ownerless_fallback",
    "nested_transport_close",
    "nested_client_force_disconnect",
    "nested_client_already_closing",
    "nested_client_disconnect_miss",
    "selftest_runs",
    "selftest_failures",
    "selftest_grant_order",
    "selftest_transactional_failure",
    "selftest_exclusive_scratch",
    "selftest_stop_exact_once",
    "selftest_abort_after_grant",
    "selftest_mapping_classification",
    "selftest_nested_same",
    "selftest_nested_cross",
}

SELFTEST_COUNTERS = {
    name for name in REQUIRED_COUNTERS if name.startswith("selftest_")
} - {"selftest_runs", "selftest_failures"}

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
    temporary = output / ".phase5-evidence.json.tmp"
    final = output / "phase5-evidence.json"
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
            raise ValueError("invalid Phase 5 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 5 counter: " + fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer Phase 5 counter: " + fields[0]) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 5 counter: " + fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing required Phase 5 counters: " + ", ".join(missing))
    return values


def parse_state(text):
    live = None
    lanes = []
    generations = []
    global_lane_unhealthy = None
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split()
        if not fields:
            continue
        if (len(fields) == 6 and fields[0] == "live_tickets" and
                fields[2] == "live_svc_attachments" and
                fields[4] == "remote_refs"):
            if live is not None:
                raise ValueError("duplicate Phase 5 live-resource line")
            try:
                live = {
                    "live_tickets": int(fields[1], 0),
                    "live_svc_attachments": int(fields[3], 0),
                    "remote_refs": int(fields[5], 0),
                }
            except ValueError as error:
                raise ValueError("invalid Phase 5 live-resource value") from error
            if any(value < 0 for value in live.values()):
                raise ValueError("negative Phase 5 live-resource value")
            continue
        if (len(fields) == 12 and fields[0] == "owner" and
                fields[2] == "generation" and fields[4] == "state" and
                fields[6] == "remote_result" and
                fields[8] == "remote_refs" and fields[10] == "issues"):
            try:
                generations.append({
                    "owner": int(fields[1], 0),
                    "generation": int(fields[3], 0),
                    "state": fields[5],
                    "remote_result": fields[7],
                    "remote_refs": int(fields[9], 0),
                    "issues": int(fields[11], 0),
                })
            except ValueError as error:
                raise ValueError("invalid Phase 5 generation state") from error
            continue
        if len(fields) == 2 and fields[0] == "global_lane_unhealthy":
            if global_lane_unhealthy is not None:
                raise ValueError("duplicate global lane health state")
            try:
                global_lane_unhealthy = int(fields[1], 0)
            except ValueError as error:
                raise ValueError("invalid global lane health state") from error
            if global_lane_unhealthy not in (0, 1):
                raise ValueError("out-of-range global lane health state")
            continue
        if (len(fields) == 8 and fields[0] == "lane_id" and
                fields[2] == "lane_epoch" and fields[4] == "valid" and
                fields[6] == "unhealthy"):
            try:
                lane = {
                    "lane_id": int(fields[1], 0),
                    "lane_epoch": int(fields[3], 0),
                    "valid": int(fields[5], 0),
                    "unhealthy": int(fields[7], 0),
                }
            except ValueError as error:
                raise ValueError("invalid Phase 5 lane state") from error
            if (lane["lane_id"] < 0 or lane["lane_epoch"] < 0 or
                    lane["valid"] not in (0, 1) or
                    lane["unhealthy"] not in (0, 1) or
                    (lane["valid"] and lane["lane_epoch"] == 0)):
                raise ValueError("out-of-range Phase 5 lane state")
            lanes.append(lane)
            continue
        raise ValueError(
            "invalid Phase 5 state line %d: %r" % (number, raw)
        )
    if live is None:
        raise ValueError("missing Phase 5 live-resource line")
    if global_lane_unhealthy is None:
        raise ValueError("missing Phase 5 global lane health state")
    return {
        "live": live,
        "generations": generations,
        "global_lane_unhealthy": global_lane_unhealthy,
        "lanes": lanes,
    }


def snapshot(vm, stage):
    return parse_stats(vm.guest(stage, "cat " + PHASE5_STATS, timeout=20).stdout)


def lane_state(vm, stage):
    command = (
        "pid=$(cat %s/server.pid); nsenter -t \"$pid\" -n -- cat %s"
        % (shlex.quote(vm.lane_root), PHASE5_STATE)
    )
    return parse_state(vm.guest(stage, command, timeout=20).stdout)


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


def client_command(vm, client, scenario, iterations=3):
    return (
        "set -eu; pid=$(cat %s/client%d.pid); exec timeout 180s "
        "nsenter -t \"$pid\" -m -n -- %s/phase5-probe %s "
        "%s/client%d/mnt %d"
        % (
            shlex.quote(vm.lane_root), client, REMOTE_DRIVER,
            shlex.quote(scenario), shlex.quote(vm.lane_root), client,
            iterations,
        )
    )


def run_probe(vm, client, scenario, iterations=3):
    result = vm.guest(
        "probe-" + scenario,
        client_command(vm, client, scenario, iterations),
        timeout=210,
    )
    value = json_object(result.stdout, scenario)
    if (value.get("status") != "pass" or value.get("scenario") != scenario or
            int(value.get("generation", 0)) <= 0 or
            int(value.get("kcov_entries", 0)) <= 0):
        raise ValueError("Phase 5 probe failed contract: " + scenario)
    return value


def participant_command(vm, client, role, sync_dir):
    return (
        "set -eu; pid=$(cat %s/client%d.pid); exec timeout 60s "
        "nsenter -t \"$pid\" -m -n -- %s/phase5-probe "
        "cross-participant %s %s/client%d/mnt %s 2"
        % (
            shlex.quote(vm.lane_root), client, REMOTE_DRIVER,
            shlex.quote(role), shlex.quote(vm.lane_root), client,
            shlex.quote(sync_dir),
        )
    )


def run_nested_cross(vm):
    sync_dir = vm.lane_root + "/sync/phase5-cross"
    vm.guest(
        "nested-cross-prepare",
        "rm -rf %s; install -d -m 0777 %s" % (
            shlex.quote(sync_dir), shlex.quote(sync_dir)
        ),
        timeout=20,
    )
    coordinator = r"""set -eu
sync=%s
count=0
while test ! -s "$sync/incumbent.id" || test ! -s "$sync/attempted.id"; do
    count=$((count + 1)); test "$count" -lt 500; sleep 0.01
done
read inc_owner inc_gen < "$sync/incumbent.id"
read try_owner try_gen < "$sync/attempted.id"
printf 'fault-arm nested-cross %%s %%s %%s %%s\n' \
    "$inc_owner" "$inc_gen" "$try_owner" "$try_gen" > %s
touch "$sync/go"
printf '{"incumbent_owner":%%s,"incumbent_generation":%%s,"attempted_owner":%%s,"attempted_generation":%%s}\n' \
    "$inc_owner" "$inc_gen" "$try_owner" "$try_gen"
""" % (shlex.quote(sync_dir), PHASE5_CONTROL)
    results = vm.guest_parallel(
        "nested-cross",
        [
            participant_command(vm, 0, "incumbent", sync_dir),
            participant_command(vm, 1, "attempted", sync_dir),
            coordinator,
        ],
        timeout=90,
    )
    participants = [
        json_object(results[0].stdout, "nested-cross incumbent"),
        json_object(results[1].stdout, "nested-cross attempted"),
    ]
    coordination = json_object(results[2].stdout, "nested-cross coordinator")
    if ({item.get("role") for item in participants} !=
            {"incumbent", "attempted"} or
            any(item.get("status") != "pass" or
                int(item.get("generation", 0)) <= 0 or
                int(item.get("kcov_entries", 0)) <= 0
                for item in participants)):
        raise ValueError("nested-cross participant contract failed")
    by_role = {item["role"]: item for item in participants}
    expected = {
        "incumbent_owner": int(by_role["incumbent"]["owner"]),
        "incumbent_generation": int(by_role["incumbent"]["generation"]),
        "attempted_owner": int(by_role["attempted"]["owner"]),
        "attempted_generation": int(by_role["attempted"]["generation"]),
    }
    actual = {name: int(coordination.get(name, 0)) for name in expected}
    if actual != expected or (
            expected["incumbent_owner"], expected["incumbent_generation"]
    ) == (
            expected["attempted_owner"], expected["attempted_generation"]
    ):
        raise ValueError("nested-cross exact owner/generation contract failed")
    return {"participants": participants, "coordination": coordination}


def collect_failure_diagnostics(vm):
    """Capture live Phase 5 resources before cleanup can disturb them."""
    diagnostics = {}
    commands = {
        "phase5_stats": "cat " + PHASE5_STATS,
        "phase5_state": "cat " + PHASE5_STATE,
        "phase4_stats": "cat " + PHASE4_STATS,
        "phase4_state": "cat " + PHASE4_STATE,
        "phase3_stats": "cat " + PHASE3_STATS,
        "phase5_tasks": r"""set +e
ps -eo pid,ppid,etimes,state,wchan:32,args | grep -E 'phase5-probe|timeout 60s|nsenter' | grep -v grep
for pid in $(pgrep -f 'phase5-probe'); do
    echo "==== pid=$pid"
    cat "/proc/$pid/stack" 2>/dev/null
done
""",
    }
    for name, command in commands.items():
        result = vm.guest("failure-" + name.replace("_", "-"), command,
                          timeout=20, check=False)
        diagnostics[name] = {
            "returncode": result.returncode,
            "stdout": result.stdout.splitlines(),
            "stderr": result.stderr.splitlines(),
        }
    return diagnostics


def balanced(before, after, acquired, released):
    return delta(before, after, acquired) == delta(before, after, released)


def validate_gate(baseline, after_selftest, snapshots, probes, cross,
                  callback_before, callback_after,
                  cross_state, same_state,
                  phase3_stats, phase4_stats, phase4_state, phase5_state,
                  callback_epoch, cross_epoch, same_epoch):
    checks = {}
    checks["selftest_once"] = delta(baseline, after_selftest, "selftest_runs") == 1
    checks["selftest_failures_zero"] = after_selftest["selftest_failures"] == 0
    for name in sorted(SELFTEST_COUNTERS):
        checks[name] = delta(baseline, after_selftest, name) == 1
    checks["selftest_mapping_identity_misses"] = (
        delta(baseline, after_selftest,
              "mapping_exact_owner_mismatch") == 2
        and delta(baseline, after_selftest,
                  "remote_grant_rejected_generation") == 2
        and delta(baseline, after_selftest,
                  "remote_grant_rejected_token") == 1
    )
    checks["selftest_mapping_exact_policy_reject"] = (
        delta(baseline, after_selftest,
              "mapping_exact_owner_match") > 0
        and delta(baseline, after_selftest, "remote_grant_attempt") ==
        delta(baseline, after_selftest, "mapping_exact_owner_match") +
        delta(baseline, after_selftest, "mapping_exact_owner_mismatch")
    )

    normal_before, normal_after = snapshots["normal"]
    checks["normal_real_nfs_pass"] = probes["normal"]["status"] == "pass"
    checks["exact_mapping_runtime"] = (
        delta(normal_before, normal_after, "mapping_exact_owner_match") > 0
        and delta(normal_before, normal_after, "wire_work_attached") > 0
        and delta(normal_before, normal_after, "wire_work_terminal") > 0
        and delta(normal_before, normal_after,
                  "mapping_exact_owner_mismatch") == 0
    )
    checks["start_grant_and_activation_runtime"] = (
        delta(normal_before, normal_after, "remote_start_granted") > 0
        and delta(normal_before, normal_after, "remote_start_ok") > 0
        and delta(normal_before, normal_after, "remote_stop") > 0
    )
    checks["normal_exact_one_stop"] = (
        delta(normal_before, normal_after, "remote_start_ok") ==
        delta(normal_before, normal_after, "remote_stop")
    )
    checks["normal_scratch_balanced"] = balanced(
        normal_before, normal_after,
        "remote_scratch_reserved", "remote_scratch_returned"
    )
    checks["normal_refs_balanced"] = balanced(
        normal_before, normal_after, "remote_ref_acquired", "remote_ref_released"
    )
    checks["normal_pins_balanced"] = balanced(
        normal_before, normal_after, "remote_target_pinned", "remote_target_unpinned"
    )

    fail_before, fail_after = snapshots["start_fail"]
    checks["start_failure_real_nfs_pass"] = probes["start-fail"]["status"] == "pass"
    checks["start_failure_injected"] = (
        delta(fail_before, fail_after, "fault_start_fail") == 1
        and delta(fail_before, fail_after,
                  "mapping_exact_owner_match") > 0
        and delta(fail_before, fail_after,
                  "mapping_exact_owner_mismatch") == 0
        and delta(fail_before, fail_after,
                  "remote_grant_rejected_generation") > 0
        and delta(fail_before, fail_after, "wire_work_attached") > 0
        and delta(fail_before, fail_after, "remote_start_incomplete") == 1
        and delta(fail_before, fail_after, "remote_result_incomplete") >= 1
    )
    checks["start_failure_resources_balanced"] = (
        balanced(fail_before, fail_after,
                 "remote_scratch_reserved", "remote_scratch_returned")
        and balanced(fail_before, fail_after,
                     "remote_ref_acquired", "remote_ref_released")
        and balanced(fail_before, fail_after,
                     "remote_target_pinned", "remote_target_unpinned")
    )
    checks["start_failure_left_no_partial_section"] = (
        delta(fail_before, fail_after, "remote_start_ok") ==
        delta(fail_before, fail_after, "remote_stop")
        and delta(fail_before, fail_after, "stop_without_start") == 0
    )

    pause_before, pause_after = snapshots["pause_abort"]
    checks["post_grant_abort_real_nfs_pass"] = probes["pause-abort"]["status"] == "pass"
    checks["post_grant_abort_interleaving"] = (
        delta(pause_before, pause_after, "fault_pause_after_grant_entered") == 1
        and delta(pause_before, pause_after, "fault_pause_after_grant_released") == 1
        and delta(pause_before, pause_after, "abort_after_grant") >= 1
        and delta(pause_before, pause_after, "start_after_abort_ok") >= 1
        and delta(pause_before, pause_after, "remote_start_ok") >= 1
        and delta(pause_before, pause_after, "remote_stop") >= 1
        and delta(pause_before, pause_after,
                  "mapping_exact_owner_match") > 0
        and delta(pause_before, pause_after, "wire_work_attached") > 0
    )
    checks["post_grant_not_revoked"] = (
        pause_after["grant_revoked_after_abort"] == 0
        and delta(pause_before, pause_after, "remote_start_ok") ==
        delta(pause_before, pause_after, "remote_stop")
    )

    cross_before, cross_after = snapshots["nested_cross"]
    checks["nested_cross_real_nfs_pass"] = all(
        item["status"] == "pass" for item in cross["participants"]
    )
    checks["nested_cross_detected"] = (
        delta(cross_before, cross_after, "remote_start_nested") == 1
        and delta(cross_before, cross_after, "nested_cross_generation") == 1
        and delta(cross_before, cross_after, "nested_transport_close") == 2
        and (delta(cross_before, cross_after,
                   "nested_client_force_disconnect") +
             delta(cross_before, cross_after,
                   "nested_client_already_closing")) == 2
        and delta(cross_before, cross_after,
                  "nested_client_disconnect_miss") == 0
        and delta(cross_before, cross_after,
                  "mapping_exact_owner_match") >= 2
    )
    checks["nested_cross_dual_invalid"] = (
        delta(cross_before, cross_after, "nested_attempted_invalid") == 1
        and delta(cross_before, cross_after, "nested_incumbent_invalid") == 1
        and delta(cross_before, cross_after, "remote_result_invalid") >= 2
        and delta(cross_before, cross_after, "lane_unhealthy") >= 1
        and delta(cross_before, cross_after,
                  "nested_incumbent_active_match") == 1
        and cross_after["nested_without_active_incumbent"] == 0
    )
    checks["nested_cross_lane_state_unhealthy"] = any(
        lane["valid"] == 1 and lane["lane_epoch"] == cross_epoch and
        lane["unhealthy"] == 1 for lane in cross_state["lanes"]
    ) and cross_state["global_lane_unhealthy"] == 1
    checks["nested_cross_resources_drained"] = (
        not cross_state["generations"] and
        all(value == 0 for value in cross_state["live"].values())
    )

    same_before, same_after = snapshots["nested_same"]
    checks["nested_same_real_nfs_pass"] = probes["nested-same"]["status"] == "pass"
    checks["nested_same_detected"] = (
        delta(same_before, same_after, "remote_start_nested") == 1
        and delta(same_before, same_after, "nested_same_generation") == 1
        and delta(same_before, same_after, "nested_transport_close") == 1
        and (delta(same_before, same_after,
                   "nested_client_force_disconnect") +
             delta(same_before, same_after,
                   "nested_client_already_closing")) == 1
        and delta(same_before, same_after,
                  "nested_client_disconnect_miss") == 0
        and delta(same_before, same_after,
                  "mapping_exact_owner_match") > 0
        and delta(same_before, same_after, "remote_result_invalid") >= 1
        and delta(same_before, same_after, "nested_attempted_invalid") == 1
        and delta(same_before, same_after, "nested_incumbent_invalid") == 1
        and delta(same_before, same_after, "lane_unhealthy") == 1
        and delta(same_before, same_after,
                  "nested_incumbent_active_match") == 1
        and same_after["nested_without_active_incumbent"] == 0
    )
    checks["nested_same_lane_state_unhealthy"] = any(
        lane["valid"] == 1 and lane["lane_epoch"] == same_epoch and
        lane["unhealthy"] == 1 for lane in same_state["lanes"]
    ) and same_state["global_lane_unhealthy"] == 1
    checks["nested_same_resources_drained"] = (
        not same_state["generations"] and
        all(value == 0 for value in same_state["live"].values())
    )

    final = snapshots["final"]
    checks["single_external_linearization"] = final["grant_order_violation"] == 0
    checks["no_runtime_mapping_mismatch"] = (
        after_selftest["mapping_exact_owner_mismatch"] == 2
        and final["mapping_exact_owner_mismatch"] ==
        after_selftest["mapping_exact_owner_mismatch"]
    )
    checks["mapping_attempts_partitioned"] = (
        final["remote_grant_attempt"] ==
        final["mapping_exact_owner_match"] +
        final["mapping_exact_owner_mismatch"]
    )
    checks["transactional_start_clean"] = final["start_transaction_violation"] == 0
    checks["no_stop_without_start"] = final["stop_without_start"] == 0
    checks["no_double_stop"] = final["remote_stop_double"] == 0
    checks["nested_never_ownerless_fallback"] = (
        final["nested_ownerless_fallback"] == 0
        and final["nested_incumbent_unknown"] == 0
        and final["nested_client_disconnect_miss"] == 0
    )
    checks["nested_disconnects_exactly_paired"] = (
        final["nested_client_force_disconnect"] +
        final["nested_client_already_closing"] == 3
        and final["nested_transport_close"] == 3
        and final["nested_client_disconnect_miss"] == 0
    )
    checks["every_success_has_exactly_one_stop"] = (
        final["remote_start_ok"] == final["remote_stop"]
    )
    checks["all_scratch_returned"] = (
        final["remote_scratch_reserved"] == final["remote_scratch_returned"]
    )
    checks["all_target_pins_released"] = (
        final["remote_target_pinned"] == final["remote_target_unpinned"]
    )
    checks["all_remote_refs_released"] = (
        final["remote_ref_acquired"] == final["remote_ref_released"]
        and final["remote_refs"] == 0
    )
    checks["tickets_not_over_retired"] = (
        final["remote_ticket_completed"] + final["remote_ticket_canceled"]
        == final["remote_ticket_created"]
    )
    checks["svc_rqst_no_stale_attachment"] = (
        final["svc_rqst_stale_attachment"] == 0
        and final["svc_rqst_fuzz_reset"] > 0
    )
    checks["svc_rqst_callback_and_short_reset_covered"] = (
        delta(callback_before, callback_after,
              "svc_rqst_callback_reset") > 0
        and final["svc_rqst_short_record_reset"] > 0
    )
    checks["phase4_accounting_clean"] = (
        phase4_stats["outstanding_tokens"] == 0
        and phase4_stats["object_refs"] == 0
        and phase4_stats["token_double_complete"] == 0
        and not phase4_state.strip()
    )
    checks["phase3_ordinals_clean"] = (
        phase3_stats["ordinal_mismatch"] == 0
        and phase3_stats["direction_role_mismatch"] == 0
        and phase3_stats["tcp_retransmit_ordinal_increment"] == 0
    )
    checks["validation_scenarios_use_fresh_lanes"] = (
        callback_epoch < cross_epoch < same_epoch
    )
    checks["phase5_state_drained"] = (
        phase5_state["live"] == {
            "live_tickets": 0,
            "live_svc_attachments": 0,
            "remote_refs": 0,
        } and not phase5_state["generations"]
    )

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 5 checks failed: " + ", ".join(failed))
    return checks


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    scripts = Path(__file__).resolve().parent
    parser.add_argument("--phase1-runner", type=Path,
                        default=scripts / "phases" / "run_frozen_phase1_vm.py")
    parser.add_argument("--phase3-runner", type=Path,
                        default=scripts / "phases" / "run_frozen_phase3_vm.py")
    parser.add_argument("--phase4-runner", type=Path,
                        default=scripts / "phases" / "run_frozen_phase4_vm.py")
    parser.add_argument("--lane-script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--bootstrap", type=Path,
                        default=scripts / "frozen_phase3_bootstrap.sh")
    parser.add_argument("--cleanup-hook", type=Path,
                        default=scripts / "frozen_phase3_cleanup.sh")
    parser.add_argument("--probe", type=Path,
                        default=scripts / "frozen_phase5_probe.c")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "phase3_runner", "phase4_runner", "lane_script", "workload",
                 "bootstrap", "cleanup_hook", "probe"):
        path = getattr(args, name).resolve()
        setattr(args, name, path)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" %
                         (name.replace("_", "-"), path))
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    if not 2 <= args.cpus <= 32:
        parser.error("--cpus must be 2..32")
    if not 2048 <= args.memory <= 32768:
        parser.error("--memory must be 2048..32768 MiB")
    return args


def main(argv=None):
    args = parse_args(argv)
    phase1 = load_module("frozen_phase1_runner", args.phase1_runner)
    phase3 = load_module("frozen_phase3_runner", args.phase3_runner)
    phase4 = load_module("frozen_phase4_runner", args.phase4_runner)
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    phase3.REMOTE_DRIVER = REMOTE_DRIVER

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION,
        "phase": 5,
        "status": "running",
        "started_at": timestamp(),
        "commands": [],
        "snapshots": {},
        "runtime_probes": {},
        "gate": {"name": "Gate 5", "status": "running"},
        "observability_contract": {
            "stats": PHASE5_STATS,
            "control": PHASE5_CONTROL,
            "state": PHASE5_STATE,
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
                     "bootstrap", "cleanup_hook", "probe"):
            path = getattr(args, name)
            evidence["inputs"][name] = {
                "path": str(path), "bytes": path.stat().st_size,
                "sha256": phase1.sha256(path),
            }
        source = args.probe.read_text(encoding="utf-8")
        grant_wait = source.find("fault_pause_after_grant_entered")
        abort_call = source.find("generation_abort(owner_session.fd, generation)",
                                 grant_wait)
        release_call = source.find("fault-release pause-after-grant", abort_call)
        if min(grant_wait, abort_call, release_call) < 0 or not (
                grant_wait < abort_call < release_call):
            raise ValueError("pause/ABORT probe ordering is not source-verifiable")
        evidence["source_contract"].update({
            "real_nfs_exact_generation_bind": "generation_bind(owner_fd, generation)" in source,
            "pause_then_abort_then_release": True,
            "nested_cross_two_real_generations": "cross-participant" in source,
        })
        if not all(evidence["source_contract"].values()):
            raise ValueError("Phase 5 source contract incomplete")
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none "
            "/sys/kernel/debug; command -v gcc ip nsenter timeout tar",
            timeout=30,
        )
        for path in (PHASE3_STATS, PHASE3_CONTROL, PHASE4_STATS,
                     PHASE4_CONTROL, PHASE4_STATE, PHASE5_STATS,
                     PHASE5_CONTROL, PHASE5_STATE):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase5-deps.tar.gz")
        vm.put("copy-lane", args.lane_script, "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-bootstrap", args.bootstrap,
               "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup", args.cleanup_hook,
               "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-probe", args.probe, "/tmp/frozen-phase5-probe.c")
        vm.guest(
            "install-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase5-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase1-lane.sh %s/lane.sh; "
            "install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; "
            "install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; "
            "gcc -O2 -Wall -Wextra -Werror -o %s/phase5-probe "
            "/tmp/frozen-phase5-probe.c"
            % (REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER,
               REMOTE_DRIVER),
            timeout=90,
        )
        allocated = vm.guest(
            "allocate-lane-root", "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10
        )
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")

        for control in (PHASE3_CONTROL, PHASE4_CONTROL, PHASE5_CONTROL):
            vm.guest("reset-" + Path(control).stem,
                     "printf 'reset\n' > " + control, timeout=20)
        baseline = snapshot(vm, "phase5-baseline")
        evidence["snapshots"]["baseline"] = baseline
        write_evidence(args.output, evidence)
        callback_epoch, callback_status = phase3.setup_lane(vm)
        active_epoch = callback_epoch
        evidence["epochs"] = {"backchannel": callback_epoch}
        evidence["lane_status"] = {"backchannel": callback_status}
        write_evidence(args.output, evidence)
        vm.guest("nfs-grace-first", "sleep 11", timeout=20)
        vm.guest("phase5-selftest", "printf 'selftest\n' > " + PHASE5_CONTROL,
                 timeout=90)
        after_selftest = snapshot(vm, "phase5-after-selftest")
        evidence["snapshots"]["after_selftest"] = after_selftest
        write_evidence(args.output, evidence)

        snapshots = {}
        probes = {}
        for scenario in ("normal", "start-fail", "pause-abort"):
            key = scenario.replace("-", "_")
            before = snapshot(vm, "before-" + scenario)
            probes[scenario] = run_probe(vm, 0, scenario)
            after = snapshot(vm, "after-" + scenario)
            snapshots[key] = (before, after)
            evidence["runtime_probes"][scenario] = probes[scenario]
            evidence["snapshots"][key] = {
                "before": before, "after": after,
            }
            write_evidence(args.output, evidence)

        callback_before = snapshot(vm, "before-real-backchannel")
        phase3.run_backchannel_recall(vm)
        callback_after = snapshot(vm, "after-real-backchannel")
        evidence["backchannel"] = {
            "before": callback_before, "after": callback_after,
        }
        write_evidence(args.output, evidence)
        phase3.wait_for_ordinal_alignment(
            vm, callback_epoch,
            phase3.parse_counter_file(vm.guest(
                "phase3-before-callback-cleanup", "cat " + PHASE3_STATS,
                timeout=20,
            ).stdout),
            require_global=False,
        )
        phase3.cleanup_lane(phase1, vm, callback_epoch, strict=True)
        active_epoch = None

        cross_epoch, cross_status = phase3.setup_lane(vm)
        active_epoch = cross_epoch
        evidence["epochs"]["nested_cross"] = cross_epoch
        evidence["lane_status"]["nested_cross"] = cross_status
        write_evidence(args.output, evidence)
        vm.guest("nfs-grace-cross", "sleep 11", timeout=20)

        cross_before = snapshot(vm, "before-nested-cross")
        cross = run_nested_cross(vm)
        cross_after = snapshot(vm, "after-nested-cross")
        cross_state = lane_state(vm, "state-after-nested-cross")
        snapshots["nested_cross"] = (cross_before, cross_after)
        evidence["nested_cross"] = cross
        evidence["nested_cross"]["state"] = cross_state
        evidence["snapshots"]["nested_cross"] = {
            "before": cross_before, "after": cross_after,
        }
        write_evidence(args.output, evidence)
        phase3.wait_for_ordinal_alignment(
            vm, cross_epoch,
            phase3.parse_counter_file(vm.guest(
                "phase3-before-cross-cleanup", "cat " + PHASE3_STATS,
                timeout=20,
            ).stdout),
            require_global=False,
        )
        phase3.cleanup_lane(phase1, vm, cross_epoch, strict=True)
        active_epoch = None

        same_epoch, same_status = phase3.setup_lane(vm)
        active_epoch = same_epoch
        evidence["epochs"]["nested_same"] = same_epoch
        evidence["lane_status"]["nested_same"] = same_status
        write_evidence(args.output, evidence)
        vm.guest("nfs-grace-same", "sleep 11", timeout=20)
        same_before = snapshot(vm, "before-nested-same")
        probes["nested-same"] = run_probe(vm, 0, "nested-same")
        same_after = snapshot(vm, "after-nested-same")
        same_state = lane_state(vm, "state-after-nested-same")
        snapshots["nested_same"] = (same_before, same_after)
        evidence["runtime_probes"]["nested-same"] = probes["nested-same"]
        evidence["snapshots"]["nested_same"] = {
            "before": same_before, "after": same_after,
        }
        evidence["nested_same_state"] = same_state
        write_evidence(args.output, evidence)
        final_phase3, final_connections = phase3.wait_for_ordinal_alignment(
            vm, same_epoch,
            phase3.parse_counter_file(vm.guest(
                "phase3-before-final", "cat " + PHASE3_STATS, timeout=20
            ).stdout),
            require_global=False,
        )
        phase3.cleanup_lane(phase1, vm, same_epoch, strict=True)
        active_epoch = None

        snapshots["final"] = snapshot(vm, "phase5-final")
        phase4_stats = phase4.parse_stats(vm.guest(
            "phase4-final", "cat " + PHASE4_STATS, timeout=20
        ).stdout)
        phase4_state = vm.guest(
            "phase4-state-final", "cat " + PHASE4_STATE, timeout=20
        ).stdout
        phase5_state_text = vm.guest(
            "phase5-state-final", "cat " + PHASE5_STATE, timeout=20
        ).stdout
        phase5_state = parse_state(phase5_state_text)
        checks = validate_gate(
            baseline, after_selftest, snapshots, probes, cross,
            callback_before, callback_after,
            cross_state, same_state,
            final_phase3, phase4_stats, phase4_state, phase5_state,
            callback_epoch, cross_epoch, same_epoch,
        )
        evidence["snapshots"] = {
            name: {"before": pair[0], "after": pair[1]}
            for name, pair in snapshots.items() if name != "final"
        }
        evidence["snapshots"]["baseline"] = baseline
        evidence["snapshots"]["after_selftest"] = after_selftest
        evidence["snapshots"]["final"] = snapshots["final"]
        evidence["runtime_probes"] = probes
        evidence["nested_cross"] = cross
        evidence["nested_cross"]["state"] = cross_state
        evidence["backchannel"] = {
            "before": callback_before, "after": callback_after,
        }
        evidence["epochs"] = {
            "backchannel": callback_epoch,
            "nested_cross": cross_epoch,
            "nested_same": same_epoch,
        }
        evidence["lane_status"] = {
            "backchannel": callback_status,
            "nested_cross": cross_status,
            "nested_same": same_status,
        }
        evidence["phase3"] = {
            "stats": final_phase3, "connections": final_connections,
        }
        evidence["phase4"] = {
            "stats": phase4_stats, "state": phase4_state.splitlines(),
        }
        evidence["phase5_state"] = phase5_state
        evidence["nested_same_state"] = same_state
        evidence["gate"] = {"name": "Gate 5", "status": "pass", "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        evidence["gate"] = {"name": "Gate 5", "status": "fail"}
        evidence["completed_at"] = timestamp()
        if vm is not None and vm.ready:
            try:
                evidence["failure_diagnostics"] = collect_failure_diagnostics(vm)
            except Exception as diagnostic_error:
                evidence.setdefault("collection_errors", []).append(
                    "failure diagnostics: " + str(diagnostic_error)
                )
        write_evidence(args.output, evidence)
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    evidence["cleanup"] = phase1.cleanup_and_validate(
                        vm, 999, strict=False
                    )
                    active_epoch = None
                    cleanup_failed = any(
                        evidence["cleanup"].get(field) != 0
                        for field in ("cleanup_returncode",
                                      "validation_returncode")
                    )
                    if cleanup_failed and exit_code == 0:
                        raise ValueError(
                            "final idempotent cleanup validation failed"
                        )
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        exit_code = 1
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr,
                    encoding="utf-8", errors="replace",
                )
                if exit_code == 0 and (dmesg.returncode or
                                       FATAL_KERNEL_RE.search(dmesg.stdout)):
                    raise ValueError("fatal kernel diagnostic in Phase 5 VM")
            except Exception as error:
                evidence.setdefault("collection_errors", []).append(str(error))
                if exit_code == 0:
                    evidence["status"] = "fail"
                    evidence["gate"]["status"] = "fail"
                    evidence["failure"] = {
                        "type": type(error).__name__, "message": str(error),
                    }
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
                    "type": "GateFailure", "message": "base image changed",
                }
                exit_code = 1
        write_evidence(args.output, evidence)

    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(args.output / "phase5-evidence.json"),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
