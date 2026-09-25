#!/usr/bin/env python3
"""Run Frozen Baseline Gate 4 against real NFS traffic in a disposable VM.

The gate reuses the accepted Phase 3 lane/pairing runner.  A dedicated guest
probe then exercises the production KCOV Generation ABI (BEGIN, exact BIND,
inherited exact binding, FINISH, and ABORT) while issuing real NFSv4.1 TCP
operations.  Deterministic
kernel race tests cover lifecycle interleavings that cannot safely be timed
from userspace, but they cannot substitute for the live ABI workloads.
"""

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
REMOTE_DRIVER = "/opt/frozen-phase4"
PHASE3_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
PHASE3_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
PHASE3_CONNECTIONS = "/sys/kernel/debug/sunrpc_fuzz/phase3_connections"
PHASE4_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase4_stats"
PHASE4_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase4_control"
PHASE4_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase4_state"

REQUIRED_COUNTERS = {
    "generation_begin",
    "generation_bind_ok",
    "generation_bind_unbound",
    "generation_bind_stale",
    "generation_finish",
    "generation_created",
    "generation_closing",
    "generation_committed",
    "generation_aborted",
    "generation_dead",
    "root_token_created",
    "root_token_completed",
    "root_token_canceled",
    "child_token_granted",
    "child_token_rejected",
    "token_created",
    "token_completed",
    "token_double_complete",
    "outstanding_tokens",
    "object_refs",
    "new_root_rejected_closing",
    "new_root_rejected_aborted",
    "closing_retry_granted",
    "abort_retry_owner_none",
    "work_owner_none_after_abort",
    "false_drain_prevented",
    "late_completion_safe",
    "generation_lookup_miss",
    "generation_begin_publish_gap_entered",
    "generation_begin_publish_gap_interrupted",
    "generation_exit_abort",
    "generation_abort_fd_current",
    "abort_connection_reset",
    "abort_lane_reset",
    "wire_token_server_consumed",
    "wire_token_connection_closed",
    "root_final_release_task",
    "root_final_exit_task",
    "selftest_runs",
    "selftest_failures",
    "selftest_exact_once",
    "selftest_late_completion",
    "selftest_closing_new_root_rejected",
    "selftest_closing_existing_retry",
    "selftest_abort_owner_none",
    "selftest_false_drain",
    "selftest_object_lifetime",
    "selftest_cancel_vs_rx",
    "selftest_conn_close_vs_abort",
    "selftest_task_final_vs_abort",
    "selftest_parent_abort_killed_child",
    "selftest_wire_token_terminal",
    "selftest_root_release_task",
    "selftest_begin_orphan_abort",
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
    temporary = output / ".phase4-evidence.json.tmp"
    final = output / "phase4-evidence.json"
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
            raise ValueError("invalid Phase 4 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 4 counter: %s" % fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer Phase 4 counter: %s" % fields[0]) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 4 counter: %s" % fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing required Phase 4 counters: " + ", ".join(missing))
    return values


def delta(before, after, name):
    value = after[name] - before[name]
    if value < 0:
        raise ValueError("counter regressed: %s" % name)
    return value


def stats_snapshot(vm, stage):
    return parse_stats(vm.guest(stage, "cat " + PHASE4_STATS, timeout=20).stdout)


def json_object(text, context):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("%s emitted invalid JSON" % context) from error
    if not isinstance(value, dict):
        raise ValueError("%s JSON is not an object" % context)
    return value


def run_probe(vm, scenario, iterations=3):
    command = (
        "set -eu; pid=$(cat %s/client0.pid); exec timeout 180s "
        "nsenter -t \"$pid\" -m -n -- %s/phase4-probe %s %s/client0/mnt %d"
        % (
            shlex.quote(vm.lane_root),
            REMOTE_DRIVER,
            shlex.quote(scenario),
            shlex.quote(vm.lane_root),
            iterations,
        )
    )
    result = vm.guest("probe-" + scenario, command, timeout=210)
    value = json_object(result.stdout, scenario + " probe")
    generation = int(value.get("generation", 0))
    if (value.get("status") != "pass" or value.get("scenario") != scenario or
            (scenario != "begin-orphan" and generation <= 0) or
            (scenario == "begin-orphan" and generation != 0) or
            int(value.get("kcov_entries", 0)) <= 0):
        raise ValueError("Phase 4 probe failed contract: %s" % scenario)
    return value


def run_executor_probe(vm):
    """Exercise the production per-program BEGIN/BIND/FINISH integration."""
    path = "%s/client0/mnt/phase4-executor" % vm.lane_root
    program = "\n".join((
        "r0 = openat(0xffffffffffffff9c, "
        "&(0x7f0000000000)='%s\\x00', 0x242, 0x1a4)" % path,
        "ftruncate(r0, 0x1000)",
        "fsync(r0)",
        "close(r0)",
        "unlinkat(0xffffffffffffff9c, "
        "&(0x7f0000000100)='%s\\x00', 0x0)" % path,
        "",
    ))
    program_path = "/tmp/frozen-phase4-executor.prog"
    vm.guest(
        "write-executor-program",
        "printf %%s %s > %s" % (
            shlex.quote(program), shlex.quote(program_path)
        ),
        timeout=20,
    )
    command = (
        "set -eu; pid=$(cat %s/client0.pid); "
        "timeout 240s nsenter -t \"$pid\" -m -n -- "
        "%s/syz-execprog -executor %s/syz-executor "
        "-os linux -arch amd64 -vmarch amd64 -sandbox none -procs 1 "
        "-repeat 1 -threaded=true -cover -output %s; "
        "test ! -e %s"
        % (
            shlex.quote(vm.lane_root), REMOTE_DRIVER, REMOTE_DRIVER,
            shlex.quote(program_path), shlex.quote(path),
        )
    )
    result = vm.guest("executor-generation-abi", command, timeout=270)
    return {
        "status": "pass",
        "program": program.splitlines(),
        "stdout_bytes": len(result.stdout.encode("utf-8")),
        "stderr_bytes": len(result.stderr.encode("utf-8")),
        "stdout_tail": result.stdout[-4000:].splitlines(),
        "stderr_tail": result.stderr[-4000:].splitlines(),
    }


def client0_connections(phase3, connections, epoch):
    return {
        item["conn_cookie"]: item
        for item in phase3.paired_connections(connections, epoch)
        if item["client_addr"] == "10.77.0.2"
    }


def validate_abort_connection_independence(phase3, before, after, epoch):
    old = client0_connections(phase3, before, epoch)
    new = client0_connections(phase3, after, epoch)
    common = sorted(set(old) & set(new))
    if not common:
        return False
    return all(
        phase3.validate_connection(new[cookie])
        and new[cookie]["c2s_tx"] >= old[cookie]["c2s_tx"]
        and new[cookie]["c2s_rx"] >= old[cookie]["c2s_rx"]
        and new[cookie]["s2c_tx"] >= old[cookie]["s2c_tx"]
        and new[cookie]["s2c_rx"] >= old[cookie]["s2c_rx"]
        for cookie in common
    )


def validate_gate(baseline, after_selftest, snapshots, probes, executor_probe,
                  abort_connection_stable, domain_before, domain_after,
                  phase3_after):
    checks = {}
    checks["selftest_ran_once"] = delta(
        baseline, after_selftest, "selftest_runs"
    ) == 1
    checks["selftest_failures_zero"] = after_selftest["selftest_failures"] == 0
    for name in sorted(SELFTEST_COUNTERS):
        checks[name] = delta(baseline, after_selftest, name) == 1

    final = snapshots["final"]
    checks["production_begin_exercised"] = delta(
        after_selftest, final, "generation_begin"
    ) >= 11
    checks["worker_exact_bind_exercised"] = delta(
        after_selftest, final, "generation_bind_ok"
    ) >= 4
    checks["fork_inherits_exact_generation"] = delta(
        snapshots["before_inherited"], snapshots["after_inherited"],
        "root_token_created"
    ) > 0
    checks["generation_objects_fully_retired"] = (
        final["generation_dead"] == final["generation_created"]
    )
    checks["normal_finish_committed"] = delta(
        after_selftest, final, "generation_committed"
    ) >= 4
    checks["abort_path_exercised"] = delta(
        after_selftest, final, "generation_aborted"
    ) >= 3
    checks["unbound_fails_closed"] = delta(
        snapshots["before_unbound"], snapshots["after_unbound"],
        "generation_bind_unbound"
    ) > 0
    checks["stale_bind_rejected"] = delta(
        snapshots["before_stale"], snapshots["after_stale"],
        "generation_bind_stale"
    ) > 0
    checks["executor_program_passed"] = executor_probe.get("status") == "pass"
    checks["executor_begin_exercised"] = delta(
        snapshots["before_executor"], snapshots["after_executor"],
        "generation_begin"
    ) > 0
    checks["executor_exact_bind_exercised"] = delta(
        snapshots["before_executor"], snapshots["after_executor"],
        "generation_bind_ok"
    ) > 0
    checks["executor_explicit_unbind_exercised"] = delta(
        snapshots["before_executor"], snapshots["after_executor"],
        "generation_bind_unbound"
    ) > 0
    checks["executor_finish_committed"] = (
        delta(snapshots["before_executor"], snapshots["after_executor"],
              "generation_finish") > 0
        and delta(snapshots["before_executor"], snapshots["after_executor"],
                  "generation_committed") > 0
    )
    checks["begin_publish_gap_entered"] = delta(
        snapshots["before_begin_orphan"], snapshots["after_begin_orphan"],
        "generation_begin_publish_gap_entered"
    ) > 0
    checks["begin_publish_gap_interrupted"] = delta(
        snapshots["before_begin_orphan"], snapshots["after_begin_orphan"],
        "generation_begin_publish_gap_interrupted"
    ) > 0
    checks["killed_begin_task_exit_aborted"] = delta(
        snapshots["before_begin_orphan"], snapshots["after_begin_orphan"],
        "generation_exit_abort"
    ) > 0
    checks["parent_abort_current_fd_fallback"] = delta(
        snapshots["before_begin_orphan"], snapshots["after_begin_orphan"],
        "generation_abort_fd_current"
    ) > 0
    generations = [
        int(item["generation"]) for item in probes
        if int(item["generation"]) > 0
    ]
    checks["kernel_generations_monotonic"] = all(
        later > earlier for earlier, later in zip(generations, generations[1:])
    )
    stale = next(item for item in probes if item["scenario"] == "stale")
    checks["old_generation_rejected"] = (
        int(stale["old_generation"]) > 0
        and int(stale["generation"]) > int(stale["old_generation"])
    )

    checks["closing_rejects_new_roots"] = final[
        "new_root_rejected_closing"
    ] > after_selftest["new_root_rejected_closing"]
    checks["aborted_generation_rejects_new_roots"] = final[
        "new_root_rejected_aborted"
    ] > after_selftest["new_root_rejected_aborted"]
    checks["closing_existing_retry_granted"] = delta(
        snapshots["before_closing_retry"], snapshots["after_closing_retry"],
        "closing_retry_granted"
    ) >= 1
    checks["abort_retry_owner_none"] = delta(
        snapshots["before_abort_retry"], snapshots["after_abort_retry"],
        "abort_retry_owner_none"
    ) >= 1
    checks["abort_real_work_owner_none"] = delta(
        snapshots["before_abort"], snapshots["after_abort"],
        "work_owner_none_after_abort"
    ) > 0
    checks["actual_nfs_continues_after_abort"] = all(
        item.get("status") == "pass" and int(item.get("kcov_entries", 0)) > 0
        for item in probes if item["scenario"] in {"abort", "abort-retry"}
    )
    checks["false_drain_prevented"] = delta(
        after_selftest, final, "false_drain_prevented"
    ) > 0
    checks["exact_once_no_double_complete"] = final["token_double_complete"] == 0
    checks["token_accounting_balanced"] = (
        final["outstanding_tokens"] == 0
        and final["object_refs"] == 0
        and final["token_completed"] <= final["token_created"]
    )
    checks["root_accounting_not_over_retired"] = (
        final["root_token_completed"] + final["root_token_canceled"]
        == final["root_token_created"]
    )
    checks["late_completion_path_safe"] = final["late_completion_safe"] > 0
    checks["real_wire_tokens_reach_server_consume"] = delta(
        after_selftest, final, "wire_token_server_consumed"
    ) > 0
    checks["connection_close_terminal_exercised"] = delta(
        after_selftest, final, "wire_token_connection_closed"
    ) > 0
    checks["roots_finalize_at_release_task"] = (
        delta(after_selftest, final, "root_final_release_task") > 0
        and final["root_final_exit_task"] == 0
    )
    checks["abort_did_not_reset_connection"] = (
        abort_connection_stable and final["abort_connection_reset"] == 0
    )
    checks["abort_did_not_reset_lane"] = (
        domain_before == domain_after and final["abort_lane_reset"] == 0
    )
    checks["phase3_ordinal_invariants_remain_clean"] = (
        phase3_after["ordinal_mismatch"] == 0
        and phase3_after["direction_role_mismatch"] == 0
        and phase3_after["tcp_retransmit_ordinal_increment"] == 0
    )
    checks["all_runtime_scenarios_passed"] = {
        item["scenario"] for item in probes
    } == {"finish", "inherited", "begin-orphan", "abort", "closing-retry",
          "abort-retry",
          "connection-close", "unbound", "stale"}

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 4 checks failed: " + ", ".join(failed))
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
                        default=scripts / "run_frozen_phase1_vm.py")
    parser.add_argument("--phase3-runner", type=Path,
                        default=scripts / "run_frozen_phase3_vm.py")
    parser.add_argument("--lane-script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--bootstrap", type=Path,
                        default=scripts / "frozen_phase3_bootstrap.sh")
    parser.add_argument("--cleanup-hook", type=Path,
                        default=scripts / "frozen_phase3_cleanup.sh")
    parser.add_argument("--probe", type=Path,
                        default=scripts / "frozen_phase4_probe.c")
    parser.add_argument(
        "--syz-executor", type=Path,
        default=Path("/home/fuzzer/tools/syzkaller-frozen-attribution/"
                     "bin/linux_amd64/syz-executor"),
    )
    parser.add_argument(
        "--syz-execprog", type=Path,
        default=Path("/home/fuzzer/tools/syzkaller-frozen-attribution/"
                     "bin/linux_amd64/syz-execprog"),
    )
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "phase3_runner", "lane_script", "workload", "bootstrap",
                 "cleanup_hook", "probe", "syz_executor", "syz_execprog"):
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
    phase3.REMOTE_DRIVER = REMOTE_DRIVER

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION,
        "phase": 4,
        "status": "running",
        "started_at": timestamp(),
        "commands": [],
        "snapshots": {},
        "runtime_probes": [],
        "gate": {"name": "Gate 4", "status": "running"},
        "observability_contract": {
            "phase4_stats": PHASE4_STATS,
            "phase4_control": PHASE4_CONTROL,
            "phase4_state": PHASE4_STATE,
            "required_counters": sorted(REQUIRED_COUNTERS),
            "production_abi": [
                "KCOV_REMOTE_GENERATION_BEGIN",
                "KCOV_REMOTE_GENERATION_BIND",
                "KCOV_REMOTE_GENERATION_FINISH",
                "KCOV_REMOTE_GENERATION_ABORT",
            ],
        },
    }
    write_evidence(args.output, evidence)
    phase1.write_evidence = write_evidence
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    vm = None
    base_hash = None
    active_epoch = None
    exit_code = 1
    try:
        phase1.validate_inputs(args, evidence)
        for name in ("phase1_runner", "phase3_runner", "bootstrap",
                     "cleanup_hook", "probe", "syz_executor",
                     "syz_execprog"):
            path = getattr(args, name)
            evidence["inputs"][name] = {
                "path": str(path), "bytes": path.stat().st_size,
                "sha256": phase1.sha256(path),
            }
        probe_source = args.probe.read_text(encoding="utf-8")
        begin_call = probe_source.find("generation_begin(owner_session.fd)")
        fork_call = probe_source.find("child = fork()", begin_call)
        bind_call = probe_source.find(
            "generation_bind(owner_session.fd, generation)", fork_call
        )
        nfs_call = probe_source.find("exercise_nfs(rootfd, 0)", bind_call)
        if min(begin_call, fork_call, bind_call, nfs_call) < 0 or not (
                begin_call < fork_call < bind_call < nfs_call):
            raise ValueError("Phase 4 probe does not BEGIN/BIND before real NFS work")
        for symbol in ("KCOV_REMOTE_GENERATION_FINISH",
                       "KCOV_REMOTE_GENERATION_ABORT"):
            if symbol not in probe_source:
                raise ValueError("Phase 4 probe omits production ABI: " + symbol)
        orphan_kill = probe_source.find("kill(child, SIGKILL)")
        orphan_wait = probe_source.find(
            "waitpid(child, &status, 0)", orphan_kill
        )
        orphan_abort = probe_source.find(
            "generation_abort(owner_session->fd, 0)", orphan_wait
        )
        if min(orphan_kill, orphan_wait, orphan_abort) < 0 or not (
                orphan_kill < orphan_wait < orphan_abort):
            raise ValueError(
                "BEGIN orphan fallback must kill/wait before ABORT(0)"
            )
        evidence["source_contract"].update({
            "production_begin_before_fork": True,
            "worker_bind_before_nfs": True,
            "finish_and_abort_ioctl_present": True,
            "begin_orphan_kill_wait_before_abort_current": True,
        })
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none "
            "/sys/kernel/debug; command -v gcc ip nsenter timeout tar",
            timeout=30,
        )
        for path in (PHASE3_STATS, PHASE3_CONTROL, PHASE3_CONNECTIONS,
                     PHASE4_STATS, PHASE4_CONTROL, PHASE4_STATE):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase4-deps.tar.gz")
        vm.put("copy-lane-script", args.lane_script,
               "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-bootstrap", args.bootstrap,
               "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup-hook", args.cleanup_hook,
               "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-phase4-probe", args.probe,
               "/tmp/frozen-phase4-probe.c")
        vm.put("copy-syz-executor", args.syz_executor,
               "/tmp/frozen-phase4-syz-executor")
        vm.put("copy-syz-execprog", args.syz_execprog,
               "/tmp/frozen-phase4-syz-execprog")
        vm.guest(
            "install-guest-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase4-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase1-lane.sh %s/lane.sh; "
            "install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; "
            "install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; "
            "install -m 0755 /tmp/frozen-phase4-syz-executor %s/syz-executor; "
            "install -m 0755 /tmp/frozen-phase4-syz-execprog %s/syz-execprog; "
            "gcc -O2 -Wall -Wextra -Werror -o %s/phase4-probe "
            "/tmp/frozen-phase4-probe.c"
            % (REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER,
               REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER),
            timeout=90,
        )
        allocated = vm.guest(
            "allocate-lane-root", "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10
        )
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")

        vm.guest("reset-phase3", "printf 'reset\n' > " + PHASE3_CONTROL,
                 timeout=20)
        vm.guest("reset-phase4", "printf 'reset\n' > " + PHASE4_CONTROL,
                 timeout=20)
        baseline = stats_snapshot(vm, "stats-baseline")
        epoch, lane_status = phase3.setup_lane(vm)
        active_epoch = epoch
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        initial_connections = phase3.connection_snapshot(
            vm, "phase4-connections-initial"
        )
        if len(phase3.paired_connections(initial_connections, epoch)) < 2:
            raise ValueError("Phase 4 lane lacks two paired NFS connections")
        domain_before = phase3.parse_domain(vm.guest(
            "phase4-domain-before", "cat /sys/kernel/debug/sunrpc_fuzz/domain",
            timeout=10,
        ).stdout)

        vm.guest("run-phase4-selftest",
                 "printf 'selftest\n' > " + PHASE4_CONTROL, timeout=90)
        after_selftest = stats_snapshot(vm, "stats-after-selftest")

        probes = []
        snapshots = {}
        for scenario in ("begin-orphan", "inherited", "finish",
                         "closing-retry"):
            snapshots["before_" + scenario.replace("-", "_")] = stats_snapshot(
                vm, "stats-before-" + scenario
            )
            probes.append(run_probe(vm, scenario))
            snapshots["after_" + scenario.replace("-", "_")] = stats_snapshot(
                vm, "stats-after-" + scenario
            )

        before_abort_connections = phase3.connection_snapshot(
            vm, "connections-before-abort"
        )
        snapshots["before_abort"] = stats_snapshot(vm, "stats-before-abort")
        probes.append(run_probe(vm, "abort"))
        snapshots["after_abort"] = stats_snapshot(vm, "stats-after-abort")
        after_abort_connections = phase3.connection_snapshot(
            vm, "connections-after-abort"
        )
        abort_connection_stable = validate_abort_connection_independence(
            phase3, before_abort_connections, after_abort_connections, epoch
        )

        for scenario in ("abort-retry", "unbound", "stale"):
            key = scenario.replace("-", "_")
            snapshots["before_" + key] = stats_snapshot(
                vm, "stats-before-" + scenario
            )
            probes.append(run_probe(vm, scenario))
            snapshots["after_" + key] = stats_snapshot(
                vm, "stats-after-" + scenario
            )

        snapshots["before_executor"] = stats_snapshot(
            vm, "stats-before-executor"
        )
        executor_probe = run_executor_probe(vm)
        snapshots["after_executor"] = stats_snapshot(
            vm, "stats-after-executor"
        )

        snapshots["before_connection_close"] = stats_snapshot(
            vm, "stats-before-connection-close"
        )
        vm.guest(
            "arm-phase4-connection-close",
            "printf 'fault-arm postcommit\\n' > " + PHASE3_CONTROL,
            timeout=20,
        )
        probes.append(run_probe(vm, "connection-close"))
        snapshots["after_connection_close"] = stats_snapshot(
            vm, "stats-after-connection-close"
        )

        aligned_phase3, aligned_connections = phase3.wait_for_ordinal_alignment(
            vm, epoch, phase3.parse_counter_file(
                vm.guest("phase3-final-baseline", "cat " + PHASE3_STATS,
                         timeout=20).stdout
            ), require_global=False,
        )
        snapshots["final"] = stats_snapshot(vm, "stats-final")
        final_state = vm.guest("phase4-state-final", "cat " + PHASE4_STATE,
                               timeout=20).stdout
        if final_state.strip():
            raise ValueError("Phase 4 generations remain live: %r" %
                             final_state.splitlines())
        domain_after = phase3.parse_domain(vm.guest(
            "phase4-domain-after", "cat /sys/kernel/debug/sunrpc_fuzz/domain",
            timeout=10,
        ).stdout)
        checks = validate_gate(
            baseline, after_selftest, snapshots, probes, executor_probe,
            abort_connection_stable, domain_before, domain_after,
            aligned_phase3,
        )
        evidence["runtime_probes"] = probes
        evidence["executor_probe"] = executor_probe
        evidence["snapshots"] = snapshots
        evidence["phase3"] = {
            "initial_connections": initial_connections,
            "before_abort_connections": before_abort_connections,
            "after_abort_connections": after_abort_connections,
            "aligned_stats": aligned_phase3,
            "aligned_connections": aligned_connections,
            "abort_connection_stable": abort_connection_stable,
        }
        evidence["domain"] = {"before": domain_before, "after": domain_after}
        evidence["phase4_state_final"] = final_state.splitlines()
        evidence["lane_status"] = lane_status

        phase3.cleanup_lane(phase1, vm, epoch, strict=True)
        active_epoch = None
        evidence["gate"] = {"name": "Gate 4", "status": "pass", "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        evidence["gate"] = {"name": "Gate 4", "status": "fail"}
        evidence["completed_at"] = timestamp()
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    cleanup = phase1.cleanup_and_validate(vm, 999, strict=False)
                    evidence["cleanup"] = cleanup
                    if exit_code == 0 and any(cleanup.get(name) != 0 for name in
                                              ("cleanup_returncode",
                                               "validation_returncode")):
                        raise ValueError("Phase 4 final lane cleanup failed")
                    active_epoch = None
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
                        evidence["failure"] = {
                            "type": type(error).__name__, "message": str(error),
                        }
                        exit_code = 1
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr,
                    encoding="utf-8", errors="replace",
                )
                if exit_code == 0 and (dmesg.returncode or
                                       FATAL_KERNEL_RE.search(dmesg.stdout)):
                    raise ValueError("fatal kernel diagnostic in Phase 4 VM")
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
        "evidence": str(args.output / "phase4-evidence.json"),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
