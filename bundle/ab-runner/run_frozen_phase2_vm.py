#!/usr/bin/env python3
"""Run the Frozen Baseline Phase 2 acceptance gate in a disposable VM.

This runner deliberately fails closed when the kernel's Phase 2 debugfs
contract or deterministic self-test evidence is absent.  A normal NFS
workload cannot reliably force rpc_rqst/XID replacement, backchannel pool
reuse, or every origin-lattice merge; inferring those properties from a
successful mount would violate the gate contract.

The runner reuses the Phase 1 QEMU/lane machinery, but executes two distinct
live workloads:

* an explicit Generation whose freshly forked task inherits the exact
  ``{handle, generation}`` pair and enables normal KCOV, proving
  syscall-origin propagation without a val-only fallback; and
* a task without KCOV enabled, proving unattributed work fails closed.

Kernel-only lifecycle cases are exercised by the debugfs ``selftest`` command
and reported in the same monotonically increasing statistics file.
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
DEFAULT_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase2_stats"
DEFAULT_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase2_control"
REMOTE_DRIVER = "/opt/frozen-phase2"

REQUIRED_COUNTERS = {
    "logical_request_created",
    "logical_request_completed",
    "logical_request_canceled",
    "request_slot_initialized",
    "request_slot_reset",
    "request_slot_stale",
    "backchannel_slot_reset",
    "origin_empty",
    "origin_unique",
    "origin_unattributed",
    "origin_mixed",
    "rpc_task_origin_unique",
    "rpc_task_owner_none",
    "selftest_runs",
    "selftest_failures",
    "selftest_cookie_retry_preserved",
    "selftest_xid_change_cookie_preserved",
    "selftest_rpc_rqst_reuse_clean",
    "selftest_backchannel_reuse_clean",
    "selftest_origin_lattice",
    "selftest_background_owner_none",
    "selftest_abort_cookie_owner_demoted",
}

SELFTEST_PASS_COUNTERS = {
    "selftest_cookie_retry_preserved",
    "selftest_xid_change_cookie_preserved",
    "selftest_rpc_rqst_reuse_clean",
    "selftest_backchannel_reuse_clean",
    "selftest_origin_lattice",
    "selftest_background_owner_none",
}

FATAL_KERNEL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:)",
    re.IGNORECASE,
)


def load_phase1(path):
    spec = importlib.util.spec_from_file_location("frozen_phase1_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Phase 1 runner: %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_evidence(output, evidence):
    temporary = output / ".phase2-evidence.json.tmp"
    final = output / "phase2-evidence.json"
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, final)


def parse_stats(text):
    counters = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.replace("=", " ", 1).split()
        if len(fields) != 2 or not re.fullmatch(r"[a-z][a-z0-9_]*", fields[0]):
            raise ValueError("invalid Phase 2 stats line %d: %r" % (number, raw_line))
        try:
            value = int(fields[1], 0)
        except ValueError as error:
            raise ValueError(
                "non-integer Phase 2 counter on line %d: %r" % (number, raw_line)
            ) from error
        if value < 0:
            raise ValueError("negative Phase 2 counter %s" % fields[0])
        if fields[0] in counters:
            raise ValueError("duplicate Phase 2 counter %s" % fields[0])
        counters[fields[0]] = value
    missing = sorted(REQUIRED_COUNTERS - counters.keys())
    if missing:
        raise ValueError("missing required Phase 2 counters: " + ", ".join(missing))
    return counters


def counter_delta(before, after, name):
    value = after[name] - before[name]
    if value < 0:
        raise ValueError("counter regressed across snapshot: %s" % name)
    return value


def json_object(text, context):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("%s did not emit valid JSON: %s" % (context, error)) from error
    if not isinstance(value, dict):
        raise ValueError("%s JSON is not an object" % context)
    return value


def guest_snapshot(vm, stage, stats_path):
    result = vm.guest(stage, "cat " + shlex.quote(stats_path), timeout=20)
    return parse_stats(result.stdout)


def client_probe_command(vm, client, mode, iterations):
    root = vm.lane_root
    pid_file = "%s/client%d.pid" % (root, client)
    mount = "%s/client%d/mnt" % (root, client)
    return (
        "set -eu; client_pid=$(cat %s); exec timeout 120s nsenter -t "
        '"$client_pid" -m -n -- %s/probe %s %s %d'
        % (
            shlex.quote(pid_file),
            REMOTE_DRIVER,
            shlex.quote(mode),
            shlex.quote(mount),
            iterations,
        )
    )


def validate_gate(baseline, after_selftest, after_attributed, after_unattributed,
                  attributed_result, unattributed_result):
    checks = {}

    checks["kernel_selftest_ran"] = counter_delta(
        baseline, after_selftest, "selftest_runs"
    ) == 1
    checks["kernel_selftest_no_failures"] = after_selftest["selftest_failures"] == 0
    for name in sorted(SELFTEST_PASS_COUNTERS):
        checks[name] = counter_delta(baseline, after_selftest, name) == 1
    checks["abort_preserves_cookie_and_demotes_owner"] = counter_delta(
        baseline, after_selftest, "selftest_abort_cookie_owner_demoted"
    ) > 0

    checks["request_slot_stale_zero"] = after_unattributed["request_slot_stale"] == 0
    checks["request_slots_initialized"] = (
        counter_delta(after_selftest, after_unattributed,
                      "request_slot_initialized") > 0
    )
    checks["request_slots_reset"] = (
        counter_delta(after_selftest, after_unattributed, "request_slot_reset") > 0
    )
    checks["backchannel_reset_exercised"] = (
        counter_delta(baseline, after_selftest, "backchannel_slot_reset") > 0
    )

    checks["attributed_probe_pass"] = (
        attributed_result.get("status") == "pass"
        and attributed_result.get("mode") == "attributed"
        and int(attributed_result.get("generation", 0)) > 0
        and int(attributed_result.get("kcov_entries", 0)) > 0
    )
    checks["syscall_unique_reaches_rpc_task"] = (
        counter_delta(after_selftest, after_attributed, "origin_unique") > 0
        and counter_delta(after_selftest, after_attributed,
                          "rpc_task_origin_unique") > 0
    )
    checks["attributed_logical_requests_created"] = (
        counter_delta(after_selftest, after_attributed,
                      "logical_request_created") > 0
    )

    checks["unattributed_probe_pass"] = (
        unattributed_result.get("status") == "pass"
        and unattributed_result.get("mode") == "unattributed"
        and int(unattributed_result.get("kcov_entries", -1)) == 0
    )
    checks["unattributed_rpc_task_owner_none"] = (
        counter_delta(after_attributed, after_unattributed,
                      "origin_unattributed") > 0
        and counter_delta(after_attributed, after_unattributed,
                          "rpc_task_owner_none") > 0
    )
    created = after_unattributed["logical_request_created"]
    retired = (
        after_unattributed["logical_request_completed"]
        + after_unattributed["logical_request_canceled"]
    )
    checks["logical_requests_not_over_retired"] = retired <= created
    checks["unique_only_attributable_selftest"] = (
        counter_delta(baseline, after_selftest, "selftest_origin_lattice") == 1
    )
    checks["background_none_selftest"] = (
        counter_delta(baseline, after_selftest,
                      "selftest_background_owner_none") == 1
    )

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 2 checks failed: " + ", ".join(failed))
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
    parser.add_argument("--lane-script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--probe", type=Path,
                        default=scripts / "frozen_phase2_probe.c")
    parser.add_argument("--stats-path", default=DEFAULT_STATS)
    parser.add_argument("--control-path", default=DEFAULT_CONTROL)
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)

    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "lane_script", "workload", "probe"):
        setattr(args, name, getattr(args, name).resolve())
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    if not 1 <= args.iterations <= 1000:
        parser.error("--iterations must be 1..1000")
    if not 2 <= args.cpus <= 32:
        parser.error("--cpus must be 2..32")
    if not 2048 <= args.memory <= 32768:
        parser.error("--memory must be 2048..32768 MiB")
    if not 30 <= args.boot_timeout <= 600:
        parser.error("--boot-timeout must be 30..600 seconds")
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "lane_script", "workload", "probe"):
        path = getattr(args, name)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" % (name.replace("_", "-"), path))
    return args


def main(argv=None):
    args = parse_args(argv)
    phase1 = load_phase1(args.phase1_runner)

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION,
        "phase": 2,
        "status": "running",
        "started_at": timestamp(),
        "commands": [],
        "snapshots": {},
        "gate": {"name": "Gate 2", "status": "running"},
        "observability_contract": {
            "stats_path": args.stats_path,
            "control_path": args.control_path,
            "required_counters": sorted(REQUIRED_COUNTERS),
            "control_commands": ["reset", "selftest"],
        },
    }
    write_evidence(args.output, evidence)

    # The reused VM class calls this module-global function after every
    # command.  Redirect it to the Phase 2 evidence filename.
    phase1.write_evidence = write_evidence
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    vm = None
    base_hash = None
    exit_code = 1
    try:
        phase1.validate_inputs(args, evidence)
        evidence["inputs"]["phase1_runner"] = {
            "path": str(args.phase1_runner),
            "bytes": args.phase1_runner.stat().st_size,
            "sha256": phase1.sha256(args.phase1_runner),
        }
        evidence["inputs"]["probe"] = {
            "path": str(args.probe),
            "bytes": args.probe.stat().st_size,
            "sha256": phase1.sha256(args.probe),
        }
        probe_source = args.probe.read_text(encoding="utf-8")
        begin_call = probe_source.find("generation_begin(owner.fd)")
        fork_call = probe_source.find("child = fork()", begin_call)
        nfs_call = probe_source.find("exercise_nfs(rootfd, i)", fork_call)
        finish_call = probe_source.find(
            "generation_finish(owner.fd, generation)", fork_call
        )
        if min(begin_call, fork_call, nfs_call, finish_call) < 0 or not (
                begin_call < fork_call < nfs_call and fork_call < finish_call):
            raise ValueError(
                "Phase 2 probe must BEGIN before fork and FINISH its generation"
            )
        evidence["source_contract"] = {
            "explicit_generation_begin_before_fork": True,
            "fork_inherits_exact_handle_generation_pair": True,
            "generation_finish_after_worker": True,
            "val_only_attribution_fallback": False,
        }
        base_hash = evidence["inputs"]["image"]["sha256"]
        write_evidence(args.output, evidence)

        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; uname -a; mountpoint -q /sys/kernel/debug || "
            "mount -t debugfs none /sys/kernel/debug; "
            "command -v gcc ip nsenter timeout tar",
            timeout=30,
        )
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase2-deps.tar.gz")
        vm.put("copy-lane-script", args.lane_script,
               "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-probe-source", args.probe,
               "/tmp/frozen-phase2-probe.c")
        install = """set -eu
test ! -e /opt/kcov-nfs/deps
test ! -e /opt/frozen-phase2
install -d /opt/kcov-nfs/deps /opt/frozen-phase2
tar -xzf /tmp/frozen-phase2-deps.tar.gz -C /opt/kcov-nfs/deps
install -m 0755 /tmp/frozen-phase1-lane.sh /opt/frozen-phase2/lane.sh
gcc -O2 -Wall -Wextra -Werror -o /opt/frozen-phase2/probe /tmp/frozen-phase2-probe.c
test -x /opt/frozen-phase2/probe
"""
        vm.guest("install-guest-inputs", install, timeout=90)
        allocation = vm.guest(
            "allocate-lane-root", "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=15
        )
        vm.lane_root = allocation.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe guest lane root: %r" % vm.lane_root)
        lane = REMOTE_DRIVER + "/lane.sh"
        vm.guest("lane-setup", shlex.join([lane, "setup", vm.lane_root]),
                 timeout=150)
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        vm.guest(
            "observability-presence",
            "set -eu; test -e /sys/kernel/debug/kcov; "
            "test -r %s; test -w %s; cat %s"
            % tuple(shlex.quote(item) for item in
                    (args.stats_path, args.control_path, args.stats_path)),
            timeout=20,
        )
        for client in (0, 1):
            pid_file = "%s/client%d.pid" % (vm.lane_root, client)
            vm.guest(
                "client%d-kcov-presence" % client,
                "set -eu; client_pid=$(cat %s); "
                "nsenter -t \"$client_pid\" -m -n -- sh -c "
                "'mount -t debugfs none /sys/kernel/debug; "
                "test -e /sys/kernel/debug/kcov'"
                % shlex.quote(pid_file),
                timeout=20,
            )

        vm.guest(
            "reset-phase2-stats",
            "printf 'reset\\n' > " + shlex.quote(args.control_path),
            timeout=20,
        )
        baseline = guest_snapshot(vm, "stats-baseline", args.stats_path)
        evidence["snapshots"]["baseline"] = baseline

        vm.guest(
            "run-phase2-selftest",
            "printf 'selftest\\n' > " + shlex.quote(args.control_path),
            timeout=60,
        )
        after_selftest = guest_snapshot(vm, "stats-after-selftest", args.stats_path)
        evidence["snapshots"]["after_selftest"] = after_selftest

        attributed = vm.guest(
            "attributed-nfs-probe",
            client_probe_command(vm, 0, "attributed", args.iterations),
            timeout=150,
        )
        attributed_result = json_object(attributed.stdout, "attributed probe")
        after_attributed = guest_snapshot(vm, "stats-after-attributed", args.stats_path)
        evidence["snapshots"]["after_attributed"] = after_attributed
        evidence["attributed_probe"] = attributed_result

        unattributed = vm.guest(
            "unattributed-nfs-probe",
            client_probe_command(vm, 1, "unattributed", args.iterations),
            timeout=150,
        )
        unattributed_result = json_object(unattributed.stdout, "unattributed probe")
        vm.guest("rpc-drain", "sync; sleep 3", timeout=20)
        after_unattributed = guest_snapshot(
            vm, "stats-after-unattributed", args.stats_path
        )
        evidence["snapshots"]["after_unattributed"] = after_unattributed
        evidence["unattributed_probe"] = unattributed_result

        checks = validate_gate(
            baseline, after_selftest, after_attributed, after_unattributed,
            attributed_result, unattributed_result,
        )
        evidence["gate"] = {"name": "Gate 2", "status": "pass", "checks": checks}

        dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
        (args.output / "dmesg.txt").write_text(
            dmesg.stdout + dmesg.stderr, encoding="utf-8", errors="replace"
        )
        evidence["runtime"]["dmesg"] = "dmesg.txt"
        if dmesg.returncode:
            raise ValueError("could not collect guest dmesg")
        if FATAL_KERNEL_RE.search(dmesg.stdout):
            raise ValueError("fatal kernel diagnostic found in dmesg")

        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        evidence["gate"] = {"name": "Gate 2", "status": "fail"}
        evidence["completed_at"] = timestamp()
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    evidence["cleanup"] = phase1.cleanup_and_validate(
                        vm, 1, strict=False
                    )
                    if any(evidence["cleanup"].get(name) != 0 for name in
                           ("cleanup_returncode", "validation_returncode")):
                        raise ValueError("Phase 2 lane cleanup validation failed")
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        exit_code = 1
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
                        evidence["failure"] = {
                            "type": type(error).__name__,
                            "message": "Phase 2 cleanup failed: %s" % error,
                        }
            try:
                result = vm.guest("post-cleanup-dmesg", "dmesg", timeout=30,
                                  check=False)
                (args.output / "dmesg.txt").write_text(
                    result.stdout + result.stderr,
                    encoding="utf-8", errors="replace",
                )
                if exit_code == 0 and (result.returncode or
                                       FATAL_KERNEL_RE.search(result.stdout)):
                    exit_code = 1
                    evidence["status"] = "fail"
                    evidence["gate"]["status"] = "fail"
                    evidence["failure"] = {
                        "type": "GateFailure",
                        "message": "kernel diagnostic after Phase 2 cleanup",
                    }
            except Exception as error:
                evidence.setdefault("collection_errors", []).append(str(error))
        if vm is not None:
            vm.stop()
        if base_hash is not None:
            final_hash = phase1.sha256(args.image)
            evidence["inputs"]["image"]["sha256_after"] = final_hash
            evidence["inputs"]["image"]["unchanged"] = final_hash == base_hash
            if final_hash != base_hash:
                exit_code = 1
                evidence["status"] = "fail"
                evidence["gate"]["status"] = "fail"
                evidence["failure"] = {
                    "type": "GateFailure",
                    "message": "raw base image changed despite snapshot mode",
                }
        write_evidence(args.output, evidence)

    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(args.output / "phase2-evidence.json"),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
