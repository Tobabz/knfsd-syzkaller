#!/usr/bin/env python3
"""Guest functional gate for ASan-instrumented Ganesha 4.3.

Uses the existing syz-execprog and two-client Ganesha lane.  Deliberately
does not apply the kernel-server remote-KCOV AB gate: a userspace NFS server
does not create kernel-server .extra coverage.  This gate instead checks
the daemon's live libasan mapping, NFS results, ASan log and cleanup.
"""

import argparse
import json
from pathlib import Path
import re
import shlex
import sys

import run_ab_adapted as ab


TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
DRIVER = "/opt/frozen-phase9"
ASAN_REPORT = re.compile(
    r"ERROR: AddressSanitizer|SUMMARY: AddressSanitizer|"
    r"AddressSanitizer:DEADLYSIGNAL|ERROR: LeakSanitizer"
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--syz-executor", type=Path, required=True)
    parser.add_argument("--syz-execprog", type=Path, required=True)
    parser.add_argument("--lane-fixture", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--asan-options", required=True)
    parser.add_argument("--executions", type=int, default=2)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=6144)
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--trial-timeout", type=int, default=300)
    args = parser.parse_args()
    for key in ("kernel", "image", "ssh_key", "deps_tar", "syz_executor",
                "syz_execprog", "lane_fixture", "workload"):
        path = getattr(args, key).resolve()
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing input --%s: %s" % (key.replace("_", "-"), path))
        setattr(args, key, path)
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    if not (1 <= args.executions <= 100 and
            4096 <= args.memory <= 65536 and 4 <= args.cpus <= 64):
        parser.error("invalid execution or VM resource count")
    if (not args.asan_options or any(c.isspace() for c in args.asan_options)
            or "detect_leaks=" not in args.asan_options):
        parser.error("--asan-options must be nonempty without whitespace and "
                     "must set detect_leaks")
    return args


def live_asan(vm, root, label):
    command = """set -eu
for pidfile in %s/lane*/server/ganesha.pid; do
    test -s "$pidfile"
    pid=$(cat "$pidfile")
    kill -0 "$pid"
    grep -q 'libasan.so.8' "/proc/$pid/maps"
    grep -q 'libganesha_nfsd.so.4.3' "/proc/$pid/maps"
    printf 'ganesha_pid=%%s libasan=loaded core=loaded\\n' "$pid"
done
""" % shlex.quote(root)
    text = vm.guest(label, command).stdout
    if text.count("libasan=loaded") != 1:
        raise ValueError("expected one live ASan Ganesha: " + text)
    return text.strip()


def collect_logs(vm, root, output):
    command = """set -eu
seen=0
for file in %s/lane*/server.log %s/lane*/server/ganesha.log %s/lane*/server/ganesha.asan.*; do
    test -f "$file" || continue
    case "$file" in */server/ganesha.log)
        test -s "$file"
        seen=$((seen + 1));;
    esac
    printf '=== %%s ===\\n' "$file"
    cat "$file"
done
test "$seen" -eq 1
""" % ((shlex.quote(root),) * 3)
    result = vm.guest("ganesha-asan-logs", command, timeout=45, check=False)
    (output / "ganesha-asan.log").write_text(result.stdout + result.stderr,
                                               encoding="utf-8")
    if result.returncode or not result.stdout:
        raise ValueError("Ganesha server/ASan log could not be collected")
    return bool(ASAN_REPORT.search(result.stdout))


def main():
    args = parse_args()
    phase1 = ab.load_module("asan_phase1", REPO / "bundle/ab-runner/run_frozen_phase1_vm.py")
    phase9 = ab.load_module("asan_phase9", TOOLS / "run_frozen_phase9_vm_ganesha.py")
    phase1.REMOTE_DRIVER = DRIVER
    phase1.write_evidence = ab.write_trial_evidence
    args.output.mkdir(parents=True)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": 1, "experiment": "ganesha-address-sanitizer-functional-smoke",
        "status": "running", "started_at": ab.timestamp(), "commands": [],
        "inputs": {name: {"sha256": ab.sha256(getattr(args, name)),
                          "path": str(getattr(args, name))}
                   for name in ("kernel", "image", "deps_tar", "lane_fixture",
                                "workload", "syz_executor", "syz_execprog")},
        "controls": {"executions": args.executions, "procs": 1,
                     "clients": 2, "server_impl": "ganesha", "remote_cover": False,
                     "asan_options": args.asan_options},
    }
    vm = phase1.FrozenPhase1VM(args, evidence)
    root = None
    baseline = ab.sha256(args.image)
    try:
        vm.start()
        vm.guest("inventory", "set -eu; command -v ip nsenter tar pgrep awk grep")
        for label, source, target in (
            ("deps", args.deps_tar, "/tmp/asan-deps.tar.gz"),
            ("fixture", args.lane_fixture, "/tmp/asan-lane.sh"),
            ("workload", args.workload, "/tmp/asan-workload.prog"),
            ("executor", args.syz_executor, "/tmp/asan-syz-executor"),
            ("execprog", args.syz_execprog, "/tmp/asan-syz-execprog"),
        ):
            vm.put("copy-" + label, source, target)
        vm.guest("install-inputs", "set -eu; "
                 "install -d /opt/kcov-nfs/deps " + DRIVER + "; "
                 "tar -xzf /tmp/asan-deps.tar.gz -C /opt/kcov-nfs/deps; "
                 "install -m 0755 /tmp/asan-lane.sh " + DRIVER + "/lane.sh; "
                 "install -m 0644 /tmp/asan-workload.prog " + DRIVER + "/workload.prog; "
                 "install -m 0755 /tmp/asan-syz-executor " + DRIVER + "/syz-executor; "
                 "install -m 0755 /tmp/asan-syz-execprog " + DRIVER + "/syz-execprog",
                 timeout=90)
        root = vm.guest("allocate-root", "mktemp -d /tmp/frozen-phase9.XXXXXX").stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-phase9\.[A-Za-z0-9]+", root):
            raise ValueError("unsafe fixture root: " + root)
        setup = ["env", "SERVER_IMPL=ganesha", "SERVER_PORT=2049",
                 "NFS_MINOR_VERSION=1", "KOOV_TMPFS_SIZE=256m",
                 "KOOV_GANESHA_DEBUG=NIV_EVENT",
                 "KOOV_GANESHA_ASAN_OPTIONS=" + args.asan_options,
                 DRIVER + "/lane.sh", "setup", root, "1"]
        status = vm.guest("fixture-setup", shlex.join(setup), timeout=300)
        evidence["fixture"] = phase9.validate_fixture_status(
            json.loads(status.stdout), 1)
        phase9.validate_source_tree(vm, root, 1)
        evidence["asan_loaded_before"] = live_asan(vm, root, "asan-loaded-before")

        cmd = [DRIVER + "/syz-execprog", "-executor=" + DRIVER + "/syz-executor",
               "-os=linux", "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
               "-procs=1", "-repeat=" + str(args.executions), "-threaded=false",
               "-cover=true", "-remote-cover=false", "-disable=all", "-debug",
               "-vv=1", "-slowdown=1", DRIVER + "/workload.prog"]
        result = vm.guest("executor-run", "set +e; timeout %ds %s "
                          ">/tmp/asan-executor.log 2>&1; rc=$?; echo rc=$rc; "
                          "exit \"$rc\"" % (args.trial_timeout, shlex.join(cmd)),
                          timeout=args.trial_timeout + 30, check=False)
        log = vm.guest("executor-log", "cat /tmp/asan-executor.log", check=False).stdout
        (args.output / "executor.log").write_text(log, encoding="utf-8")
        if result.returncode:
            raise ValueError("syz-execprog failed, rc=%d" % result.returncode)
        evidence["functional"] = ab.validate_executor_log(log, args.executions, 1)

        after = ["env", "SERVER_IMPL=ganesha", "SERVER_PORT=2049",
                 "NFS_MINOR_VERSION=1", DRIVER + "/lane.sh", "status", root]
        evidence["fixture_after"] = phase9.validate_fixture_status(json.loads(
            vm.guest("fixture-status-after", shlex.join(after), timeout=60).stdout), 1)
        evidence["asan_loaded_after"] = live_asan(vm, root, "asan-loaded-after")
        evidence["asan_report"] = collect_logs(vm, root, args.output)
        if evidence["asan_report"]:
            raise ValueError("Ganesha produced an AddressSanitizer report")
        evidence["cleanup"] = phase9.cleanup_fixture(vm, root, 1, strict=True)
        root = None
        evidence["status"] = "pass"
        print("Ganesha ASan guest smoke: %d calls, %d local KCOV records, "
              "libasan loaded before/after, no ASan reports, cleanup clean" %
              (evidence["functional"]["call_count"],
               evidence["functional"]["local_coverage_records_reported"]))
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if vm.ready and root:
            try:
                evidence["asan_report"] = collect_logs(vm, root, args.output)
            except Exception as error:
                evidence["log_collection_error"] = str(error)
            try:
                evidence["emergency_cleanup"] = phase9.cleanup_fixture(
                    vm, root, 1, strict=False)
            except Exception as error:
                evidence["cleanup_error"] = str(error)
        vm.stop()
        evidence["base_image"] = {"sha256_before": baseline,
                                  "sha256_after": ab.sha256(args.image)}
        evidence["base_image"]["unchanged"] = (
            evidence["base_image"]["sha256_before"] ==
            evidence["base_image"]["sha256_after"])
        if not evidence["base_image"]["unchanged"]:
            evidence["status"] = "fail"
            evidence["failure"] = {"type": "ValueError",
                                   "message": "base VM image changed"}
        evidence["completed_at"] = ab.timestamp()
        ab.write_trial_evidence(args.output, evidence)
    if not evidence["base_image"]["unchanged"]:
        raise ValueError("base VM image changed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Ganesha ASan smoke failed: %s" % exc, file=sys.stderr)
        sys.exit(1)
