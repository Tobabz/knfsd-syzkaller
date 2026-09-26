#!/usr/bin/env python3
"""Run fresh-VM deterministic Remote KCOV OFF/ON A/B trials."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time


REMOTE_DRIVER = "/opt/frozen-phase9"
PHASE9_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase9_control"
# KCSAN reports begin with "BUG: KCSAN:" (kernel/kcsan/report.c) and are
# findings, not crashes: the kernel keeps running after reporting.
# Excluding that banner keeps KCSAN builds able to produce AB evidence;
# KASAN builds never emit it, so the exclusion is a no-op there.
FATAL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:(?! KCSAN:)|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:|"
    r"refcount_t:|Out of memory:|oom-kill:|Killed process)", re.IGNORECASE)
CALL_RE = re.compile(
    r"CALL\s+(\d+):\s+signal\s+\d+,\s+coverage\s+(\d+)\s+errno\s+(\d+)"
    r"([^\n]*)")
BIND_RE = re.compile(
    r"NFS fuzz lane bound: proc=(\d+) (?:clients-only )?source=/syz-nfs-lanes/proc-(\d+) "
    r"target=/nfs-lane")
EXPECTED_CALLS = 34
CONFLICT_CALL = 14


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_json(path, value):
    temporary = path.with_name("." + path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)


def write_trial_evidence(output, evidence):
    write_json(output / "trial_evidence.json", evidence)


def delta(before, after, name):
    value = after[name] - before[name]
    if value < 0:
        raise ValueError("counter regressed: %s" % name)
    return value


def parse_cpu_snapshot(text):
    fields = text.split()
    if len(fields) < 9 or fields[0] != "cpu":
        raise ValueError("invalid /proc/stat CPU row")
    values = [int(value) for value in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return {"total": sum(values), "idle": idle}


def cpu_snapshot(vm, stage):
    text = vm.guest(stage, "head -n 1 /proc/stat", timeout=15).stdout
    return parse_cpu_snapshot(text)


def cpu_percent(before, after):
    total = after["total"] - before["total"]
    idle = after["idle"] - before["idle"]
    if total <= 0 or not 0 <= idle <= total:
        raise ValueError("invalid CPU interval")
    return 100.0 * (total - idle) / total


def pull(vm, stage, remote, local):
    command = [*vm.scp, "root@127.0.0.1:" + remote, str(local)]
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    vm._record(stage, "scp %s %s" % (remote, local), result,
               time.monotonic() - started)
    if result.returncode:
        raise ValueError("%s failed: %s" % (stage, result.stderr.strip()))


def extract_cover(archive, destination):
    destination.mkdir()
    allowed = re.compile(r"cover_prog\d+\.(?:\d+|extra|meta)$")
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        names = []
        for member in members:
            name = member.name.removeprefix("./")
            if member.isdir() and name in ("", "."):
                continue
            if not member.isfile() or not allowed.fullmatch(name):
                raise ValueError("unexpected coverage archive member: %r" % member.name)
            member.name = name
            names.append(name)
        if len(names) != len(set(names)):
            raise ValueError("duplicate coverage archive member")
        stream.extractall(destination,
                          members=[member for member in members if member.isfile()])
    return sorted(names)


def validate_executor_log(log, executions, procs):
    calls = [(int(index), int(coverage), int(error), flags.strip())
             for index, coverage, error, flags in CALL_RE.findall(log)]
    by_call = {index: [] for index in range(EXPECTED_CALLS)}
    for index, coverage, error, flags in calls:
        if index not in by_call:
            raise ValueError("unexpected syscall result index %d" % index)
        by_call[index].append((coverage, error, flags))
    for index, results in by_call.items():
        if len(results) != executions:
            raise ValueError("call %d count %d != %d" %
                             (index, len(results), executions))
        for _coverage, error, flags in results:
            if "unfinished" in flags:
                raise ValueError("call %d was unfinished" % index)
            expected = 11 if index == CONFLICT_CALL else 0
            if error != expected:
                raise ValueError("call %d errno %d != %d" %
                                 (index, error, expected))
    bindings = {(int(proc), int(source)) for proc, source in BIND_RE.findall(log)}
    expected_bindings = {(proc, proc) for proc in range(procs)}
    if bindings != expected_bindings:
        raise ValueError("fixed lane bindings differ: %r" % sorted(bindings))
    local_records = sum(value[0] for results in by_call.values()
                        for value in results)
    if local_records <= 0:
        raise ValueError("normal/local KCOV returned no coverage")
    return {
        "call_count": len(calls),
        "calls_per_execution": EXPECTED_CALLS,
        "expected_lock_conflicts": len(by_call[CONFLICT_CALL]),
        "local_coverage_records_reported": local_records,
        "bindings": [{"proc": proc, "source": source}
                     for proc, source in sorted(bindings)],
    }


def validate_cover_files(directory, names, executions, remote_on):
    meta = sorted(directory.glob("cover_prog*.meta"),
                  key=lambda path: int(re.search(r"prog(\d+)", path.name).group(1)))
    if len(meta) != executions:
        raise ValueError("coverage metadata count %d != %d" %
                         (len(meta), executions))
    indexes = [int(re.search(r"prog(\d+)", path.name).group(1)) for path in meta]
    if indexes != list(range(1, executions + 1)):
        raise ValueError("coverage execution indexes are not contiguous")
    elapsed = []
    for path in meta:
        values = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, value = line.split()
            values[key] = int(value)
        if set(values) != {"completed_unix_nano", "elapsed_nano"}:
            raise ValueError("invalid sample metadata: %s" % path)
        elapsed.append(values["elapsed_nano"])
    if elapsed != sorted(elapsed) or elapsed[-1] <= 0:
        raise ValueError("sample completion times are invalid")
    call_files = [name for name in names if re.search(r"\.\d+$", name)]
    extra_files = [name for name in names if name.endswith(".extra")]
    if not call_files:
        raise ValueError("no local per-call KCOV files")
    if remote_on and len(extra_files) != executions:
        raise ValueError("ON extra coverage file count %d != %d" %
                         (len(extra_files), executions))
    if not remote_on and extra_files:
        raise ValueError("OFF unexpectedly returned extra coverage")
    records = 0
    for path in directory.glob("cover_prog*.*"):
        if path.suffix == ".meta":
            continue
        records += sum(1 for line in path.read_text().splitlines() if line.strip())
    return {
        "metadata_files": len(meta), "call_files": len(call_files),
        "extra_files": len(extra_files), "raw_pc_records": records,
        "last_elapsed_seconds": elapsed[-1] / 1e9,
    }


def counter_diagnostics(before, after):
    phase3_before, phase3_after = before["phase3"], after["phase3"]
    phase4_before = before["phase4"]["stats"]
    phase4_after = after["phase4"]["stats"]
    phase5_before = before["phase5"]["stats"]
    phase5_after = after["phase5"]["stats"]
    phase6_before = before["phase6"]["stats"]
    phase6_after = after["phase6"]["stats"]
    phase9_before, phase9_after = before["phase9"], after["phase9"]
    names4 = ("generation_begin", "generation_committed", "generation_aborted",
              "token_double_complete", "outstanding_tokens", "object_refs")
    names5 = ("mapping_exact_owner_match", "mapping_exact_owner_mismatch",
              "remote_start_granted", "remote_start_ok",
              "remote_start_incomplete", "remote_start_nested", "remote_stop",
              "remote_scratch_reserved", "remote_scratch_returned",
              "remote_result_valid", "remote_result_incomplete",
              "remote_result_invalid", "nested_cross_generation",
              "lane_unhealthy", "remote_refs")
    names6 = ("remote_section_created", "remote_section_completed",
              "remote_section_discarded", "scratch_reserved", "scratch_returned",
              "scratch_peak", "scratch_overflow", "aggregate_merge_completed",
              "aggregate_merge_truncated", "aggregate_entries_merged",
              "aggregate_committed", "aggregate_published",
              "aggregate_entries_published", "aggregate_discarded",
              "aggregate_publish_suppressed", "incomplete_published",
              "invalid_published", "aborted_published", "remote_refs",
              "publish_readers")
    names3 = ("ordinal_tx_c2s", "ordinal_rx_c2s", "ordinal_tx_s2c",
              "ordinal_rx_s2c", "ordinal_mismatch", "connection_pair_ok",
              "connection_pair_miss", "lane_epoch_collision",
              "lane_epoch_immutable_violation")
    names9 = ("owner_lane_match", "cross_lane_attribution", "lane_seen_mask")
    result = {
        "phase3": {name: delta(phase3_before, phase3_after, name)
                   for name in names3},
        "phase4": {name: delta(phase4_before, phase4_after, name)
                   for name in names4},
        "phase5": {name: delta(phase5_before, phase5_after, name)
                   for name in names5},
        "phase6": {name: delta(phase6_before, phase6_after, name)
                   for name in names6},
        "phase9": {name: delta(phase9_before, phase9_after, name)
                   for name in names9},
    }
    # Gauges are required to be zero at drain; deltas can be meaningless.
    result["drained_gauges"] = {
        "outstanding_tokens": phase4_after["outstanding_tokens"],
        "object_refs": phase4_after["object_refs"],
        "phase5_remote_refs": phase5_after["remote_refs"],
        "phase6_remote_refs": phase6_after["remote_refs"],
        "publish_readers": phase6_after["publish_readers"],
    }
    return result


def validate_gate(mode, diagnostics, functional, cover, rpc_delta,
                  memory_samples, cpu_usage, final_snapshot):
    remote_on = mode == "on"
    p3, p4, p5, p6, p9 = (diagnostics[name]
                           for name in ("phase3", "phase4", "phase5",
                                        "phase6", "phase9"))
    checks = {
        "functional_workload": functional["call_count"] > 0,
        "local_kcov_positive": functional["local_coverage_records_reported"] > 0,
        "raw_coverage_positive": cover["raw_pc_records"] > 0,
        "nfsd_rpc_positive": rpc_delta > 0,
        "cpu_measurement_valid": 0 <= cpu_usage <= 100,
        "memory_measurement_valid": len(memory_samples) >= 2,
        "ordinal_mismatch_zero": p3["ordinal_mismatch"] == 0,
        "pair_miss_zero": p3["connection_pair_miss"] == 0,
        "lane_epoch_collision_zero": p3["lane_epoch_collision"] == 0,
        "cross_lane_attribution_zero": p9["cross_lane_attribution"] == 0,
        "double_complete_zero": p4["token_double_complete"] == 0,
        "all_gauges_drained": all(value == 0 for value in
                                   diagnostics["drained_gauges"].values()),
        "live_resources_drained": final_snapshot["phase4"]["state"] == [] and
            final_snapshot["phase5"]["state"]["generations"] == [] and
            final_snapshot["phase6"]["state"]["generations"] == [],
        "no_incomplete_publish": p6["incomplete_published"] == 0,
        "no_invalid_publish": p6["invalid_published"] == 0,
        "no_aborted_publish": p6["aborted_published"] == 0,
    }
    if remote_on:
        checks.update({
            "managed_generations_positive": p4["generation_begin"] > 0,
            "remote_start_positive": p5["remote_start_ok"] > 0,
            "remote_grant_start_equal":
                p5["remote_start_granted"] == p5["remote_start_ok"],
            "remote_stop_exact": p5["remote_start_ok"] == p5["remote_stop"],
            "scratch_balanced": p5["remote_scratch_reserved"] > 0 and
                p5["remote_scratch_reserved"] == p5["remote_scratch_returned"],
            "remote_start_integrity": p5["remote_start_incomplete"] == 0 and
                p5["remote_start_nested"] == 0,
            "remote_result_integrity": p5["remote_result_incomplete"] == 0 and
                p5["remote_result_invalid"] == 0,
            "attribution_integrity": p5["mapping_exact_owner_mismatch"] == 0 and
                p5["nested_cross_generation"] == 0,
            "coverage_loss_zero": p6["scratch_overflow"] == 0 and
                p6["aggregate_merge_truncated"] == 0,
            "merge_positive": p6["aggregate_merge_completed"] > 0,
            "publish_positive": p6["aggregate_published"] > 0,
            "extra_files_exact": cover["extra_files"] > 0,
        })
    else:
        checks.update({
            "managed_generations_zero": p4["generation_begin"] == 0,
            "remote_start_zero": p5["remote_start_granted"] == 0 and
                p5["remote_start_ok"] == 0,
            "remote_scratch_zero": p5["remote_scratch_reserved"] == 0,
            "remote_merge_zero": p6["aggregate_merge_completed"] == 0,
            "remote_publish_zero": p6["aggregate_published"] == 0,
            "extra_files_zero": cover["extra_files"] == 0,
        })
    failed = sorted(name for name, passed in checks.items() if not passed)
    return checks, failed


def run_trial(args, modules, phase1, phase9, mode, trial_number, trial_dir):
    trial_dir.mkdir(parents=True)
    (trial_dir / "commands").mkdir()
    remote_on = mode == "on"
    evidence = {
        "schema": 1, "experiment": "nfs-remote-kcov-on-off",
        "mode": mode, "trial": trial_number, "status": "running",
        "started_at": timestamp(), "commands": [],
    }
    vm_args = argparse.Namespace(**vars(args))
    vm_args.output = trial_dir
    vm = phase1.FrozenPhase1VM(vm_args, evidence)
    phase1.write_evidence = write_trial_evidence
    archive = trial_dir / "coverage.tar.gz"
    base_image_hash = sha256(args.image)
    active_root = None
    try:
        vm.start()
        vm.guest("inventory",
                 "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs "
                 "none /sys/kernel/debug; command -v ip nsenter timeout tar "
                 "findmnt pgrep setsid awk ps stat sha256sum", timeout=30)
        vm.put("copy-deps", args.deps_tar, "/tmp/ab-deps.tar.gz")
        vm.put("copy-fixture", args.lane_fixture, "/tmp/ab-lane.sh")
        vm.put("copy-workload", args.workload, "/tmp/ab-workload.prog")
        vm.put("copy-executor", args.syz_executor, "/tmp/ab-syz-executor")
        vm.put("copy-execprog", args.syz_execprog, "/tmp/ab-syz-execprog")
        vm.guest(
            "install-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/ab-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/ab-lane.sh %s/lane.sh; "
            "install -m 0644 /tmp/ab-workload.prog %s/ab-workload.prog; "
            "install -m 0755 /tmp/ab-syz-executor %s/syz-executor; "
            "install -m 0755 /tmp/ab-syz-execprog %s/syz-execprog"
            % ((REMOTE_DRIVER,) * 5), timeout=90)
        root_result = vm.guest("allocate-root",
                               "mktemp -d /tmp/frozen-phase9.XXXXXX")
        active_root = root_result.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-phase9\.[A-Za-z0-9]+", active_root):
            raise ValueError("unsafe fixture root")
        setup = vm.guest(
            "fixture-setup", shlex.join([REMOTE_DRIVER + "/lane.sh", "setup",
                                          active_root, str(args.procs)]),
            timeout=300)
        fixture = phase9.validate_fixture_status(
            json.loads(setup.stdout), args.procs)
        phase9.validate_source_tree(vm, active_root, args.procs)
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        vm.guest("reset-phase9", "printf 'reset\\n' > " + PHASE9_CONTROL)
        baseline = [phase9.lane_snapshot(vm, modules, active_root, lane,
                                         "ab-baseline")
                    for lane in range(args.procs)]
        cpu_before = cpu_snapshot(vm, "cpu-before")
        memory_samples = [phase9.memory_snapshot(vm, "memory-before")]

        command = [
            REMOTE_DRIVER + "/syz-execprog",
            "-executor=" + REMOTE_DRIVER + "/syz-executor",
            "-os=linux", "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
            "-procs=%d" % args.procs, "-repeat=%d" % args.executions,
            "-threaded=false", "-cover=true", "-coverfile=/tmp/ab-cover/cover",
            "-remote-cover=" + str(remote_on).lower(), "-disable=all", "-debug",
            "-vv=1", "-slowdown=1", REMOTE_DRIVER + "/ab-workload.prog",
        ]
        inner = (
            "set +e; rm -rf /tmp/ab-cover; mkdir /tmp/ab-cover; "
            "start=$(date +%%s%%N); timeout %ds %s >/tmp/ab-executor.log 2>&1; "
            "value=$?; end=$(date +%%s%%N); head -n 1 /proc/stat "
            ">/tmp/ab-cpu-after; "
            "printf 'rc %%s\\nstart_ns %%s\\nend_ns %%s\\n' \"$value\" "
            "\"$start\" \"$end\" >/tmp/ab-exec.done; "
            "tar -C /tmp/ab-cover -czf /tmp/ab-cover.tar.gz .; "
            "cp /tmp/ab-exec.done /tmp/ab-run.meta"
            % (args.trial_timeout, shlex.join(command)))
        launch = ("set -eu; rm -f /tmp/ab-run.meta /tmp/ab-exec.done "
                  "/tmp/ab-cpu-after /tmp/ab-executor.log /tmp/ab-cover.tar.gz; "
                  "setsid sh -c %s </dev/null "
                  ">/dev/null 2>&1 & printf '%%s\\n' \"$!\"" %
                  shlex.quote(inner))
        supervisor = vm.guest("executor-start", launch).stdout.strip()
        if not supervisor.isdigit():
            raise ValueError("invalid supervisor PID")
        deadline = time.monotonic() + args.trial_timeout + 60
        while time.monotonic() < deadline:
            result = vm.guest("executor-poll", "test -s /tmp/ab-exec.done",
                              timeout=15, check=False)
            memory_samples.append(phase9.memory_snapshot(vm, "memory-live"))
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise ValueError("executor trial timed out")
        run_meta_text = vm.guest("executor-meta", "cat /tmp/ab-exec.done").stdout
        run_meta = {key: int(value) for key, value in
                    (line.split() for line in run_meta_text.splitlines())}
        cpu_after = parse_cpu_snapshot(vm.guest(
            "cpu-after", "cat /tmp/ab-cpu-after", timeout=15).stdout)
        vm.guest(
            "coverage-archive-wait",
            "set -eu; i=0; while ! test -s /tmp/ab-run.meta; do "
            "i=$((i + 1)); test \"$i\" -lt 300; sleep 1; done",
            timeout=310)
        log = vm.guest("executor-log", "cat /tmp/ab-executor.log",
                       timeout=60, check=False).stdout
        (trial_dir / "executor.log").write_text(log, encoding="utf-8")
        if run_meta.get("rc") != 0:
            raise ValueError("syz-execprog failed rc=%r" % run_meta.get("rc"))
        pull(vm, "pull-coverage", "/tmp/ab-cover.tar.gz", archive)
        names = extract_cover(archive, trial_dir / "coverage")
        functional = validate_executor_log(log, args.executions, args.procs)
        cover = validate_cover_files(trial_dir / "coverage", names,
                                     args.executions, remote_on)
        vm.guest(
            "workload-clean",
            "set -eu; i=0; while test \"$i\" -lt %d; do "
            "for c in client0 client1; do "
            "test ! -e /syz-nfs-lanes/proc-$i/$c/.remote-kcov-ab; "
            "test ! -e /syz-nfs-lanes/proc-$i/$c/.remote-kcov-ab-renamed; "
            "done; i=$((i + 1)); done" % args.procs)
        final = phase9.wait_for_drains(vm, modules, active_root, args.procs,
                                       timeout=45)
        post_memory = phase9.memory_snapshot(vm, "memory-after")
        diagnostics = counter_diagnostics(baseline[0], final[0])
        rpc_delta = sum(final[lane]["nfsd_rpcs"] - baseline[lane]["nfsd_rpcs"]
                        for lane in range(args.procs))
        elapsed = (run_meta["end_ns"] - run_meta["start_ns"]) / 1e9
        cpu_usage = cpu_percent(cpu_before, cpu_after)
        checks, failed = validate_gate(
            mode, diagnostics, functional, cover, rpc_delta,
            memory_samples, cpu_usage, final[0])
        cleanup = phase9.cleanup_fixture(vm, active_root, args.procs, strict=True)
        active_root = None
        dmesg = vm.guest("dmesg", "dmesg", timeout=30, check=False)
        (trial_dir / "dmesg.txt").write_text(dmesg.stdout + dmesg.stderr,
                                                encoding="utf-8")
        if dmesg.returncode or FATAL_RE.search(dmesg.stdout + dmesg.stderr):
            failed.append("kernel_diagnostic_clean")
        kcsan_reports = len(re.findall(r"BUG:\s*KCSAN:",
                                        dmesg.stdout + dmesg.stderr))
        metrics = {
            "kcsan_reports": kcsan_reports,
            "elapsed_seconds": elapsed,
            "executions": args.executions,
            "exec_per_second": args.executions / elapsed,
            "nfsd_rpcs": rpc_delta,
            "rpc_per_second": rpc_delta / elapsed,
            "cpu_utilization_percent": cpu_usage,
            "memory_peak_used_kib": max(item["mem_used_kib"]
                                         for item in memory_samples),
            "memory_peak_process_rss_kib": max(item["process_rss_kib"]
                                                 for item in memory_samples),
            "scratch_peak": final[0]["phase6"]["stats"]["scratch_peak"],
            "aggregate_allocated": diagnostics["phase6"]["aggregate_committed"] +
                diagnostics["phase6"]["aggregate_discarded"],
        }
        evidence.update({
            "status": "pass" if not failed else "fail",
            "completed_at": timestamp(), "fixture": fixture,
            "executor_command": command, "run_meta": run_meta,
            "functional": functional, "coverage_export": cover,
            "coverage_members": names, "diagnostics": diagnostics,
            "metrics": metrics, "memory_samples": memory_samples,
            "post_memory_snapshot": post_memory,
            "checks": checks, "failed_checks": sorted(set(failed)),
            "cleanup": cleanup,
        })
        if failed:
            raise ValueError("trial gate failed: " + ", ".join(sorted(set(failed))))
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__,
                               "message": str(error)}
        evidence["completed_at"] = timestamp()
        raise
    finally:
        if vm.ready and active_root is not None:
            try:
                phase9.cleanup_fixture(vm, active_root, args.procs, strict=False)
            except Exception as cleanup_error:
                evidence.setdefault("cleanup_errors", []).append(str(cleanup_error))
        if vm.ready:
            try:
                vm.guest("emergency-executor-stop",
                         "pkill -KILL -x syz-execprog || true; "
                         "pkill -KILL -x syz-executor || true", check=False)
            except Exception:
                pass
        vm.stop()
        image_hash_after = sha256(args.image)
        evidence["base_image"] = {
            "sha256_before": base_image_hash,
            "sha256_after": image_hash_after,
            "unchanged": image_hash_after == base_image_hash,
        }
        if image_hash_after != base_image_hash:
            evidence["status"] = "fail"
            evidence.setdefault("failed_checks", []).append("base_image_unchanged")
        write_trial_evidence(trial_dir, evidence)
    return evidence


def parse_args(argv=None):
    # Adapted runner copy lives in tools/; keep all module defaults pointing
    # at the handoff repo's scripts (checkpoint artifacts stay untouched).
    work_root = Path(os.environ.get("KOOV_WORK_ROOT",
                                     Path(__file__).resolve().parent.parent))
    scripts = Path(os.environ.get("KOOV_ABRUNNER_DIR",
                                   work_root / "bundle" / "ab-runner"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--vmlinux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    parser.add_argument("--phase8-runner", type=Path,
                        default=scripts / "run_frozen_phase8_vm.py")
    parser.add_argument("--phase9-runner", type=Path,
                        default=scripts / "run_frozen_phase9_vm.py")
    parser.add_argument("--lane-script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--lane-fixture", type=Path,
                        default=scripts / "frozen_phase9_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "nfs_remote_kcov_ab_workload.prog")
    parser.add_argument("--syz-bin", type=Path, default=None,
                        help="syzkaller build root containing "
                             "bin/linux_amd64/; derives --syz-executor and "
                             "--syz-execprog when the individual flags are "
                             "omitted (e.g. an externally built tree)")
    parser.add_argument("--syz-executor", type=Path, default=None,
                        help="explicit executor binary; overrides --syz-bin")
    parser.add_argument("--syz-execprog", type=Path, default=None,
                        help="explicit execprog binary; overrides --syz-bin")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--mode", choices=("both", "off", "on"), default="both",
                        help="run both A/B groups or one screenshot session group")
    parser.add_argument("--executions", type=int, default=60)
    parser.add_argument("--sample-every", type=int, default=10)
    parser.add_argument("--procs", type=int, default=2)
    parser.add_argument("--cpus", type=int, default=8)
    parser.add_argument("--memory", type=int, default=8192)
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--trial-timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.syz_bin is not None:
        args.syz_bin = args.syz_bin.resolve()
        if not args.syz_bin.is_dir():
            parser.error("--syz-bin must be a directory: %s" % args.syz_bin)
    if args.syz_executor is None or args.syz_execprog is None:
        base = (args.syz_bin
                if args.syz_bin is not None else Path(os.environ.get(
                    "KOOV_SYZ_ROOT",
                    "/home/fuzzer/tools/syzkaller-frozen-attribution")))
        if args.syz_executor is None:
            args.syz_executor = base / "bin" / "linux_amd64" / "syz-executor"
        if args.syz_execprog is None:
            args.syz_execprog = base / "bin" / "linux_amd64" / "syz-execprog"
    path_names = ("kernel", "image", "ssh_key", "deps_tar", "vmlinux",
                  "phase1_runner", "phase3_runner", "phase4_runner",
                  "phase5_runner", "phase6_runner", "phase8_runner",
                  "phase9_runner", "lane_script", "lane_fixture", "workload",
                  "syz_executor", "syz_execprog")
    for name in path_names:
        path = getattr(args, name).resolve()
        setattr(args, name, path)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" %
                         (name.replace("_", "-"), path))
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    if args.trials < 1 or args.executions < 1 or args.procs < 1:
        parser.error("trials, executions, and procs must be positive")
    if not 1 <= args.sample_every <= args.executions:
        parser.error("sample-every must be within execution budget")
    return args


def main(argv=None):
    args = parse_args(argv)
    phase1 = load_module("ab_phase1", args.phase1_runner)
    phase3 = load_module("ab_phase3", args.phase3_runner)
    phase4 = load_module("ab_phase4", args.phase4_runner)
    phase5 = load_module("ab_phase5", args.phase5_runner)
    phase6 = load_module("ab_phase6", args.phase6_runner)
    phase8 = load_module("ab_phase8", args.phase8_runner)
    phase9 = load_module("ab_phase9", args.phase9_runner)
    modules = phase9.ModuleBundle([phase3, phase4, phase5, phase6, phase8])
    modules.scale = args.procs
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    args.output.mkdir(parents=True)
    (args.output / "remote_off").mkdir()
    (args.output / "remote_on").mkdir()
    inputs = {name: {"path": str(getattr(args, name)),
                     "sha256": sha256(getattr(args, name))}
              for name in ("kernel", "image", "deps_tar", "vmlinux",
                           "lane_fixture", "workload", "syz_executor",
                           "syz_execprog")}
    manifest = {
        "schema": 1, "status": "running", "started_at": timestamp(),
        "baseline_checkpoint": "7294db9", "inputs": inputs,
        "syz_bin_root": str(args.syz_bin or ""),
        "controls": {
            "trials_per_mode": args.trials, "executions_per_trial": args.executions,
            "sample_every_executions": args.sample_every, "procs": args.procs,
            "lanes": args.procs, "cpus": args.cpus, "memory_mib": args.memory,
            "nfs_version": "4.1", "transport": "tcp", "localio": "disabled",
            "kaslr": "disabled (nokaslr)", "mutation": "disabled",
            "threaded_executor": False,
            "selected_mode": args.mode,
            "only_intended_difference": "FeatureExtraCoverage / remote-cover",
        },
        "trial_order": [],
    }
    write_json(args.output / "experiment_manifest.json", manifest)
    if args.mode == "both":
        order = [(mode, trial) for trial in range(1, args.trials + 1)
                 for mode in (("off", "on") if trial % 2 else ("on", "off"))]
    else:
        order = [(args.mode, trial) for trial in range(1, args.trials + 1)]
    try:
        for mode, trial in order:
            trial_dir = (args.output / ("remote_" + mode) /
                         ("trial_%02d" % trial))
            result = run_trial(args, modules, phase1, phase9, mode, trial,
                               trial_dir)
            manifest["trial_order"].append({
                "mode": mode, "trial": trial,
                "status": result["status"],
                "directory": str(trial_dir.relative_to(args.output)),
            })
            write_json(args.output / "experiment_manifest.json", manifest)
        manifest["status"] = "collected"
        manifest["completed_at"] = timestamp()
    except Exception as error:
        manifest["status"] = "fail"
        manifest["failure"] = {"type": type(error).__name__,
                               "message": str(error)}
        manifest["completed_at"] = timestamp()
        write_json(args.output / "experiment_manifest.json", manifest)
        raise
    write_json(args.output / "experiment_manifest.json", manifest)


if __name__ == "__main__":
    main()
