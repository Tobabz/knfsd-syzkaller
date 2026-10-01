#!/usr/bin/env python3
"""Minimal lane-attribution check for the reduced series.

Boots one VM, brings up the lane fixture, runs a program with syz-execprog
and remote coverage on, and reports .extra coverage (fs/nfsd split), the
sunrpc_fuzz/kcov counters before and after, executor errors and dmesg.
"""
import argparse
import importlib.util
import json
import re
import shlex
import subprocess
import tarfile
import time
from pathlib import Path

HARNESS = Path.home() / "prune-evidence/inputs/run_frozen_phase1_vm.py"
DRV = "/opt/frozen-phase9"
FATAL = re.compile(r"BUG:(?! KCSAN:)|KASAN:|kernel BUG|Kernel panic|Oops:|WARNING:")


def load_phase1():
    spec = importlib.util.spec_from_file_location("phase1", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    for name in ("kernel", "vmlinux", "image", "ssh-key", "deps", "fixture",
                 "workload", "syz-dir", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--executions", type=int, default=30)
    ap.add_argument("--procs", type=int, default=1)
    ap.add_argument("--cpus", type=int, default=6)
    ap.add_argument("--memory", type=int, default=6144)
    ap.add_argument("--boot-timeout", type=int, default=180)
    ap.add_argument("--cmdline-extra", default="")
    args = ap.parse_args()
    args.output.mkdir(parents=True)
    (args.output / "commands").mkdir()
    phase1 = load_phase1()
    evidence = {"commands": []}
    vm = phase1.FrozenPhase1VM(args, evidence)
    if args.cmdline_extra:
        i = vm.qemu.index("-append") + 1
        vm.qemu[i] += " " + args.cmdline_extra
    result = {"workload": str(args.workload), "procs": args.procs,
              "executions": args.executions}
    stats = ("for f in /sys/kernel/debug/sunrpc_fuzz/*_stats; do "
             "echo \"== $f\"; cat $f; done")
    try:
        vm.start()
        vm.guest("debugfs", "mountpoint -q /sys/kernel/debug || "
                 "mount -t debugfs none /sys/kernel/debug")
        vm.put("deps", args.deps, "/tmp/deps.tar.gz")
        vm.put("fixture", args.fixture, "/tmp/lane.sh")
        vm.put("workload", args.workload, "/tmp/w.prog")
        vm.put("executor", args.syz_dir / "bin/linux_amd64/syz-executor", "/tmp/syz-executor")
        vm.put("execprog", args.syz_dir / "bin/linux_amd64/syz-execprog", "/tmp/syz-execprog")
        vm.guest("install", "set -eu; install -d /opt/kcov-nfs/deps %s; "
                 "tar -xzf /tmp/deps.tar.gz -C /opt/kcov-nfs/deps; "
                 "install -m 0755 /tmp/lane.sh %s/lane.sh; "
                 "install -m 0644 /tmp/w.prog %s/w.prog; "
                 "install -m 0755 /tmp/syz-executor %s/syz-executor; "
                 "install -m 0755 /tmp/syz-execprog %s/syz-execprog" % ((DRV,) * 5),
                 timeout=120)
        root = vm.guest("root", "mktemp -d /tmp/frozen-phase9.XXXXXX").stdout.strip()
        setup = vm.guest("setup", shlex.join([DRV + "/lane.sh", "setup", root,
                                              str(args.procs)]), timeout=300)
        result["fixture"] = setup.stdout.strip()[:400]
        vm.guest("grace", "sleep 11", timeout=30)
        result["stats_before"] = vm.guest("stats-before", stats).stdout
        result["lane_state"] = vm.guest(
            "lane-state", "ip netns exec f9l0s nsenter -t 1 -m -- "
            "cat /sys/kernel/debug/sunrpc_fuzz/lane_state", check=False).stdout
        cmd = [DRV + "/syz-execprog", "-executor=" + DRV + "/syz-executor",
               "-os=linux", "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
               "-procs=%d" % args.procs, "-repeat=%d" % args.executions,
               "-threaded=false", "-cover=true", "-coverfile=/tmp/cov/cover",
               "-remote-cover=true", "-disable=all", "-debug", "-vv=1",
               "-slowdown=1", DRV + "/w.prog"]
        run = vm.guest("execprog", "rm -rf /tmp/cov; mkdir /tmp/cov; "
                       "timeout 600 %s > /tmp/exec.log 2>&1; echo rc=$?"
                       % shlex.join(cmd), timeout=700)
        result["execprog_rc"] = run.stdout.strip()
        log = vm.guest("exec-log", "cat /tmp/exec.log", check=False).stdout
        (args.output / "executor.log").write_text(log)
        calls = re.findall(r"CALL (\d+): signal \d+, coverage \d+ errno (\d+)", log)
        result["calls"] = len(calls)
        result["calls_errno_nonzero"] = sum(1 for _, e in calls if e != "0")
        result["errno_by_call"] = sorted({(int(c), int(e)) for c, e in calls if e != "0"})
        vm.guest("drain", "sleep 10", timeout=30)
        result["stats_after"] = vm.guest("stats-after", stats).stdout
        vm.guest("tar", "tar -C /tmp/cov -czf /tmp/cov.tgz .", timeout=120)
        subprocess.run([*vm.scp, "root@127.0.0.1:/tmp/cov.tgz",
                        str(args.output / "cov.tgz")], check=True)
        vm.guest("cleanup", shlex.join([DRV + "/lane.sh", "cleanup", root]),
                 timeout=300, check=False)
        dmesg = vm.guest("dmesg", "dmesg", check=False).stdout
        (args.output / "dmesg.txt").write_text(dmesg)
        result["dmesg_fatal"] = [m.group(0) for m in FATAL.finditer(dmesg)][:5]
    finally:
        vm.stop()
    with tarfile.open(args.output / "cov.tgz") as tf:
        tf.extractall(args.output / "cov", filter="data")
    extra = sorted((args.output / "cov").glob("cover_prog*.extra"))
    pcs = set()
    for f in extra:
        pcs.update(int(t, 16) for t in re.findall(r"0x[0-9a-f]+", f.read_text()))
    result["extra_files"] = len(extra)
    result["extra_nonempty"] = sum(1 for f in extra if f.stat().st_size)
    lines = subprocess.run(["addr2line", "-e", str(args.vmlinux)],
                           input="\n".join(hex(p) for p in sorted(pcs)),
                           capture_output=True, text=True).stdout.splitlines()
    result["extra_pcs"] = len(pcs)
    result["extra_fs_nfsd"] = sum(1 for l in lines if "fs/nfsd/" in l)
    result["extra_net_sunrpc"] = sum(1 for l in lines if "net/sunrpc/" in l)
    (args.output / "result.json").write_text(json.dumps(result, indent=1))
    print(json.dumps({k: v for k, v in result.items()
                      if not k.startswith("stats_") and k != "fixture"}, indent=1))


if __name__ == "__main__":
    main()
