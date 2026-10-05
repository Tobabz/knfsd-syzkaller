#!/usr/bin/env python3
"""Boot one NFS version, record kernel trace events during one stimulus, save the trace.

The stimulus is either a syzkaller program (--seed) run by syz-execprog, or a
shell script (--shell) run inside the guest. The trace file is the only
evidence this tool produces; handoffs.py judges it.
"""
import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "bootstrap", repo / "tools" / "bootstrap-kcov-env.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

TRACEFS = "/sys/kernel/tracing"
ROOT = "/tmp/frozen-phase9.manager"


def read_events(path):
    """events.txt: 'event group:name' or 'kprobe name symbol' lines."""
    events, kprobes = [], []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind, *rest = line.split()
        if kind == "event":
            events.append(rest[0])
        elif kind == "kprobe":
            kprobes.append((rest[0], rest[1]))
        else:
            raise SystemExit("bad events.txt line: " + raw)
    return events, kprobes


def trace_setup(vm, events, kprobes):
    """Enable events, attach kprobes, return the list of kprobes that failed."""
    script = ["set -e",
              "mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing",
              "cd " + TRACEFS,
              "echo 0 > tracing_on",
              "echo > trace",
              "echo 32768 > buffer_size_kb",
              "echo > kprobe_events",
              "echo 0 > events/enable"]
    failed = []
    for name, symbol in kprobes:
        script.append("if echo 'p:koov/%s %s' >> kprobe_events 2>/dev/null; "
                      "then :; else echo KPROBE_FAIL %s >&2; fi" % (name, symbol, symbol))
    for event in events:
        # 'group:pattern' is expanded by the guest shell against events/<group>/.
        # The 'system:glob' form of set_event only matched exact names on this kernel.
        group, pattern = event.split(":")
        script.append("n=0; for d in events/%s/%s; do "
                      "if [ -d \"$d\" ] && echo 1 > \"$d/enable\" 2>/dev/null; "
                      "then n=$((n+1)); fi; done; "
                      "[ $n -gt 0 ] || echo EVENT_FAIL %s >&2" % (group, pattern, event))
    for name, _ in kprobes:
        script.append("test ! -d events/koov/%s || echo 1 > events/koov/%s/enable" % (name, name))
    script.append("echo 1 > tracing_on")
    result = subprocess.run([*vm.ssh, "sh -c '%s'" % "\n".join(script).replace("'", "'\\''")],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError("trace setup failed: " + result.stderr[-1500:])
    failed = [l.split()[1] for l in result.stderr.splitlines() if l.startswith("KPROBE_FAIL")]
    failed += [l.split()[1] for l in result.stderr.splitlines() if l.startswith("EVENT_FAIL")]
    return failed


def fetch_trace(vm, local):
    vm.guest("cd %s && echo 0 > tracing_on && gzip -c trace > /tmp/flow.trace.gz" % TRACEFS,
             timeout=120)
    result = subprocess.run([*vm.ssh, "cat /tmp/flow.trace.gz"], capture_output=True,
                            timeout=300)
    if result.returncode:
        raise RuntimeError("trace fetch failed: " + result.stderr.decode()[-500:])
    local.write_bytes(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=("3", "4.0", "4.1", "4.2"), required=True)
    parser.add_argument("--events", type=Path, default=Path(__file__).with_name("events.txt"))
    parser.add_argument("--seed", type=Path, help="syzkaller program for syz-execprog")
    parser.add_argument("--shell", type=Path, help="shell script run in the guest")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--restart-fixture", action="store_true",
                        help="restart the lane fixture service inside the traced window "
                        "(records server start, grace, rpcbind registration, mounts, session setup)")
    parser.add_argument("--stop-fixture", action="store_true",
                        help="stop the lane fixture service inside the traced window "
                        "(records unmount, session destroy, server stop)")
    parser.add_argument("--settle", type=int, default=0,
                        help="seconds to wait after the stimulus before the trace stops")
    parser.add_argument("--image", type=Path,
                        default=repo / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--kernel", type=Path, default=repo / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path, default=repo / "artifacts/bookworm.id_rsa")
    args = parser.parse_args()
    if args.seed and args.shell:
        raise SystemExit("give at most one of --seed or --shell")
    args.out.mkdir(parents=True, exist_ok=True)
    events, kprobes = read_events(args.events)
    vm = bootstrap.VM(args.image.resolve(), args.kernel.resolve(),
                      args.ssh_key.resolve(), 240, args.version)
    try:
        vm.start()
        state = vm.guest("systemctl is-active frozen-phase9-fixture.service || true").strip()
        if state != "active":
            raise RuntimeError("fixture service %s" % state)
        status = vm.guest("/run/frozen-phase9/lane.sh status " + ROOT)
        (args.out / "fixture-status.json").write_text(status)
        meta = {"nfs_version": args.version, "kernel": str(args.kernel.resolve()),
                "events": events, "kprobes": [k[0] for k in kprobes]}
        meta["kprobe_failed"] = trace_setup(vm, events, kprobes)
        started = time.time()
        if args.restart_fixture:
            vm.guest("systemctl restart frozen-phase9-fixture.service", timeout=600)
        if not args.seed and not args.shell:
            pass
        elif args.seed:
            syz = repo / "env/syzkaller/bin/linux_amd64"
            vm.put(syz / "syz-execprog", "/tmp/syz-execprog")
            vm.put(syz / "syz-executor", "/tmp/syz-executor")
            vm.put(args.seed.resolve(), "/tmp/stimulus.prog")
            vm.guest("chmod 755 /tmp/syz-execprog /tmp/syz-executor")
            output = vm.guest("cd /tmp && ./syz-execprog -executor ./syz-executor -procs 1 "
                              "-repeat 1 -threaded=false -cover -remote-cover -output -vv 2 "
                              "stimulus.prog 2>&1", timeout=600)
            (args.out / "stimulus.log").write_text(output)
        else:
            vm.put(args.shell.resolve(), "/tmp/stimulus.sh")
            # Keep the output and the exit code even when the script fails.
            output = vm.guest("ROOT=%s NFS_VERSION=%s sh -x /tmp/stimulus.sh 2>&1; "
                              "echo STIMULUS_RC=$?" % (ROOT, args.version), timeout=900)
            (args.out / "stimulus.log").write_text(output)
            meta["stimulus_rc"] = int(output.rsplit("STIMULUS_RC=", 1)[1].split()[0])
        if args.settle:
            time.sleep(args.settle)
        if args.stop_fixture:
            vm.guest("systemctl stop frozen-phase9-fixture.service", timeout=600)
        meta["stimulus_seconds"] = round(time.time() - started, 1)
        fetch_trace(vm, args.out / "trace.txt.gz")
        (args.out / "meta.json").write_text(json.dumps(meta, indent=2))
        print("trace saved:", args.out / "trace.txt.gz", "kprobe_failed:", meta["kprobe_failed"])
        if not args.stop_fixture:
            vm.guest("systemctl stop frozen-phase9-fixture.service", timeout=180)
    finally:
        vm.stop()


if __name__ == "__main__":
    sys.exit(main())
