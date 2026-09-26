#!/usr/bin/env python3

# tools/run_frozen_phase9_vm_ganesha.py -- adapted copy of
# bundle/ab-runner/run_frozen_phase9_vm.py.  The upstream file is not modified;
# this copy exists because validate_fixture_status() hard-codes a knfsd-only
# contract and cannot accept a lane served by NFS-Ganesha.
#
# The ONLY change is that the per-lane backend gate accepts EITHER backend:
#
#   * knfsd  -- has worker threads, so /proc/fs/nfsd/threads >= 2.  There is no
#               alternative: the count is the evidence the kernel server is up.
#   * Ganesha -- has no kernel server at all, so /proc/fs/nfsd does not exist
#               and the count is legitimately 0.  Its liveness is asserted by
#               the lane fixture instead (status JSON: ganesha_live,
#               ganesha_listen >= 1, and a distinct ganesha_backing_source, so
#               the second backend really has its own store).
#
# Requiring server_threads >= 2 unconditionally rejected every Ganesha lane.
# Everything else in the contract -- lane id, epoch, proc id, tcp_connections
# >= 2, backing_source -- is unchanged and still enforced.

"""Run Gate 9's 1 -> 2 -> 4 real-executor lane and memory canaries.

The base image is attached only through QEMU's temporary snapshot.  Every
stage creates a fresh set of proc-indexed NFS lanes, runs the real
syz-execprog/syz-executor IPC path, combines exact handshake binding evidence
with live kernel owner/lane state, and strictly destroys the fixture before
scaling.
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
SCALES = (1, 2, 4)
REMOTE_DRIVER = "/opt/frozen-phase9"
EXECUTOR_LANES = "/syz-nfs-lanes"
PHASE3_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
PHASE3_CONNECTIONS = "/sys/kernel/debug/sunrpc_fuzz/phase3_connections"
PHASE4_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase4_stats"
PHASE4_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase4_state"
PHASE5_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase5_stats"
PHASE5_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase5_state"
PHASE6_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase6_stats"
PHASE6_STATE = "/sys/kernel/debug/sunrpc_fuzz/phase6_state"
PHASE8_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase8_stats"
PHASE9_STATS = "/sys/kernel/debug/sunrpc_fuzz/phase9_stats"
PHASE9_CONTROL = "/sys/kernel/debug/sunrpc_fuzz/phase9_control"

FATAL_KERNEL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:|"
    r"refcount_t:|Out of memory:|oom-kill:|Killed process)",
    re.IGNORECASE,
)
CALL_RE = re.compile(
    r"CALL\s+(\d+):\s+signal\s+\d+,\s+coverage\s+\d+\s+errno\s+(\d+)"
)
START_RE = re.compile(
    r"proc\s+(\d+):\s+start executing request\s+(\d+)"
)
RECV_RE = re.compile(
    r"recv exec request\s+(\d+):\s+type=(\d+)\s+flags=0x([0-9a-f]+)\s+"
    r"env=0x([0-9a-f]+)",
    re.IGNORECASE,
)
PROCID_RE = re.compile(r"\bprocid=(\d+)\b")
PRIMARY_WRITE_RE = re.compile(r"<- write=0x24(?:\s|$)")
PRIMARY_READ_RE = re.compile(r"<- read=0x24(?:\s|$)")
PEER_WRITE_RE = re.compile(r"<- write=0x1b(?:\s|$)")
EXPECTED_SUCCESS_CALLS = set(range(20))
BIND_RE = re.compile(
    r"NFS fuzz lane bound: proc=(\d+) "
    r"source=/syz-nfs-lanes/proc-(\d+) target=/nfs-lane"
)
ISOLATION_RE = re.compile(
    r"NFS fuzz lane isolated: proc=(\d+) "
    r"source-tree-hidden=/syz-nfs-lanes"
)


class ModuleBundle(list):
    """Imported older-gate parsers plus the active Gate 9 scale."""

    scale = 0


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
    temporary = output / ".phase9-evidence.json.tmp"
    final = output / "phase9-evidence.json"
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, final)


def json_object(text, context):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(context + " emitted invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(context + " JSON is not an object")
    return value


def nonnegative_delta(before, after, name):
    value = after[name] - before[name]
    if value < 0:
        raise ValueError("counter regressed: " + name)
    return value


def parse_key_values(text, context):
    values = {}
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split()
        if not fields:
            continue
        if len(fields) != 2 or not re.fullmatch(r"[a-z][a-z0-9_]*", fields[0]):
            raise ValueError("invalid %s line %d: %r" % (context, number, raw))
        if fields[0] in values:
            raise ValueError("duplicate %s key: %s" % (context, fields[0]))
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("invalid %s value: %s" %
                             (context, fields[0])) from error
        if values[fields[0]] < 0:
            raise ValueError("negative %s value: %s" %
                             (context, fields[0]))
    return values


def memory_snapshot(vm, stage):
    command = r"""set -eu
awk '
$1 == "MemTotal:" { print "mem_total_kib", $2 }
$1 == "MemAvailable:" { print "mem_available_kib", $2 }
$1 == "Slab:" { print "slab_kib", $2 }
$1 == "SUnreclaim:" { print "sunreclaim_kib", $2 }
$1 == "PageTables:" { print "page_tables_kib", $2 }
$1 == "KernelStack:" { print "kernel_stack_kib", $2 }
$1 == "Committed_AS:" { print "committed_as_kib", $2 }
' /proc/meminfo
awk '$1 == "oom_kill" { print "vmstat_oom_kill", $2; found=1 }
     END { if (!found) print "vmstat_oom_kill 0" }' /proc/vmstat
if test -r /sys/fs/cgroup/memory.events; then
    awk '$1 == "oom" { print "cgroup_oom", $2 }
         $1 == "oom_kill" { print "cgroup_oom_kill", $2 }' \
        /sys/fs/cgroup/memory.events
else
    printf 'cgroup_oom 0\ncgroup_oom_kill 0\n'
fi
ps -e -o rss= | awk '{ total += $1 } END { print "process_rss_kib", total + 0 }'
"""
    values = parse_key_values(
        vm.guest(stage, command, timeout=20).stdout, "memory snapshot"
    )
    required = {
        "mem_total_kib", "mem_available_kib", "slab_kib",
        "sunreclaim_kib", "page_tables_kib", "kernel_stack_kib",
        "committed_as_kib", "vmstat_oom_kill", "cgroup_oom",
        "cgroup_oom_kill", "process_rss_kib",
    }
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError("memory snapshot missing: " + ", ".join(missing))
    values["mem_used_kib"] = (
        values["mem_total_kib"] - values["mem_available_kib"]
    )
    return values


def lane_command(root, lane, command):
    del root
    server_namespace = "f9l%ds" % lane
    return (
        "set -eu; test -e /run/netns/%s; "
        "exec nsenter --net=/run/netns/%s -- sh -c %s"
        % (server_namespace, server_namespace, shlex.quote(command))
    )


def lane_read(vm, root, lane, stage, path):
    return vm.guest(
        stage,
        lane_command(root, lane, "cat " + shlex.quote(path)),
        timeout=20,
    ).stdout


def parse_nfsd_rpc(text):
    for raw in text.splitlines():
        fields = raw.split()
        if len(fields) >= 2 and fields[0] == "rpc":
            try:
                value = int(fields[1], 0)
            except ValueError as error:
                raise ValueError("invalid nfsd rpc counter") from error
            if value < 0:
                raise ValueError("negative nfsd rpc counter")
            return value
    raise ValueError("missing nfsd rpc counter")


def parse_phase9_stats(text):
    values = parse_key_values(text, "Phase 9 stats")
    required = {"owner_lane_match", "cross_lane_attribution", "lane_seen_mask"}
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError("missing Phase 9 stats: " + ", ".join(missing))
    return values


def lane_snapshot(vm, modules, root, lane, stage):
    phase3, phase4, phase5, phase6, phase8 = modules
    prefix = "scale%d-lane%d-%s" % (modules.scale, lane, stage)
    return {
        "phase3": phase3.parse_counter_file(lane_read(
            vm, root, lane, prefix + "-phase3", PHASE3_STATS)),
        "phase4": {
            "stats": phase4.parse_stats(lane_read(
                vm, root, lane, prefix + "-phase4-stats", PHASE4_STATS)),
            "state": lane_read(
                vm, root, lane, prefix + "-phase4-state", PHASE4_STATE
            ).splitlines(),
        },
        "phase5": {
            "stats": phase5.parse_stats(lane_read(
                vm, root, lane, prefix + "-phase5-stats", PHASE5_STATS)),
            "state": phase5.parse_state(lane_read(
                vm, root, lane, prefix + "-phase5-state", PHASE5_STATE)),
        },
        "phase6": {
            "stats": phase6.parse_stats(lane_read(
                vm, root, lane, prefix + "-phase6-stats", PHASE6_STATS)),
            "state": phase6.parse_state(lane_read(
                vm, root, lane, prefix + "-phase6-state", PHASE6_STATE)),
        },
        "phase8": phase8.parse_stats(lane_read(
            vm, root, lane, prefix + "-phase8", PHASE8_STATS)),
        "phase9": parse_phase9_stats(lane_read(
            vm, root, lane, prefix + "-phase9", PHASE9_STATS)),
        "nfsd_rpcs": parse_nfsd_rpc(lane_read(
            vm, root, lane, prefix + "-nfsd", "/proc/net/rpc/nfsd")),
    }


def read_live_phase5(vm, phase5, root, scale, attempt):
    states = []
    for lane in range(scale):
        text = lane_read(
            vm, root, lane,
            "scale%d-live-%02d-lane%d" % (scale, attempt, lane),
            PHASE5_STATE,
        )
        states.append(phase5.parse_state(text))
    return states


def validate_fixture_status(value, scale):
    lanes = value.get("lanes")
    if (value.get("localio") != "N" or
            int(value.get("lane_count", 0)) != scale or
            not isinstance(lanes, list) or len(lanes) != scale):
        raise ValueError("Phase 9 fixture status contract failed")
    for lane, item in enumerate(lanes):
        if (not isinstance(item, dict) or int(item.get("lane_id", -1)) != lane or
                int(item.get("lane_epoch", 0)) <= 0 or
                int(item.get("proc", -1)) != lane or
                int(item.get("tcp_connections", 0)) < 2 or
                item.get("backing_source") != "frozen-phase9-lane%d" % lane):
            raise ValueError("invalid Phase 9 lane status: %r" % item)
        # Backend gate.  Reached only for a dict, so item.get is safe here.
        knfsd_serving = int(item.get("server_threads", 0)) >= 2
        ganesha_serving = (int(item.get("ganesha_live", 0)) == 1 and
                           int(item.get("ganesha_listen", 0)) >= 1 and
                           bool(item.get("ganesha_backing_source")))
        if not (knfsd_serving or ganesha_serving):
            raise ValueError(
                "no serving backend on Phase 9 lane %d: server_threads=%r "
                "ganesha_live=%r ganesha_listen=%r" % (
                    lane, item.get("server_threads"),
                    item.get("ganesha_live"), item.get("ganesha_listen")))
    epochs = [int(item["lane_epoch"]) for item in lanes]
    if len(set(epochs)) != scale:
        raise ValueError("Phase 9 lane epochs are not globally unique")
    return value


def validate_source_tree(vm, root, scale):
    command = r"""set -eu
root=%s
count=%d
test "$(cat /syz-nfs-lanes/enabled)" = 1
test "$(cat /syz-nfs-lanes/.lane_count)" -eq "$count"
i=0
while test "$i" -lt "$count"; do
    source=/syz-nfs-lanes/proc-$i
    test -d "$source/client0"
    test -d "$source/client1"
    test -f "$source/.lane_id"
    test "$(cat "$source/.lane_id")" -eq "$i"
    test "$(find "$source" -mindepth 1 -maxdepth 1 -printf '%%f\n' | sort | tr '\n' ' ')" = ".client0_netns .client0_pid .client1_netns .client1_pid .lane_id .server0_ipv4 .server1_ipv4 client0 client1 "
    mountpoint -q "$source/.client0_netns"
    mountpoint -q "$source/.client1_netns"
    test "$(findmnt -n -o FSTYPE -T "$source/client0")" = nfs4
    test "$(findmnt -n -o FSTYPE -T "$source/client1")" = nfs4
    printf 'proc %%s source %%s epoch %%s client0 %%s client1 %%s\n' \
        "$i" "$source" "$(cat "$root/lane$i/lane_epoch")" \
        "$(findmnt -n -o SOURCE -T "$source/client0")" \
        "$(findmnt -n -o SOURCE -T "$source/client1")"
    i=$((i + 1))
done
test "$(find /syz-nfs-lanes -mindepth 1 -maxdepth 1 -type d -name 'proc-*' | wc -l)" -eq "$count"
""" % (shlex.quote(root), scale)
    return vm.guest(
        "scale%d-source-tree" % scale, command, timeout=30
    ).stdout.splitlines()


def start_executor(vm, root, scale, execution_waves):
    # -repeat is a global rpcserver request count.  Multiplying by scale
    # supplies enough work for every fixed proc, but does not assume that the
    # scheduler gives every proc the same number of requests.
    total = scale * execution_waves
    stem = "/tmp/frozen-phase9-executor-%d" % scale
    log = stem + ".log"
    rc = stem + ".rc"
    command = [
        REMOTE_DRIVER + "/syz-execprog",
        "-executor=" + REMOTE_DRIVER + "/syz-executor",
        "-os=linux", "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
        "-procs=%d" % scale, "-repeat=%d" % total,
        "-threaded=false", "-cover=true", "-disable=all", "-debug",
        "-output", "-vv=1", "-slowdown=1",
        REMOTE_DRIVER + "/phase9-probe.prog",
    ]
    inner = (
        "set +e; timeout 180s %s >%s 2>&1; value=$?; "
        "printf '%%s\\n' \"$value\" >%s"
        % (shlex.join(command), shlex.quote(log), shlex.quote(rc))
    )
    launch = (
        "set -eu; rm -f %s %s; setsid sh -c %s </dev/null >/dev/null 2>&1 & "
        "printf '%%s\\n' \"$!\""
        % (shlex.quote(log), shlex.quote(rc), shlex.quote(inner))
    )
    result = vm.guest("scale%d-executor-start" % scale, launch, timeout=20)
    pid = result.stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise ValueError("invalid executor supervisor PID: %r" % pid)
    return {"pid": int(pid), "log": log, "rc": rc,
            "command": command, "expected_executions": total}


def run_fail_closed_probe(vm):
    """A mismatched proc source must kill handshake, never select a fallback."""
    command = [
        REMOTE_DRIVER + "/syz-execprog",
        "-executor=" + REMOTE_DRIVER + "/syz-executor",
        "-os=linux", "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
        "-procs=1", "-repeat=1", "-threaded=false", "-cover=true",
        "-disable=all", "-debug", "-output", "-vv=1", "-slowdown=1",
        REMOTE_DRIVER + "/phase9-probe.prog",
    ]
    script = """set -eu
source=/syz-nfs-lanes/proc-0/.lane_id
test "$(cat "$source")" = 0
restore()
{
    printf '0\n' > "$source"
}
trap restore EXIT HUP INT TERM
printf '1\n' > "$source"
set +e
timeout 45s %s
value=$?
set -e
restore
trap - EXIT HUP INT TERM
test "$(cat "$source")" = 0
printf '\nPHASE9_FAIL_CLOSED_RC=%%s\n' "$value"
""" % shlex.join(command)
    result = vm.guest("scale1-executor-fail-closed", script,
                      timeout=60, check=False)
    if result.returncode:
        raise ValueError("could not complete executor fail-closed preflight")
    match = re.search(r"PHASE9_FAIL_CLOSED_RC=(\d+)", result.stdout +
                      result.stderr)
    if not match:
        raise ValueError("missing executor fail-closed status")
    returncode = int(match.group(1))
    if returncode in (0, 124):
        raise ValueError(
            "mismatched executor lane did not fail closed promptly rc=%d" %
            returncode)
    if BIND_RE.search(result.stdout + result.stderr):
        raise ValueError("mismatched executor lane emitted successful bind")
    if "NFS fuzz lane marker mismatch" not in result.stdout + result.stderr:
        raise ValueError("executor did not report the mismatched lane marker")
    vm.guest("scale1-fail-closed-process-drain",
             "set -eu; ! pgrep -x syz-executor; ! pgrep -x syz-execprog",
             timeout=20)
    return {"status": "pass", "returncode": returncode,
            "command": command,
            "tail": (result.stdout + result.stderr)[-8000:].splitlines()}


def executor_mount_snapshot(vm, scale, attempt):
    command = r"""set -eu
found=0
for comm_path in /proc/[0-9]*/comm; do
    test -r "$comm_path" || continue
    comm=$(cat "$comm_path" 2>/dev/null || true)
    case "$comm" in
        syz-executor|syz.[0-9]*.[0-9]*) ;;
        *) continue ;;
    esac
    pid=${comm_path#/proc/}
    pid=${pid%%/*}
    enter="nsenter -t $pid -m --root=/proc/$pid/root --wd=/ --"
    if $enter test -r /nfs-lane/.lane_id 2>/dev/null; then
        lane=$($enter cat /nfs-lane/.lane_id)
        $enter test -d /nfs-lane/client0
        $enter test -d /nfs-lane/client1
        $enter test ! -e /syz-nfs-lanes/enabled
        entries=$($enter find /nfs-lane -mindepth 1 -maxdepth 1 -printf '%%f ')
        printf 'pid %%s lane %%s entries %%s\n' "$pid" "$lane" "$entries"
        found=$((found + 1))
    fi
done
test "$found" -gt 0
"""
    result = vm.guest(
        "scale%d-executor-mounts-%02d" % (scale, attempt), command,
        timeout=20, check=False,
    )
    lanes = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            match = re.match(r"pid (\d+) lane (\d+) entries (.*)", line)
            if not match:
                raise ValueError("invalid executor mount evidence: " + line)
            lanes.append(int(match.group(2)))
    return {"returncode": result.returncode,
            "lines": result.stdout.splitlines(), "lanes": lanes}


def executor_diagnostic(vm, scale, background, label):
    command = (
        "set +e; printf 'rc='; "
        "if test -s %s; then cat %s; else printf 'PENDING\\n'; fi; "
        "printf '%%s\\n' '--- executor log ---'; tail -n 240 %s 2>&1"
        % (shlex.quote(background["rc"]), shlex.quote(background["rc"]),
           shlex.quote(background["log"])))
    result = vm.guest(
        "scale%d-executor-diagnostic-%s" % (scale, label), command,
        timeout=30, check=False,
    )
    return (result.stdout + result.stderr)[-24000:]


def wait_for_live_mapping(vm, phase5, root, scale, samples, background,
                          timeout=25):
    deadline = time.monotonic() + timeout
    attempt = 0
    latest_states = []
    mount_evidence = {"returncode": 1, "lines": [], "lanes": []}
    while time.monotonic() < deadline:
        attempt += 1
        samples.append(memory_snapshot(
            vm, "scale%d-memory-live-%02d" % (scale, attempt)))
        mount_evidence = executor_mount_snapshot(vm, scale, attempt)
        mounts_ready = set(mount_evidence["lanes"]) == set(range(scale))
        if mounts_ready:
            break
        time.sleep(0.1)
    else:
        diagnostic = executor_diagnostic(
            vm, scale, background, "live-timeout")
        raise ValueError(
            "executor lane mount namespaces did not become simultaneously "
            "observable: %r executor_tail=%r"
            % (mount_evidence, diagnostic)
        )

    # Generation rows are kernel-global and can change between sequential SSH
    # reads.  Read each netns only to validate its persistent lane row; exact
    # owner attribution is established by the proc/lane bind evidence plus the
    # post-run Phase 4/5/9 accounting under the kernel locks.
    latest_states = read_live_phase5(vm, phase5, root, scale, attempt)
    observed_generations = set()
    mapping = []
    for lane, state in enumerate(latest_states):
        generations = state["generations"]
        lane_rows = [row for row in state["lanes"] if row["valid"]]
        if (len(lane_rows) != 1 or lane_rows[0]["lane_id"] != lane or
                lane_rows[0]["unhealthy"] != 0):
            raise ValueError("live lane state mismatch: %r" % lane_rows)
        if any(int(item["issues"]) != 0 for item in generations):
            raise ValueError("live generation reports attribution issues")
        observed_generations.update(
            int(item["generation"]) for item in generations)
        mapping.append({
            "proc_id": lane, "expected_owner": lane + 1,
            "lane_id": lane, "lane_epoch": lane_rows[0]["lane_epoch"],
            "observed_generations": sorted(
                int(item["generation"]) for item in generations),
        })
    return {"mapping": mapping, "phase5_states": latest_states,
            "expected_owners": list(range(1, scale + 1)),
            "observed_generations": sorted(observed_generations),
            "executor_mounts": mount_evidence}


def finish_executor(vm, scale, background, timeout=190):
    command = """set -eu
i=0
while ! test -s %s; do
    i=$((i + 1))
    test "$i" -lt %d
    sleep 1
done
cat %s
""" % (shlex.quote(background["rc"]), timeout,
         shlex.quote(background["rc"]))
    result = vm.guest(
        "scale%d-executor-wait" % scale, command, timeout=timeout + 10
    )
    rc_text = result.stdout.strip()
    log_result = vm.guest(
        "scale%d-executor-log" % scale,
        "cat " + shlex.quote(background["log"]), timeout=30, check=False,
    )
    log = log_result.stdout + log_result.stderr
    vm.guest(
        "scale%d-executor-log-clean" % scale,
        "rm -f %s %s" % (shlex.quote(background["log"]),
                          shlex.quote(background["rc"])), timeout=20,
        check=False,
    )
    if log_result.returncode:
        raise ValueError(
            "scale %d executor log collection failed rc=%d" %
            (scale, log_result.returncode))
    if not rc_text.isdigit() or int(rc_text):
        raise ValueError(
            "scale %d executor failed rc=%r log_tail=%r" %
            (scale, rc_text, log[-8000:].splitlines()))
    return log


def verify_and_remove_canaries(vm, scale):
    """Verify exact bytes through each proc's two imported NFS clients."""
    command = r"""set -eu
check_file()
{
    path=$1
    size=$2
    digest=$3
    test -f "$path"
    test "$(stat -c %%s "$path")" -eq "$size"
    actual=$(sha256sum "$path" | awk '{print $1}')
    test "$actual" = "$digest"
    printf 'lane %%s client %%s bytes %%s sha256 %%s\n' \
        "$lane" "$client" "$size" "$actual"
}
lane=0
while test "$lane" -lt %d; do
    base=/syz-nfs-lanes/proc-$lane
    client=client0
    primary=$base/client0/.phase9-executor
    check_file "$primary" 36 \
        263c6e623968482287e39fd2d2b67ae3ce7125ae7ffc222b432dc029738f29e6
    client=client1
    peer=$base/client1/.phase9-peer
    check_file "$peer" 27 \
        26af4fb8869a3550b1b46700ac833cc0537ffdb241bb97deedf8867f15f3d353
    rm -f -- "$primary" "$peer"
    test ! -e "$primary"
    test ! -e "$peer"
    lane=$((lane + 1))
done
""" % scale
    lines = vm.guest(
        "scale%d-canary-content" % scale, command, timeout=30
    ).stdout.splitlines()
    if len(lines) != scale * 2:
        raise ValueError("incomplete exact canary evidence: %r" % lines)
    return {
        "status": "pass",
        "exact_content_and_lengths": True,
        "removed_after_validation": True,
        "lines": lines,
    }


def validate_executor_log(log, scale, expected_executions):
    calls = [(int(index), int(error)) for index, error in CALL_RE.findall(log)]
    counts = {}
    for index, error in calls:
        counts[index] = counts.get(index, 0) + 1
        if index in EXPECTED_SUCCESS_CALLS and error != 0:
            raise ValueError("executor NFS/probe call %d failed errno=%d" %
                             (index, error))
        if index not in EXPECTED_SUCCESS_CALLS:
            raise ValueError("unexpected executor call index: %d" % index)
    expected_indexes = EXPECTED_SUCCESS_CALLS
    if set(counts) != expected_indexes or any(
            counts[index] != expected_executions for index in expected_indexes):
        raise ValueError("executor call accounting mismatch: %r" % counts)
    requests = {
        int(request): {
            "type": int(request_type),
            "flags": int(flags, 16),
            "env": int(env, 16),
        }
        for request, request_type, flags, env in RECV_RE.findall(log)
    }
    started = [(int(proc), int(request))
               for proc, request in START_RE.findall(log)]
    main_request_ids = {
        request for request, item in requests.items()
        if item["type"] == 0 and item["flags"] == 0
    }
    starts = {}
    for proc, request in started:
        if request not in main_request_ids:
            continue
        starts[proc] = starts.get(proc, 0) + 1
    if set(starts) != set(range(scale)) or any(
            count <= 0 for count in starts.values()):
        raise ValueError("executor start proc IDs mismatch: %r" % starts)
    if sum(starts.values()) != expected_executions:
        raise ValueError(
            "executor request start accounting mismatch: %r expected=%d" %
            (starts, expected_executions))
    if len(main_request_ids) != expected_executions:
        raise ValueError(
            "executor main request receive accounting mismatch: %r expected=%d"
            % (sorted(main_request_ids), expected_executions))
    first_main_start = min(
        match.start() for match in START_RE.finditer(log)
        if int(match.group(2)) in main_request_ids)
    first_main_result = next(
        match.start() for match in CALL_RE.finditer(log)
        if match.start() > first_main_start and int(match.group(1)) == 0)
    concurrent_start_procs = sorted({
        int(match.group(1)) for match in START_RE.finditer(log)
        if (first_main_start <= match.start() < first_main_result and
            int(match.group(2)) in main_request_ids)
    })
    if concurrent_start_procs != list(range(scale)):
        raise ValueError(
            "not all proc workers started before the first workload result: "
            "%r" % concurrent_start_procs)
    # Feature probing runs before the supplied programs.  Only a successfully
    # started feature request carrying ExecEnvExtraCover (bit 8) opens a
    # managed Generation and therefore belongs in kernel generation deltas.
    extra_feature_requests = {
        request for request, item in requests.items()
        if item["type"] == 0 and item["flags"] != 0 and
        item["env"] & 0x100
    }
    extra_feature_starts = sum(
        request in extra_feature_requests for _proc, request in started)
    proc_ids = set(starts) | {int(proc) for proc in PROCID_RE.findall(log)}
    if proc_ids != set(range(scale)):
        raise ValueError("executor proc IDs mismatch: %r" % sorted(proc_ids))
    bindings = {(int(proc), int(source))
                for proc, source in BIND_RE.findall(log)}
    expected_bindings = {(proc, proc) for proc in range(scale)}
    if bindings != expected_bindings:
        raise ValueError("executor lane binding log mismatch: %r" %
                         sorted(bindings))
    isolations = {int(proc) for proc in ISOLATION_RE.findall(log)}
    if isolations != set(range(scale)):
        raise ValueError(
            "executor source-tree isolation log mismatch: %r" %
            sorted(isolations))
    exact_lengths = {
        "primary_write_36": len(PRIMARY_WRITE_RE.findall(log)),
        "primary_read_36": len(PRIMARY_READ_RE.findall(log)),
        "peer_write_27": len(PEER_WRITE_RE.findall(log)),
    }
    if any(count != expected_executions
           for count in exact_lengths.values()):
        raise ValueError(
            "executor exact I/O length accounting mismatch: %r" %
            exact_lengths)
    return {
        "call_counts": {str(key): counts[key] for key in sorted(counts)},
        "proc_ids": sorted(proc_ids),
        "executions_by_proc": {str(proc): starts[proc]
                               for proc in sorted(starts)},
        "exact_io_lengths": exact_lengths,
        "request_starts_total": sum(starts.values()),
        "configured_total_requests": expected_executions,
        "main_request_ids": sorted(main_request_ids),
        "concurrent_start_procs": concurrent_start_procs,
        "extra_cover_feature_starts": extra_feature_starts,
        "expected_generation_executions": (
            expected_executions + extra_feature_starts),
        "bindings": [{"proc_id": proc, "source_proc_id": source}
                     for proc, source in sorted(bindings)],
        "source_tree_hidden_by_proc": sorted(isolations),
        "bytes": len(log.encode("utf-8")),
        "tail": log[-8000:].splitlines(),
    }


def mapping_from_executor(executor, epochs, scale):
    """Build fixed-lane evidence from successful executor bind handshakes.

    The bind diagnostic is emitted only after the proc-specific source was
    mounted into that executor's private chroot.  Exact NFS canary content and
    the kernel Phase 9 owner/lane counters validate the data and attribution
    sides after this structural mapping is established.
    """
    bindings = {(item["proc_id"], item["source_proc_id"])
                for item in executor["bindings"]}
    expected = {(proc, proc) for proc in range(scale)}
    if bindings != expected:
        raise ValueError("executor fixed-lane bindings differ: %r" %
                         sorted(bindings))
    return {
        "source": "successful executor private-chroot bind diagnostics",
        "mapping": [
            {
                "proc_id": proc,
                "expected_owner": proc + 1,
                "lane_id": proc,
                "lane_epoch": epochs[proc],
            }
            for proc in range(scale)
        ],
        "expected_owners": list(range(1, scale + 1)),
        "bindings": executor["bindings"],
    }


def resources_drained(snapshot):
    phase4 = snapshot["phase4"]
    phase5 = snapshot["phase5"]
    phase6 = snapshot["phase6"]
    phase8 = snapshot["phase8"]
    return (
        phase4["stats"]["outstanding_tokens"] == 0 and
        phase4["stats"]["object_refs"] == 0 and
        not phase4["state"] and
        not phase5["state"]["generations"] and
        all(value == 0 for value in phase5["state"]["live"].values()) and
        not phase6["state"]["generations"] and
        all(value == 0 for value in phase6["state"]["live"].values()) and
        all(phase8[name] == 0 for name in (
            "live_saved_work", "abort_next_deferred_armed",
            "abort_next_async_armed", "pause_next_deferred_armed",
            "pause_next_async_armed", "deferred_direct_active",
            "async_direct_active"))
    )


def wait_for_drains(vm, modules, root, scale, timeout=30):
    deadline = time.monotonic() + timeout
    attempt = 0
    latest = []
    while time.monotonic() < deadline:
        attempt += 1
        latest = [lane_snapshot(
            vm, modules, root, lane, "drain-%02d" % attempt
        ) for lane in range(scale)]
        if all(resources_drained(item) for item in latest):
            return latest
        time.sleep(0.5)
    raise ValueError("Phase 9 resources did not drain: %r" % latest)


def validate_stage(scale, baseline, final, mapping, executor,
                   memory_samples, args, modules):
    checks = {}
    rpc_deltas = []
    for lane in range(scale):
        before = baseline[lane]
        after = final[lane]
        prefix = "lane%d_" % lane
        checks[prefix + "fixed_owner"] = (
            mapping["mapping"][lane]["proc_id"] == lane and
            mapping["mapping"][lane]["expected_owner"] == lane + 1 and
            mapping["mapping"][lane]["lane_id"] == lane and
            {item["proc_id"] for item in executor["bindings"]
             if item["source_proc_id"] == lane} == {lane})
        lane_rows = [row for row in after["phase5"]["state"]["lanes"]
                     if row["valid"]]
        checks[prefix + "lane_healthy"] = (
            len(lane_rows) == 1 and lane_rows[0]["lane_id"] == lane and
            lane_rows[0]["lane_epoch"] ==
            mapping["mapping"][lane]["lane_epoch"] and
            lane_rows[0]["unhealthy"] == 0)
        checks[prefix + "resources_drained"] = resources_drained(after)
        rpc_delta = after["nfsd_rpcs"] - before["nfsd_rpcs"]
        rpc_deltas.append(rpc_delta)
        checks[prefix + "real_nfsd_rpcs_positive"] = rpc_delta > 0

    # Phase 3-8 counters and generation rows are kernel-global.  Use exactly
    # one snapshot for accounting; the per-netns reads above exist only to
    # validate each lane row and its distinct nfsd RPC counter.
    global_before = baseline[0]
    global_after = final[0]
    phase4_before = global_before["phase4"]["stats"]
    phase4_after = global_after["phase4"]["stats"]
    phase5_before = global_before["phase5"]["stats"]
    phase5_after = global_after["phase5"]["stats"]
    phase6_before = global_before["phase6"]["stats"]
    phase6_after = global_after["phase6"]["stats"]
    execution_delta = nonnegative_delta(
        global_before["phase4"]["stats"],
        global_after["phase4"]["stats"], "generation_begin")
    committed_delta = nonnegative_delta(
        global_before["phase4"]["stats"],
        global_after["phase4"]["stats"], "generation_committed")
    actual_starts = sum(executor["executions_by_proc"].values())
    checks["all_executor_generations_accounted"] = (
        execution_delta == executor["expected_generation_executions"] and
        committed_delta == execution_delta)
    checks["every_proc_executed"] = (
        set(map(int, executor["executions_by_proc"])) == set(range(scale)) and
        all(count > 0 for count in executor["executions_by_proc"].values()))
    checks["all_proc_workers_concurrent"] = (
        executor["concurrent_start_procs"] == list(range(scale)))
    checks["remote_scratch_peak_positive_and_monotonic"] = (
        phase6_after["scratch_peak"] > 0 and
        phase6_after["scratch_peak"] >= phase6_before["scratch_peak"])
    checks["every_proc_lane_binding"] = (
        {(item["proc_id"], item["source_proc_id"])
         for item in mapping["bindings"]} ==
        {(proc, proc) for proc in range(scale)})
    checks["all_generations_remote_result_initialized_valid"] = (
        nonnegative_delta(
            global_before["phase5"]["stats"],
            global_after["phase5"]["stats"], "remote_result_valid") ==
        execution_delta)
    checks["exact_owner_mapping_observed"] = nonnegative_delta(
        global_before["phase5"]["stats"],
        global_after["phase5"]["stats"],
        "mapping_exact_owner_match") > 0
    checks["no_owner_mismatch"] = nonnegative_delta(
        global_before["phase5"]["stats"],
        global_after["phase5"]["stats"],
        "mapping_exact_owner_mismatch") == 0
    checks["no_cross_generation"] = nonnegative_delta(
        global_before["phase5"]["stats"],
        global_after["phase5"]["stats"], "nested_cross_generation") == 0
    checks["no_lane_unhealthy_event"] = nonnegative_delta(
        global_before["phase5"]["stats"],
        global_after["phase5"]["stats"], "lane_unhealthy") == 0
    checks["phase3_attribution_clean"] = all(
        global_after["phase3"][name] == 0 for name in (
            "lane_epoch_collision", "lane_epoch_immutable_violation",
            "connection_pair_miss", "connection_pair_expired",
            "connection_cookie_reuse", "direction_role_mismatch",
            "ordinal_mismatch", "tcp_retransmit_ordinal_increment",
            "wire_attempt_postcommit_incomplete",
            "corrupted_connection_closed"))
    checks["phase3_connections_paired"] = (
        global_after["phase3"]["connection_pair_ok"] >= scale * 2)
    checks["phase3_c2s_ordinals_aligned"] = (
        global_after["phase3"]["ordinal_tx_c2s"] ==
        global_after["phase3"]["ordinal_rx_c2s"])
    checks["phase3_s2c_ordinals_aligned"] = (
        global_after["phase3"]["ordinal_tx_s2c"] ==
        global_after["phase3"]["ordinal_rx_s2c"])
    checks["direct_owner_lane_matches_observed"] = nonnegative_delta(
        global_before["phase9"], global_after["phase9"],
        "owner_lane_match") > 0
    checks["direct_cross_lane_attribution_zero"] = nonnegative_delta(
        global_before["phase9"], global_after["phase9"],
        "cross_lane_attribution") == 0
    checks["direct_lane_seen_mask_exact"] = (
        global_after["phase9"]["lane_seen_mask"] == (1 << scale) - 1)
    checks["phase9_reset_baseline_clean"] = all(
        global_before["phase9"][name] == 0 for name in (
            "owner_lane_match", "cross_lane_attribution", "lane_seen_mask"))

    attributed_work = {
        "phase4_child_token_granted": nonnegative_delta(
            phase4_before, phase4_after, "child_token_granted"),
        "phase4_wire_token_server_consumed": nonnegative_delta(
            phase4_before, phase4_after, "wire_token_server_consumed"),
        "phase5_mapping_exact_owner_match": nonnegative_delta(
            phase5_before, phase5_after, "mapping_exact_owner_match"),
        "phase5_remote_grant_attempt": nonnegative_delta(
            phase5_before, phase5_after, "remote_grant_attempt"),
        "phase5_wire_work_attached": nonnegative_delta(
            phase5_before, phase5_after, "wire_work_attached"),
        "phase5_wire_work_terminal": nonnegative_delta(
            phase5_before, phase5_after, "wire_work_terminal"),
        "phase5_remote_start_granted": nonnegative_delta(
            phase5_before, phase5_after, "remote_start_granted"),
        "phase5_remote_start_ok": nonnegative_delta(
            phase5_before, phase5_after, "remote_start_ok"),
        "phase5_remote_stop": nonnegative_delta(
            phase5_before, phase5_after, "remote_stop"),
        "phase5_ticket_created": nonnegative_delta(
            phase5_before, phase5_after, "remote_ticket_created"),
        "phase5_ticket_completed": nonnegative_delta(
            phase5_before, phase5_after, "remote_ticket_completed"),
        "phase5_scratch_reserved": nonnegative_delta(
            phase5_before, phase5_after, "remote_scratch_reserved"),
        "phase5_scratch_returned": nonnegative_delta(
            phase5_before, phase5_after, "remote_scratch_returned"),
        "phase5_target_pinned": nonnegative_delta(
            phase5_before, phase5_after, "remote_target_pinned"),
        "phase5_target_unpinned": nonnegative_delta(
            phase5_before, phase5_after, "remote_target_unpinned"),
        "phase5_ref_acquired": nonnegative_delta(
            phase5_before, phase5_after, "remote_ref_acquired"),
        "phase5_ref_released": nonnegative_delta(
            phase5_before, phase5_after, "remote_ref_released"),
        "phase6_section_created": nonnegative_delta(
            phase6_before, phase6_after, "remote_section_created"),
        "phase6_section_completed": nonnegative_delta(
            phase6_before, phase6_after, "remote_section_completed"),
        "phase6_scratch_reserved": nonnegative_delta(
            phase6_before, phase6_after, "scratch_reserved"),
        "phase6_scratch_returned": nonnegative_delta(
            phase6_before, phase6_after, "scratch_returned"),
        "phase6_merge_started": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_merge_started"),
        "phase6_merge_completed": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_merge_completed"),
        "phase9_owner_lane_match": nonnegative_delta(
            global_before["phase9"], global_after["phase9"],
            "owner_lane_match"),
    }
    checks["attributed_work_exact_across_layers"] = (
        min(attributed_work.values()) > 0 and
        len(set(attributed_work.values())) == 1)
    checks["attribution_admission_rejections_zero"] = (
        nonnegative_delta(
            phase4_before, phase4_after, "child_token_rejected") == 0 and
        all(nonnegative_delta(phase5_before, phase5_after, name) == 0
            for name in ("mapping_exact_owner_mismatch",
                         "remote_grant_rejected_generation",
                         "remote_grant_rejected_root",
                         "remote_grant_rejected_token")))
    remote_entries = {
        "scratch_trace": nonnegative_delta(
            phase6_before, phase6_after, "scratch_trace_entries"),
        "aggregate_merged": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_entries_merged"),
        "aggregate_published": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_entries_published"),
    }
    checks["remote_coverage_positive_and_exact"] = (
        min(remote_entries.values()) > 0 and
        len(set(remote_entries.values())) == 1)

    generation_success = {
        "generation_created": nonnegative_delta(
            phase4_before, phase4_after, "generation_created"),
        "generation_begin": execution_delta,
        "generation_finish": nonnegative_delta(
            phase4_before, phase4_after, "generation_finish"),
        "generation_closing": nonnegative_delta(
            phase4_before, phase4_after, "generation_closing"),
        "generation_committed": committed_delta,
        "generation_dead": nonnegative_delta(
            phase4_before, phase4_after, "generation_dead"),
        "phase5_remote_result_valid": nonnegative_delta(
            phase5_before, phase5_after, "remote_result_valid"),
        "phase6_aggregate_allocated": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_allocated"),
        "phase6_aggregate_committed": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_committed"),
        "phase6_aggregate_publishing": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_publishing"),
        "phase6_aggregate_published": nonnegative_delta(
            phase6_before, phase6_after, "aggregate_published"),
        "phase6_publisher_lease_get": nonnegative_delta(
            phase6_before, phase6_after, "publisher_read_lease_get"),
        "phase6_publisher_lease_put": nonnegative_delta(
            phase6_before, phase6_after, "publisher_read_lease_put"),
    }
    checks["generation_commit_publish_exact"] = (
        min(generation_success.values()) > 0 and
        len(set(generation_success.values())) == 1 and
        next(iter(generation_success.values())) ==
        executor["expected_generation_executions"] and
        nonnegative_delta(
            phase4_before, phase4_after, "generation_aborted") == 0 and
        all(nonnegative_delta(phase5_before, phase5_after, name) == 0
            for name in ("remote_result_incomplete", "remote_result_invalid",
                         "remote_start_incomplete", "remote_start_nested")) and
        all(nonnegative_delta(phase6_before, phase6_after, name) == 0
            for name in ("aggregate_quarantined", "aggregate_discarded",
                         "aggregate_publish_suppressed", "scratch_overflow",
                         "aggregate_merge_truncated")))

    checks["phase4_lifecycle_invariants_clean"] = (
        phase4_after["token_double_complete"] == 0 and
        phase4_after["token_created"] == phase4_after["token_completed"] and
        phase4_after["root_token_created"] ==
        phase4_after["root_token_completed"] +
        phase4_after["root_token_canceled"])
    phase5_zero = (
        "grant_order_violation", "start_transaction_violation",
        "stop_without_start", "remote_stop_double",
        "nested_ownerless_fallback", "nested_incumbent_unknown",
        "nested_client_disconnect_miss", "grant_revoked_after_abort",
        "svc_rqst_stale_attachment", "selftest_failures",
    )
    checks["phase5_lifecycle_invariants_clean"] = (
        all(phase5_after[name] == 0 for name in phase5_zero) and
        phase5_after["remote_start_ok"] == phase5_after["remote_stop"] and
        phase5_after["remote_scratch_reserved"] ==
        phase5_after["remote_scratch_returned"] and
        phase5_after["remote_target_pinned"] ==
        phase5_after["remote_target_unpinned"] and
        phase5_after["remote_ref_acquired"] ==
        phase5_after["remote_ref_released"] and
        phase5_after["remote_ticket_created"] ==
        phase5_after["remote_ticket_completed"] +
        phase5_after["remote_ticket_canceled"])
    checks["phase6_lifecycle_invariants_clean"] = (
        all(phase6_after[name] == 0
            for name in modules[-2].ZERO_VIOLATIONS) and
        phase6_after["remote_section_created"] ==
        phase6_after["remote_section_completed"] +
        phase6_after["remote_section_discarded"] and
        phase6_after["scratch_reserved"] ==
        phase6_after["scratch_returned"] and
        phase6_after["scratch_in_use"] == 0 and
        phase6_after["publisher_read_lease_get"] ==
        phase6_after["publisher_read_lease_put"] and
        phase6_after["publish_readers"] == 0)
    phase8 = global_after["phase8"]
    checks["phase8_lifecycle_invariants_clean"] = (
        all(phase8[name] == 0 for name in modules[-1].PHASE8_ZERO_FINAL) and
        phase8["deferred_child_created"] ==
        phase8["deferred_completed"] + phase8["deferred_dropped"] and
        phase8["async_child_created"] ==
        phase8["async_completed"] + phase8["async_dropped"])

    minimum_available = min(
        sample["mem_available_kib"] for sample in memory_samples
    )
    peak_used = max(sample["mem_used_kib"] for sample in memory_samples)
    start_used = memory_samples[0]["mem_used_kib"]
    checks["memory_floor_respected"] = (
        minimum_available >= args.min_available_mib * 1024)
    checks["memory_growth_bounded"] = (
        peak_used - start_used <= args.max_memory_growth_mib * 1024)
    for key in ("vmstat_oom_kill", "cgroup_oom", "cgroup_oom_kill"):
        checks["no_" + key] = (
            memory_samples[-1][key] == memory_samples[0][key])
    checks["actual_executor_proc_ids_exact"] = (
        executor["proc_ids"] == list(range(scale)))
    checks["alternate_lane_sources_inaccessible"] = (
        executor["source_tree_hidden_by_proc"] == list(range(scale)))
    checks["positive_rpc_total"] = sum(rpc_deltas) > 0
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError(
            "Gate 9 scale %d checks failed: %s" % (scale, ", ".join(failed))
        )
    metrics = {
        "executor_processes": scale,
        "executions": actual_starts,
        "executions_by_proc": executor["executions_by_proc"],
        "nfsd_rpcs_by_lane": rpc_deltas,
        "nfsd_rpcs_total": sum(rpc_deltas),
        "minimum_mem_available_kib": minimum_available,
        "peak_mem_used_kib": peak_used,
        "peak_process_rss_kib": max(
            sample["process_rss_kib"] for sample in memory_samples),
        "peak_slab_kib": max(sample["slab_kib"] for sample in memory_samples),
        "oom_kills": (memory_samples[-1]["vmstat_oom_kill"] -
                      memory_samples[0]["vmstat_oom_kill"]),
        "duration_includes_deliberate_probe_holds": True,
        "attributed_work_by_layer": attributed_work,
        "remote_entries": remote_entries,
        "generation_success_by_layer": generation_success,
    }
    return checks, metrics


def cleanup_fixture(vm, root, scale, strict=True):
    result = vm.guest(
        "scale%d-fixture-cleanup" % scale,
        shlex.join([REMOTE_DRIVER + "/lane.sh", "cleanup", root]),
        timeout=120, check=strict,
    )
    if result.returncode:
        return {"returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}
    value = json_object(result.stdout, "Phase 9 cleanup")
    fields = (
        "mount_leaks", "namespace_leaks", "nfsd_resource_leaks",
        "veth_leaks", "domain_retire_failures", "source_tree_leaks",
        "active_executor_mounts",
    )
    lane_count_mismatch = int(value.get("lane_count", 0)) != scale
    resource_failure = any(int(value.get(field, -1)) != 0
                           for field in fields)
    if resource_failure or (strict and lane_count_mismatch):
        raise ValueError("Phase 9 strict cleanup failed: %r" % value)
    vm.guest(
        "scale%d-post-cleanup-validation" % scale,
        "set -eu; test ! -e %s; test ! -e /syz-nfs-lanes/enabled; "
        "! ip netns list | awk '{print $1}' | grep -Eq '^f9l[0-3](s|c[01])$'; "
        "i=0; while test -s %s && test \"$i\" -lt 60; do "
        "i=$((i + 1)); sleep 0.5; done; test ! -s %s; "
        "created=$(awk '$1 == \"domain_created\" {print $2}' %s); "
        "retired=$(awk '$1 == \"domain_retired\" {print $2}' %s); "
        "test \"$created\" -eq \"$retired\""
        % (shlex.quote(root), PHASE3_CONNECTIONS, PHASE3_CONNECTIONS,
           PHASE3_STATS, PHASE3_STATS), timeout=45,
    )
    return value


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
    parser.add_argument("--phase8-runner", type=Path,
                        default=scripts / "run_frozen_phase8_vm.py")
    parser.add_argument("--phase1-lane-script", dest="lane_script", type=Path,
                        default=scripts / "frozen_phase1_lane.sh")
    parser.add_argument("--workload", type=Path,
                        default=scripts / "frozen_phase1_workload.py")
    parser.add_argument("--lane-fixture", type=Path,
                        default=scripts / "frozen_phase9_lane.sh")
    parser.add_argument("--probe", type=Path,
                        default=scripts / "frozen_phase9_probe.prog")
    parser.add_argument(
        "--syz-executor", type=Path,
        default=Path("/home/fuzzer/tools/syzkaller-frozen-attribution/"
                     "bin/linux_amd64/syz-executor"))
    parser.add_argument(
        "--syz-execprog", type=Path,
        default=Path("/home/fuzzer/tools/syzkaller-frozen-attribution/"
                     "bin/linux_amd64/syz-execprog"))
    parser.add_argument(
        "--execution-waves", type=int, default=10,
        help=("global request count is SCALE * N; actual per-proc counts are "
              "taken from executor start logs and each must be positive"))
    parser.add_argument("--min-available-mib", type=int, default=512)
    parser.add_argument("--max-memory-growth-mib", type=int, default=2048)
    parser.add_argument("--cpus", type=int, default=8)
    parser.add_argument("--memory", type=int, default=8192)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    paths = (
        "kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
        "phase3_runner", "phase4_runner", "phase5_runner", "phase6_runner",
        "phase8_runner", "lane_script", "workload", "lane_fixture", "probe",
        "syz_executor", "syz_execprog",
    )
    for name in paths:
        path = getattr(args, name).resolve()
        setattr(args, name, path)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" %
                         (name.replace("_", "-"), path))
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path")
    if not 1 <= args.execution_waves <= 100:
        parser.error("--execution-waves must be 1..100")
    if not 4 <= args.cpus <= 64:
        parser.error("--cpus must be 4..64")
    if not 4096 <= args.memory <= 65536:
        parser.error("--memory must be 4096..65536 MiB")
    if not 128 <= args.min_available_mib < args.memory:
        parser.error("--min-available-mib must be 128..memory-1")
    if not 128 <= args.max_memory_growth_mib < args.memory:
        parser.error("--max-memory-growth-mib must be 128..memory-1")
    return args


def main(argv=None):
    args = parse_args(argv)
    phase1 = load_module("frozen_phase1_runner", args.phase1_runner)
    phase3 = load_module("frozen_phase3_runner", args.phase3_runner)
    phase4 = load_module("frozen_phase4_runner", args.phase4_runner)
    phase5 = load_module("frozen_phase5_runner", args.phase5_runner)
    phase6 = load_module("frozen_phase6_runner", args.phase6_runner)
    phase8 = load_module("frozen_phase8_runner", args.phase8_runner)
    modules = ModuleBundle([phase3, phase4, phase5, phase6, phase8])
    phase1.REMOTE_DRIVER = REMOTE_DRIVER
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION, "phase": 9, "status": "running",
        "started_at": timestamp(), "commands": [], "stages": [],
        "gate": {"name": "Gate 9", "status": "running"},
        "scale_order": list(SCALES),
        "mapping_contract": {
            "executor": "real syz-execprog/syz-executor IPC",
            "common_owner": "proc_id + 1",
            "source": "/syz-nfs-lanes/proc-<proc_id>",
            "sandbox_target": "/nfs-lane",
            "one_fixed_lane_per_proc": True,
            "direct_kernel_diagnostic": PHASE9_STATS,
        },
        "observability_contract": {
            "stats": PHASE9_STATS, "control": PHASE9_CONTROL,
            "required_counters": [
                "owner_lane_match", "cross_lane_attribution",
                "lane_seen_mask",
            ],
        },
    }
    write_evidence(args.output, evidence)
    phase1.write_evidence = write_evidence
    vm = None
    base_hash = None
    active_scale = None
    exit_code = 1

    def record_finalization_error(error):
        nonlocal exit_code
        item = {"type": type(error).__name__, "message": str(error)}
        evidence.setdefault("collection_errors", []).append(item)
        evidence["status"] = "fail"
        evidence.setdefault("gate", {"name": "Gate 9"})["status"] = "fail"
        evidence.setdefault("failure", item)
        evidence["completed_at"] = timestamp()
        exit_code = 1

    try:
        phase1.validate_inputs(args, evidence)
        base_hash = evidence["inputs"]["image"]["sha256"]
        evidence["inputs"]["phase9_runner"] = {
            "path": str(Path(__file__).resolve()),
            "bytes": Path(__file__).resolve().stat().st_size,
            "sha256": phase1.sha256(Path(__file__).resolve()),
        }
        for name in (
                "phase1_runner", "phase3_runner", "phase4_runner",
                "phase5_runner", "phase6_runner", "phase8_runner",
                "lane_fixture", "probe", "syz_executor", "syz_execprog"):
            path = getattr(args, name)
            evidence["inputs"][name] = {
                "path": str(path), "bytes": path.stat().st_size,
                "sha256": phase1.sha256(path),
            }
        probe_source = args.probe.read_text(encoding="utf-8")
        evidence["source_contract"] = {
            "real_primary_nfs": "nfs-lane/client0" in probe_source,
            "real_peer_nfs": "nfs-lane/client1" in probe_source,
            "lane_identity": "nfs-lane/.lane_id" in probe_source,
            "bounded_two_second_hold": "{0x2, 0x0}" in probe_source,
            "fixture_source_paths_absent": "syz-nfs-lanes" not in probe_source,
        }
        if not all(evidence["source_contract"].values()):
            raise ValueError("Phase 9 probe source contract incomplete")
        executor_image = args.syz_executor.read_bytes()
        executor_markers = {
            "proc_source_selector": b"/syz-nfs-lanes/proc-%llu",
            "sandbox_target": b"/nfs-lane",
            "binding_diagnostic": b"NFS fuzz lane bound: proc=%llu",
            "isolation_diagnostic": b"NFS fuzz lane isolated: proc=%llu",
            "workdir_lane_link": b"failed to link NFS fuzz lane into workdir",
            "mismatch_fail_closed": b"NFS fuzz lane marker mismatch",
            "generation_begin": b"KCOV generation begin failed",
            "generation_bind": b"KCOV generation bind failed",
            "generation_finish": b"KCOV generation finish failed",
        }
        evidence["executor_binary_contract"] = {
            name: marker in executor_image
            for name, marker in executor_markers.items()
        }
        if not all(evidence["executor_binary_contract"].values()):
            missing = sorted(name for name, present in
                             evidence["executor_binary_contract"].items()
                             if not present)
            raise ValueError(
                "syz-executor lacks Gate 9 contract: " + ", ".join(missing))
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none "
            "/sys/kernel/debug; command -v ip nsenter timeout tar findmnt "
            "mount.nfs4 pgrep setsid awk ps stat find sort sha256sum",
            timeout=30,
        )
        for path in (PHASE3_STATS, PHASE3_CONNECTIONS,
                     PHASE4_STATS, PHASE4_STATE,
                     PHASE5_STATS, PHASE5_STATE, PHASE6_STATS,
                     PHASE6_STATE, PHASE8_STATS, PHASE9_STATS,
                     PHASE9_CONTROL):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase9-deps.tar.gz")
        vm.put("copy-lane-fixture", args.lane_fixture,
               "/tmp/frozen-phase9-lane.sh")
        vm.put("copy-phase9-probe", args.probe,
               "/tmp/frozen-phase9-probe.prog")
        vm.put("copy-syz-executor", args.syz_executor,
               "/tmp/frozen-phase9-syz-executor")
        vm.put("copy-syz-execprog", args.syz_execprog,
               "/tmp/frozen-phase9-syz-execprog")
        vm.guest(
            "install-inputs",
            "set -eu; test ! -e %s; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase9-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase9-lane.sh %s/lane.sh; "
            "install -m 0644 /tmp/frozen-phase9-probe.prog %s/phase9-probe.prog; "
            "install -m 0755 /tmp/frozen-phase9-syz-executor %s/syz-executor; "
            "install -m 0755 /tmp/frozen-phase9-syz-execprog %s/syz-execprog"
            % ((REMOTE_DRIVER,) * 6), timeout=90,
        )
        root_result = vm.guest(
            "allocate-phase9-root", "mktemp -d /tmp/frozen-phase9.XXXXXX",
            timeout=15,
        )
        vm.lane_root = root_result.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-phase9\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe Phase 9 root")

        previous_epochs = []
        initial_memory = memory_snapshot(vm, "memory-initial")
        evidence["initial_memory"] = initial_memory
        for scale in SCALES:
            active_scale = scale
            modules.scale = scale
            stage = {"scale": scale, "status": "running",
                     "started_at": timestamp()}
            evidence["stages"].append(stage)
            write_evidence(args.output, evidence)
            samples = [memory_snapshot(vm, "scale%d-memory-before" % scale)]
            setup = vm.guest(
                "scale%d-fixture-setup" % scale,
                shlex.join([REMOTE_DRIVER + "/lane.sh", "setup",
                            vm.lane_root, str(scale)]),
                timeout=300,
            )
            status = validate_fixture_status(
                json_object(setup.stdout, "Phase 9 fixture setup"), scale
            )
            # Exercise the separately callable status path as part of the ABI.
            reported = validate_fixture_status(json_object(vm.guest(
                "scale%d-fixture-status" % scale,
                shlex.join([REMOTE_DRIVER + "/lane.sh", "status",
                            vm.lane_root]), timeout=60,
            ).stdout, "Phase 9 fixture status"), scale)
            if reported != status:
                raise ValueError("fixture setup/status reports differ")
            epochs = [int(item["lane_epoch"]) for item in status["lanes"]]
            if previous_epochs and min(epochs) <= max(previous_epochs):
                raise ValueError("lane epochs are not globally monotonic")
            previous_epochs.extend(epochs)
            stage["fixture"] = status
            stage["source_tree"] = validate_source_tree(
                vm, vm.lane_root, scale)
            if scale == 1:
                stage["fail_closed_preflight"] = run_fail_closed_probe(vm)
            vm.guest("scale%d-grace" % scale, "sleep 11", timeout=20)
            vm.guest(
                "scale%d-reset-phase9" % scale,
                "printf 'reset\\n' > " + PHASE9_CONTROL, timeout=20)
            samples.append(memory_snapshot(
                vm, "scale%d-memory-after-setup" % scale))
            baseline = [lane_snapshot(
                vm, modules, vm.lane_root, lane, "baseline"
            ) for lane in range(scale)]
            background = start_executor(
                vm, vm.lane_root, scale, args.execution_waves)
            vm.guest("scale%d-workload-observation-delay" % scale,
                     "sleep 2", timeout=10)
            samples.append(memory_snapshot(
                vm, "scale%d-memory-during-executor" % scale))
            log = finish_executor(vm, scale, background)
            executor = validate_executor_log(
                log, scale, background["expected_executions"])
            mapping = mapping_from_executor(executor, epochs, scale)
            canaries = verify_and_remove_canaries(vm, scale)
            samples.append(memory_snapshot(
                vm, "scale%d-memory-after-executor" % scale))
            final = wait_for_drains(
                vm, modules, vm.lane_root, scale)
            samples.append(memory_snapshot(
                vm, "scale%d-memory-before-cleanup" % scale))
            checks, metrics = validate_stage(
                scale, baseline, final, mapping,
                executor, samples, args, modules)
            cleanup = cleanup_fixture(vm, vm.lane_root, scale, strict=True)
            active_scale = None
            samples.append(memory_snapshot(
                vm, "scale%d-memory-after-cleanup" % scale))
            # OOM checks include cleanup, not just the timed workload window.
            if any(samples[-1][key] != samples[0][key] for key in
                   ("vmstat_oom_kill", "cgroup_oom", "cgroup_oom_kill")):
                raise ValueError("OOM event occurred during scale %d" % scale)
            cleanup_growth = (samples[-1]["mem_used_kib"] -
                              samples[0]["mem_used_kib"])
            if cleanup_growth > args.max_memory_growth_mib * 1024:
                raise ValueError(
                    "memory did not recover after scale %d cleanup: %d KiB" %
                    (scale, cleanup_growth))
            checks["post_cleanup_memory_growth_bounded"] = True
            metrics["post_cleanup_mem_growth_kib"] = cleanup_growth
            stage.update({
                "status": "pass", "completed_at": timestamp(),
                "baseline": baseline, "live_mapping": mapping,
                "final": final, "executor": executor,
                "canaries": canaries,
                "executor_command": background["command"],
                "memory_samples": samples, "metrics": metrics,
                "checks": checks, "cleanup": cleanup,
            })
            write_evidence(args.output, evidence)

        total_execs = sum(item["metrics"]["executions"]
                          for item in evidence["stages"])
        total_rpcs = sum(item["metrics"]["nfsd_rpcs_total"]
                         for item in evidence["stages"])
        gate_checks = {
            "sequential_scale_exact": [item["scale"] for item in
                                        evidence["stages"]] == list(SCALES),
            "all_stages_passed": all(item["status"] == "pass"
                                      for item in evidence["stages"]),
            "strict_cleanup_between_stages": all(
                all(int(item["cleanup"][field]) == 0 for field in (
                    "mount_leaks", "namespace_leaks", "nfsd_resource_leaks",
                    "veth_leaks", "domain_retire_failures",
                    "source_tree_leaks", "active_executor_mounts"))
                for item in evidence["stages"]),
            "fixed_proc_lane_mapping_all_scales": all(
                len(item["live_mapping"]["mapping"]) == item["scale"]
                for item in evidence["stages"]),
            "cross_generation_and_lane_attribution_zero": all(
                all(value for name, value in item["checks"].items()
                    if ("no_cross_generation" in name or
                        "no_owner_mismatch" in name or
                        "phase3_attribution_clean" in name or
                        "direct_cross_lane_attribution_zero" in name))
                for item in evidence["stages"]),
            "memory_and_oom_canaries_passed": all(
                item["metrics"]["oom_kills"] == 0
                for item in evidence["stages"]),
            "real_executor_executions_positive": total_execs > 0,
            "real_nfsd_rpcs_positive": total_rpcs > 0,
        }
        failed = sorted(name for name, passed in gate_checks.items()
                        if not passed)
        if failed:
            raise ValueError("Gate 9 checks failed: " + ", ".join(failed))
        evidence["totals"] = {"executions": total_execs,
                              "nfsd_rpcs": total_rpcs}
        evidence["gate"] = {"name": "Gate 9", "status": "pass",
                            "checks": gate_checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__,
                               "message": str(error)}
        evidence["gate"] = {"name": "Gate 9", "status": "fail"}
        evidence["completed_at"] = timestamp()
        try:
            write_evidence(args.output, evidence)
        except Exception as evidence_error:
            record_finalization_error(evidence_error)
    finally:
        if vm is not None and vm.ready:
            try:
                vm.guest(
                    "emergency-stop-executors",
                    "set -eu; pkill -TERM -x syz-execprog || true; "
                    "pkill -TERM -x syz-executor || true; sleep 1; "
                    "pkill -KILL -x syz-execprog || true; "
                    "pkill -KILL -x syz-executor || true; "
                    "! pgrep -x syz-execprog; ! pgrep -x syz-executor",
                    timeout=20,
                )
            except Exception as stop_error:
                record_finalization_error(stop_error)
            if vm.lane_root is not None and active_scale is not None:
                try:
                    evidence["emergency_cleanup"] = cleanup_fixture(
                        vm, vm.lane_root, active_scale, strict=False)
                    if evidence["emergency_cleanup"].get("returncode", 0):
                        raise RuntimeError("emergency fixture cleanup failed")
                except Exception as cleanup_error:
                    evidence["emergency_cleanup"] = {
                        "type": type(cleanup_error).__name__,
                        "error": str(cleanup_error),
                    }
                    record_finalization_error(cleanup_error)
            try:
                final_memory = memory_snapshot(vm, "memory-final")
                evidence["final_memory"] = final_memory
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30,
                                 check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr, encoding="utf-8",
                    errors="replace")
                evidence["dmesg"] = "dmesg.txt"
                if (dmesg.returncode or
                        FATAL_KERNEL_RE.search(dmesg.stdout + dmesg.stderr)):
                    raise ValueError("fatal kernel/OOM diagnostic in Gate 9 VM")
            except Exception as diagnostic_error:
                record_finalization_error(diagnostic_error)
        if vm is not None:
            try:
                vm.stop()
            except Exception as vm_stop_error:
                record_finalization_error(vm_stop_error)
        if base_hash is not None:
            try:
                final_hash = phase1.sha256(args.image)
                evidence["inputs"]["image"]["sha256_after"] = final_hash
                evidence["inputs"]["image"]["unchanged"] = (
                    final_hash == base_hash)
                if final_hash != base_hash:
                    raise ValueError("base image changed")
            except Exception as image_error:
                record_finalization_error(image_error)
        try:
            write_evidence(args.output, evidence)
        except Exception as final_evidence_error:
            record_finalization_error(final_evidence_error)
            print("could not write Gate 9 evidence: %s" %
                  final_evidence_error, file=sys.stderr)
    print(json.dumps({"status": evidence["status"],
                      "evidence": str(args.output / "phase9-evidence.json")},
                     sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
