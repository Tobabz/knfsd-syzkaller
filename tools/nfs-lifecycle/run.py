#!/usr/bin/env python3
"""Run versioned NFS lifecycle scenarios in a disposable fixture VM."""

import argparse
import importlib.util
import json
import re
import shlex
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CRASH_PATTERNS = (
    "BUG: KASAN:", "Kernel panic", "Oops:",
    "general protection fault", "kernel BUG at",
)
SCENARIOS = {
    "v40-lease-expiry": {"version": "4.0", "kind": "lease"},
    "v41-client-expiry": {"version": "4.1", "kind": "admin"},
    "v41-control-restart": {"version": "4.1", "kind": "control"},
    "v42-control-restart": {"version": "4.2", "kind": "control"},
}
LEASE_EVENTS = (
    "nfsd/nfsd_clid_confirmed",
    "nfsd/nfsd_mark_client_expired",
    "nfsd/nfsd_clid_purged",
)
LEASE_ORDER = (
    "nfsd_clid_confirmed",
    "nfsd_mark_client_expired",
    "nfsd_clid_purged",
)
CONTROL_EVENTS = (
    "nfsd/nfsd_ctl_threads",
    "nfsd/nfsd_ctl_ports_addxprt",
    "nfsd/nfsd_grace_start",
    "nfsd/nfsd_grace_complete",
    "nfsd/nfsd_compound",
    "nfsd/nfsd_compound_status",
)
CONTROL_ORDER = (
    "nfsd_ctl_threads: newthreads=0",
    "nfsd_ctl_ports_addxprt: transport=tcp port=20490",
    "nfsd_ctl_threads: newthreads=4",
)
ADMIN_EVENTS = (
    "nfsd/nfsd_clid_admin_expired",
    "nfsd/nfsd_clid_fresh",
    "nfsd/nfsd_clid_confirmed",
    "nfsd/nfsd_slot_seqid_unconf",
    "nfsd/nfsd_compound_status",
)
ADMIN_PROGRAMS = {
    "control": ROOT / "tools/nfs-lifecycle/programs/v41-client-io-control.prog",
    "stimulus": ROOT / "tools/nfs-lifecycle/programs/v41-client-expire.prog",
}
ADMIN_GUEST = "/tmp/nfs-lifecycle-admin"
ADMIN_GATE = ADMIN_GUEST + "/gate"
ADMIN_RC = ADMIN_GUEST + "/exec.rc"
ADMIN_LOG = ADMIN_GUEST + "/exec.log"
STATS_COMMAND = ("for f in /sys/kernel/debug/sunrpc_fuzz/*_stats; do "
                 "echo \"== $f\"; cat \"$f\"; done")
STATE_COMMAND = "cat /sys/kernel/debug/sunrpc_fuzz/phase4_state"
CLIENT_RE = re.compile(r"\bclient ([0-9a-fA-F]{8}:[0-9a-fA-F]{8})\b")
EVENT_RE = re.compile(r"\s(?P<timestamp>\d+\.\d+): (?P<name>[A-Za-z0-9_]+): ")
SECTION_RE = re.compile(r"^== .*/([A-Za-z0-9_]+)$")
COUNTER_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*) (-?[0-9]+)$")
LIFECYCLE_RE = re.compile(
    r"^lifecycle request lane=0 op=1 client=0 status=0 "
    r"clientid=0x([0-9a-fA-F]{16}) minor=1 sessions=([1-9][0-9]*)$",
    re.MULTILINE)


def load_vm_class():
    path = ROOT / "tools/bootstrap-kcov-env.py"
    spec = importlib.util.spec_from_file_location("knfsd_bootstrap", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VM


def trace_root(vm, events):
    tests = " && ".join(
        "test -e $d/events/%s/enable" % event for event in events)
    return vm.guest(
        "for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do "
        + tests + " && { echo $d; exit 0; }; done; exit 1").strip()


def set_tracing(vm, tracing, events, enabled, clear=False):
    controls = " ".join(
        "%s/events/%s/enable" % (tracing, event) for event in events)
    commands = ["echo 0 > %s/tracing_on" % tracing]
    if clear:
        commands.append("echo > %s/trace" % tracing)
    commands.extend(("for e in %s; do echo %d > $e; done" %
                     (controls, 1 if enabled else 0),
                     "echo %d > %s/tracing_on" %
                     (1 if enabled else 0, tracing)))
    vm.guest("; ".join(commands))


def parse_stats(text):
    stats = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        section = SECTION_RE.match(line)
        if section:
            current = stats.setdefault(section.group(1), {})
            continue
        counter = COUNTER_RE.match(line)
        if current is not None and counter:
            current[counter.group(1)] = int(counter.group(2))
    return stats


def counter_delta(before, after, section, name):
    try:
        old = before[section][name]
        new = after[section][name]
    except KeyError as error:
        raise RuntimeError("missing generation counter %s.%s" %
                           (section, name)) from error
    if new < old:
        raise RuntimeError("generation counter went backwards: %s.%s" %
                           (section, name))
    return new - old


def unsettled_generations(text):
    busy = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        pairs = dict(zip(fields[::2], fields[1::2]))
        if (pairs.get("state") not in ("ABORTED", "COMMITTED", "DEAD") or
                pairs.get("outstanding_tokens") != "0" or
                pairs.get("active_roots") != "0"):
            busy.append(line.strip())
    return busy


def generation_evidence(before_text, after_text):
    before = parse_stats(before_text)
    after = parse_stats(after_text)
    evidence = {
        "generation_begin": counter_delta(
            before, after, "phase4_stats", "generation_begin"),
        "generation_aborted": counter_delta(
            before, after, "phase4_stats", "generation_aborted"),
        "remote_start_ok": counter_delta(
            before, after, "phase5_stats", "remote_start_ok"),
        "aggregate_published": counter_delta(
            before, after, "phase6_stats", "aggregate_published"),
        "scratch_overflow": counter_delta(
            before, after, "phase6_stats", "scratch_overflow"),
        "merge_truncation": counter_delta(
            before, after, "phase6_stats", "aggregate_merge_truncated"),
        "outstanding_tokens": after.get(
            "phase4_stats", {}).get("outstanding_tokens"),
        "remote_refs": after.get("phase6_stats", {}).get("remote_refs"),
    }
    expected = {
        "generation_begin": 1,
        "generation_aborted": 0,
        "aggregate_published": 1,
        "scratch_overflow": 0,
        "merge_truncation": 0,
        "outstanding_tokens": 0,
        "remote_refs": 0,
    }
    for name, value in expected.items():
        if evidence[name] != value:
            raise RuntimeError("invalid generation %s=%r, want %d" %
                               (name, evidence[name], value))
    if evidence["remote_start_ok"] < 1:
        raise RuntimeError("generation has no successful remote KCOV start")
    evidence["attributed"] = True
    return evidence


def parse_cover(text):
    pcs = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not re.fullmatch(r"0x[0-9a-fA-F]+", line):
            raise RuntimeError("malformed remote coverage PC: %r" % line[:80])
        value = int(line, 16)
        if value <= 0 or value >= 2 ** 64:
            raise RuntimeError("remote coverage PC out of range: %s" % line)
        pcs.add(value)
    return pcs


def load_target_pcs(path):
    mapping = json.loads(path.read_text())
    if mapping.get("schema_version") != "q1-target-pcs-v1" or not mapping.get(
            "verified"):
        raise RuntimeError("target PC mapping is not verified q1-target-pcs-v1")
    pcs = mapping.get("target_pcs")
    if not isinstance(pcs, list) or not pcs or any(
            not isinstance(pc, int) or pc <= 0 or pc >= 2 ** 64 for pc in pcs):
        raise RuntimeError("target PC mapping has invalid target_pcs")
    return mapping, set(pcs)


def wait_admin_exec(vm, gate, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = vm.guest(
            "if test -f %s; then echo exited; "
            "elif test -f %s.ready; then echo ready; fi" %
            (ADMIN_RC, ADMIN_GATE)).strip()
        if state == "exited" or (gate and state == "ready"):
            return state
        time.sleep(1)
    raise RuntimeError("syz-execprog timed out %s" %
                       ("before gate" if gate else "after gate"))


def start_admin_exec(vm, guest_program):
    argv = [ADMIN_GUEST + "/syz-execprog",
            "-executor=" + ADMIN_GUEST + "/syz-executor",
            "-os=linux", "-arch=amd64", "-vmarch=amd64",
            "-sandbox=none", "-procs=1", "-repeat=1", "-threaded=false",
            "-cover=true", "-coverfile=/tmp/cov/cover",
            "-remote-cover=true", "-disable=all", "-debug", "-vv=1",
            "-slowdown=1", "-gate=" + ADMIN_GATE, guest_program]
    body = ("timeout 300 %s > %s 2>&1; echo $? > %s" %
            (shlex.join(argv), ADMIN_LOG, ADMIN_RC))
    command = (
        "rm -rf /tmp/cov %s.ready %s.go %s; mkdir -p /tmp/cov; "
        "setsid nohup sh -c %s < /dev/null > /dev/null 2>&1 &" %
        (ADMIN_GATE, ADMIN_GATE, ADMIN_RC, shlex.quote(body)))
    vm.guest(command)


def one_trace_match(trace, pattern, description):
    matches = list(re.finditer(pattern, trace, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError("%s count=%d, want 1" % (description, len(matches)))
    return matches[0]


def validate_admin_trace(trace, lifecycle_log):
    requests = list(LIFECYCLE_RE.finditer(lifecycle_log))
    if len(requests) != 1:
        raise RuntimeError("successful lifecycle request count=%d, want 1" %
                           len(requests))
    old_value = int(requests[0].group(1), 16)
    # client_info_show() memcpy()s clientid_t into a native u64 before
    # printing it. On this tool's fixed linux/amd64 target that reverses the
    # two 32-bit words relative to the tracepoint's cl_boot:cl_id format.
    old_client = "%08x:%08x" % (old_value & 0xffffffff, old_value >> 32)
    admin = one_trace_match(
        trace, r"nfsd_clid_admin_expired: client " + re.escape(old_client),
        "admin-expired trace for broker clientid")
    fresh = one_trace_match(
        trace, r"nfsd_clid_fresh: .* client=([0-9a-f]{8}:[0-9a-f]{8})",
        "fresh client trace")
    new_client = fresh.group(1)
    exchange = one_trace_match(
        trace, r"nfsd_compound_status: .* OP_EXCHANGE_ID status=0(?:\s|$)",
        "successful EXCHANGE_ID")
    slot = one_trace_match(
        trace, r"nfsd_slot_seqid_unconf: .* client " + re.escape(new_client) +
        r"(?:\s|$)", "unconfirmed CREATE_SESSION slot")
    confirmed = one_trace_match(
        trace, r"nfsd_clid_confirmed: client " + re.escape(new_client) +
        r"(?:\s|$)", "confirmed recovered client")
    create = one_trace_match(
        trace, r"nfsd_compound_status: .* OP_CREATE_SESSION status=0(?:\s|$)",
        "successful CREATE_SESSION")
    positions = [item.start() for item in
                 (admin, fresh, exchange, slot, confirmed, create)]
    if positions != sorted(positions):
        raise RuntimeError("lifecycle trace events are out of order")
    if old_client == new_client:
        raise RuntimeError("recovery reused the expired clientid")
    return {
        "expired_clientid": old_client,
        "recovered_clientid": new_client,
        "session_count_before_expiry": int(requests[0].group(2)),
        "ordered_events": [
            "nfsd_clid_admin_expired", "nfsd_clid_fresh",
            "OP_EXCHANGE_ID", "nfsd_slot_seqid_unconf",
            "nfsd_clid_confirmed", "OP_CREATE_SESSION",
        ],
        "selected_trace_lines": [item.group(0).rstrip() for item in
                                 (admin, fresh, exchange, slot,
                                  confirmed, create)],
    }


def validate_admin_control(trace, lifecycle_log):
    forbidden = ("nfsd_clid_admin_expired:", "nfsd_clid_fresh:",
                 "OP_EXCHANGE_ID", "OP_CREATE_SESSION")
    present = [marker for marker in forbidden if marker in trace]
    if lifecycle_log.strip():
        raise RuntimeError("neutral control invoked lifecycle broker")
    if present:
        raise RuntimeError("neutral control entered recovery: %s" % present)
    return {"forbidden_recovery_events": present}


def run_admin_program(vm, output, phase, iteration, tracing, target_pcs):
    guest_program = "%s/%s.prog" % (ADMIN_GUEST, phase)
    set_tracing(vm, tracing, ADMIN_EVENTS, False, clear=True)
    start_admin_exec(vm, guest_program)
    if wait_admin_exec(vm, True) != "ready":
        raise RuntimeError("syz-execprog exited before the program gate")
    state_before = vm.guest(STATE_COMMAND)
    busy = unsettled_generations(state_before)
    if busy:
        raise RuntimeError("unsettled generation at window start: %s" % busy[0])
    stats_before = vm.guest(STATS_COMMAND)
    lifecycle_lines = int(vm.guest(
        "wc -l < /tmp/frozen-phase9.manager/lane0/server/lifecycle.log").strip())
    set_tracing(vm, tracing, ADMIN_EVENTS, True, clear=True)
    vm.guest("touch %s.go" % ADMIN_GATE)
    if wait_admin_exec(vm, False) != "exited":
        raise RuntimeError("syz-execprog did not exit")
    rc = vm.guest("cat %s" % ADMIN_RC).strip()
    executor_log = vm.guest("cat %s" % ADMIN_LOG, timeout=120)
    if rc != "0":
        raise RuntimeError("syz-execprog rc=%s: %s" %
                           (rc, executor_log[-1000:]))
    time.sleep(10)
    stats_after = vm.guest(STATS_COMMAND)
    trace = vm.guest("cat %s/trace" % tracing)
    set_tracing(vm, tracing, ADMIN_EVENTS, False)
    lifecycle_log = vm.guest(
        "tail -n +%d /tmp/frozen-phase9.manager/lane0/server/lifecycle.log" %
        (lifecycle_lines + 1))
    cover_files = vm.guest(
        "find /tmp/cov -maxdepth 1 -type f -printf '%f\\n' | sort").splitlines()
    extra_files = [name for name in cover_files if name.endswith(".extra")]
    meta_files = [name for name in cover_files if name.endswith(".meta")]
    if len(extra_files) != 1 or len(meta_files) != 1:
        raise RuntimeError("coverage files extra=%r meta=%r" %
                           (extra_files, meta_files))
    extra = vm.guest("cat /tmp/cov/%s" % extra_files[0], timeout=120)
    meta = vm.guest("cat /tmp/cov/%s" % meta_files[0])
    stem = "%s-%03d" % (phase, iteration)
    artifacts = {
        "trace.txt": trace,
        "lifecycle.log": lifecycle_log,
        "executor.log": executor_log,
        "coverage.extra": extra,
        "coverage.meta": meta,
        "stats-before.txt": stats_before,
        "stats-after.txt": stats_after,
        "state-before.txt": state_before,
    }
    for suffix, contents in artifacts.items():
        (output / (stem + "." + suffix)).write_text(contents)
    pcs = parse_cover(extra)
    hits = sorted(pcs & target_pcs)
    generation = generation_evidence(stats_before, stats_after)
    if phase == "control":
        lineage = validate_admin_control(trace, lifecycle_log)
        if hits:
            raise RuntimeError("neutral control reached target PCs: %s" %
                               [hex(pc) for pc in hits])
    else:
        lineage = validate_admin_trace(trace, lifecycle_log)
        if not hits:
            raise RuntimeError("expiry stimulus did not reach a target PC")
    return {
        "phase": phase,
        "iteration": iteration,
        "generation": generation,
        "coverage_pc_count": len(pcs),
        "target_hit_count": len(hits),
        "target_hits": ["0x%016x" % pc for pc in hits],
        "coverage_files": cover_files,
        "lineage": lineage,
    }


def run_admin(vm, output, repeat, syzkaller, mapping_path):
    mapping, target_pcs = load_target_pcs(mapping_path)
    tracing = trace_root(vm, ADMIN_EVENTS)
    syz_bin = syzkaller / "bin/linux_amd64"
    vm.guest("mkdir -p %s; dmesg -c >/dev/null" % ADMIN_GUEST)
    for name in ("syz-executor", "syz-execprog"):
        vm.put(syz_bin / name, ADMIN_GUEST + "/" + name)
    for phase, path in ADMIN_PROGRAMS.items():
        vm.put(path, "%s/%s.prog" % (ADMIN_GUEST, phase))
    vm.guest("chmod 0755 %s/syz-executor %s/syz-execprog" %
             (ADMIN_GUEST, ADMIN_GUEST))
    cycles = {"control": [], "stimulus": []}
    for phase in ("control", "stimulus"):
        for iteration in range(1, repeat + 1):
            cycles[phase].append(run_admin_program(
                vm, output, phase, iteration, tracing, target_pcs))
    return tracing, cycles, {
        "candidate_id": mapping["target"]["candidate_id"],
        "kernel_commit": mapping["target"]["kernel_commit"],
        "path": mapping["target"]["path"],
        "symbol": mapping["target"]["symbol"],
        "target_pcs": ["0x%016x" % pc for pc in sorted(target_pcs)],
    }


def lease_guest_script(path):
    path.write_text("""#!/bin/sh
set -eu
iteration=$1
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
root=/tmp/frozen-phase9.manager
client_ns=$(printf 'l40c%03d' "$iteration")
server_link=$(printf 'l40s%03d' "$iteration")
client_link=$(printf 'l40c%03d' "$iteration")
mountpoint_dir=$(printf '%s/lifecycle-v40/mnt-%03d' "$root" "$iteration")
mounted=0
cleanup()
{
    set +e
    test "$mounted" -ne 1 || umount "$mountpoint_dir"
    ip netns del "$client_ns" 2>/dev/null || true
    rm -rf "$mountpoint_dir"
}
trap cleanup EXIT
mkdir -p "$mountpoint_dir"
ip netns add "$client_ns"
ip link add "$client_link" type veth peer name "$server_link"
ip link set "$client_link" netns "$client_ns"
ip link set "$server_link" netns f9l0s
ip -n f9l0s addr add 10.250.0.1/30 dev "$server_link"
ip -n f9l0s link set "$server_link" up
ip -n "$client_ns" link set lo up
ip -n "$client_ns" addr add 10.250.0.2/30 dev "$client_link"
ip -n "$client_ns" link set "$client_link" up
ip netns exec "$client_ns" sh -c \
    "printf '%s\\n' lifecycle-v40-client-$iteration > /sys/fs/nfs/net/nfs_client/identifier"
nsenter --net="/run/netns/$client_ns" -- mount.nfs4 \
    -o vers=4.0,minorversion=0,proto=tcp,port=20490,sec=sys,ro,actimeo=0,lookupcache=none,nosharecache \
    10.250.0.1:/ "$mountpoint_dir"
mounted=1
printf 'iteration=%s identifier=lifecycle-v40-client-%s\\n' "$iteration" "$iteration"
cat "$mountpoint_dir/shared/fixture"
stat "$mountpoint_dir/shared/fixture"
umount "$mountpoint_dir"
mounted=0
ip netns del "$client_ns"
rm -rf "$mountpoint_dir"
trap - EXIT
""")


def control_guest_script(path):
    path.write_text("""#!/bin/sh
set -eu
iteration=$1
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
root=/tmp/frozen-phase9.manager
server_pid=$(cat "$root/lane0/server.pid")
client_mount="$root/lane0/client0/mnt"
server() { nsenter -t "$server_pid" -m -n -- "$@"; }
server_sh() { nsenter -t "$server_pid" -m -n -- sh -c "$1"; }
printf 'iteration=%s\\n' "$iteration"
printf 'pre_io='; timeout 30 cat "$client_mount/shared/fixture"
cld_before=$(server pgrep -xo nfsdcld)
printf 'nfsdcld_before=%s\\n' "$cld_before"
server sh -c 'printf "threads_before="; cat /proc/fs/nfsd/threads; cat /proc/fs/nfsd/portlist'
server_sh 'printf "0\\n" > /proc/fs/nfsd/threads'
server_sh 'printf "tcp 20490\\n" > /proc/fs/nfsd/portlist'
server_sh 'printf "4\\n" > /proc/fs/nfsd/threads'
server sh -c 'printf "threads_after="; cat /proc/fs/nfsd/threads; cat /proc/fs/nfsd/portlist'
grace=$(server cat /proc/fs/nfsd/v4_end_grace)
printf 'grace_before_force=%s\\n' "$grace"
test "$grace" = Y || server_sh 'printf "Y\\n" > /proc/fs/nfsd/v4_end_grace'
printf 'grace_after_force='; server cat /proc/fs/nfsd/v4_end_grace
cld_after=$(server pgrep -xo nfsdcld)
printf 'nfsdcld_after=%s\\n' "$cld_after"
test "$cld_before" = "$cld_after"
printf 'post_io='; timeout 60 cat "$client_mount/shared/fixture"
timeout 60 stat "$client_mount/shared/fixture"
""")


def events_for_client(trace, client):
    events = []
    for line in trace.splitlines():
        client_match = CLIENT_RE.search(line)
        event_match = EVENT_RE.search(line)
        if (client_match and event_match and
                client_match.group(1).lower() == client):
            events.append({"name": event_match.group("name"),
                           "timestamp": event_match.group("timestamp"),
                           "line": line})
    return events


def confirmed_clients(trace):
    clients = []
    for match in re.finditer(
            r"nfsd_clid_confirmed: client ([0-9a-fA-F]{8}:[0-9a-fA-F]{8})",
            trace):
        client = match.group(1).lower()
        if client not in clients:
            clients.append(client)
    return clients


def validate_control(iteration, trace, fixture_log):
    positions = []
    for marker in CONTROL_ORDER:
        matches = [match.start() for match in re.finditer(re.escape(marker), trace)]
        if len(matches) != 1:
            raise RuntimeError("iteration %d marker %r count=%d" %
                               (iteration, marker, len(matches)))
        positions.append(matches[0])
    if positions != sorted(positions):
        raise RuntimeError("iteration %d control events are out of order" % iteration)
    starts = len(re.findall(r"\bnfsd_grace_start:", trace))
    completes = len(re.findall(r"\bnfsd_grace_complete:", trace))
    start_pos = trace.find("nfsd_grace_start:")
    complete_pos = trace.find("nfsd_grace_complete:")
    if starts != 1 or completes != 1 or not (
            positions[-1] < start_pos < complete_pos):
        raise RuntimeError("iteration %d invalid grace sequence" % iteration)
    post_restart = trace[positions[-1]:]
    compounds = len(re.findall(r"\bnfsd_compound:", post_restart))
    successes = len(re.findall(
        r"\bnfsd_compound_status: .* status=0(?:\s|$)", post_restart))
    if compounds < 1 or successes < 1:
        raise RuntimeError("iteration %d has no successful post-restart I/O" % iteration)
    pids = re.findall(r"nfsdcld_(?:before|after)=(\d+)", fixture_log)
    if len(pids) != 2 or pids[0] != pids[1]:
        raise RuntimeError("iteration %d changed nfsdcld identity" % iteration)
    for marker in ("pre_io=frozen Phase 9 lane 0 fixture",
                   "post_io=frozen Phase 9 lane 0 fixture"):
        if marker not in fixture_log:
            raise RuntimeError("iteration %d missing %s" % (iteration, marker))
    return {"iteration": iteration, "ordered_control_events": list(CONTROL_ORDER),
            "grace_start_events": starts, "grace_complete_events": completes,
            "post_restart_compounds": compounds,
            "post_restart_success_statuses": successes,
            "nfsdcld_pid_before": int(pids[0]),
            "nfsdcld_pid_after": int(pids[1])}


def run_control(vm, output, repeat):
    tracing = trace_root(vm, CONTROL_EVENTS)
    script = output / "guest-control.sh"
    control_guest_script(script)
    vm.put(script, "/tmp/guest-control.sh")
    vm.guest("chmod 755 /tmp/guest-control.sh; dmesg -c >/dev/null")
    cycles = []
    fixture_logs = []
    traces = []
    for iteration in range(1, repeat + 1):
        set_tracing(vm, tracing, CONTROL_EVENTS, True, clear=True)
        fixture_log = vm.guest(
            "/tmp/guest-control.sh %d" % iteration, timeout=180)
        set_tracing(vm, tracing, CONTROL_EVENTS, False)
        trace = vm.guest("cat %s/trace" % tracing)
        cycles.append(validate_control(iteration, trace, fixture_log))
        fixture_logs.append("=== iteration %d ===\n%s" %
                            (iteration, fixture_log))
        traces.append("# iteration %d\n%s" % (iteration, trace))
        (output / ("control-trace-%03d.txt" % iteration)).write_text(trace)
    (output / "fixture.txt").write_text("\n".join(fixture_logs))
    (output / "control-trace.txt").write_text("\n".join(traces))
    return tracing, cycles


def run_lease(vm, output, repeat):
    tracing = trace_root(vm, LEASE_EVENTS)
    server_pid = vm.guest(
        "cat /tmp/frozen-phase9.manager/lane0/server.pid").strip()
    vm.guest(
        "deps=/opt/kcov-nfs/deps; "
        "PATH=$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin; "
        "LD_LIBRARY_PATH=$deps/usr/lib/x86_64-linux-gnu:"
        "$deps/lib/x86_64-linux-gnu; export PATH LD_LIBRARY_PATH; "
        "nsenter -t %s -m -n -- exportfs -i "
        "-o ro,sync,insecure,no_subtree_check,no_root_squash,fsid=0 "
        "10.250.0.0/30:/tmp/frozen-phase9.manager/lane0/server/export" %
        server_pid)
    set_tracing(vm, tracing, LEASE_EVENTS, True, clear=True)
    vm.guest("dmesg -c >/dev/null")
    script = output / "guest-lease.sh"
    lease_guest_script(script)
    vm.put(script, "/tmp/guest-lease.sh")
    vm.guest("chmod 755 /tmp/guest-lease.sh")
    seen = set()
    cycles = []
    fixture_logs = []
    trace = ""
    for iteration in range(1, repeat + 1):
        fixture_log = vm.guest(
            "/tmp/guest-lease.sh %d" % iteration, timeout=90)
        fixture_logs.append("=== iteration %d ===\n%s" %
                            (iteration, fixture_log))
        deadline = time.monotonic() + 50
        client = None
        while time.monotonic() < deadline:
            trace = vm.guest("cat %s/trace" % tracing)
            new_clients = [item for item in confirmed_clients(trace)
                           if item not in seen]
            if len(new_clients) > 1:
                raise RuntimeError("iteration %d found multiple clients" % iteration)
            if new_clients:
                client = new_clients[0]
                names = [event["name"] for event in
                         events_for_client(trace, client)]
                if "nfsd_clid_purged" in names:
                    break
            time.sleep(1)
        if client is None:
            raise RuntimeError("iteration %d did not confirm a client" % iteration)
        events = events_for_client(trace, client)
        names = [event["name"] for event in events]
        if names != list(LEASE_ORDER):
            raise RuntimeError("iteration %d lifecycle %s != %s" %
                               (iteration, names, list(LEASE_ORDER)))
        if "cl_rpc_users=0" not in events[1]["line"]:
            raise RuntimeError("iteration %d expired with RPC users" % iteration)
        seen.add(client)
        cycles.append({"iteration": iteration, "client": client,
                       "ordered_events": names,
                       "timestamps": {event["name"]: event["timestamp"]
                                      for event in events},
                       "selected_trace_lines": [event["line"]
                                                for event in events]})
    set_tracing(vm, tracing, LEASE_EVENTS, False)
    (output / "fixture.txt").write_text("\n".join(fixture_logs))
    (output / "lease-trace.txt").write_text(trace)
    return tracing, cycles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=tuple(SCENARIOS), required=True)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", type=Path,
                        default=ROOT / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--kernel", type=Path,
                        default=ROOT / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path,
                        default=ROOT / "artifacts/bookworm.id_rsa")
    parser.add_argument("--syzkaller", type=Path,
                        default=ROOT / "env/syzkaller",
                        help="patched syzkaller tree (required by client expiry)")
    parser.add_argument("--target-pcs", type=Path,
                        help="verified q1 target-PC mapping (required by client expiry)")
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args()
    if args.repeat < 1 or args.repeat > 999:
        parser.error("--repeat must be between 1 and 999")
    for name in ("image", "kernel", "ssh_key"):
        path = getattr(args, name).resolve()
        if not path.is_file():
            parser.error("missing --%s: %s" % (name.replace("_", "-"), path))
        setattr(args, name, path)
    definition = SCENARIOS[args.scenario]
    if definition["kind"] == "admin":
        args.syzkaller = args.syzkaller.resolve()
        for binary in ("syz-executor", "syz-execprog"):
            path = args.syzkaller / "bin/linux_amd64" / binary
            if not path.is_file():
                parser.error("missing patched syzkaller binary: %s" % path)
        if args.target_pcs is None:
            parser.error("--target-pcs is required by v41-client-expiry")
        args.target_pcs = args.target_pcs.resolve()
        if not args.target_pcs.is_file():
            parser.error("missing --target-pcs: %s" % args.target_pcs)
        for path in ADMIN_PROGRAMS.values():
            if not path.is_file():
                parser.error("missing lifecycle program: %s" % path)
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must not already exist: %s" % output)
    output.mkdir(parents=True)

    result = {"scenario": args.scenario, "native_version": definition["version"],
              "iterations": args.repeat, "transport": "TCP", "status": "fail"}
    vm = load_vm_class()(args.image, args.kernel, args.ssh_key,
                         args.boot_timeout, definition["version"])
    tracing = None
    try:
        vm.start()
        fixture_state = vm.guest(
            "systemctl is-active frozen-phase9-fixture.service || true").strip()
        if fixture_state != "active":
            raise RuntimeError("fixture service is " + fixture_state)
        status = json.loads(vm.guest(
            "/run/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager"))
        if (status.get("fixture_mode") != "single" or
                status.get("nfs_version") != definition["version"]):
            raise RuntimeError("fixture selected the wrong profile")
        if definition["kind"] == "lease":
            tracing, cycles = run_lease(vm, output, args.repeat)
            result["complete_lifecycle_chains"] = len(cycles)
        elif definition["kind"] == "admin":
            vm.guest("test -S /syz-nfs-lanes/proc-0/control/lifecycle.sock")
            tracing, cycles, target = run_admin(
                vm, output, args.repeat, args.syzkaller, args.target_pcs)
            result["complete_control_runs"] = len(cycles["control"])
            result["complete_stimulus_runs"] = len(cycles["stimulus"])
            result["target"] = target
        else:
            tracing, cycles = run_control(vm, output, args.repeat)
            result["complete_control_cycles"] = len(cycles)
        dmesg = vm.guest("dmesg")
        (output / "dmesg.txt").write_text(dmesg)
        crashes = [pattern for pattern in CRASH_PATTERNS if pattern in dmesg]
        if crashes:
            raise RuntimeError("kernel crash signatures: %s" % crashes)
        result.update({"status": "pass", "fixture_service": fixture_state,
                       "trace_root": tracing, "cycles": cycles,
                       "crash_signatures": crashes})
    except Exception as error:
        result["error"] = "%s: %s" % (type(error).__name__, error)
        if tracing:
            try:
                (output / "failure-trace.txt").write_text(
                    vm.guest("cat %s/trace" % tracing))
                (output / "dmesg.txt").write_text(vm.guest("dmesg"))
            except Exception:
                pass
        raise
    finally:
        vm.stop()
        (output / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
