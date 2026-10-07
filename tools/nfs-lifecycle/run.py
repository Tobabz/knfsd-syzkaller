#!/usr/bin/env python3
"""Run versioned NFS lifecycle scenarios in a disposable fixture VM."""

import argparse
import importlib.util
import json
import re
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CRASH_PATTERNS = (
    "BUG: KASAN:", "Kernel panic", "Oops:",
    "general protection fault", "kernel BUG at",
)
SCENARIOS = {
    "v40-lease-expiry": {"version": "4.0", "kind": "lease"},
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
CLIENT_RE = re.compile(r"\bclient ([0-9a-fA-F]{8}:[0-9a-fA-F]{8})\b")
EVENT_RE = re.compile(r"\s(?P<timestamp>\d+\.\d+): (?P<name>[A-Za-z0-9_]+): ")


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
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args()
    if args.repeat < 1 or args.repeat > 999:
        parser.error("--repeat must be between 1 and 999")
    for name in ("image", "kernel", "ssh_key"):
        path = getattr(args, name).resolve()
        if not path.is_file():
            parser.error("missing --%s: %s" % (name.replace("_", "-"), path))
        setattr(args, name, path)
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must not already exist: %s" % output)
    output.mkdir(parents=True)

    definition = SCENARIOS[args.scenario]
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
