#!/usr/bin/env python3
"""Gate ASan Ganesha, four NFSv4 relay routes and optional syzkaller/replay."""
import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import struct
import sys


TOOLS = Path(__file__).resolve().parent.parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import run_ab_adapted as ab  # noqa: E402


def args_parse():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kernel", "image", "ssh-key", "deps-tar", "proxy-binary",
                 "lane-fixture", "four-mount-script", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--asan-options", required=True)
    parser.add_argument("--syz-executor", type=Path)
    parser.add_argument("--syz-execprog", type=Path)
    parser.add_argument("--workload", type=Path)
    parser.add_argument("--replay-probe", type=Path)
    parser.add_argument("--executions", type=int, default=1)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=6144)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args()
    for name in ("kernel", "image", "ssh_key", "deps_tar", "proxy_binary",
                 "lane_fixture", "four_mount_script"):
        path = getattr(args, name).resolve()
        if not path.is_file() or not path.stat().st_size:
            parser.error("missing --%s: %s" % (name.replace("_", "-"), path))
        setattr(args, name, path)
    syz_args = (args.syz_executor, args.syz_execprog, args.workload)
    if any(syz_args) and not all(syz_args):
        parser.error("--syz-executor, --syz-execprog, --workload are required together")
    if all(syz_args):
        for name in ("syz_executor", "syz_execprog", "workload"):
            path = getattr(args, name).resolve()
            if not path.is_file() or not path.stat().st_size:
                parser.error("missing --%s: %s" % (name.replace("_", "-"), path))
            setattr(args, name, path)
    if args.replay_probe is not None:
        args.replay_probe = args.replay_probe.resolve()
        if not args.replay_probe.is_file() or not args.workload:
            parser.error("--replay-probe needs a syzkaller workload and a file")
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a fresh path")
    if not 4096 <= args.memory <= 65536 or not 4 <= args.cpus <= 64:
        parser.error("invalid guest resource count")
    if not 1 <= args.executions <= 100 or (args.executions != 1 and not args.workload):
        parser.error("--executions must be 1..100 with a syzkaller workload")
    if not args.asan_options or any(c.isspace() for c in args.asan_options):
        parser.error("invalid ASan options")
    return args


def proxy_snapshot(vm, root, output):
    command = """set -eu
log=%s/lane0/server/proxy.log
pid=$(cat %s/lane0/server/proxy.pid)
kill -0 "$pid"
count=$(grep -c '^stats_end snapshot$' "$log" || true)
kill -USR1 "$pid"
i=0
while test "$(grep -c '^stats_end snapshot$' "$log" || true)" -le "$count"; do
    i=$((i + 1))
    test "$i" -lt 100
    kill -0 "$pid"
    sleep 0.1
done
cat "$log"
""" % (shlex.quote(root), shlex.quote(root))
    log = vm.guest("relay-snapshot", command, timeout=20).stdout
    (output / "relay.log").write_text(log, encoding="utf-8")
    blocks = re.findall(r"^stats_begin snapshot\n(.*?)^stats_end snapshot$",
                        log, re.MULTILINE | re.DOTALL)
    if not blocks:
        raise ValueError("relay produced no live stats snapshot")
    block = blocks[-1]
    tuples = {}
    for line in block.splitlines():
        match = re.fullmatch(
            r"client=(\d) backend=(\d) accepted=(\d+) connected=(\d+) "
            r"failed=(\d+) c2s=(\d+) s2c=(\d+) sent_c2s=(\d+) sent_s2c=(\d+)",
            line)
        if match:
            c, b, *values = (int(value) for value in match.groups())
            tuples[(c, b)] = values
    if set(tuples) != {(c, b) for c in range(2) for b in range(2)}:
        raise ValueError("relay did not account for all four tuples: %r" % tuples)
    for key, (accepted, connected, failed, c2s, s2c, sent_c2s, sent_s2c) in tuples.items():
        if min(accepted, connected, c2s, s2c, sent_c2s, sent_s2c) <= 0 or failed:
            raise ValueError("request/reply was absent or connect failed on %s: %s"
                             % (key, tuples[key]))
    tail = re.search(r"^peak_active=(\d+) active=(\d+) framing_errors=(\d+) "
                     r"relay_errors=(\d+) mutation_errors=(\d+) "
                     r"rejected_client=(\d+)$", block, re.MULTILINE)
    if tail is None:
        raise ValueError("relay snapshot summary missing")
    peak, active, framing, relay, mutation, rejected = map(int, tail.groups())
    if peak < 4 or active < 4 or any((framing, relay, mutation, rejected)):
        raise ValueError("relay not concurrently healthy: %s" % (tail.group(0),))
    return {"peak_active": peak, "active": active,
            "tuples": {"%d,%d" % key: value for key, value in tuples.items()},
            "framing_errors": framing, "relay_errors": relay,
            "mutation_errors": mutation, "rejected_client": rejected}


def relay_source_tree(vm):
    return vm.guest("relay-source-tree", """set -eu
source=/syz-nfs-lanes/proc-0
test -S "$source/control/arm.sock"
test "$(cat "$source/.lane_id")" = 0
test "$(cat "$source/.server0_ipv4")" = 10.89.0.1
test "$(cat "$source/.server1_ipv4")" = 10.89.0.5
for entry in client0 client1 client0-knfsd client0-ganesha client1-knfsd client1-ganesha; do
    grep -F " $source/$entry nfs4 " /proc/mounts >/dev/null
done
test "$(findmnt -n -o SOURCE -- "$source/client0-knfsd")" = 10.89.0.1:/
test "$(findmnt -n -o SOURCE -- "$source/client1-knfsd")" = 10.89.0.1:/
test "$(findmnt -n -o SOURCE -- "$source/client0-ganesha")" = 10.89.0.5:/
test "$(findmnt -n -o SOURCE -- "$source/client1-ganesha")" = 10.89.0.5:/
echo 'four_executor_mount_sources=pass control_socket=pass'
""", timeout=30).stdout.strip()


def syzkaller_four_routes(vm, args, output):
    for label, source in (("executor", args.syz_executor),
                          ("execprog", args.syz_execprog),
                          ("workload", args.workload)):
        vm.put("copy-syz-" + label, source, "/tmp/relay-" + label)
    vm.guest("install-syz", "install -m 0755 /tmp/relay-executor "
             "/opt/frozen-phase9/syz-executor; install -m 0755 "
             "/tmp/relay-execprog /opt/frozen-phase9/syz-execprog; "
             "install -m 0644 /tmp/relay-workload /opt/frozen-phase9/four.prog")
    cmd = ["/opt/frozen-phase9/syz-execprog",
           "-executor=/opt/frozen-phase9/syz-executor", "-os=linux",
           "-arch=amd64", "-vmarch=amd64", "-sandbox=none", "-procs=1",
           "-repeat=" + str(args.executions), "-threaded=false", "-cover=true",
           "-remote-cover=true", "-disable=all", "-debug", "-vv=1",
           "-slowdown=1", "/opt/frozen-phase9/four.prog"]
    result = vm.guest("syz-four-executor", "timeout 150s %s "
                      ">/tmp/relay-syz.log 2>&1" % shlex.join(cmd),
                      timeout=175, check=False)
    log = vm.guest("syz-four-executor-log", "cat /tmp/relay-syz.log").stdout
    (output / "syz-executor.log").write_text(log, encoding="utf-8")
    raw_stats = vm.guest("syz-kernel-wire-stats", "cat "
                         "/sys/kernel/debug/sunrpc_fuzz/phase7_stats; "
                         "cat /sys/kernel/debug/sunrpc_fuzz/phase3_connections",
                         check=False).stdout
    (output / "syz-kernel-wire-stats.log").write_text(raw_stats, encoding="utf-8")
    if result.returncode:
        raise ValueError("syz-execprog exited %d" % result.returncode)
    expected_calls = 4 * args.executions
    for name in ("syz_open_nfs_lane_pair", "syz_socket_connect_nfs_pair",
                 "syz_send_nfs_fuzz", "recvfrom"):
        suffix = r"\$[^\n=]*" if name.startswith("syz_") else ""
        matches = re.findall(r"<- %s%s=(0x[0-9a-f]+)" % (name, suffix),
                             log)
        if len(matches) != expected_calls or any(int(x, 16) in (0, 0xffffffffffffffff)
                                    for x in matches):
            raise ValueError("executor %s expected %d successes: %r" %
                             (name, expected_calls, matches))
    if ("raw_tx_full %d" % expected_calls not in raw_stats or
            "raw_rx_record %d" % expected_calls not in raw_stats):
        raise ValueError("four tagged RPCs did not complete both directions")
    if "syz_arm_nfs_proxy" in args.workload.read_text(encoding="utf-8"):
        arms = re.findall(r"<- syz_arm_nfs_proxy\$[^\n=]*=(0x[0-9a-f]+)", log)
        if len(arms) != 2 * args.executions or any(
                int(x, 16) == 0xffffffffffffffff for x in arms):
            raise ValueError("scoped arm registrations did not ACK: %r" % arms)
    return {"executions": args.executions, "four_pair_connects_each": True,
            "four_rpc_round_trips_each": True,
            "duration_seconds": next(entry["duration_seconds"] for entry in
                                     vm.evidence["commands"] if
                                     entry["stage"] == "syz-four-executor")}


def collect_live_deltas(vm, root, output, executions):
    expected = 2 * executions
    count = int(vm.guest("delta-count", "find " + shlex.quote(root) +
                         "/lane0/server/deltas -maxdepth 1 -name 'arm-*.delta' "
                         "-type f | wc -l").stdout.strip())
    if count != expected:
        raise ValueError("expected %d arm delta files, got %d" % (expected, count))
    records = []
    for index in sorted({0, 1, expected - 2, expected - 1}):
        direction = index % 2
        orig = b"\x22" * 4 if direction == 0 else b"\x22\x22\x22\x23"
        repl = b"\x22\x22\x22\x23" if direction == 0 else b"\x22" * 4
        guest_path = "%s/lane0/server/deltas/arm-%d.delta" % (root, index)
        encoded = vm.guest("delta-%d" % index, "base64 -w0 " +
                           shlex.quote(guest_path)).stdout.strip()
        data = base64.b64decode(encoded, validate=True)
        (output / ("arm-%d.delta" % index)).write_bytes(data)
        if data[:8] != b"NFSPDLT1" or len(data) != 72:
            raise ValueError("delta %d is incomplete or has bad magic" % index)
        fields = struct.unpack(">10I", data[20:60])
        if (fields[:3] != (direction, 1, 0) or fields[4] != 0xffffffff or
                fields[5:9] != (4, 4, 4, 4) or fields[9] != 1 or
                data[60:64] != orig or data[64:68] != orig or
                data[68:72] != repl):
            raise ValueError("delta %d has wrong scope, original or application count: %r"
                             % (index, fields))
        records.append({"file": "arm-%d.delta" % index, "sha256": ab.sha256(
            output / ("arm-%d.delta" % index)), "applied": fields[9],
            "direction": direction, "client": 0, "backend": 1})
    return records


def replay_guest_delta(vm, root, index, output):
    cmd = """set -eu
root=%s
index=%d
log=/tmp/relay-replay-$index.log
ip netns exec f9l0s /opt/kcov-nfs/deps/usr/sbin/nfs-proxy \
    10.89.0.2 10.89.0.6 10.89.0.1:20549 10.89.0.5:20549 \
    10.89.0.1:20490 10.89.0.5:20491 \
    --replay "$root/lane0/server/deltas/arm-$index.delta" >"$log" 2>&1 &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
i=0
until grep -q '^relay ready:' "$log"; do
    kill -0 "$pid"
    i=$((i + 1))
    test "$i" -lt 80
    sleep 0.1
done
ip netns exec f9l0c0 /opt/frozen-phase9/replay-probe "$index"
kill -TERM "$pid"
wait "$pid"
trap - EXIT
cat "$log"
""" % (shlex.quote(root), index)
    text = vm.guest("replay-%d" % index, cmd, timeout=40).stdout
    (output / ("replay-%d.log" % index)).write_text(text, encoding="utf-8")
    if ("replay_direction=%d " % index not in text or
            "replay rule=0 expected=1 applied=1 refused_orig=0" not in text or
            "proxy setup, poll or replay failed" in text):
        raise ValueError("guest replay mode did not reapply delta %d" % index)
    return {"direction": index, "log": "replay-%d.log" % index,
            "sha256": ab.sha256(output / ("replay-%d.log" % index))}


def replay_refused_original(vm, output):
    source = (output / "arm-0.delta").read_bytes()
    if len(source) != 72 or source[60:68] != b"\x22" * 8:
        raise ValueError("C2S delta cannot form the original-byte refusal probe")
    # Keep the persisted original bytes intact, but make the predicate match
    # the probe's different XID.  The replay must refuse rather than send the
    # replacement, count the refusal, and exit nonzero (expected 1, applied 0).
    variant = output / "refused-original.delta"
    variant.write_bytes(source[:60] + b"\x22\x22\x22\x24" + source[64:])
    vm.put("copy-refusal-delta", variant, "/tmp/relay-refused-original.delta")
    cmd = """set -eu
log=/tmp/relay-refused-original.log
ip netns exec f9l0s /opt/kcov-nfs/deps/usr/sbin/nfs-proxy \
    10.89.0.2 10.89.0.6 10.89.0.1:20549 10.89.0.5:20549 \
    10.89.0.1:20490 10.89.0.5:20491 \
    --replay /tmp/relay-refused-original.delta >"$log" 2>&1 &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
i=0
until grep -q '^relay ready:' "$log"; do
    kill -0 "$pid"
    i=$((i + 1))
    test "$i" -lt 80
    sleep 0.1
done
ip netns exec f9l0c0 /opt/frozen-phase9/replay-probe 2
kill -TERM "$pid"
status=0
wait "$pid" || status=$?
test "$status" -eq 1
trap - EXIT
cat "$log"
"""
    text = vm.guest("replay-refused-original", cmd, timeout=40).stdout
    log = output / "replay-refused-original.log"
    log.write_text(text, encoding="utf-8")
    if ("replay_direction=2 response_xid=0x22222224" not in text or
            "control mode=replay armed=1 expired=0 applied=0 refused_orig=1 "
            not in text or
            "replay rule=0 expected=1 applied=0 refused_orig=1" not in text or
            "proxy setup, poll or replay failed" not in text):
        raise ValueError("guest failed to count and reject the original-byte mismatch")
    return {"derived_delta": variant.name, "delta_sha256": ab.sha256(variant),
            "log": log.name, "log_sha256": ab.sha256(log)}


def main():
    args = args_parse()
    phase1 = ab.load_module("relay_phase1", REPO / "bundle/ab-runner/phases/run_frozen_phase1_vm.py")
    phase9 = ab.load_module("relay_phase9", TOOLS / "run_frozen_phase9_vm_ganesha.py")
    asan = ab.load_module("relay_asan", TOOLS / "run-ganesha-asan-smoke.py")
    phase1.REMOTE_DRIVER = "/opt/frozen-phase9"
    phase1.write_evidence = ab.write_trial_evidence
    args.output.mkdir(parents=True)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": 1, "experiment": "ganesha-asan-relay-four-mounts",
        "status": "running", "started_at": ab.timestamp(), "commands": [],
        "inputs": {name: {"path": str(getattr(args, name)),
                          "sha256": ab.sha256(getattr(args, name))}
                   for name in ("kernel", "image", "deps_tar", "proxy_binary",
                                "lane_fixture", "four_mount_script")},
        "controls": {"clients": 2, "backends": 2, "nfs_minor": 1,
                     "relay_only": args.workload is None,
                     "asan_options": args.asan_options,
                     "syzkaller_four_choice_integrated": args.workload is not None,
                     "delta_replay": args.replay_probe is not None,
                     "executions": args.executions},
    }
    for name in ("syz_executor", "syz_execprog", "workload", "replay_probe"):
        path = getattr(args, name)
        if path is not None:
            evidence["inputs"][name] = {"path": str(path), "sha256": ab.sha256(path)}
    vm = phase1.FrozenPhase1VM(args, evidence)
    root = None
    before = ab.sha256(args.image)
    try:
        vm.start()
        vm.guest("inventory", "set -eu; command -v ip nsenter mount.nfs4 tar grep findmnt")
        for label, source, remote in (
                ("deps", args.deps_tar, "/tmp/relay-deps.tar.gz"),
                ("proxy", args.proxy_binary, "/tmp/relay-proxy"),
                ("fixture", args.lane_fixture, "/tmp/relay-lane.sh"),
                ("mount-script", args.four_mount_script, "/tmp/relay-four-mounts.sh")):
            vm.put("copy-" + label, source, remote)
        vm.guest("install-inputs", "set -eu; install -d /opt/kcov-nfs/deps "
                 "/opt/kcov-nfs/deps/usr/sbin /opt/frozen-phase9; "
                 "tar -xzf /tmp/relay-deps.tar.gz -C /opt/kcov-nfs/deps; "
                 "install -m 0755 /tmp/relay-proxy /opt/kcov-nfs/deps/usr/sbin/nfs-proxy; "
                 "install -m 0755 /tmp/relay-lane.sh /opt/frozen-phase9/lane.sh; "
                 "install -m 0755 /tmp/relay-four-mounts.sh "
                 "/opt/frozen-phase9/four-mounts.sh", timeout=90)
        root = vm.guest("allocate-root", "mktemp -d /tmp/frozen-phase9.XXXXXX").stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-phase9\.[A-Za-z0-9]+", root):
            raise ValueError("unsafe lane root")
        setup = ["env", "SERVER_IMPL=both", "SERVER_PORT=2049",
                 "NFS_MINOR_VERSION=1", "KOOV_TMPFS_SIZE=256m",
                 "KOOV_GANESHA_DEBUG=NIV_EVENT",
                 "KOOV_GANESHA_ASAN_OPTIONS=" + args.asan_options,
                 "/opt/frozen-phase9/lane.sh", "setup", root, "1"]
        status = vm.guest("fixture-setup", shlex.join(setup), timeout=300)
        evidence["fixture"] = phase9.validate_fixture_status(json.loads(status.stdout), 1)
        lane = evidence["fixture"]["lanes"][0]
        if lane["server_threads"] < 2 or lane["ganesha_live"] != 1 or \
                lane["ganesha_listen"] < 1 or lane["tcp_connections"] < 4:
            raise ValueError("both backends or four connections not live: %s" % lane)
        evidence["executor_source_tree"] = relay_source_tree(vm)
        evidence["asan_loaded_before"] = asan.live_asan(vm, root, "asan-loaded-before")
        paths = vm.guest("four-mount-io", shlex.join([
            "/opt/frozen-phase9/four-mounts.sh", root]), timeout=90).stdout
        if paths.count("client=") != 4 or \
                "four_mounts=pass backend_isolation=pass" not in paths:
            raise ValueError("four mounts did not prove backend sharing/isolation")
        evidence["mount_io"] = paths.strip().splitlines()
        if args.workload is not None:
            evidence["executor_four_routes"] = syzkaller_four_routes(vm, args,
                                                                      args.output)
            if "syz_arm_nfs_proxy" in args.workload.read_text(encoding="utf-8"):
                evidence["deltas"] = collect_live_deltas(vm, root, args.output,
                                                         args.executions)
                evidence["delta_total"] = 2 * args.executions
                if args.replay_probe is not None:
                    vm.put("copy-replay-probe", args.replay_probe,
                           "/tmp/relay-replay-probe")
                    vm.guest("install-replay-probe", "install -m 0755 "
                             "/tmp/relay-replay-probe /opt/frozen-phase9/replay-probe")
                    evidence["replay"] = [replay_guest_delta(vm, root, index,
                                                              args.output)
                                          for index in (0, 1)]
                    evidence["refused_original"] = replay_refused_original(
                        vm, args.output)
        after = ["env", "SERVER_IMPL=both", "SERVER_PORT=2049",
                 "NFS_MINOR_VERSION=1", "/opt/frozen-phase9/lane.sh", "status", root]
        evidence["fixture_after"] = phase9.validate_fixture_status(json.loads(
            vm.guest("fixture-after", shlex.join(after), timeout=60).stdout), 1)
        evidence["asan_loaded_after"] = asan.live_asan(vm, root, "asan-loaded-after")
        evidence["relay"] = proxy_snapshot(vm, root, args.output)
        if args.workload is not None and "deltas" not in evidence:
            control = re.findall(r"^control mode=live armed=(\d+) expired=(\d+) "
                                 r"applied=(\d+) refused_orig=(\d+) "
                                 r"refused_bounds=(\d+) unknown_layout=(\d+) "
                                 r"invalid_arms=(\d+)$",
                                 (args.output / "relay.log").read_text(), re.MULTILINE)
            if not control or any(map(int, control[-1])):
                raise ValueError("OFF group received a proxy arm: %r" % control[-1:])
        if "deltas" in evidence:
            control = re.findall(r"^control mode=live armed=(\d+) expired=(\d+) "
                                 r"applied=(\d+) refused_orig=(\d+) "
                                 r"refused_bounds=(\d+) unknown_layout=(\d+) "
                                 r"invalid_arms=(\d+)$",
                                 (args.output / "relay.log").read_text(), re.MULTILINE)
            want = 2 * args.executions
            if not control or tuple(map(int, control[-1])) != (
                    want, want, want, 0, 0, 0, 0):
                raise ValueError("proxy control did not apply two scoped rules: %r"
                                 % control[-1:])
            evidence["control"] = list(map(int, control[-1]))
        evidence["asan_report"] = asan.collect_logs(vm, root, args.output)
        if evidence["asan_report"]:
            raise ValueError("Ganesha produced an AddressSanitizer report")
        evidence["cleanup"] = phase9.cleanup_fixture(vm, root, 1, strict=True)
        root = None
        evidence["status"] = "pass"
        print("ASan Ganesha + relay: 4 NFSv4 mounts, 4 live routes, "
              "shared per backend, isolated across backends, no ASan report, "
              "cleanup clean" + (", executor 4 RPC round trips" if args.workload
                                else "") + (", two live deltas replayed" if
                                "replay" in evidence else ""))
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if vm.ready and root:
            try:
                evidence["relay"] = proxy_snapshot(vm, root, args.output)
            except Exception as error:
                evidence["relay_snapshot_error"] = str(error)
            try:
                evidence["asan_report"] = asan.collect_logs(vm, root, args.output)
            except Exception as error:
                evidence["log_collection_error"] = str(error)
            try:
                evidence["emergency_cleanup"] = phase9.cleanup_fixture(
                    vm, root, 1, strict=False)
            except Exception as error:
                evidence["cleanup_error"] = str(error)
        vm.stop()
        evidence["base_image"] = {"sha256_before": before,
                                  "sha256_after": ab.sha256(args.image)}
        evidence["base_image"]["unchanged"] = (
            evidence["base_image"]["sha256_before"] ==
            evidence["base_image"]["sha256_after"])
        if not evidence["base_image"]["unchanged"]:
            evidence["status"] = "fail"
            evidence["failure"] = {"type": "ValueError", "message": "base image changed"}
        evidence["completed_at"] = ab.timestamp()
        ab.write_trial_evidence(args.output, evidence)
    if not evidence["base_image"]["unchanged"]:
        raise ValueError("base image changed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Ganesha relay smoke failed: %s" % error, file=sys.stderr)
        sys.exit(1)
