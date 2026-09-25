#!/usr/bin/env python3
"""Run the Frozen Baseline Phase 3 gate in a disposable VM.

The gate combines real NFSv4.1 TCP connections with deterministic kernel
self-test/fault hooks.  It fails closed if connection pairing, per-direction
ordinals, retransmission semantics, or Record-Marker-inclusive commit evidence
is unavailable.
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
REMOTE_DRIVER = "/opt/frozen-phase3"
STATS_PATH = "/sys/kernel/debug/sunrpc_fuzz/phase3_stats"
CONTROL_PATH = "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
CONNECTIONS_PATH = "/sys/kernel/debug/sunrpc_fuzz/phase3_connections"
DOMAIN_CONTROL_PATH = "/sys/kernel/debug/sunrpc_fuzz/domain_control"
DOMAIN_PATH = "/sys/kernel/debug/sunrpc_fuzz/domain"

REQUIRED_COUNTERS = {
    "domain_created",
    "domain_joined",
    "domain_retired",
    "lane_epoch_allocated",
    "lane_epoch_collision",
    "lane_epoch_immutable_violation",
    "connection_pair_ok",
    "connection_pair_miss",
    "connection_pair_expired",
    "connection_cookie_reuse",
    "direction_role_mismatch",
    "ordinal_tx_c2s",
    "ordinal_rx_c2s",
    "ordinal_tx_s2c",
    "ordinal_rx_s2c",
    "ordinal_mismatch",
    "record_ownerless",
    "record_background",
    "record_backchannel",
    "tcp_segment_retransmit",
    "tcp_retransmit_ordinal_increment",
    "sunrpc_logical_retry",
    "sunrpc_retry_same_cookie",
    "sunrpc_retry_new_ordinal",
    "wire_attempt_created",
    "wire_attempt_committed",
    "wire_attempt_rolled_back",
    "wire_attempt_postcommit_incomplete",
    "record_marker_first_byte_commit",
    "corrupted_connection_closed",
    "selftest_runs",
    "selftest_failures",
    "selftest_pairing_same_cookie",
    "selftest_reconnect_new_cookie",
    "selftest_lane_epoch_monotonic",
    "selftest_lane_epoch_immutable",
    "selftest_role_direction",
    "selftest_all_record_classes_ordinal",
    "selftest_tcp_retransmit_no_ordinal",
    "selftest_sunrpc_retry_new_ordinal_same_cookie",
    "selftest_record_marker_commit",
    "selftest_precommit_rollback",
    "selftest_postcommit_preserved",
}

SELFTEST_COUNTERS = {
    name for name in REQUIRED_COUNTERS if name.startswith("selftest_")
} - {"selftest_runs", "selftest_failures"}

CONNECTION_FIELDS = {
    "conn_cookie",
    "lane_id",
    "lane_epoch",
    "state",
    "client_cookie",
    "server_cookie",
    "client_attached",
    "server_attached",
    "family",
    "protocol",
    "client_addr",
    "client_port",
    "server_addr",
    "server_port",
    "c2s_tx",
    "c2s_rx",
    "s2c_tx",
    "s2c_rx",
    "ordinal_mismatch",
}

NUMERIC_CONNECTION_FIELDS = CONNECTION_FIELDS - {
    "state", "client_addr", "server_addr",
}

FATAL_KERNEL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:)",
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
    temporary = output / ".phase3-evidence.json.tmp"
    final = output / "phase3-evidence.json"
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, final)


def parse_counter_file(text):
    values = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.replace("=", " ", 1).split()
        if len(fields) != 2 or not re.fullmatch(r"[a-z][a-z0-9_]*", fields[0]):
            raise ValueError("invalid Phase 3 stats line %d: %r" % (number, raw))
        if fields[0] in values:
            raise ValueError("duplicate Phase 3 counter: %s" % fields[0])
        try:
            values[fields[0]] = int(fields[1], 0)
        except ValueError as error:
            raise ValueError("non-integer counter on line %d" % number) from error
        if values[fields[0]] < 0:
            raise ValueError("negative Phase 3 counter: %s" % fields[0])
    missing = sorted(REQUIRED_COUNTERS - values.keys())
    if missing:
        raise ValueError("missing required Phase 3 counters: " + ", ".join(missing))
    return values


def parse_pair_line(line, required):
    words = shlex.split(line)
    value = {}
    if words and all("=" in word for word in words):
        pairs = [word.split("=", 1) for word in words]
    else:
        if len(words) % 2:
            raise ValueError("odd key/value field count: %r" % line)
        pairs = [(words[index], words[index + 1])
                 for index in range(0, len(words), 2)]
    for key, item in pairs:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ValueError("invalid key %r" % key)
        if key in value:
            raise ValueError("duplicate key %s" % key)
        value[key] = item
    missing = sorted(required - value.keys())
    if missing:
        raise ValueError("missing fields: " + ", ".join(missing))
    return value


def parse_connections(text):
    connections = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value = parse_pair_line(line, CONNECTION_FIELDS)
        for key in NUMERIC_CONNECTION_FIELDS:
            try:
                value[key] = int(value[key], 0)
            except ValueError as error:
                raise ValueError("invalid numeric connection field %s" % key) from error
        connections.append(value)
    return connections


def parse_domain(text):
    value = parse_pair_line(text.strip(), {"lane_id", "lane_epoch", "active"})
    for key in ("lane_id", "lane_epoch", "active"):
        value[key] = int(value[key], 0)
    return value


def delta(before, after, name):
    difference = after[name] - before[name]
    if difference < 0:
        raise ValueError("counter regressed: %s" % name)
    return difference


def json_object(text, context):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("%s emitted invalid JSON" % context) from error
    if not isinstance(value, dict):
        raise ValueError("%s JSON is not an object" % context)
    return value


def client_probe_command(vm, client, mode, iterations=2):
    root = vm.lane_root
    return (
        "set -eu; client_pid=$(cat %s/client%d.pid); "
        "exec timeout 150s nsenter -t \"$client_pid\" -m -n -- "
        "%s/phase2-probe %s %s/client%d/mnt %d"
        % (
            shlex.quote(root), client, REMOTE_DRIVER, shlex.quote(mode),
            shlex.quote(root), client, iterations,
        )
    )


def stats_snapshot(vm, stage):
    result = vm.guest(stage, "cat " + STATS_PATH, timeout=20)
    return parse_counter_file(result.stdout)


def connection_snapshot(vm, stage):
    result = vm.guest(stage, "cat " + CONNECTIONS_PATH, timeout=20)
    return parse_connections(result.stdout)


def paired_connections(connections, epoch):
    return [
        connection for connection in connections
        if connection["state"] == "PAIRED"
        and connection["lane_id"] == 0
        and connection["lane_epoch"] == epoch
        and connection["client_attached"] == 1
        and connection["server_attached"] == 1
    ]


def validate_connection(connection):
    return (
        connection["conn_cookie"] > 0
        and connection["conn_cookie"] == connection["client_cookie"]
        and connection["conn_cookie"] == connection["server_cookie"]
        and connection["protocol"] == 6
        and connection["server_port"] == 2049
        and connection["c2s_tx"] == connection["c2s_rx"]
        and connection["s2c_tx"] == connection["s2c_rx"]
        and connection["ordinal_mismatch"] == 0
    )


def wait_for_ordinal_alignment(vm, epoch, counter_baseline, timeout=30,
                               require_global=True):
    """Wait for a quiescent cross-endpoint record boundary.

    Lease and callback traffic can be in flight when a snapshot is taken.  A
    single fixed sleep would turn that harmless transient into a flaky Gate 3
    failure, so require one observed, fully aligned state without weakening
    any of the ordinal invariants.
    """
    deadline = time.monotonic() + timeout
    latest_stats = None
    latest_connections = []
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        latest_stats = stats_snapshot(
            vm, "ordinal-align-stats-%02d" % attempt
        )
        latest_connections = connection_snapshot(
            vm, "ordinal-align-connections-%02d" % attempt
        )
        paired = paired_connections(latest_connections, epoch)
        if (
            len(paired) >= 2
            and latest_stats["ordinal_mismatch"] == 0
            # The in-kernel structural selftest deliberately exercises two
            # local TX commits without a peer.  Compare real-runtime deltas
            # after that selftest while per-connection state remains an
            # uncompensated, exact cross-endpoint check.
            and (
                not require_global
                or (
                    delta(counter_baseline, latest_stats, "ordinal_tx_c2s")
                    == delta(counter_baseline, latest_stats, "ordinal_rx_c2s")
                    and delta(counter_baseline, latest_stats, "ordinal_tx_s2c")
                    == delta(counter_baseline, latest_stats, "ordinal_rx_s2c")
                )
            )
            and all(validate_connection(item) for item in paired)
        ):
            return latest_stats, latest_connections
        time.sleep(1)
    raise ValueError(
        "RPC record ordinals did not reach an aligned state: stats=%r "
        "connections=%r" % (latest_stats, latest_connections)
    )


def wait_for_new_connection(vm, old_cookie, epoch, timeout=45):
    deadline = time.monotonic() + timeout
    latest = []
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        latest = connection_snapshot(vm, "reconnect-poll-%02d" % attempt)
        candidates = [
            item for item in paired_connections(latest, epoch)
            if item["conn_cookie"] != old_cookie
            and item["client_addr"] == "10.77.0.2"
        ]
        if candidates:
            return candidates[0], latest
        time.sleep(1)
    raise ValueError("reconnect did not produce a new paired conn_cookie")


def setup_lane(vm):
    command = (
        "FROZEN_NFS_PRE_MOUNT_HOOK=%s/bootstrap.sh "
        "FROZEN_NFS_PRE_CLEANUP_HOOK=%s/cleanup.sh "
        "%s/lane.sh setup %s"
        % (REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER,
           shlex.quote(vm.lane_root))
    )
    result = vm.guest("phase3-lane-setup", command, timeout=180)
    status = json_object(result.stdout, "lane setup")
    if status.get("localio") != "N" or int(status.get("tcp_connections", 0)) < 2:
        raise ValueError("Phase 3 lane setup did not establish two TCP mounts")
    epoch_text = vm.guest(
        "read-lane-epoch", "cat %s/lane_epoch" % shlex.quote(vm.lane_root),
        timeout=10,
    ).stdout.strip()
    if not epoch_text.isdigit() or int(epoch_text) <= 0:
        raise ValueError("invalid lane epoch evidence: %r" % epoch_text)
    epoch = int(epoch_text)
    root = shlex.quote(vm.lane_root)
    for role in ("server", "client0", "client1"):
        result = vm.guest(
            "domain-%s" % role,
            "pid=$(cat %s/%s.pid); nsenter -t \"$pid\" -n -- cat %s"
            % (root, role, DOMAIN_PATH),
            timeout=10,
        )
        domain = parse_domain(result.stdout)
        if domain != {"lane_id": 0, "lane_epoch": epoch, "active": 1}:
            raise ValueError("domain mismatch for %s: %r" % (role, domain))
        if role.startswith("client"):
            vm.guest(
                "client-kcov-" + role,
                "pid=$(cat %s/%s.pid); nsenter -t \"$pid\" -m -n -- "
                "sh -c 'mkdir -p /sys/kernel/debug; "
                "mount -t debugfs none /sys/kernel/debug; "
                "test -e /sys/kernel/debug/kcov'" % (root, role),
                timeout=10,
            )
    return epoch, status


def cleanup_lane(phase1, vm, epoch, strict):
    return phase1.cleanup_and_validate(vm, epoch, strict=strict)


def arm_and_probe(vm, fault, mode="attributed"):
    before = stats_snapshot(vm, "stats-before-fault-" + fault)
    vm.guest(
        "arm-fault-" + fault,
        "printf 'fault-arm %s\\n' > %s" % (fault, CONTROL_PATH),
        timeout=20,
    )
    result = vm.guest(
        "probe-fault-" + fault,
        client_probe_command(vm, 0, mode, 1),
        timeout=180,
    )
    value = json_object(result.stdout, fault + " fault probe")
    if value.get("status") != "pass":
        raise ValueError("fault probe did not complete: %s" % fault)
    after = stats_snapshot(vm, "stats-after-fault-" + fault)
    return before, after, value


def run_backchannel_recall(vm):
    root = vm.lane_root
    mount0 = "%s/client0/mnt" % root
    mount1 = "%s/client1/mnt" % root
    sync = "%s/sync" % root
    path = ".frozen-phase3-delegation"
    vm.guest(
        "delegation-seed",
        "pid=$(cat %s/client0.pid); nsenter -t \"$pid\" -m -n -- "
        "sh -c 'printf seed > \"$1\"; sync' sh %s/%s"
        % (shlex.quote(root), shlex.quote(mount0), path),
        timeout=30,
    )
    holder = """set -eu
pid=$(cat %s/client0.pid)
exec nsenter -t "$pid" -m -n -- sh -c '
    set -eu
    exec 9<"$1"
    dd if=/proc/self/fd/9 of=/dev/null bs=4 count=1 2>/dev/null
    : > "$2/holder-ready"
    count=0
    while ! test -e "$2/writer-done"; do
        count=$((count + 1)); test "$count" -lt 300; sleep 0.1
    done
    dd if=/proc/self/fd/9 of=/dev/null bs=4 count=1 2>/dev/null
    exec 9<&-
' sh %s/%s %s
""" % (shlex.quote(root), shlex.quote(mount0), path, shlex.quote(sync))
    writer = """set -eu
pid=$(cat %s/client1.pid)
exec nsenter -t "$pid" -m -n -- sh -c '
    set -eu
    count=0
    while ! test -e "$2/holder-ready"; do
        count=$((count + 1)); test "$count" -lt 300; sleep 0.1
    done
    printf conflict >> "$1"
    sync
    : > "$2/writer-done"
' sh %s/%s %s
""" % (shlex.quote(root), shlex.quote(mount1), path, shlex.quote(sync))
    vm.guest_parallel("delegation-recall", [holder, writer], timeout=60)
    vm.guest(
        "delegation-cleanup",
        "pid=$(cat %s/client0.pid); nsenter -t \"$pid\" -m -n -- rm -f %s/%s; "
        "rm -f %s/holder-ready %s/writer-done"
        % (shlex.quote(root), shlex.quote(mount0), path,
           shlex.quote(sync), shlex.quote(sync)),
        timeout=30,
    )


def validate_gate(baseline, after_selftest, before_recall, after_recall,
                  aligned_stats, after_runtime, fault_results,
                  aligned_connections, postcommit_old_cookie,
                  postcommit_connection, postcommit_connections,
                  tcp_retransmit_aligned_stats,
                  tcp_retransmit_aligned_connections,
                  reconnect_connection, first_epoch, second_epoch):
    checks = {}
    checks["selftest_ran_once"] = delta(
        baseline, after_selftest, "selftest_runs"
    ) == 1
    checks["selftest_failures_zero"] = after_selftest["selftest_failures"] == 0
    for name in sorted(SELFTEST_COUNTERS):
        checks[name] = delta(baseline, after_selftest, name) == 1

    paired = paired_connections(aligned_connections, first_epoch)
    checks["two_real_paired_connections"] = len(paired) >= 2
    checks["same_cookie_on_both_endpoints"] = bool(paired) and all(
        validate_connection(item) for item in paired
    )
    checks["both_clients_same_lane_epoch"] = {
        item["client_addr"] for item in paired
    }.issuperset({"10.77.0.2", "10.77.0.6"})
    checks["reconnect_new_cookie"] = (
        reconnect_connection["conn_cookie"] > 0
        and all(reconnect_connection["conn_cookie"] != item["conn_cookie"]
                for item in paired if item["client_addr"] == "10.77.0.2")
        and validate_connection(reconnect_connection)
    )
    checks["lane_epoch_monotonic"] = second_epoch > first_epoch
    checks["no_lane_epoch_collisions"] = after_runtime["lane_epoch_collision"] == 0
    checks["lane_epoch_immutable"] = (
        after_runtime["lane_epoch_immutable_violation"] == 0
    )
    checks["nfs_role_direction_valid"] = (
        aligned_stats["direction_role_mismatch"] == 0
        and aligned_stats["ordinal_tx_c2s"] > 0
        and aligned_stats["ordinal_tx_s2c"] > 0
    )
    checks["global_ordinals_aligned"] = (
        aligned_stats["ordinal_mismatch"] == 0
        and delta(after_selftest, aligned_stats, "ordinal_tx_c2s")
        == delta(after_selftest, aligned_stats, "ordinal_rx_c2s")
        and delta(after_selftest, aligned_stats, "ordinal_tx_s2c")
        == delta(after_selftest, aligned_stats, "ordinal_rx_s2c")
        and all(item["ordinal_mismatch"] == 0 for item in paired)
    )
    checks["ownerless_records_counted"] = aligned_stats["record_ownerless"] > 0
    checks["real_background_records_counted"] = (
        delta(after_recall, aligned_stats, "record_background") > 0
    )
    checks["real_backchannel_records_counted"] = (
        delta(before_recall, after_recall, "record_backchannel") > 0
    )

    pre_before, pre_after, _ = fault_results["precommit"]
    checks["precommit_runtime_rollback"] = (
        delta(pre_before, pre_after, "wire_attempt_rolled_back") == 1
        and delta(pre_before, pre_after, "wire_attempt_committed") > 0
    )
    post_before, post_after, _ = fault_results["postcommit"]
    checks["postcommit_runtime_preserved"] = (
        delta(post_before, post_after, "wire_attempt_postcommit_incomplete") == 1
        and delta(post_before, post_after, "corrupted_connection_closed") == 1
    )
    postcommit_paired = paired_connections(
        postcommit_connections, first_epoch
    )
    checks["postcommit_connection_replaced"] = (
        postcommit_connection["conn_cookie"] != postcommit_old_cookie
        and validate_connection(postcommit_connection)
        and all(item["conn_cookie"] != postcommit_old_cookie
                for item in postcommit_paired)
    )
    retry_before, retry_after, _ = fault_results["sunrpc-retry"]
    checks["sunrpc_retry_runtime_semantics"] = (
        delta(retry_before, retry_after, "sunrpc_logical_retry") == 1
        and delta(retry_before, retry_after, "sunrpc_retry_same_cookie") == 1
        and delta(retry_before, retry_after, "sunrpc_retry_new_ordinal") == 1
    )
    tcp_before, tcp_after, _ = fault_results["tcp-retransmit"]
    checks["tcp_retransmit_runtime_semantics"] = (
        delta(tcp_before, tcp_after, "tcp_segment_retransmit") >= 1
        and delta(tcp_before, tcp_after,
                  "tcp_retransmit_ordinal_increment") == 0
    )
    retransmit_paired = paired_connections(
        tcp_retransmit_aligned_connections, first_epoch
    )
    checks["tcp_retransmit_blackbox_alignment"] = (
        tcp_retransmit_aligned_stats["ordinal_mismatch"] == 0
        # A prior forced SUNRPC reconnect can intentionally leave a
        # committed record undelivered on a retired connection.  The TCP
        # retransmission itself must not change that cumulative divergence.
        and (tcp_retransmit_aligned_stats["ordinal_tx_c2s"]
             - tcp_retransmit_aligned_stats["ordinal_rx_c2s"])
        == (tcp_before["ordinal_tx_c2s"] - tcp_before["ordinal_rx_c2s"])
        and (tcp_retransmit_aligned_stats["ordinal_tx_s2c"]
             - tcp_retransmit_aligned_stats["ordinal_rx_s2c"])
        == (tcp_before["ordinal_tx_s2c"] - tcp_before["ordinal_rx_s2c"])
        and len(retransmit_paired) >= 2
        and all(validate_connection(item) for item in retransmit_paired)
    )
    checks["record_marker_commit_observed"] = (
        delta(after_selftest, aligned_stats,
              "record_marker_first_byte_commit") > 0
    )
    checks["connection_pairing_no_miss"] = after_runtime["connection_pair_miss"] == 0
    checks["pending_pairing_never_expired"] = (
        after_runtime["connection_pair_expired"] == 0
    )
    checks["connection_cookie_never_reused"] = (
        after_runtime["connection_cookie_reuse"] == 0
    )
    checks["both_domains_retired"] = (
        delta(baseline, after_runtime, "domain_created") >= 2
        and delta(baseline, after_runtime, "domain_joined") >= 4
        and delta(baseline, after_runtime, "domain_retired") >= 2
    )

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise ValueError("Gate 3 checks failed: " + ", ".join(failed))
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
    parser.add_argument("--phase2-probe", type=Path,
                        default=scripts / "frozen_phase2_probe.c")
    parser.add_argument("--bootstrap", type=Path,
                        default=scripts / "frozen_phase3_bootstrap.sh")
    parser.add_argument("--cleanup-hook", type=Path,
                        default=scripts / "frozen_phase3_cleanup.sh")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    for name in ("kernel", "image", "ssh_key", "deps_tar", "phase1_runner",
                 "lane_script", "workload", "phase2_probe", "bootstrap",
                 "cleanup_hook"):
        setattr(args, name, getattr(args, name).resolve())
        path = getattr(args, name)
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing or empty --%s: %s" % (name.replace("_", "-"), path))
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
    args.probe = args.phase2_probe

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION,
        "phase": 3,
        "status": "running",
        "started_at": timestamp(),
        "commands": [],
        "snapshots": {},
        "gate": {"name": "Gate 3", "status": "running"},
        "observability_contract": {
            "stats": STATS_PATH,
            "control": CONTROL_PATH,
            "connections": CONNECTIONS_PATH,
            "domain_control": DOMAIN_CONTROL_PATH,
            "domain": DOMAIN_PATH,
            "required_counters": sorted(REQUIRED_COUNTERS),
            "fault_commands": {
                "precommit": "fail before any Record Marker byte is committed",
                "postcommit": "fail after the first on-wire record byte commits",
                "sunrpc-retry": "force one real SUNRPC logical retry",
                "tcp-retransmit": (
                    "drop one actual paired-socket TCP segment; "
                    "tcp_segment_retransmit is counted only in tcp_retransmit_skb"
                ),
            },
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
        for name in ("phase1_runner", "phase2_probe", "bootstrap",
                     "cleanup_hook"):
            path = getattr(args, name)
            evidence["inputs"][name] = {
                "path": str(path), "bytes": path.stat().st_size,
                "sha256": phase1.sha256(path),
            }
        phase2_probe_source = args.phase2_probe.read_text(encoding="utf-8")
        generation_begin_offset = phase2_probe_source.find(
            "generation_begin(owner.fd)"
        )
        attributed_fork_offset = phase2_probe_source.find(
            "child = fork()", generation_begin_offset
        )
        if (generation_begin_offset < 0 or attributed_fork_offset < 0 or
                generation_begin_offset >= attributed_fork_offset):
            raise ValueError(
                "Phase 3 attributed probe must BEGIN an exact generation "
                "before its per-program fork"
            )
        lane_source = args.lane_script.read_text(encoding="utf-8")
        hook_offset = lane_source.find('"$pre_mount_hook" "$root"')
        server_start_offset = lane_source.find(
            'ip netns exec "$server_ns" unshare --mount'
        )
        retire_hook_offset = lane_source.find(
            '"$hook" "$root" "$server_ns" "$client0_ns" "$client1_ns"'
        )
        namespace_delete_offset = lane_source.find(
            'stop_namespace "$client0_ns"'
        )
        if hook_offset < 0 or server_start_offset < 0 or hook_offset >= server_start_offset:
            raise ValueError("Phase 3 domain hook is not before server/connect setup")
        if (retire_hook_offset < 0 or namespace_delete_offset < 0 or
                retire_hook_offset >= namespace_delete_offset):
            raise ValueError("Phase 3 retire hook is not before netns deletion")
        evidence["source_contract"] = {
            "phase2_probe_exact_generation_before_fork": True,
            "pre_mount_hook_before_server_and_client_connections": True,
            "retire_hook_before_namespace_delete": True,
            "hook_offset": hook_offset,
            "server_start_offset": server_start_offset,
            "retire_hook_offset": retire_hook_offset,
            "namespace_delete_offset": namespace_delete_offset,
        }
        base_hash = evidence["inputs"]["image"]["sha256"]
        vm = phase1.FrozenPhase1VM(args, evidence)
        vm.start()
        vm.guest(
            "guest-inventory",
            "set -eu; mountpoint -q /sys/kernel/debug || mount -t debugfs none "
            "/sys/kernel/debug; command -v gcc ip nsenter timeout tar",
            timeout=30,
        )
        for path in (STATS_PATH, CONTROL_PATH, CONNECTIONS_PATH,
                     DOMAIN_CONTROL_PATH, DOMAIN_PATH):
            vm.guest("interface-" + Path(path).name,
                     "test -e " + shlex.quote(path), timeout=10)
        vm.put("copy-dependencies", args.deps_tar,
               "/tmp/frozen-phase3-deps.tar.gz")
        vm.put("copy-lane-script", args.lane_script,
               "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-bootstrap", args.bootstrap,
               "/tmp/frozen-phase3-bootstrap.sh")
        vm.put("copy-cleanup-hook", args.cleanup_hook,
               "/tmp/frozen-phase3-cleanup.sh")
        vm.put("copy-phase2-probe", args.phase2_probe,
               "/tmp/frozen-phase2-probe.c")
        vm.guest(
            "install-guest-inputs",
            "set -eu; install -d /opt/kcov-nfs/deps %s; "
            "tar -xzf /tmp/frozen-phase3-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/frozen-phase1-lane.sh %s/lane.sh; "
            "install -m 0755 /tmp/frozen-phase3-bootstrap.sh %s/bootstrap.sh; "
            "install -m 0755 /tmp/frozen-phase3-cleanup.sh %s/cleanup.sh; "
            "gcc -O2 -Wall -Wextra -Werror -o %s/phase2-probe "
            "/tmp/frozen-phase2-probe.c"
            % (REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER, REMOTE_DRIVER,
               REMOTE_DRIVER),
            timeout=90,
        )
        allocated = vm.guest(
            "allocate-lane-root", "mktemp -d /tmp/frozen-nfs.XXXXXX", timeout=10
        )
        vm.lane_root = allocated.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise ValueError("unsafe lane root")

        vm.guest("reset-phase3", "printf 'reset\\n' > " + CONTROL_PATH,
                 timeout=20)
        baseline = stats_snapshot(vm, "stats-baseline")
        first_epoch, first_status = setup_lane(vm)
        active_epoch = first_epoch
        vm.guest("nfs-grace", "sleep 11", timeout=20)
        first_connections = connection_snapshot(vm, "connections-initial")
        if len(paired_connections(first_connections, first_epoch)) < 2:
            raise ValueError("initial mounts lack two paired connection records")

        vm.guest("run-phase3-selftest",
                 "printf 'selftest\\n' > " + CONTROL_PATH, timeout=60)
        after_selftest = stats_snapshot(vm, "stats-after-selftest")

        attributed = vm.guest(
            "runtime-attributed", client_probe_command(vm, 0, "attributed", 3),
            timeout=180,
        )
        unattributed = vm.guest(
            "runtime-unattributed", client_probe_command(vm, 1, "unattributed", 3),
            timeout=180,
        )
        evidence["runtime_probes"] = [
            json_object(attributed.stdout, "attributed probe"),
            json_object(unattributed.stdout, "unattributed probe"),
        ]
        before_recall = stats_snapshot(vm, "stats-before-backchannel-recall")
        run_backchannel_recall(vm)
        after_recall = stats_snapshot(vm, "stats-after-backchannel-recall")
        # The Phase 1 fixture configures a ten-second v4 lease.  Crossing one
        # lease interval deterministically gives the client state manager an
        # opportunity to emit an ownerless renewal/background RPC.
        vm.guest("background-renewal-window", "sync; sleep 12", timeout=20)
        vm.guest("runtime-record-drain", "sync", timeout=20)
        aligned_stats, aligned_connections = wait_for_ordinal_alignment(
            vm, first_epoch, after_selftest
        )

        faults = {}
        postcommit_old_cookie = None
        postcommit_connection = None
        postcommit_connections = None
        tcp_retransmit_aligned_stats = None
        tcp_retransmit_aligned_connections = None
        for fault in ("precommit", "sunrpc-retry", "tcp-retransmit", "postcommit"):
            if fault == "postcommit":
                snapshot = connection_snapshot(
                    vm, "connections-before-postcommit"
                )
                current = [
                    item for item in paired_connections(snapshot, first_epoch)
                    if item["client_addr"] == "10.77.0.2"
                ]
                if not current:
                    raise ValueError(
                        "postcommit fault has no paired client0 connection"
                    )
                postcommit_old_cookie = max(
                    item["conn_cookie"] for item in current
                )
            faults[fault] = arm_and_probe(vm, fault)
            if fault == "tcp-retransmit":
                (tcp_retransmit_aligned_stats,
                 tcp_retransmit_aligned_connections) = (
                    wait_for_ordinal_alignment(
                        vm, first_epoch, after_selftest,
                        require_global=False
                    )
                )
            if fault == "postcommit":
                postcommit_connection, postcommit_connections = (
                    wait_for_new_connection(
                        vm, postcommit_old_cookie, first_epoch
                    )
                )
        evidence["faults"] = {
            name: {"before": value[0], "after": value[1], "probe": value[2]}
            for name, value in faults.items()
        }
        evidence["postcommit_reconnect"] = {
            "old_cookie": postcommit_old_cookie,
            "new_connection": postcommit_connection,
            "connections": postcommit_connections,
        }
        evidence["tcp_retransmit_alignment"] = {
            "stats": tcp_retransmit_aligned_stats,
            "connections": tcp_retransmit_aligned_connections,
        }

        before_disconnect = connection_snapshot(vm, "connections-before-disconnect")
        client0 = [item for item in paired_connections(before_disconnect, first_epoch)
                   if item["client_addr"] == "10.77.0.2"]
        if not client0:
            raise ValueError("could not identify client0 paired connection")
        old_cookie = max(item["conn_cookie"] for item in client0)
        vm.guest(
            "force-disconnect",
            "printf 'disconnect %d\\n' > %s" % (old_cookie, CONTROL_PATH),
            timeout=30,
        )
        vm.guest(
            "reconnect-trigger",
            client_probe_command(vm, 0, "unattributed", 1), timeout=180,
        )
        reconnect_connection, reconnect_snapshot = wait_for_new_connection(
            vm, old_cookie, first_epoch
        )

        after_runtime = stats_snapshot(vm, "stats-after-runtime")
        evidence["snapshots"].update({
            "baseline": baseline,
            "after_selftest": after_selftest,
            "runtime_aligned_stats": aligned_stats,
            "runtime_aligned_connections": aligned_connections,
            "before_backchannel_recall": before_recall,
            "after_backchannel_recall": after_recall,
            "after_runtime": after_runtime,
            "initial_connections": first_connections,
            "reconnect_connections": reconnect_snapshot,
        })
        evidence["epochs"] = {"first": first_epoch}
        evidence["first_lane_status"] = first_status

        cleanup_lane(phase1, vm, first_epoch, strict=True)
        active_epoch = None
        second_epoch, second_status = setup_lane(vm)
        active_epoch = second_epoch
        second_connections = connection_snapshot(vm, "connections-second-epoch")
        evidence["epochs"]["second"] = second_epoch
        evidence["second_lane_status"] = second_status
        evidence["snapshots"]["second_connections"] = second_connections

        # Make resource retirement part of Gate 3 rather than a best-effort
        # finally action.  The pre-cleanup hook retires the immutable domain
        # only after mounts and knfsd have drained, but before netns deletion.
        cleanup_lane(phase1, vm, second_epoch, strict=True)
        active_epoch = None
        final_stats = stats_snapshot(vm, "stats-final")
        evidence["snapshots"]["final_stats"] = final_stats
        checks = validate_gate(
            baseline, after_selftest, before_recall, after_recall,
            aligned_stats, final_stats, faults, aligned_connections,
            postcommit_old_cookie, postcommit_connection,
            postcommit_connections, tcp_retransmit_aligned_stats,
            tcp_retransmit_aligned_connections, reconnect_connection,
            first_epoch, second_epoch,
        )
        evidence["gate"] = {"name": "Gate 3", "status": "pass", "checks": checks}
        evidence["status"] = "pass"
        evidence["completed_at"] = timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        evidence["gate"] = {"name": "Gate 3", "status": "fail"}
        evidence["completed_at"] = timestamp()
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                cleanup_ok = False
                try:
                    result = phase1.cleanup_and_validate(vm, 999, strict=False)
                    evidence["cleanup"] = result
                    cleanup_ok = all(result.get(name) == 0 for name in
                                     ("cleanup_returncode",
                                      "validation_returncode"))
                    if not cleanup_ok:
                        raise ValueError("Phase 3 final lane cleanup failed")
                except Exception as error:
                    evidence["cleanup"] = {"error": str(error)}
                    if exit_code == 0:
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
                        evidence["failure"] = {
                            "type": type(error).__name__, "message": str(error),
                        }
                        exit_code = 1
                if active_epoch is not None and cleanup_ok:
                    active_epoch = None
            try:
                dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
                (args.output / "dmesg.txt").write_text(
                    dmesg.stdout + dmesg.stderr,
                    encoding="utf-8", errors="replace",
                )
                if exit_code == 0 and (dmesg.returncode or
                                       FATAL_KERNEL_RE.search(dmesg.stdout)):
                    raise ValueError("fatal kernel diagnostic in Phase 3 VM")
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
        "evidence": str(args.output / "phase3-evidence.json"),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
