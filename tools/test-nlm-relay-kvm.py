#!/usr/bin/env python3
"""Non-promoting NLM target-relay smoke test in a disposable KVM snapshot."""

import argparse
import hashlib
import json
import re
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

from agent_pipeline.data import canonical_json
from agent_pipeline.stage1.host.vm import QemuGuest, VmConfig
from agent_pipeline.stage2.kvm import _JournalChannels, _lane_template
from nlm_callback_attribution import diagnostic, grant_trace_statuses
from tools.nlm_capture_lifecycle import (
    CAPTURE, COMPLETE, EVENT_LOG, MARKER_SOCKET, STATS, STOP, instrument_lane,
)
from tools.nlm_callback_verify import verify_capture, verify_ordered_capture
from tools.nlm_ordered_capture import build_manifest
from agent_pipeline.semantic_delta import SealedJournal


SCHEMA = "nlm4/sha256:9986d9f2be8bc5e36de582c10f89f1124448718cdd89ea266f3e61cb7b5442d4"
MUTATION_MODES = (
    "offset_noop_control",
    "offset_identity_break",
    "cookie_identity_preserving",
)
COOKIE_REPLACEMENT = b"KOOV"


def _contention_diagnostic_status(summary, mutation_mode):
    """Classify separate forwarding, callback, and syscall observations."""
    completed = summary.get("waiting_fcntl_completed") is True
    if mutation_mode == "offset_identity_break":
        expected = (summary.get("mutation_forwarded") is True
                    and summary.get("mutation_value_changed") is True
                    and summary.get("callback_received") is True
                    and summary.get("callback_client_status") == "LCK_DENIED"
                    and summary.get("granted_res_status") == "LCK_DENIED")
        if not expected:
            return "offset_identity_break_diagnostic_incomplete"
        return "offset_identity_break_callback_denied_diagnostic_only"
    changed = summary.get("mutation_value_changed") is True
    expected = (summary.get("mutation_forwarded") is True
                and summary.get("callback_received") is True
                and summary.get("callback_client_status") == "LCK_GRANTED"
                and summary.get("granted_res_status") == "LCK_GRANTED"
                and completed
                and (changed if mutation_mode == "cookie_identity_preserving"
                     else not changed))
    prefix = ("cookie_identity_preserving"
              if mutation_mode == "cookie_identity_preserving"
              else "offset_noop_control")
    return (prefix + "_callback_accepted_and_fcntl_completed_diagnostic_only"
            if expected else prefix + "_diagnostic_incomplete")


def xdr_string(value):
    data = value.encode("ascii")
    return struct.pack(">I", len(data)) + data + b"\0" * (-len(data) % 4)


def xdr_opaque(value):
    return struct.pack(">I", len(value)) + value + b"\0" * (-len(value) % 4)


def diagnostic_rules(mutation_mode="offset_noop_control", client=1):
    u32 = lambda value: struct.pack(">I", value)
    if mutation_mode not in MUTATION_MODES:
        raise ValueError(f"unknown NLM mutation mode: {mutation_mode}")
    cookie = mutation_mode == "cookie_identity_preserving"
    target = ("nlm4.request.LOCK.args.cookie" if cookie else
              "nlm4.request.LOCK.args.alock.l_offset")
    rule_id = "nlm-lock-cookie" if cookie else "nlm-lock-offset"
    if cookie:
        predicates = u32(0)
        transform = u32(6) + xdr_opaque(COOKIE_REPLACEMENT)
    else:
        replacement = 1 if mutation_mode == "offset_identity_break" else 0
        # Limit the range rule to the offset-zero request used by this fixture.
        predicates = (u32(1) + u32(0) + xdr_string("") + u32(0)
                      + u32(0) + u32(3) + struct.pack(">Q", 0))
        transform = u32(3) + struct.pack(">Q", replacement)
    rule = b"".join((
        xdr_string(rule_id), xdr_string("nlm-route-diagnostic"),
        u32(0), u32(0), u32(client),            # c2s, knfsd, selected client
        u32(0), u32(100021), u32(4),          # NLMv4 call
        u32(1), u32(2),                       # LOCK procedure
        xdr_string("nlm4"), u32(0), u32(0), u32(0),
        u32(0), xdr_string(target), u32(0), predicates,
        u32(0), u32(1), u32(0), transform,
        u32(0), u32(0) * 3, u32(0) * 3, u32(0),
    ))
    return (b"NFSPRUL1" + u32(1) + xdr_string(SCHEMA)
            + xdr_string("nlm-relay-diagnostic") + u32(1) + rule)


def checked(guest, command, timeout=60):
    rc, output = guest.run(command, timeout=timeout)
    if rc:
        raise RuntimeError(f"guest rc={rc}: {command}\n{output[-3000:]}")
    return output


def snapshot(guest):
    path = "/tmp/frozen-phase9.manager/lane0/server/proxy.log"
    before = checked(guest, "cat " + path).count("stats_end snapshot")
    checked(guest, "kill -USR1 $(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid)")
    deadline = time.monotonic() + 20
    while True:
        log = checked(guest, "cat " + path)
        if log.count("stats_end snapshot") > before:
            break
        if time.monotonic() >= deadline:
            state = checked(
                guest, "p=$(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid); "
                       "echo pid=$p; cat /proc/$p/wchan /proc/$p/stack; "
                       "cat /proc/$p/syscall /proc/$p/status; "
                       "awk '{print \"exit_code=\" $52}' /proc/$p/stat; "
                       "ps -T -p $p -o pid,tid,stat,wchan:25,comm")
            raise RuntimeError("Proxy snapshot stalled: " + state)
        time.sleep(0.2)
    blocks = re.findall(r"stats_begin snapshot\n(.*?)stats_end snapshot", log, re.S)
    if not blocks:
        raise RuntimeError("Proxy did not report snapshot stats")
    totals = {"accepted": 0, "c2s": 0, "s2c": 0}
    for line in blocks[-1].splitlines():
        if not line.startswith("client="):
            continue
        fields = dict(part.split("=", 1) for part in line.split())
        for key in totals:
            totals[key] += int(fields[key])
    return totals


def cleanup_capture_lifecycle(guest):
    """Return cleanup evidence and an error; recovery never validates capture."""
    rc, output = guest.run(
        "/run/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager",
        timeout=180)
    evidence = {"returncode": rc, "output": output[-4000:]}
    if rc:
        # The capture is already invalid. This is process recovery only and
        # cannot turn its completion marker into lifecycle evidence.
        guest.run(f": > {STOP}; sleep 1; pkill -TERM -x nlm-pcap || true",
                  timeout=15)
        return evidence, f"fixture cleanup failed: rc={rc}"
    checked(guest, f"test -e {COMPLETE} && ! pgrep -x nlm-pcap >/dev/null")
    return evidence, None


def _install_fixture_replacements(guest, proxy, boot_fixture,
                                  lockd_port_helper, rpcbind_front_helper):
    """Install the disposable fixture binaries before starting its lanes."""
    guest.put(proxy, "/tmp/nfs-proxy-replacement")
    guest.put(boot_fixture, "/tmp/boot-fixture-replacement")
    guest.put(lockd_port_helper, "/tmp/lockd-netlink-port-replacement")
    guest.put(rpcbind_front_helper, "/tmp/nlm-rpcbind-front-replacement")
    checked(
        guest,
        "install -m 0755 /tmp/nfs-proxy-replacement "
        "/opt/kcov-nfs/deps/usr/sbin/nfs-proxy; "
        "install -m 0755 /tmp/lockd-netlink-port-replacement "
        "/opt/kcov-nfs/deps/usr/sbin/lockd-netlink-port; "
        "install -m 0755 /tmp/nlm-rpcbind-front-replacement "
        "/opt/kcov-nfs/deps/usr/sbin/nlm-rpcbind-front; "
        "install -m 0755 /tmp/boot-fixture-replacement "
        "/opt/frozen-phase9/boot-fixture.sh; "
        "/opt/frozen-phase9/boot-fixture.sh",
        timeout=240)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--bzimage", required=True, type=Path)
    parser.add_argument("--ssh-key", required=True, type=Path)
    parser.add_argument("--lock-probe", required=True, type=Path)
    parser.add_argument("--activation-driver", type=Path)
    parser.add_argument("--proxy", type=Path,
                        help="Guest ABI proxy to replace in the disposable VM")
    parser.add_argument("--lockd-port-helper", type=Path,
                        help="Guest ABI lockd netlink helper for the disposable fixture")
    parser.add_argument("--rpcbind-front-helper", type=Path,
                        help="Guest ABI rpcbind front-end for the disposable fixture")
    parser.add_argument("--packet-capture", type=Path,
                        help="Static diagnostic AF_PACKET recorder copied to disposable VM")
    parser.add_argument("--capture-lifecycle", action="store_true",
                        help="instrument only the disposable lane to capture setup and cleanup")
    parser.add_argument("--contention", action="store_true",
                        help="Have client1 wait for client0's record lock")
    parser.add_argument("--activate", action="store_true",
                        help="Activate an NLM LOCK diagnostic rule")
    parser.add_argument("--mutation-mode", choices=MUTATION_MODES,
                        help="Explicit diagnostic mutation and expected callback identity")
    parser.add_argument("--mutation-offset", type=int, choices=(0, 1),
                        help="Compatibility alias for an offset control/break mode")
    parser.add_argument("--deactivate-before-grant", action="store_true",
                        help="Diagnostic negative case: close generation while grant is pending")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    helpers = (args.lockd_port_helper, args.rpcbind_front_helper)
    if any(helpers) and not all(helpers):
        parser.error(
            "--lockd-port-helper and --rpcbind-front-helper must be provided together")
    if args.proxy and not all(helpers):
        parser.error(
            "--proxy requires --lockd-port-helper and --rpcbind-front-helper")
    if args.activate and (not args.proxy or not args.activation_driver):
        parser.error("--activate requires --proxy and --activation-driver")
    if args.deactivate_before_grant and not (args.activate and args.contention):
        parser.error("--deactivate-before-grant requires --activate --contention")
    if args.capture_lifecycle and not (args.packet_capture and args.proxy):
        parser.error("--capture-lifecycle requires --packet-capture and --proxy")
    mutation_mode = args.mutation_mode
    if args.mutation_offset is not None:
        legacy_mode = ("offset_identity_break" if args.mutation_offset else
                       "offset_noop_control")
        if mutation_mode is not None and mutation_mode != legacy_mode:
            parser.error("--mutation-mode conflicts with --mutation-offset")
        mutation_mode = legacy_mode
    if mutation_mode is None:
        mutation_mode = "offset_noop_control"
    args.mutation_mode = mutation_mode
    return args


def main():
    args = _parse_args()
    mutation_mode = args.mutation_mode
    args.output.mkdir(parents=True, exist_ok=False)
    rules = (diagnostic_rules(mutation_mode) if args.activate else
             b"NFSPRUL1" + struct.pack(">I", 1) + xdr_string(SCHEMA)
             + xdr_string("nlm-relay-smoke") + struct.pack(">I", 0))
    if args.activate:
        check = subprocess.run([str(args.proxy), "--check-rules", "/dev/stdin"],
                               input=rules, capture_output=True)
        if check.returncode:
            raise RuntimeError("diagnostic rules refused: "
                               + (check.stdout + check.stderr).decode(errors="replace"))
    prefix = tuple(f"nlm-smoke-{lane}" for lane in range(4))
    vm_instance_id = ("nlm-smoke-" + secrets.token_hex(16)
                      if args.capture_lifecycle else "nlm-smoke-vm")
    marker_nonces = {
        "activation_open": secrets.token_hex(32),
        "activation_close": secrets.token_hex(32),
    }
    lane_source = Path("bundle/lane").resolve()
    lane_dir = _lane_template(lane_source, args.output / "lane", rules, prefix)
    if args.capture_lifecycle:
        instrument_lane(lane_dir / "lane.sh", vm_instance_id)
    result = args.output / "result.json"
    guest = None
    channels = None
    capture_path = CAPTURE
    activation_time = None
    closure_time = None
    summary = {"status": "failed", "rule_set_id": hashlib.sha256(rules).hexdigest(),
               "mutation_mode": mutation_mode if args.activate else None}

    def mark(phase):
        if not args.capture_lifecycle:
            return
        checked(guest, f"/tmp/nlm-pcap --mark {MARKER_SOCKET} {phase} "
                + marker_nonces[phase])

    try:
        channels = _JournalChannels(args.output / "journal", "smoke",
                                    vm_instance_id, 4, rules, prefix)
        guest = QemuGuest(VmConfig(
            qemu="qemu-system-x86_64", bzimage=args.bzimage, image=args.image,
            lane_dir=lane_dir, ssh_key=args.ssh_key,
            cmdline=("console=ttyS0 root=/dev/sda rw nokaslr nfs.localio_enabled=N "
                     "koov.nfs_fixture=nlm-knfsd koov.nfs_target=1 "
                     "koov.nlm_relay_experiment=1 koov.lane_sha256="
                     + hashlib.sha256((lane_dir / "lane.sh").read_bytes()).hexdigest()
                     + (" systemd.mask=frozen-phase9-fixture.service" if args.proxy else "")),
            console_log=args.output / "console.log", boot_timeout_s=300,
            extra_args=channels.qemu_args(controller=True)))
        guest.start()
        if args.capture_lifecycle:
            guest.put(args.packet_capture, "/tmp/nlm-pcap")
            checked(guest, "chmod 0700 /tmp/nlm-pcap")
        if args.proxy is not None:
            enabled = checked(guest, "systemctl is-enabled frozen-phase9-fixture.service || true").strip()
            if enabled not in ("masked", "masked-runtime"):
                raise RuntimeError(f"fixture did not start masked: {enabled}")
            _install_fixture_replacements(
                guest, args.proxy, lane_dir / "boot-fixture.sh",
                args.lockd_port_helper, args.rpcbind_front_helper)
            summary["guest_proxy_sha256"] = checked(
                guest, "sha256sum /opt/kcov-nfs/deps/usr/sbin/nfs-proxy").split()[0]
            summary["guest_boot_fixture_sha256"] = checked(
                guest, "sha256sum /opt/frozen-phase9/boot-fixture.sh").split()[0]
        deadline = time.monotonic() + 150
        while True:
            state = ("active" if args.proxy else checked(
                guest, "systemctl is-active frozen-phase9-fixture.service || true").strip())
            if state == "active":
                break
            if state == "failed" or time.monotonic() >= deadline:
                summary["service_journal"] = checked(
                    guest, "journalctl -u frozen-phase9-fixture.service -b --no-pager -n 50 || true")[-8000:]
                summary["virtio_diag"] = checked(guest, "ls -la /dev/virtio-ports /sys/class/virtio-ports /sys/bus/virtio/devices 2>&1 || true")
                summary["port_diag"] = checked(guest, "ls -l /dev/vport* 2>&1; for p in /sys/class/virtio-ports/*; do cat \"$p/name\" \"$p/dev\"; done; udevadm info -q property -p /sys/class/virtio-ports/vport1p1 2>&1 || true")
                raise RuntimeError(f"fixture service {state}")
            time.sleep(3)
        status = json.loads(checked(guest, "/run/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager"))
        summary["fixture_mode"] = status["fixture_mode"]
        summary["nlm_port"] = status["nlm_port"]
        guest.put(args.lock_probe, "/tmp/nlm-lock-probe")
        if args.packet_capture and not args.capture_lifecycle:
            guest.put(args.packet_capture, "/tmp/nlm-pcap")
            checked(guest, "chmod 0700 /tmp/nlm-pcap; "
                           "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/server.pid) -n -- "
                           f"/tmp/nlm-pcap {capture_path} {STATS} >/tmp/nlm-pcap.log 2>&1 "
                           "< /dev/null & sleep 1; pgrep -f '/tmp/nlm-pcap '")
        if args.activate:
            guest.put(args.activation_driver, "/tmp/nlm-activate")
            checked(guest, "chmod 0755 /tmp/nlm-activate")
        summary["grant_trace_available"] = checked(
            guest, "test -e /sys/kernel/tracing/events/lockd/nlmclnt_grant/enable "
                   "&& echo yes || echo no").strip() == "yes"
        if summary["grant_trace_available"]:
            checked(guest, "echo 0 > /sys/kernel/tracing/tracing_on; "
                           ": > /sys/kernel/tracing/trace; "
                           "echo 1 > /sys/kernel/tracing/events/lockd/nlmclnt_grant/enable; "
                           "echo 1 > /sys/kernel/tracing/tracing_on")
        summary["rpc_request_trace_available"] = checked(
            guest, "test -e /sys/kernel/tracing/events/sunrpc/rpc_request/enable "
                   "&& echo yes || echo no").strip() == "yes"
        if summary["rpc_request_trace_available"]:
            checked(guest, "echo 1 > /sys/kernel/tracing/events/sunrpc/rpc_request/enable")
        summary["mount_diag"] = checked(guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) -m -n -- findmnt -T /tmp/frozen-phase9.manager/lane0/client0/mnt/shared/fixture -o TARGET,SOURCE,FSTYPE,OPTIONS -n")
        summary["proxy_before"] = snapshot(guest)
        summary["proxy_state_after_first_snapshot"] = checked(
            guest, "p=$(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid); "
                   "ps -p $p -o pid,stat,comm; awk '{print \"exit_code=\" $52}' /proc/$p/stat")
        summary["rpcinfo"] = checked(guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) -m -n -- sh -c 'PATH=/opt/kcov-nfs/deps/usr/bin:/opt/kcov-nfs/deps/usr/sbin:$PATH; LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:/opt/kcov-nfs/deps/lib/x86_64-linux-gnu; export PATH LD_LIBRARY_PATH; rpcinfo -T tcp 10.89.0.1 nlockmgr 4'")
        try:
            summary["proxy_after_rpcinfo"] = snapshot(guest)
        except RuntimeError as error:
            summary["snapshot_error_after_rpcinfo"] = str(error)
        summary["proxy_state_after_rpcinfo"] = checked(
            guest, "p=$(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid); "
                   "ps -p $p -o pid,stat,comm; awk '{print \"exit_code=\" $52}' /proc/$p/stat")
        # POSIX fcntl record locks invoke NLM for these NFSv3 mounts.
        def probe(client, hold):
            mount = "mnt" if client == 0 else "knfsd"
            return ("nsenter -t "
                    f"$(cat /tmp/frozen-phase9.manager/lane0/client{client}.pid) "
                    "-m -n -- /tmp/nlm-lock-probe "
                    f"/tmp/frozen-phase9.manager/lane0/client{client}/{mount}/shared/fixture "
                    f"{hold} > /tmp/nlm-lock-probe-{client}.out 2>&1 < /dev/null")

        if args.activate and not args.contention:
            summary["activation"] = checked(
                guest, "/tmp/nlm-activate "
                       "/syz-nfs-lanes/proc-0/activation/activation.sock "
                       + summary["rule_set_id"] + " activate")
            mark("activation_open")
        checked(guest, "sh -c 'timeout 45 " + probe(0, 20 if args.contention else 0) + " &'")
        if args.contention:
            deadline = time.monotonic() + 20
            while "LOCK_OK" not in checked(guest, "cat /tmp/nlm-lock-probe-0.out"):
                if time.monotonic() >= deadline:
                    raise RuntimeError("client0 did not acquire the lock")
                time.sleep(0.5)
            if args.activate:
                summary["activation"] = checked(
                    guest, "/tmp/nlm-activate "
                           "/syz-nfs-lanes/proc-0/activation/activation.sock "
                           + summary["rule_set_id"] + " activate")
                mark("activation_open")
                activation_time = time.time()
            checked(guest, "sh -c 'timeout 45 " + probe(1, 0) + " &'")
            time.sleep(3)
            summary["client1_waiting"] = checked(guest, "cat /tmp/nlm-lock-probe-1.out")
            if args.deactivate_before_grant:
                # Close the diagnostic window before requesting deactivation.
                # This can exclude a still-active callback, but cannot assign
                # one that raced with the deactivation ACK.
                mark("activation_close")
                summary["deactivation"] = checked(
                    guest, "/tmp/nlm-activate "
                           "/syz-nfs-lanes/proc-0/activation/activation.sock "
                           + summary["rule_set_id"] + " deactivate")
                closure_time = time.time()
        else:
            time.sleep(5)
        summary["server_rpcbind"] = checked(
            guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/server.pid) -m -n -- "
                   "sh -c 'PATH=/opt/kcov-nfs/deps/usr/bin:$PATH; rpcinfo -p 127.0.0.1'")
        summary["server_tcp"] = checked(
            guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/server.pid) -n -- ss -tnp")
        summary["client_tcp"] = checked(
            guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) -n -- ss -tnp")
        summary["probe_inflight"] = checked(guest, "cat /tmp/nlm-lock-probe-0.out")
        summary["probe_process"] = checked(
            guest, "for p in $(pgrep -f '^/tmp/nlm-lock-probe '); do "
                   "echo pid=$p; cat /proc/$p/wchan; cat /proc/$p/stack; done || true")
        summary["netns_diag"] = checked(
            guest, "for p in 1 $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) "
                   "$(cat /tmp/frozen-phase9.manager/lane0/server.pid) "
                   "$(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid) "
                   "$(pgrep -f '^/tmp/nlm-lock-probe '); do "
                   "echo pid=$p; readlink /proc/$p/ns/net /proc/$p/ns/mnt; done; "
                   "echo root_tcp; ss -tan; echo root_rpc; cat /proc/net/rpc/nfs 2>&1")
        summary["server_routes"] = checked(
            guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/server.pid) -n -- "
                   "sh -c 'ip rule; ip route show table 100; ss -ltnp'")
        try:
            summary["proxy_after"] = snapshot(guest)
        except RuntimeError as error:
            summary["snapshot_error_after"] = str(error)
        summary["proxy_log"] = checked(
            guest, "tail -n 80 /tmp/frozen-phase9.manager/lane0/server/proxy.log")
        summary["client_routes"] = checked(
            guest, "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) -n -- "
                   "sh -c 'ip route; ss -tanp; cat /proc/net/tcp'")
        summary["nfs_rpc"] = checked(
            guest, "timeout 8 nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/client0.pid) "
                   "-m -n -- sh -c 'PATH=/opt/kcov-nfs/deps/usr/bin:$PATH; "
                   "rpcinfo -T tcp 10.89.0.1 nfs 3' || true")
        summary["lock_output"] = checked(
            guest, "sleep 25; cat /tmp/nlm-lock-probe-0.out", timeout=40).strip()
        if args.contention:
            summary["client1_output"] = checked(guest, "cat /tmp/nlm-lock-probe-1.out").strip()
            if summary["grant_trace_available"] or summary["rpc_request_trace_available"]:
                trace = checked(guest, "cat /sys/kernel/tracing/trace")
                statuses = grant_trace_statuses(trace)
                summary["grant_trace_count"] = len(statuses)
                summary["callback_client_statuses"] = statuses
                summary["callback_client_status"] = (
                    statuses[0] if len(statuses) == 1 else None)
                summary["granted_rpc_request_counts"] = {
                    name: sum("rpc_request:" in line and name in line
                              for line in trace.splitlines())
                    for name in ("GRANTED_MSG", "GRANTED_RES")}
        if args.activate and not args.deactivate_before_grant:
            mark("activation_close")
            summary["deactivation"] = checked(
                guest, "/tmp/nlm-activate "
                       "/syz-nfs-lanes/proc-0/activation/activation.sock "
                       + summary["rule_set_id"] + " deactivate")
            closure_time = time.time()
        if "proxy_after" in summary and "proxy_after_rpcinfo" in summary:
            summary["proxy_delta"] = {
                key: summary["proxy_after"][key] - summary["proxy_after_rpcinfo"][key]
                for key in summary["proxy_before"]}
        if "proxy_after_rpcinfo" in summary:
            summary["rpcinfo_delta"] = {
                key: summary["proxy_after_rpcinfo"][key] - summary["proxy_before"][key]
                for key in summary["proxy_before"]}
        if "LOCK_OK\nUNLOCK_OK" not in summary["lock_output"]:
            raise RuntimeError("POSIX lock failed")
        if args.contention:
            if "LOCK_OK" in summary["client1_waiting"] or "LOCK_BEGIN" not in summary["client1_waiting"]:
                raise RuntimeError("client1 did not wait for client0 lock")
            summary["waiting_fcntl_completed"] = (
                "LOCK_OK\nUNLOCK_OK" in summary["client1_output"])
            if (mutation_mode != "offset_identity_break"
                    and not summary["waiting_fcntl_completed"]):
                raise RuntimeError("client1 did not acquire lock after grant")
        summary["proxy_log"] = checked(guest, "tail -n 35 /tmp/frozen-phase9.manager/lane0/server/proxy.log")
        summary["status"] = ("contention_diagnostic_pending" if args.contention
                             and args.activate and args.packet_capture
                             else "blocked_grant_completed_route_unproven" if args.contention
                             else "lock_completed_route_unproven")
    except Exception as error:
        summary["error"] = str(error)
        if guest is not None and guest.process is not None and guest.process.poll() is None:
            for key, command in (
                    ("failure_service_journal", "journalctl -u frozen-phase9-fixture.service -b --no-pager -n 80"),
                    ("failure_lane_logs", "for f in /tmp/frozen-phase9.manager/lane*/server*.log /tmp/frozen-phase9.manager/lane*/server/proxy.log /tmp/frozen-phase9.manager/lane*/client*.nlm.log; do echo $f; tail -n 30 $f || true; done"),
                    ("failure_rpc_state", "ps -ef | grep -E 'rpcbind|rpc.statd|lockd' | grep -v grep || true; ss -ltnup; for ns in /run/netns/f9l*c*; do echo $ns; ip netns exec $(basename $ns) sh -c 'rpcinfo -p 127.0.0.1 2>&1; ss -ltnup' || true; done")):
                try:
                    summary[key] = checked(guest, command, timeout=15)[-12000:]
                except Exception:
                    pass
        raise
    finally:
        active_error = sys.exc_info()[0] is not None
        if guest is not None and args.packet_capture and guest.process is not None and guest.process.poll() is None:
            try:
                if args.capture_lifecycle:
                    cleanup, capture_error = cleanup_capture_lifecycle(guest)
                    summary["capture_fixture_cleanup"] = cleanup
                    if capture_error:
                        summary["capture_error"] = capture_error
                    else:
                        guest.get(capture_path,
                                  args.output / "nlm-callback-diagnostic.pcap")
                        guest.get(STATS,
                                  args.output / "nlm-callback-diagnostic.stats")
                        guest.get(EVENT_LOG,
                                  args.output / "nlm-callback-diagnostic.events")
                        guest.get(COMPLETE,
                                  args.output / "nlm-callback-diagnostic.complete")
                        guest.get("/tmp/nlm-pcap",
                                  args.output / "nlm-pcap.collector")
                else:
                    checked(guest, "pkill -TERM -x nlm-pcap || true; sleep 1")
                    guest.get(capture_path,
                              args.output / "nlm-callback-diagnostic.pcap")
                    guest.get(STATS,
                              args.output / "nlm-callback-diagnostic.stats")
            except Exception as error:
                summary["capture_error"] = str(error)
        if guest is not None:
            guest.stop()
        if channels is not None:
            exposures = [event.request.payload.model_dump(mode="json")
                         for event in channels.journal.events()
                         if event.request.event_type == "EXPOSURE_INTENT"]
            if args.packet_capture and activation_time and closure_time and not summary.get("capture_error"):
                try:
                    summary["callback_diagnostic"] = diagnostic(
                        exposures, args.output / "nlm-callback-diagnostic.pcap",
                        activation_time, closure_time)
                except (OSError, ValueError) as error:
                    summary["capture_error"] = str(error)
            summary["events"] = [
                {"type": event.request.event_type,
                 "generation": getattr(getattr(event.request.payload, "correlation", None),
                                       "kcov_generation", None),
                 "route": getattr(getattr(event.request.payload, "record_context", None),
                                  "route", None),
                 "program": getattr(getattr(event.request.payload, "record_context", None),
                                    "program", None),
                 "procedure": getattr(getattr(event.request.payload, "record_context", None),
                                      "procedure", None)}
                for event in channels.journal.events()]
            summary["rejections"] = [r.reason for r in channels.journal.rejections()]
            channels.close()
            if args.packet_capture and not summary.get("capture_error"):
                try:
                    sealed = SealedJournal(args.output / "journal", "smoke")
                    summary["reassembled_diagnostic"] = verify_capture(
                        sealed,
                        args.output / "nlm-callback-diagnostic.pcap",
                        vm_instance_id, reassemble=True)
                    if args.capture_lifecycle and args.activate:
                        paths = {
                            "collector": args.output / "nlm-pcap.collector",
                            "pcap": args.output / "nlm-callback-diagnostic.pcap",
                            "event_log": args.output / "nlm-callback-diagnostic.events",
                            "stats": args.output / "nlm-callback-diagnostic.stats",
                            "complete": args.output / "nlm-callback-diagnostic.complete",
                        }
                        manifest, _ = build_manifest(
                            vm_instance_id=vm_instance_id, **paths,
                            journal_manifest_sha256=sealed.manifest_sha256(),
                            expected_markers=marker_nonces)
                        manifest_path = args.output / "nlm-ordered-capture-manifest.json"
                        manifest_path.write_bytes(canonical_json(manifest))
                        summary["ordered_callback_diagnostic"] = (
                            verify_ordered_capture(
                                sealed, manifest, vm_instance_id=vm_instance_id,
                                **paths))
                except (OSError, ValueError) as error:
                    if args.capture_lifecycle and args.activate:
                        summary["ordered_capture_error"] = str(error)
                    else:
                        summary["reassembly_error"] = str(error)
        if (not active_error and args.contention and args.activate
                and args.packet_capture and not summary.get("capture_error")):
            callbacks = summary.get("callback_diagnostic", {})
            responses = callbacks.get("granted_responses", [])
            response_statuses = sorted({item.get("status_name") for item in responses})
            summary["callback_received"] = callbacks.get("callback_calls", 0) > 0
            summary["granted_res_statuses"] = response_statuses
            summary["granted_res_status"] = (
                response_statuses[0] if len(response_statuses) == 1 else None)
            anchors = summary.get("reassembled_diagnostic", {}).get("anchors", [])
            summary["mutation_forwarded_count"] = sum(
                item.get("reason") == "journal_backend_lock_bytes_observed"
                for item in anchors)
            summary["mutation_forwarded"] = summary["mutation_forwarded_count"] > 0
            expected_path = ("nlm4.request.LOCK.args.cookie"
                             if mutation_mode == "cookie_identity_preserving" else
                             "nlm4.request.LOCK.args.alock.l_offset")
            changed = [application
                       for exposure in exposures
                       for application in exposure.get("applications", [])
                       if application.get("semantic_path") == expected_path
                       and application.get("original_value") !=
                           application.get("mutated_value")]
            summary["mutation_value_changed_count"] = len(changed)
            summary["mutation_value_changed"] = bool(changed)
            summary["waiting_fcntl_completion_source"] = (
                "callback_or_later_retry_unresolved"
                if summary.get("waiting_fcntl_completed") else
                "not_completed_within_observation_window")
            status = _contention_diagnostic_status(summary, mutation_mode)
            summary["status"] = status
            if status.endswith("_incomplete"):
                summary["error"] = "typed callback diagnostic did not meet its contract"
        summary["capture_lifecycle_requested"] = args.capture_lifecycle
        if args.capture_lifecycle and summary.get("capture_error"):
            summary["status"] = "failed"
        if args.capture_lifecycle and summary.get("ordered_capture_error"):
            summary["status"] = "failed"
        result.write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2), flush=True)
        post_error = ((summary.get("capture_error") or
                       summary.get("ordered_capture_error"))
                      if args.capture_lifecycle else None)
        if not post_error and summary.get("status", "").endswith("_incomplete"):
            post_error = summary["error"]
        if post_error and not active_error:
            raise RuntimeError(post_error)


if __name__ == "__main__":
    main()
