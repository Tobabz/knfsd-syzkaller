"""Instrumentation belongs only to an explicitly disposable lane copy."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from tools.nlm_capture_lifecycle import (
    COMPLETE, EVENT_LOG, MARKER_SOCKET, PID, READY, STATS, STOP, instrument_lane,
)


def relay_kvm_module():
    path = Path(__file__).parents[2] / "tools/test-nlm-relay-kvm.py"
    spec = importlib.util.spec_from_file_location("test_nlm_relay_kvm", path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class FakeGuest:
    def __init__(self, cleanup_rc=0):
        self.cleanup_rc = cleanup_rc
        self.commands = []
        self.puts = []

    def run(self, command, timeout=60):
        self.commands.append((command, timeout))
        if command.startswith("/run/frozen-phase9/lane.sh cleanup"):
            return self.cleanup_rc, "cleanup output"
        return 0, ""

    def put(self, source, destination):
        self.puts.append((source, destination))


def test_instrumentation_precedes_mounts_and_retains_shell_syntax(tmp_path):
    original = Path(__file__).parents[2] / "bundle/lane/lane.sh"
    before = original.read_bytes()
    copy = tmp_path / "lane.sh"
    copy.write_bytes(before)
    instrument_lane(copy, "vm-run-test")
    text = copy.read_text()
    assert text.index("/tmp/nlm-pcap") < text.index(
        '        setup_client "$setup_lane_id"')
    assert text.index("while ! test -f " + READY) < text.index(
        '    ip netns exec "$setup_client0_ns" ping')
    assert f"{STATS} && test -e {COMPLETE}" in text
    assert f"rm -f /tmp/nlm-callback-diagnostic.pcap {STATS} {READY} {COMPLETE} {STOP} {PID}" in text
    assert f"{EVENT_LOG} {MARKER_SOCKET} vm-run-test" in text
    assert "! pgrep -x nlm-pcap" in text
    assert "diagnostic_capture_start=$(awk" in text
    assert text.count('"/proc/$diagnostic_capture_pid/stat"') >= 4
    assert 'test "$(cat "/proc/$diagnostic_capture_pid/comm")" = nlm-pcap' in text
    assert text.count('diagnostic_has_capture=0') == 3
    assert 'diagnostic_capture_net=$(stat -Lc' in text
    assert '[ "$diagnostic_capture_net" = "$diagnostic_stop_net" ]' in text
    subprocess.run(["sh", "-n", str(copy)], check=True)
    assert original.read_bytes() == before
    with pytest.raises(ValueError, match="boundary changed"):
        instrument_lane(copy)


def test_instrumentation_refuses_unknown_or_repeated_boundary(tmp_path):
    copy = tmp_path / "lane.sh"
    copy.write_text("#!/bin/sh\n")
    with pytest.raises(ValueError, match="boundary changed"):
        instrument_lane(copy)
    original = Path(__file__).parents[2] / "bundle/lane/lane.sh"
    copy.write_bytes(original.read_bytes())
    with pytest.raises(ValueError, match="VM instance"):
        instrument_lane(copy, "bad vm identity")


def test_instrumented_cleanup_orders_other_processes_before_recorder(tmp_path):
    original = Path(__file__).parents[2] / "bundle/lane/lane.sh"
    copy = tmp_path / "lane.sh"
    copy.write_bytes(original.read_bytes())
    instrument_lane(copy)
    text = copy.read_text()
    stop = text.index(f": > {STOP}")
    assert text.index('kill $diagnostic_other_pids') < stop
    assert text.index('[ "$diagnostic_cleanup_wait" -lt 20 ]') < stop
    assert text.index('kill -KILL $diagnostic_other_pids') < stop
    assert text.index('test "$diagnostic_cleanup_wait" -lt 50') < stop
    assert 'kill -TERM "$diagnostic_capture_pid"' not in text
    assert stop < text.index('test -s ' + STATS, stop)
    assert stop < text.index('rm -f ' + PID, stop)


def test_capture_cleanup_success_requires_completion_and_no_collector():
    module = relay_kvm_module()
    guest = FakeGuest()
    evidence, error = module.cleanup_capture_lifecycle(guest)
    assert evidence == {"returncode": 0, "output": "cleanup output"}
    assert error is None
    assert guest.commands == [
        ("/run/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager", 180),
        (f"test -e {COMPLETE} && ! pgrep -x nlm-pcap >/dev/null", 60),
    ]


def test_capture_cleanup_failure_is_recovery_only():
    module = relay_kvm_module()
    guest = FakeGuest(cleanup_rc=9)
    evidence, error = module.cleanup_capture_lifecycle(guest)
    assert evidence == {"returncode": 9, "output": "cleanup output"}
    assert error == "fixture cleanup failed: rc=9"
    assert guest.commands == [
        ("/run/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager", 180),
        (f": > {STOP}; sleep 1; pkill -TERM -x nlm-pcap || true", 15),
    ]


def test_proxy_replacement_requires_both_lane_helpers(tmp_path):
    module = relay_kvm_module()
    required = [
        "--image", str(tmp_path / "image"),
        "--bzimage", str(tmp_path / "bzImage"),
        "--ssh-key", str(tmp_path / "key"),
        "--lock-probe", str(tmp_path / "probe"),
        "--proxy", str(tmp_path / "proxy"),
        "--output", str(tmp_path / "output"),
    ]
    with pytest.raises(SystemExit):
        module._parse_args(required)
    with pytest.raises(SystemExit):
        module._parse_args(required + [
            "--lockd-port-helper", str(tmp_path / "lockd-helper")])
    args = module._parse_args(required + [
        "--lockd-port-helper", str(tmp_path / "lockd-helper"),
        "--rpcbind-front-helper", str(tmp_path / "rpcbind-helper"),
    ])
    assert args.lockd_port_helper == tmp_path / "lockd-helper"
    assert args.rpcbind_front_helper == tmp_path / "rpcbind-helper"


def test_activation_requires_proxy_and_driver_during_argument_parsing(tmp_path):
    module = relay_kvm_module()
    required = [
        "--image", str(tmp_path / "image"),
        "--bzimage", str(tmp_path / "bzImage"),
        "--ssh-key", str(tmp_path / "key"),
        "--lock-probe", str(tmp_path / "probe"),
        "--output", str(tmp_path / "output"),
        "--activate",
    ]
    with pytest.raises(SystemExit):
        module._parse_args(required)
    with pytest.raises(SystemExit):
        module._parse_args(required + [
            "--proxy", str(tmp_path / "proxy"),
            "--lockd-port-helper", str(tmp_path / "lockd-helper"),
            "--rpcbind-front-helper", str(tmp_path / "rpcbind-helper"),
        ])
    args = module._parse_args(required + [
        "--proxy", str(tmp_path / "proxy"),
        "--lockd-port-helper", str(tmp_path / "lockd-helper"),
        "--rpcbind-front-helper", str(tmp_path / "rpcbind-helper"),
        "--activation-driver", str(tmp_path / "activation-driver"),
    ])
    assert args.activate is True


def test_fixture_replacements_install_lane_helpers_without_source_changes(tmp_path):
    module = relay_kvm_module()
    original = Path(__file__).parents[2] / "bundle/lane/lane.sh"
    before = original.read_bytes()
    guest = FakeGuest()
    proxy = tmp_path / "nfs-proxy"
    boot = tmp_path / "boot-fixture.sh"
    lockd = tmp_path / "lockd-netlink-port"
    rpcbind = tmp_path / "nlm-rpcbind-front"

    module._install_fixture_replacements(guest, proxy, boot, lockd, rpcbind)

    assert guest.puts == [
        (proxy, "/tmp/nfs-proxy-replacement"),
        (boot, "/tmp/boot-fixture-replacement"),
        (lockd, "/tmp/lockd-netlink-port-replacement"),
        (rpcbind, "/tmp/nlm-rpcbind-front-replacement"),
    ]
    assert len(guest.commands) == 1
    command, timeout = guest.commands[0]
    assert timeout == 240
    assert ("install -m 0755 /tmp/lockd-netlink-port-replacement "
            "/opt/kcov-nfs/deps/usr/sbin/lockd-netlink-port") in command
    assert ("install -m 0755 /tmp/nlm-rpcbind-front-replacement "
            "/opt/kcov-nfs/deps/usr/sbin/nlm-rpcbind-front") in command
    assert command.endswith("/opt/frozen-phase9/boot-fixture.sh")
    assert original.read_bytes() == before
