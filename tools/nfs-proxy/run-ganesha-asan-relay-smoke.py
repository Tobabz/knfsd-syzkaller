#!/usr/bin/env python3
"""Boot four real NFSv4 mounts through the relay and ASan Ganesha.

This is a relay/guest integration gate.  It does not claim four syzkaller
executor connection choices or an A/B throughput result.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
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
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a fresh path")
    if not 4096 <= args.memory <= 65536 or not 4 <= args.cpus <= 64:
        parser.error("invalid guest resource count")
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


def main():
    args = args_parse()
    phase1 = ab.load_module("relay_phase1", REPO / "bundle/ab-runner/run_frozen_phase1_vm.py")
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
                     "relay_only": True, "asan_options": args.asan_options,
                     "syzkaller_four_choice_integrated": False},
    }
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
        phase9.validate_source_tree(vm, root, 1)
        evidence["asan_loaded_before"] = asan.live_asan(vm, root, "asan-loaded-before")
        paths = vm.guest("four-mount-io", shlex.join([
            "/opt/frozen-phase9/four-mounts.sh", root]), timeout=90).stdout
        if paths.count("client=") != 4 or \
                "four_mounts=pass backend_isolation=pass" not in paths:
            raise ValueError("four mounts did not prove backend sharing/isolation")
        evidence["mount_io"] = paths.strip().splitlines()
        after = ["env", "SERVER_IMPL=both", "SERVER_PORT=2049",
                 "NFS_MINOR_VERSION=1", "/opt/frozen-phase9/lane.sh", "status", root]
        evidence["fixture_after"] = phase9.validate_fixture_status(json.loads(
            vm.guest("fixture-after", shlex.join(after), timeout=60).stdout), 1)
        evidence["asan_loaded_after"] = asan.live_asan(vm, root, "asan-loaded-after")
        evidence["relay"] = proxy_snapshot(vm, root, args.output)
        evidence["asan_report"] = asan.collect_logs(vm, root, args.output)
        if evidence["asan_report"]:
            raise ValueError("Ganesha produced an AddressSanitizer report")
        evidence["cleanup"] = phase9.cleanup_fixture(vm, root, 1, strict=True)
        root = None
        evidence["status"] = "pass"
        print("ASan Ganesha + relay: 4 NFSv4 mounts, 4 live routes, "
              "shared per backend, isolated across backends, no ASan report, "
              "cleanup clean")
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
