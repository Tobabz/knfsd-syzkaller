#!/usr/bin/env python3
"""Minimal lane-attribution check for the reduced series.

Boots one VM, brings up the lane fixture, runs a program with syz-execprog
and remote coverage on, and reports .extra coverage (fs/nfsd split), the
sunrpc_fuzz/kcov counters before and after, executor errors and dmesg.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import re
import shlex
import struct
import subprocess
import tarfile
from pathlib import Path

HARNESS = Path.home() / "prune-evidence/inputs/run_frozen_phase1_vm.py"
DRV = "/opt/frozen-phase9"
FATAL = re.compile(r"BUG:(?! KCSAN:)|KASAN:|kernel BUG|Kernel panic|Oops:|WARNING:")


def load_phase1():
    spec = importlib.util.spec_from_file_location("phase1", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tar_member_sha256(path, suffix):
    with tarfile.open(path) as archive:
        matches = [member for member in archive.getmembers()
                   if member.isfile() and member.name.endswith(suffix)]
        if len(matches) != 1:
            raise ValueError("expected one %s in %s, got %d" %
                             (suffix, path, len(matches)))
        stream = archive.extractfile(matches[0])
        if stream is None:
            raise ValueError("cannot read %s from %s" % (suffix, path))
        return hashlib.sha256(stream.read()).hexdigest()


def capture_dmesg(vm, output, result):
    dmesg = vm.guest("dmesg", "dmesg", check=False).stdout
    (output / "dmesg.txt").write_text(dmesg)
    result["dmesg_fatal"] = [m.group(0) for m in FATAL.finditer(dmesg)][:5]


def write_result(output, result):
    (output / "result.json").write_text(json.dumps(result, indent=1))


def delta_metadata(path):
    data = path.read_bytes()
    if len(data) < 60:
        raise ValueError("short delta file: %s" % path)
    magic = data[:8].decode("ascii", errors="strict")
    version = struct.unpack_from(">I", data, 8)[0]
    seed = struct.unpack_from(">Q", data, 12)[0]
    fields = struct.unpack_from(">10I", data, 20)
    metadata = {"file": path.name, "sha256": sha256(path), "bytes": len(data),
                "magic": magic, "version": version, "seed": "0x%016x" % seed}
    if magic == "NFSPDLT1" and version == 1:
        names = ("dir", "backend", "client", "first_opcode", "match_index",
                 "anchor_off", "anchor_len", "patch_off", "patch_w",
                 "applied_count")
        record_len = 40 + fields[6] + 2 * fields[8]
        if 20 + record_len != len(data):
            raise ValueError("NFSPDLT1 has trailing or truncated bytes: %s" % path)
        metadata["record"] = dict(zip(names, fields))
    elif magic == "NFSPDLT2" and version == 2:
        names = ("dir", "backend", "client", "first_opcode", "anchor_off",
                 "anchor_len", "mode", "nedits", "applied_count", "reserved")
        record = dict(zip(names, fields))
        offset = 60 + fields[5]
        edits = []
        for _ in range(fields[7]):
            if offset + 16 > len(data):
                raise ValueError("short NFSPDLT2 edit header: %s" % path)
            edit = struct.unpack_from(">4I", data, offset)
            offset += 16
            if offset + edit[2] + edit[3] > len(data):
                raise ValueError("short NFSPDLT2 edit bytes: %s" % path)
            edits.append({"kind": edit[0], "offset": edit[1],
                          "orig_len": edit[2], "data_len": edit[3]})
            offset += edit[2] + edit[3]
        if offset != len(data):
            raise ValueError("NFSPDLT2 has trailing bytes: %s" % path)
        record["edits"] = edits
        metadata["record"] = record
    else:
        raise ValueError("unknown delta format %r version %d" % (magic, version))
    return metadata


def collect_deltas(vm, root, output):
    guest_dir = "%s/lane0/server/deltas" % root
    listing = vm.guest(
        "delta-list", "find %s -maxdepth 1 -type f -name 'arm-*.delta' -printf '%%f\\n' | sort -V"
        % shlex.quote(guest_dir)).stdout.splitlines()
    delta_dir = output / "deltas"
    delta_dir.mkdir()
    paths = []
    for index, name in enumerate(listing):
        if not re.fullmatch(r"arm-[0-9]+\.delta", name):
            raise ValueError("unsafe delta name: %r" % name)
        encoded = vm.guest(
            "delta-%d" % index,
            "base64 -w0 %s" % shlex.quote(guest_dir + "/" + name)).stdout.strip()
        path = delta_dir / name
        path.write_bytes(base64.b64decode(encoded, validate=True))
        paths.append(path)
    return paths


def put_be32(data, offset, value):
    struct.pack_into(">I", data, offset, value)


def replay_once(vm, probe, delta, label, target, request_xid, expected_xid,
                expected_proxy_rc, edit, expected_count, applied, refused_orig,
                output):
    remote_delta = "/tmp/%s.delta" % label
    vm.put("put-" + label, delta, remote_delta)
    command = r"""set -u
log=/tmp/%s.log
rm -f "$log"
ip netns exec f9l0s /opt/kcov-nfs/deps/usr/sbin/nfs-proxy \
    10.89.0.2 10.89.0.6 10.89.0.1:20549 10.89.0.5:20549 \
    10.89.0.1:20490 10.89.0.5:20491 --replay %s >"$log" 2>&1 &
pid=$!
i=0
ready=0
while test "$i" -lt 80; do
    if grep -q '^relay ready:' "$log"; then ready=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    i=$((i + 1))
    sleep 0.1
done
probe_rc=99
if test "$ready" -eq 1; then
    ip netns exec f9l0c0 %s %s %s %s
    probe_rc=$?
fi
kill -TERM "$pid" 2>/dev/null || true
proxy_rc=0
wait "$pid" || proxy_rc=$?
printf '__ready=%%s __probe_rc=%%s __proxy_rc=%%s\n' "$ready" "$probe_rc" "$proxy_rc"
cat "$log"
""" % (label, shlex.quote(remote_delta), shlex.quote(DRV + "/replay-probe"),
       shlex.quote(target), hex(request_xid), hex(expected_xid))
    text = vm.guest("replay-" + label, command, timeout=40, check=False).stdout
    log = output / (label + ".log")
    log.write_text(text)
    marker = re.search(r"__ready=(\d+) __probe_rc=(\d+) __proxy_rc=(\d+)", text)
    if marker is None:
        raise ValueError("replay %s did not report process statuses" % label)
    ready, probe_rc, proxy_rc = map(int, marker.groups())
    rule = ("replay rule=0 edit=%d expected=%d applied=%d refused_orig=%d" %
            (edit, expected_count, applied, refused_orig))
    if ready != 1 or probe_rc != 0 or proxy_rc != expected_proxy_rc or rule not in text:
        raise ValueError("replay %s failed: ready=%d probe=%d proxy=%d; want proxy=%d and %r" %
                         (label, ready, probe_rc, proxy_rc, expected_proxy_rc, rule))
    return {"case": label, "delta": delta.name, "delta_sha256": sha256(delta),
            "target": target, "request_xid": "0x%08x" % request_xid,
            "expected_response_xid": "0x%08x" % expected_xid,
            "probe_rc": probe_rc, "proxy_rc": proxy_rc, "rule": rule,
            "probe_sha256": sha256(probe), "log": log.name,
            "log_sha256": sha256(log)}


def exercise_legacy_replay(vm, args, deltas):
    profile = args.legacy_profile
    metadata = [delta_metadata(path) for path in deltas]
    expected_magic = "NFSPDLT1" if profile == "v1" else "NFSPDLT2"
    expected_count = 2 if profile == "v1" else 1
    if len(deltas) != expected_count or any(item["magic"] != expected_magic
                                             for item in metadata):
        raise ValueError("%s expected %d %s deltas, got %r" %
                         (profile, expected_count, expected_magic,
                          [(item["file"], item["magic"]) for item in metadata]))
    replay = []
    if profile == "v1":
        expected = [
            (0, "10.89.0.5", 0x22222222, 0x22222223),
            (1, "10.89.0.5", 0x22222223, 0x22222222),
        ]
        for index, target, request, response in expected:
            item = metadata[index]
            if (item["record"]["backend"], item["record"]["client"],
                    item["record"]["applied_count"]) != (1, 0, 1):
                raise ValueError("unexpected v1 delta scope/count: %r" % item)
            replay.append(replay_once(vm, args.replay_probe, deltas[index],
                                      "v1-exact-%d" % index, target, request, response,
                                      0, 0, 1, 1, 0, args.output))
        replay.append(replay_once(vm, args.replay_probe, deltas[0],
                                  "v1-unmatched-count", "10.89.0.5",
                                  0x22222224, 0x22222224, 1, 0, 1, 0, 0,
                                  args.output))
        base = bytearray(deltas[0].read_bytes())
        if (metadata[0]["record"]["anchor_len"],
                metadata[0]["record"]["patch_w"]) != (4, 4):
            raise ValueError("v1 refusal requires four-byte XID anchor and patch")
        original_off = 60 + metadata[0]["record"]["anchor_len"]
        put_be32(base, original_off, 0x22222224)
        refusal = args.output / "deltas/v1-original-mismatch.delta"
        refusal.write_bytes(base)
        replay.append(replay_once(vm, args.replay_probe, refusal,
                                  "v1-original-mismatch", "10.89.0.5",
                                  0x22222222, 0x22222222, 1, 0, 1, 0, 1,
                                  args.output))
        count = bytearray(deltas[0].read_bytes())
        put_be32(count, 56, 2)
        mismatch = args.output / "deltas/v1-count-mismatch.delta"
        mismatch.write_bytes(count)
        replay.append(replay_once(vm, args.replay_probe, mismatch,
                                  "v1-count-mismatch", "10.89.0.5",
                                  0x22222222, 0x22222223, 1, 0, 2, 1, 0,
                                  args.output))
    elif profile == "v2":
        item = metadata[0]
        record = item["record"]
        if (record["backend"], record["client"], record["applied_count"]) != (0, 0, 1):
            raise ValueError("unexpected v2 delta scope/count: %r" % item)
        replay.append(replay_once(vm, args.replay_probe, deltas[0], "v2-exact",
                                  "10.89.0.1", 0x11111111, 0x11111111,
                                  0, 1, 1, 1, 0, args.output))
        base = bytearray(deltas[0].read_bytes())
        edit_header = 60 + record["anchor_len"]
        orig_len = struct.unpack_from(">I", base, edit_header + 8)[0]
        if orig_len == 0:
            raise ValueError("v2 refusal requires an edit with original bytes")
        base[edit_header + 16:edit_header + 16 + orig_len] = b"Z" * orig_len
        refusal = args.output / "deltas/v2-original-mismatch.delta"
        refusal.write_bytes(base)
        replay.append(replay_once(vm, args.replay_probe, refusal,
                                  "v2-original-mismatch", "10.89.0.1",
                                  0x11111111, 0x11111111, 1, 1, 1, 0, 1,
                                  args.output))
        count = bytearray(deltas[0].read_bytes())
        put_be32(count, 52, 2)
        mismatch = args.output / "deltas/v2-count-mismatch.delta"
        mismatch.write_bytes(count)
        replay.append(replay_once(vm, args.replay_probe, mismatch,
                                  "v2-count-mismatch", "10.89.0.1",
                                  0x11111111, 0x11111111, 1, 1, 2, 1, 0,
                                  args.output))
    else:
        item = metadata[0]
        if item["record"]["applied_count"] != 0:
            raise ValueError("v2 refusal unexpectedly applied: %r" % item)
        replay.append(replay_once(vm, args.replay_probe, deltas[0],
                                  "v2-live-refusal-replay", "10.89.0.1",
                                  0x11111111, 0x11111111, 1, 1, 0, 0, 1,
                                  args.output))
    return metadata, replay


def parse_control(line):
    values = dict(re.findall(r"([a-z_]+)=([a-z]+|[0-9]+)", line))
    return {key: (int(value) if value.isdigit() else value)
            for key, value in values.items()}


def validate_legacy_live(profile, proxy_log, control_line):
    control = parse_control(control_line)
    expected = {
        "v1": {"armed": 2, "expired": 2, "applied": 2,
               "refused_orig": 0, "edit_applied": 0,
               "edit_refused_orig": 0},
        "v2": {"armed": 1, "expired": 1, "applied": 0,
               "refused_orig": 0, "edit_applied": 1,
               "edit_refused_orig": 0},
        "v2-refusal": {"armed": 1, "expired": 1, "applied": 0,
                       "refused_orig": 0, "edit_applied": 0,
                       "edit_refused_orig": 1},
    }[profile]
    wrong = {key: (control.get(key), value) for key, value in expected.items()
             if control.get(key) != value}
    if wrong:
        raise ValueError("unexpected live control counters: %r in %r" % (wrong, control))
    aggregate = re.findall(r"^peak_active=.*$", proxy_log, re.MULTILINE)
    if not aggregate or any(token not in aggregate[-1] for token in
                            ("framing_errors=0", "relay_errors=0", "mutation_errors=0")):
        raise ValueError("proxy error counters are not zero: %r" % aggregate[-1:])
    if profile == "v1":
        routes = {}
        for match in re.finditer(
                r"^client=(\d+) backend=(\d+) accepted=(\d+) connected=(\d+) "
                r"failed=(\d+) c2s=(\d+) s2c=(\d+)", proxy_log, re.MULTILINE):
            routes[(int(match[1]), int(match[2]))] = tuple(map(int, match.groups()[2:]))
        if set(routes) != {(0, 0), (0, 1), (1, 0), (1, 1)} or any(
                accepted < 1 or connected < 1 or failed != 0 or c2s < 1 or s2c < 1
                for accepted, connected, failed, c2s, s2c in routes.values()):
            raise ValueError("four-route oracle failed: %r" % routes)
    return control


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
    ap.add_argument("--legacy-profile", choices=("v1", "v2", "v2-refusal"))
    ap.add_argument("--replay-probe", type=Path)
    args = ap.parse_args()
    if args.legacy_profile:
        if args.executions != 1 or args.procs != 1:
            ap.error("legacy replay profiles require --executions 1 --procs 1")
        if args.replay_probe is None or not args.replay_probe.is_file():
            ap.error("legacy replay profiles require an existing --replay-probe")
    args.output.mkdir(parents=True)
    (args.output / "commands").mkdir()
    phase1 = load_phase1()
    evidence = {"commands": []}
    vm = phase1.FrozenPhase1VM(args, evidence)
    if args.cmdline_extra:
        i = vm.qemu.index("-append") + 1
        vm.qemu[i] += " " + args.cmdline_extra
    result = {"workload": str(args.workload), "procs": args.procs,
              "executions": args.executions,
              "legacy_profile": args.legacy_profile,
              "input_sha256": {
                  "workload": sha256(args.workload),
                  "deps": sha256(args.deps),
              }}
    if args.replay_probe:
        result["input_sha256"]["replay_probe"] = sha256(args.replay_probe)
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
        if args.replay_probe:
            vm.put("replay-probe", args.replay_probe, "/tmp/replay-probe")
        install = ("set -eu; install -d /opt/kcov-nfs/deps %s; "
                   "tar -xzf /tmp/deps.tar.gz -C /opt/kcov-nfs/deps; "
                   "install -m 0755 /tmp/lane.sh %s/lane.sh; "
                   "install -m 0644 /tmp/w.prog %s/w.prog; "
                   "install -m 0755 /tmp/syz-executor %s/syz-executor; "
                   "install -m 0755 /tmp/syz-execprog %s/syz-execprog" %
                   ((DRV,) * 5))
        if args.replay_probe:
            install += "; install -m 0755 /tmp/replay-probe %s/replay-probe" % DRV
        vm.guest("install", install, timeout=120)
        relay_sha256 = tar_member_sha256(args.deps, "/usr/sbin/nfs-proxy")
        inventory_command = (
            "uname -m; uname -r; "
            "sha256sum /opt/kcov-nfs/deps/usr/sbin/nfs-proxy")
        if args.replay_probe:
            inventory_command += " %s/replay-probe" % DRV
        inventory = vm.guest("guest-inventory", inventory_command).stdout.strip()
        inventory_lines = inventory.splitlines()
        result["guest_inventory"] = inventory_lines
        identity_mismatch = (len(inventory_lines) < 3 or
                             inventory_lines[0] != "x86_64" or
                             not inventory_lines[1] or
                             relay_sha256 not in inventory)
        if args.replay_probe:
            identity_mismatch = (identity_mismatch or
                                 sha256(args.replay_probe) not in inventory)
        if identity_mismatch:
            raise ValueError("guest architecture/kernel/binary identity mismatch: %r" %
                             inventory)
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
        if result["execprog_rc"] != "rc=0":
            capture_dmesg(vm, args.output, result)
            write_result(args.output, result)
            raise ValueError("syz-execprog failed: %s" % result["execprog_rc"])
        calls = re.findall(r"CALL (\d+): signal \d+, coverage \d+ errno (\d+)", log)
        result["calls"] = len(calls)
        result["calls_errno_nonzero"] = sum(1 for _, e in calls if e != "0")
        result["errno_by_call"] = sorted({(int(c), int(e)) for c, e in calls if e != "0"})
        vm.guest("drain", "sleep 10", timeout=30)
        result["stats_after"] = vm.guest("stats-after", stats).stdout
        result["lane_states"] = {}
        for lane in range(args.procs):
            result["lane_states"][str(lane)] = vm.guest(
                "lane-state-%d" % lane,
                "ip netns exec f9l%ds nsenter -t 1 -m -- " % lane +
                "cat /sys/kernel/debug/sunrpc_fuzz/lane_state",
                check=False).stdout
        result["proxy_lanes"] = {}
        for lane in range(args.procs):
            lane_root = "%s/lane%d" % (root, lane)
            pid = vm.guest("proxy-pid-%d" % lane,
                           "cat %s/server/proxy.pid" % lane_root,
                           check=False).stdout.strip()
            if pid:
                vm.guest("proxy-snapshot-%d" % lane, "kill -USR1 %s" % pid,
                         check=False)
        vm.guest("proxy-snapshot-drain", "sleep 1", timeout=10)
        for lane in range(args.procs):
            lane_root = "%s/lane%d" % (root, lane)
            proxy_log = vm.guest("proxy-log-%d" % lane,
                                 "cat %s/server/proxy.log" % lane_root,
                                 check=False).stdout
            (args.output / ("proxy-lane%d.log" % lane)).write_text(proxy_log)
            stats_lines = re.findall(r"^peak_active=.*$", proxy_log, re.MULTILINE)
            control_lines = re.findall(r"^control .*$", proxy_log, re.MULTILINE)
            result["proxy_lanes"][str(lane)] = {
                "stats": stats_lines[-1] if stats_lines else "",
                "control": control_lines[-1] if control_lines else "",
            }
        if args.legacy_profile:
            lane0 = result["proxy_lanes"]["0"]
            result["legacy_control"] = validate_legacy_live(
                args.legacy_profile, (args.output / "proxy-lane0.log").read_text(),
                lane0["control"])
            deltas = collect_deltas(vm, root, args.output)
            result["deltas"], result["replay"] = exercise_legacy_replay(
                vm, args, deltas)
        vm.guest("tar", "tar -C /tmp/cov -czf /tmp/cov.tgz .", timeout=120)
        subprocess.run([*vm.scp, "root@127.0.0.1:/tmp/cov.tgz",
                        str(args.output / "cov.tgz")], check=True)
        vm.guest("cleanup", shlex.join([DRV + "/lane.sh", "cleanup", root]),
                 timeout=300, check=False)
        capture_dmesg(vm, args.output, result)
        if result["dmesg_fatal"]:
            write_result(args.output, result)
            raise ValueError("fatal guest diagnostics: %r" % result["dmesg_fatal"])
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
    write_result(args.output, result)
    print(json.dumps({k: v for k, v in result.items()
                      if not k.startswith("stats_") and k != "fixture"}, indent=1))


if __name__ == "__main__":
    main()
