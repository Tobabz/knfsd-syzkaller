#!/usr/bin/env python3
"""Check V15.6 NFSv4.1/v4.2 reads through the relay and a direct mount."""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "bootstrap", repo / "tools" / "bootstrap-kcov-env.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def read_plus_count(mountstats, target):
    for block in mountstats.split("\ndevice "):
        if " mounted on %s " % target not in block:
            continue
        match = re.search(r"^\s*READ_PLUS:\s+(\d+)", block, re.MULTILINE)
        if match:
            return int(match.group(1))
    raise RuntimeError("READ_PLUS counter missing for %s" % target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, default=repo / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path, default=repo / "artifacts/bookworm.id_rsa")
    parser.add_argument("--minor", choices=(1, 2), type=int, default=2)
    parser.add_argument("--seed", type=Path,
                        help="optional syz-execprog seed to run before cleanup")
    args = parser.parse_args()
    vm = bootstrap.VM(args.image.resolve(), args.kernel.resolve(),
                      args.ssh_key.resolve(), 240)
    root = "/tmp/frozen-phase9.manager"
    ganesha_mount = root + "/lane0/client0/ganesha"
    try:
        vm.start()
        state = vm.guest("systemctl is-active frozen-phase9-fixture.service").strip()
        if state != "active":
            raise RuntimeError("fixture service is %s" % state)
        version = vm.guest(
            "LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:"
            "/opt/kcov-nfs/deps/lib/x86_64-linux-gnu "
            "/opt/kcov-nfs/deps/usr/sbin/ganesha.nfsd -v 2>&1")
        if "V15.6" not in version:
            raise RuntimeError("wrong Ganesha version: %s" % version)
        print(version.strip(), flush=True)

        vm.put(repo / "tools/nfs-proxy/test/guest-four-mounts.sh",
               "/tmp/guest-four-mounts.sh")
        print(vm.guest("NFS_MINOR_VERSION=%d sh /tmp/guest-four-mounts.sh %s" %
                       (args.minor, root),
                       timeout=120).strip(), flush=True)
        if args.minor == 2:
            stats = vm.guest("cat /proc/self/mountstats")
            count = read_plus_count(stats, ganesha_mount)
            if count < 1:
                raise RuntimeError("relay Ganesha mount did not issue READ_PLUS")
            print("relay READ_PLUS calls=%d" % count, flush=True)

        direct = "/tmp/ganesha-v15-direct"
        direct_check = (
            "set -eu; PATH=/opt/kcov-nfs/deps/usr/sbin:"
            "/opt/kcov-nfs/deps/sbin:$PATH; "
            "LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:"
            "/opt/kcov-nfs/deps/lib/x86_64-linux-gnu; "
            "export PATH LD_LIBRARY_PATH; mkdir -p {d}; "
            "nsenter --net=/run/netns/f9l0c0 -- mount.nfs4 "
            "-o vers=4.{minor},minorversion={minor},proto=tcp,port=20491,sec=sys,"
            "actimeo=0,lookupcache=none,nosharecache 10.89.0.5:/ {d}; "
            "trap 'umount {d}; rmdir {d}' EXIT; "
            "test -s {d}/shared/fixture; "
            "cmp {d}/shared/fixture {g}/shared/fixture; "
            "printf 'Ganesha V15.6 direct read\\n' > {d}/shared/v15-direct-check; "
            "test \"$(cat {g}/shared/v15-direct-check)\" = "
            "'Ganesha V15.6 direct read'; "
            "rm {g}/shared/v15-direct-check; "
            "test ! -e {d}/shared/v15-direct-check; "
            "grep -F ' {d} nfs4 ' /proc/mounts"
        ).format(d=direct, g=ganesha_mount, minor=args.minor)
        print(vm.guest(direct_check, timeout=120).strip(), flush=True)
        print("direct read/write and relay visibility: PASS", flush=True)
        if args.seed:
            syz_bin = repo / "env/syzkaller/bin/linux_amd64"
            vm.put(syz_bin / "syz-execprog", "/tmp/syz-execprog")
            vm.put(syz_bin / "syz-executor", "/tmp/syz-executor")
            vm.put(args.seed.resolve(), "/tmp/ganesha-seed.prog")
            vm.guest("chmod 755 /tmp/syz-execprog /tmp/syz-executor")
            output = vm.guest(
                "cd /tmp && ./syz-execprog -executor ./syz-executor "
                "-procs 1 -repeat 1 -threaded=false -cover -remote-cover "
                "-output -vv 2 "
                "ganesha-seed.prog 2>&1",
                timeout=300)
            calls = re.findall(
                r"CALL (\d+): signal (\d+), coverage (\d+) errno (\d+)",
                output)
            if [int(c[0]) for c in calls] != list(range(34)) or any(
                int(c[3]) != (11 if int(c[0]) == 14 else 0) for c in calls
            ) or max((int(c[2]) for c in calls), default=0) == 0:
                raise RuntimeError("seed oracle or coverage failed:\n" + output[-7000:])
            print("seed: 34 calls, expected errno, KCOV coverage: PASS", flush=True)
        vm.guest("systemctl stop frozen-phase9-fixture.service", timeout=180)
        vm.guest("test ! -e " + root + " && test ! -e /syz-nfs-lanes")
        loops = vm.guest("losetup -a")
        if loops.strip():
            raise RuntimeError("loop devices remain after cleanup: %s" % loops)
        print("lane cleanup and loop-device release: PASS", flush=True)
    finally:
        vm.stop()


if __name__ == "__main__":
    sys.exit(main())
