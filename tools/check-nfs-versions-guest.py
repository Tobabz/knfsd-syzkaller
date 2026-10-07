#!/usr/bin/env python3
"""Boot a single-version or broad NFS fixture and check mounts and cleanup."""
import argparse
import importlib.util
import json
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "bootstrap", repo / "tools" / "bootstrap-kcov-env.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--version", choices=("3", "4.0", "4.1", "4.2"))
    selection.add_argument("--broad-knfsd", action="store_true")
    parser.add_argument("--image", type=Path,
                        default=repo / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--kernel", type=Path,
                        default=repo / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path,
                        default=repo / "artifacts/bookworm.id_rsa")
    args = parser.parse_args()
    vm = bootstrap.VM(args.image.resolve(), args.kernel.resolve(),
                      args.ssh_key.resolve(), 240, args.version,
                      "broad-knfsd" if args.broad_knfsd else None)
    root = "/tmp/frozen-phase9.manager"
    try:
        vm.start()
        state = vm.guest("systemctl is-active frozen-phase9-fixture.service || true").strip()
        if state != "active":
            journal = vm.guest(
                "journalctl -u frozen-phase9-fixture.service -b --no-pager -n 160 || true")
            raise RuntimeError("fixture service %s:\n%s" % (state, journal[-14000:]))
        status = vm.guest("/run/frozen-phase9/lane.sh status " + root)
        fixture = json.loads(status)
        expected_version = "4.1" if args.broad_knfsd else args.version
        expected_mode = "broad-knfsd" if args.broad_knfsd else "single"
        if (fixture["nfs_version"] != expected_version or
                fixture["fixture_mode"] != expected_mode or
                fixture["lane_count"] != 4):
            raise RuntimeError("wrong lane status: " + status)
        if args.broad_knfsd:
            expected_profiles = [
                "knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42"]
            if fixture["profiles"] != expected_profiles:
                raise RuntimeError("wrong broad profiles: " + status)
            result = vm.guest("""
set -eu
base=/syz-nfs-lanes/proc-0
test ! -e "$base/client0-ganesha-v41"
for suffix in v3 v40 v41 v42; do
    left="$base/client0-knfsd-$suffix"
    right="$base/client1-knfsd-$suffix"
    test -f "$left/shared/fixture"
    test -f "$right/shared/fixture"
    marker=".broad-$suffix"
    printf 'broad %s\\n' "$suffix" > "$left/shared/$marker"
    grep -Fx "broad $suffix" "$right/shared/$marker"
    rm -f "$left/shared/$marker"
done
printf 'broad_mounts=pass cross_client=pass ganesha_excluded=pass\\n'
""", timeout=180)
            if "broad_mounts=pass cross_client=pass ganesha_excluded=pass" not in result:
                raise RuntimeError("broad oracle missing: " + result)
            print("broad-knfsd: " + result.strip().splitlines()[-1], flush=True)
        else:
            vm.put(repo / "tools/nfs-proxy/test/guest-four-mounts.sh",
                   "/tmp/guest-four-mounts.sh")
            result = vm.guest("NFS_VERSION=%s sh /tmp/guest-four-mounts.sh %s"
                              % (args.version, root), timeout=120)
            if "four_mounts=pass backend_isolation=pass" not in result:
                raise RuntimeError("four-mount oracle missing: " + result)
            print("NFS %s: %s" %
                  (args.version, result.strip().splitlines()[-1]), flush=True)
        vm.guest("systemctl stop frozen-phase9-fixture.service", timeout=180)
        vm.guest("test ! -e %s && test ! -e /syz-nfs-lanes" % root)
        if vm.guest("losetup -a").strip():
            raise RuntimeError("loop device leaked")
        print("cleanup=pass", flush=True)
    finally:
        vm.stop()


if __name__ == "__main__":
    main()
