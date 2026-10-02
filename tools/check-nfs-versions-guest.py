#!/usr/bin/env python3
"""Boot one NFS version and check both clients, both backends, and cleanup."""
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
    parser.add_argument("--version", choices=("3", "4.0", "4.1", "4.2"), required=True)
    parser.add_argument("--image", type=Path,
                        default=repo / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--kernel", type=Path,
                        default=repo / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path,
                        default=repo / "artifacts/bookworm.id_rsa")
    args = parser.parse_args()
    vm = bootstrap.VM(args.image.resolve(), args.kernel.resolve(),
                      args.ssh_key.resolve(), 240, args.version)
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
        if fixture["nfs_version"] != args.version or fixture["lane_count"] != 4:
            raise RuntimeError("wrong lane status: " + status)
        vm.put(repo / "tools/nfs-proxy/test/guest-four-mounts.sh",
               "/tmp/guest-four-mounts.sh")
        result = vm.guest("NFS_VERSION=%s sh /tmp/guest-four-mounts.sh %s"
                          % (args.version, root), timeout=120)
        if "four_mounts=pass backend_isolation=pass" not in result:
            raise RuntimeError("four-mount oracle missing: " + result)
        print("NFS %s: %s" % (args.version, result.strip().splitlines()[-1]), flush=True)
        vm.guest("systemctl stop frozen-phase9-fixture.service", timeout=180)
        vm.guest("test ! -e %s && test ! -e /syz-nfs-lanes" % root)
        if vm.guest("losetup -a").strip():
            raise RuntimeError("loop device leaked")
        print("cleanup=pass", flush=True)
    finally:
        vm.stop()


if __name__ == "__main__":
    main()
