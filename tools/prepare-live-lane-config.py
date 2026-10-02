#!/usr/bin/env python3
"""Freeze the current lane script and add its read-only 9P share to a manager config."""
import argparse
import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="existing syz-manager JSON config")
    parser.add_argument("output", type=Path, help="new config path")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--version", choices=("3", "4.0", "4.1", "4.2"))
    selection.add_argument("--minor", choices=("1", "2"),
                           help="legacy alias for --version 4.1 or 4.2")
    parser.add_argument("--image", type=Path,
                        default=REPO / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--lane-script", type=Path,
                        default=REPO / "bundle/lane/lane.sh")
    args = parser.parse_args()
    version = args.version or "4." + args.minor
    if args.output.exists() or args.output.is_symlink():
        parser.error("output already exists")
    if not args.image.is_file():
        parser.error("missing reusable image: %s" % args.image)
    source = args.lane_script.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    snapshot = args.output.resolve().parent / ("lane-template-" + digest[:16])
    if any(char.isspace() for char in str(snapshot)) or "," in str(snapshot):
        parser.error("snapshot path cannot contain whitespace or commas")
    config = json.loads(args.config.read_text())
    vm = config.get("vm")
    if config.get("type") != "qemu" or not isinstance(vm, dict):
        parser.error("expected a qemu syz-manager config")
    if config.get("workdir_template") or vm.get("qemu_args"):
        parser.error("config already has a VM template or custom qemu_args")
    cmdline = vm.get("cmdline", "")
    if "nfs.localio_enabled=N" not in cmdline.split():
        parser.error("vm.cmdline must contain nfs.localio_enabled=N")
    if any(part.startswith("koov.") for part in cmdline.split()):
        parser.error("vm.cmdline already has koov arguments")

    snapshot.mkdir(parents=True, exist_ok=True)
    lane_copy = snapshot / "lane.sh"
    if lane_copy.exists():
        if lane_copy.read_bytes() != source:
            parser.error("existing lane snapshot does not match its hash")
    else:
        lane_copy.write_bytes(source)
        lane_copy.chmod(0o444)
    config["workdir_template"] = str(snapshot)
    config["image"] = str(args.image.resolve())
    vm["qemu_args"] = (
        "-enable-kvm -cpu host,migratable=off "
        "-fsdev local,id=koov_lane,path={{TEMPLATE}},security_model=none,readonly=on "
        "-device virtio-9p-pci,fsdev=koov_lane,mount_tag=koov-lane"
    )
    vm["cmdline"] = (cmdline + " koov.nfs_version=%s koov.lane_sha256=%s"
                     % (version, digest)).strip()
    args.output.write_text(json.dumps(config, indent=2) + "\n")
    print("config=%s lane_sha256=%s" % (args.output, digest))


if __name__ == "__main__":
    main()
