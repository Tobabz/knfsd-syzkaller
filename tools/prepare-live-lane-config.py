#!/usr/bin/env python3
"""Freeze the current lane script and add its read-only 9P share to a manager config."""
import argparse
import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PROFILE_VERSIONS = {
    "knfsd-v3": "3",
    "knfsd-v40": "4.0",
    "knfsd-v41": "4.1",
    "knfsd-v42": "4.2",
    "ganesha-v41": "4.1",
}
PROFILE_VARIANTS = {
    profile: [
        "syz_open_nfs_lane_profile$client%d_%s" %
        (client, profile.replace("-", "_"))
        for client in (0, 1)
    ]
    for profile in PROFILE_VERSIONS
}
BROAD_PROFILES = ("knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42")
PROFILE_CALL = "syz_open_nfs_lane_profile"
RAW_CALL_PREFIXES = (
    "syz_socket_connect_nfs",
    "syz_socket_connect_nfs_pair",
    "syz_send_nfs_fuzz",
    "sendmsg$inet_nfs_fuzz",
    "recvfrom$inet_nfs_fuzz",
)


def select_profile_calls(parser, config, profiles, allow_raw):
    enabled = config.get("enable_syscalls")
    if not isinstance(enabled, list):
        parser.error("config.enable_syscalls must be a list")
    profile_entries = [
        entry for entry in enabled
        if isinstance(entry, str) and
        (entry == PROFILE_CALL or entry.startswith(PROFILE_CALL + "$"))
    ]
    if not profile_entries:
        parser.error("enable_syscalls does not contain %s" % PROFILE_CALL)
    selected = [variant for profile in profiles for variant in PROFILE_VARIANTS[profile]]
    insertion = min(enabled.index(entry) for entry in profile_entries)
    enabled = [entry for entry in enabled if entry not in profile_entries]
    enabled[insertion:insertion] = selected
    filtered = []
    for entry in enabled:
        is_raw = any(entry == prefix or entry.startswith(prefix + "$")
                     for prefix in RAW_CALL_PREFIXES)
        if is_raw and not allow_raw:
            continue
        if (entry == "syz_socket_connect_nfs_pair" or
                (entry.startswith("syz_socket_connect_nfs_pair$") and
                 not entry.endswith("_knfsd"))):
            continue
        filtered.append(entry)
    enabled = filtered
    config["enable_syscalls"] = enabled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="existing syz-manager JSON config")
    parser.add_argument("output", type=Path, help="new config path")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--profile", choices=tuple(PROFILE_VERSIONS),
                           help="stable native backend/version profile")
    selection.add_argument("--version", choices=("3", "4.0", "4.1", "4.2"),
                           help="legacy knfsd-only profile alias")
    selection.add_argument("--minor", choices=("1", "2"),
                           help="legacy alias for --version 4.1 or 4.2")
    selection.add_argument("--broad-knfsd", action="store_true",
                           help="experimental knfsd v3/v4.0/v4.1/v4.2 fixture")
    parser.add_argument("--image", type=Path,
                        default=REPO / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--lane-script", type=Path,
                        default=REPO / "bundle/lane/lane.sh")
    args = parser.parse_args()
    profile = args.profile
    if args.version or args.minor:
        version_alias = args.version or "4." + args.minor
        profile = {
            "3": "knfsd-v3", "4.0": "knfsd-v40",
            "4.1": "knfsd-v41", "4.2": "knfsd-v42",
        }[version_alias]
    version = None if args.broad_knfsd else PROFILE_VERSIONS[profile]
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

    profiles = BROAD_PROFILES if args.broad_knfsd else (profile,)
    allow_raw = args.broad_knfsd or profile == "knfsd-v3"
    select_profile_calls(parser, config, profiles, allow_raw)

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
    # vm.snapshot controls syzkaller's executor snapshot mode.  Parallel lane
    # campaigns keep that false, but QEMU must still protect the shared base
    # image from guest writes (and syz-manager's image-integrity guard).
    disk_snapshot = "" if vm.get("snapshot") else " -snapshot"
    vm["qemu_args"] = (
        "-enable-kvm -cpu host,migratable=off" + disk_snapshot + " "
        "-fsdev local,id=koov_lane,path={{TEMPLATE}},security_model=none,readonly=on "
        "-device virtio-9p-pci,fsdev=koov_lane,mount_tag=koov-lane"
    )
    fixture_arg = ("koov.nfs_fixture=broad-knfsd" if args.broad_knfsd else
                   "koov.nfs_version=%s" % version)
    vm["cmdline"] = (cmdline + " %s koov.lane_sha256=%s"
                     % (fixture_arg, digest)).strip()
    args.output.write_text(json.dumps(config, indent=2) + "\n")
    print("config=%s lane_sha256=%s" % (args.output, digest))


if __name__ == "__main__":
    main()
