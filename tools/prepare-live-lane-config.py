#!/usr/bin/env python3
"""Freeze the current lane script and add its read-only 9P share to a manager config."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

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
# boot-fixture.sh always sets up this many lanes.
LANES = 4
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


def chardev_reconnect(parser, args, vm):
    """The chardev reconnect option of the QEMU that will run the VM.

    QEMU 9.2 added reconnect-ms=MS and deprecated reconnect=SECONDS, which
    older QEMU (e.g. 6.2) only knows.
    """
    version = args.qemu_version
    if version is None:
        binary = vm.get("qemu") or "qemu-system-x86_64"
        try:
            out = subprocess.run([binary, "--version"], capture_output=True,
                                 text=True, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        found = re.search(r"version (\d+)\.(\d+)", out)
        if not found:
            parser.error("cannot tell the QEMU version of %s; pass --qemu-version"
                         % binary)
        version = "%s.%s" % found.groups()
    parsed = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", version)
    if not parsed:
        parser.error("--qemu-version must look like 9.2")
    if (int(parsed.group(1)), int(parsed.group(2))) >= (9, 2):
        return "reconnect-ms=1000"
    return "reconnect=1"


def target_inputs(parser, args):
    """Per-lane target-mode inputs as (name, bytes), or [] without --nfs-target."""
    if args.nfs_target is None:
        if args.journal_socket_dir is not None:
            parser.error("--journal-socket-dir needs --nfs-target")
        if args.qemu_version is not None:
            parser.error("--qemu-version needs --nfs-target")
        return []
    if args.journal_socket_dir is None:
        parser.error("--nfs-target needs --journal-socket-dir")
    socket_dir = str(args.journal_socket_dir.resolve())
    if any(char.isspace() for char in socket_dir) or "," in socket_dir:
        parser.error("journal socket path cannot contain whitespace or commas")
    files = []
    for lane in range(LANES):
        for name in ("lane%d.nfsprul1" % lane, "lane%d.session" % lane):
            path = args.nfs_target / name
            if not path.is_file():
                parser.error("missing target input: %s" % path)
            files.append((name, path.read_bytes()))
        session = files[-1][1].decode("ascii", "replace").strip()
        if not session or any(not (char.isalnum() or char in "_.:/-") for char in session):
            parser.error("lane%d.session is not a proxy session id" % lane)
    return files


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
                           help="knfsd v3/v4.0/v4.1/v4.2 campaign fixture")
    parser.add_argument("--image", type=Path,
                        default=REPO / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--lane-script", type=Path,
                        default=REPO / "bundle/lane/lane.sh")
    parser.add_argument(
        "--nfs-target", type=Path, metavar="DIR",
        help=("proxy target mode: DIR holds laneN.nfsprul1 (rule set) and "
              "laneN.session (proxy session id) for every lane; the executor "
              "then brackets each program with the activation barrier"))
    parser.add_argument(
        "--journal-socket-dir", type=Path, metavar="DIR",
        help=("with --nfs-target: host directory of the journal sinks' "
              "sockets, laneN.sock (python -m agent_pipeline.journal_sink "
              "--socket DIR/laneN.sock --channel nfsp-journal-N)"))
    parser.add_argument(
        "--qemu-version", metavar="X.Y",
        help=("with --nfs-target: the QEMU version that runs the VM, which "
              "picks the journal ports' reconnect option; by default it is "
              "read from vm.qemu (or qemu-system-x86_64) --version"))
    parser.add_argument(
        "--state-dir", type=Path,
        help=("persistent campaign state directory; sets config.workdir to "
              "<state-dir>/workdir and stores the frozen lane template there"))
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
    target_files = target_inputs(parser, args)
    template_id = hashlib.sha256(source)
    for name, data in target_files:
        template_id.update(b"\0%s\0%d\0" % (name.encode(), len(data)) + data)
    state_dir = args.state_dir.resolve() if args.state_dir else None
    snapshot_parent = state_dir or args.output.resolve().parent
    snapshot = snapshot_parent / ("lane-template-" + template_id.hexdigest()[:16])
    if any(char.isspace() for char in str(snapshot)) or "," in str(snapshot):
        parser.error("snapshot path cannot contain whitespace or commas")
    config = json.loads(args.config.read_text())
    vm = config.get("vm")
    if config.get("type") != "qemu" or not isinstance(vm, dict):
        parser.error("expected a qemu syz-manager config")
    if config.get("workdir_template") or vm.get("qemu_args"):
        parser.error("config already has a VM template or custom qemu_args")
    if target_files and vm.get("count", 1) != 1:
        # Every VM would attach its journal ports to the same host sinks.
        parser.error("--nfs-target needs vm.count 1")
    cmdline = vm.get("cmdline", "")
    if "nfs.localio_enabled=N" not in cmdline.split():
        parser.error("vm.cmdline must contain nfs.localio_enabled=N")
    if any(part.startswith("koov.") for part in cmdline.split()):
        parser.error("vm.cmdline already has koov arguments")

    profiles = BROAD_PROFILES if args.broad_knfsd else (profile,)
    allow_raw = args.broad_knfsd or profile == "knfsd-v3"
    select_profile_calls(parser, config, profiles, allow_raw)

    if state_dir:
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            parser.error("cannot create state directory %s: %s" %
                         (state_dir, error))
        config["workdir"] = str(state_dir / "workdir")
    snapshot.mkdir(parents=True, exist_ok=True)
    lane_copy = snapshot / "lane.sh"
    if lane_copy.exists():
        if lane_copy.read_bytes() != source:
            parser.error("existing lane snapshot does not match its hash")
    else:
        lane_copy.write_bytes(source)
        lane_copy.chmod(0o444)
    if target_files:
        target_dir = snapshot / "target"
        target_dir.mkdir(exist_ok=True)
        for name, data in target_files:
            copy = target_dir / name
            if copy.exists():
                if copy.read_bytes() != data:
                    parser.error("existing target snapshot does not match its hash")
            else:
                copy.write_bytes(data)
                copy.chmod(0o444)
    config["workdir_template"] = str(snapshot)
    config["image"] = str(args.image.resolve())
    # vm.snapshot is QEMU's -snapshot disk overlay (default true); program
    # snapshot mode is the top-level "snapshot" setting.  The qemu backend adds
    # -snapshot itself when vm.snapshot is true; add it here otherwise so the
    # shared base image never takes guest writes (and syz-manager's
    # image-integrity guard holds).
    disk_snapshot = "" if vm.get("snapshot") else " -snapshot"
    vm["qemu_args"] = (
        "-enable-kvm -cpu host,migratable=off" + disk_snapshot + " "
        "-fsdev local,id=koov_lane,path={{TEMPLATE}},security_model=none,readonly=on "
        "-device virtio-9p-pci,fsdev=koov_lane,mount_tag=koov-lane"
    )
    fixture_arg = ("koov.nfs_fixture=broad-knfsd" if args.broad_knfsd else
                   "koov.nfs_version=%s" % version)
    if target_files:
        # One virtio-serial journal port per lane (/dev/virtio-ports/
        # nfsp-journal-N in the guest), each a client of its host sink.
        # Start the sinks before the VM.
        reconnect = chardev_reconnect(parser, args, vm)
        sockets = args.journal_socket_dir.resolve()
        vm["qemu_args"] += " -device virtio-serial-pci,id=nfspser"
        for lane in range(LANES):
            vm["qemu_args"] += (
                " -chardev socket,id=nfspj%d,path=%s,%s"
                " -device virtserialport,bus=nfspser.0,chardev=nfspj%d,"
                "name=nfsp-journal-%d" % (lane, sockets / ("lane%d.sock" % lane),
                                          reconnect, lane, lane))
        fixture_arg += " koov.nfs_target=1"
    vm["cmdline"] = (cmdline + " %s koov.lane_sha256=%s"
                     % (fixture_arg, digest)).strip()
    args.output.write_text(json.dumps(config, indent=2) + "\n")
    print("config=%s workdir=%s lane_sha256=%s" %
          (args.output, config["workdir"], digest))


if __name__ == "__main__":
    main()
