#!/usr/bin/env python3
"""Bake a manager-ready NFS protocol image from a clean base image.

Reproduces the (previously manual) protocol-image build: raw base ->
standalone qcow2 -> boot RW -> install deps + frozen phase9 fixture ->
enable fixture service -> clean poweroff -> verification boot with
service-active + lane-status gates.

Only stdlib is used; repository and syzkaller locations follow
REPO_ROOT/SYZ_TREE when set so the same script ports to other hosts.

Example:
  scripts/bake_nfs_protocol_image.py --base-image /path/bookworm.img \\
      --output /path/bookworm-nfs-protocol-v42.qcow2 --minor 2 \\
      --kernel artifacts/.../bzImage --ssh-key /path/bookworm.id_rsa \\
      --deps-tar artifacts/.../guest-deps.tar.gz
"""
import argparse
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parent.parent))

# An SSH key/auth rejection never heals by waiting for the guest.
SSH_AUTH_MARKERS = ("Permission denied", "Load key",
                    "Too many authentication failures")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class VM:
    def __init__(self, args):
        self.args = args
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.ssh_port = reservation.getsockname()[1]
        common = ["-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
                  "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                  "-o", "ConnectTimeout=5", "-i", str(args.ssh_key)]
        self.ssh = ["ssh", *common, "-p", str(self.ssh_port),
                    "root@127.0.0.1"]
        self.scp = ["scp", "-O", *common, "-P", str(self.ssh_port)]
        self.process = None
        self.boots = 0
        self.log_files = []
        self.qemu_log = None
        self.serial_log = None
        self.last_ssh_error = ""

    def diagnostics(self):
        parts = []
        if self.last_ssh_error:
            parts.append("last ssh error: %s" % self.last_ssh_error)
        if self.serial_log is not None:
            try:
                tail = self.serial_log.read_text(errors="replace").splitlines()[-20:]
                parts.append("serial log tail (%s):\n%s"
                             % (self.serial_log, "\n".join(tail)))
            except OSError:
                pass
        return "\n".join(parts)

    def start(self, snapshot):
        self.boots += 1
        prefix = "%s.boot%d" % (self.args.output.name, self.boots)
        self.serial_log = self.args.output.with_name(prefix + ".serial.log")
        qemu_log_path = self.args.output.with_name(prefix + ".qemu.log")
        self.qemu_log = qemu_log_path.open("wb")
        self.log_files += [self.serial_log, qemu_log_path]
        self.last_ssh_error = ""
        drive = "file=%s,format=qcow2,if=ide" % self.args.output
        cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host",
               "-m", str(self.args.memory), "-smp", str(self.args.cpus),
               "-display", "none", "-serial", "file:%s" % self.serial_log,
               "-no-reboot"]
        if snapshot:
            cmd.append("-snapshot")
        cmd += ["-drive", drive, "-kernel", str(self.args.kernel),
                "-append", "root=/dev/sda console=ttyS0 nokaslr "
                "nfs.localio_enabled=N",
                "-device", "e1000,netdev=net0",
                "-netdev", "user,id=net0,restrict=on,"
                "hostfwd=tcp:127.0.0.1:%d-:22" % self.ssh_port]
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=self.qemu_log,
            stderr=subprocess.STDOUT)
        deadline = time.monotonic() + self.args.boot_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("QEMU exited before SSH became ready\n%s"
                                   % self.diagnostics())
            result = subprocess.run([*self.ssh, "true"], capture_output=True,
                                    text=True, timeout=8)
            if result.returncode == 0:
                return
            self.last_ssh_error = result.stderr.strip()
            if any(m in self.last_ssh_error for m in SSH_AUTH_MARKERS):
                raise RuntimeError("guest SSH rejected the key (not a boot "
                                   "problem)\n%s" % self.diagnostics())
            time.sleep(3)
        raise RuntimeError("timed out waiting for guest SSH\n%s"
                           % self.diagnostics())

    def guest(self, command, timeout=60):
        result = subprocess.run([*self.ssh, command], capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("guest command failed rc=%d: %s\n%s" % (
                result.returncode, command, result.stderr[-2000:]))
        return result.stdout

    def put(self, source, destination):
        result = subprocess.run(
            [*self.scp, str(source), "root@127.0.0.1:" + destination],
            capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError("scp %s failed: %s" % (source,
                                                     result.stderr[-1000:]))

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        if self.qemu_log is not None:
            self.qemu_log.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-image", type=Path, required=True,
                        help="clean raw base image (never opened RW)")
    parser.add_argument("--output", type=Path, required=True,
                        help="new standalone .qcow2 image (must not exist)")
    parser.add_argument("--minor", choices=("1", "2"), required=True,
                        help="NFS minor version for the baked fixture")
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--lane-script", type=Path,
                        default=REPO / "scripts" / "frozen_phase9_lane.sh")
    parser.add_argument("--boot-fixture", type=Path,
                        default=REPO / "scripts" / "frozen_phase9_boot_fixture.sh")
    parser.add_argument("--service", type=Path,
                        default=REPO / "scripts" / "frozen-phase9-fixture.service")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args(argv)
    for field in ("base_image", "kernel", "ssh_key", "deps_tar",
                  "lane_script", "boot_fixture", "service"):
        path = getattr(args, field).resolve()
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing input --%s: %s" % (field.replace("_", "-"),
                                                    path))
        setattr(args, field, path)
    args.output = args.output.absolute()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path; refusing to overwrite")
    if args.output.suffix != ".qcow2":
        parser.error("--output must end in .qcow2")
    return args


def main(argv=None):
    args = parse_args(argv)
    base_sha = sha256(args.base_image)
    print("base %s sha256=%s" % (args.base_image, base_sha), flush=True)
    print("converting to %s" % args.output, flush=True)
    subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                    str(args.base_image), str(args.output)], check=True,
                   timeout=600)
    vm = VM(args)
    try:
        print("install boot (RW)", flush=True)
        vm.start(snapshot=False)
        vm.put(args.deps_tar, "/tmp/bake-deps.tar.gz")
        vm.put(args.lane_script, "/tmp/bake-lane.sh")
        vm.put(args.boot_fixture, "/tmp/bake-boot-fixture.sh")
        vm.put(args.service, "/tmp/bake-fixture.service")
        vm.guest(
            "set -eu; "
            "test ! -e /opt/frozen-phase9; test ! -e /opt/kcov-nfs; "
            "install -d /opt/kcov-nfs/deps /opt/frozen-phase9; "
            "tar -xzf /tmp/bake-deps.tar.gz -C /opt/kcov-nfs/deps; "
            "install -m 0755 /tmp/bake-lane.sh /opt/frozen-phase9/lane.sh; "
            "install -m 0755 /tmp/bake-boot-fixture.sh /opt/frozen-phase9/boot-fixture.sh; "
            "install -m 0644 /tmp/bake-fixture.service /etc/systemd/system/frozen-phase9-fixture.service; "
            "install -d /etc/systemd/system/frozen-phase9-fixture.service.d; "
            "printf '[Service]\\nEnvironment=NFS_MINOR_VERSION=%s\\n' %s "
            "> /etc/systemd/system/frozen-phase9-fixture.service.d/nfs-v%s.conf; "
            "systemctl daemon-reload; "
            "systemctl enable frozen-phase9-fixture.service; "
            "systemctl is-enabled frozen-phase9-fixture.service; "
            "sync" % (args.minor, shlex.quote(args.minor), args.minor),
            timeout=180)
        vm.guest("systemctl poweroff", timeout=10)
        try:
            vm.process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            raise RuntimeError("guest did not power off cleanly")
        if vm.process.returncode != 0:
            raise RuntimeError("guest shutdown rc=%d" % vm.process.returncode)
        vm.process = None

        print("verification boot (RW, service must go active)", flush=True)
        vm.start(snapshot=False)
        state = vm.guest(
            "systemctl is-active frozen-phase9-fixture.service",
            timeout=60).strip()
        if state != "active":
            raise RuntimeError("fixture service not active: %r" % state)
        status = vm.guest(
            "NFS_MINOR_VERSION=%s /opt/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager"
            % args.minor, timeout=90)
        fixture = json.loads(status)
        if int(fixture.get("lane_count", 0)) < 1:
            raise RuntimeError("no lanes reported: %s" % status[:300])
        print("lanes: %s" % fixture["lane_count"], flush=True)
        vm.guest("systemctl poweroff", timeout=10)
        try:
            vm.process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            raise RuntimeError("verification guest did not power off")
        vm.process = None
    finally:
        vm.stop()
    if sha256(args.base_image) != base_sha:
        raise RuntimeError("shared base image changed during bake")
    for log in vm.log_files:  # kept only when the bake fails
        log.unlink(missing_ok=True)
    manifest = {
        "output": str(args.output),
        "sha256": sha256(args.output),
        "bytes": args.output.stat().st_size,
        "base_image": str(args.base_image),
        "base_sha256": base_sha,
        "nfs_minor": args.minor,
        "lane_script_sha256": sha256(args.lane_script),
        "boot_fixture_sha256": sha256(args.boot_fixture),
        "service_sha256": sha256(args.service),
        "deps_tar_sha256": sha256(args.deps_tar),
    }
    manifest_path = args.output.with_suffix(".json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
