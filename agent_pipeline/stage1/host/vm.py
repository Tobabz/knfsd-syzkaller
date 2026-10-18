"""One disposable KVM guest booted from the pinned kernel and image.

Same boot as ``tools/bootstrap-kcov-env.py`` (``-snapshot`` disk overlay,
the lane script over 9p, SSH on a loopback port), but the kernel command
line is the approved descriptor's, and the serial console is kept as a
file so a crash leaves evidence.
"""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class GuestError(RuntimeError):
    pass


class Guest(Protocol):
    def start(self) -> None: ...
    def run(self, command: str, *, timeout: float = 60) -> tuple[int, str]: ...
    def put(self, source: Path, destination: str) -> None: ...
    def get(self, source: str, destination: Path) -> None: ...
    def stop(self) -> None: ...


@dataclass(frozen=True)
class VmConfig:
    qemu: str
    bzimage: Path
    image: Path
    lane_dir: Path
    ssh_key: Path
    cmdline: str
    console_log: Path
    memory_mb: int = 4096
    cpus: int = 4
    boot_timeout_s: float = 300
    #: Trusted host-only QEMU arguments, used by Stage 2 journal channels.
    extra_args: tuple[str, ...] = ()


class QemuGuest:
    def __init__(self, config: VmConfig) -> None:
        self.config = config
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        common = ["-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
                  "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                  "-o", "ConnectTimeout=5", "-i", str(config.ssh_key)]
        self.ssh = ["ssh", *common, "-p", str(self.port), "root@127.0.0.1"]
        self.scp = ["scp", "-O", *common, "-P", str(self.port)]
        self.process: subprocess.Popen | None = None

    def qemu_argv(self) -> list[str]:
        c = self.config
        return [
            c.qemu, "-enable-kvm", "-cpu", "host",
            "-m", str(c.memory_mb), "-smp", str(c.cpus), "-display", "none",
            "-serial", f"file:{c.console_log}", "-no-reboot", "-snapshot",
            "-fsdev", f"local,id=koov_lane,path={c.lane_dir},"
                      "security_model=none,readonly=on",
            "-device", "virtio-9p-pci,fsdev=koov_lane,mount_tag=koov-lane",
            "-drive", f"file={c.image},format=qcow2,if=ide",
            "-kernel", str(c.bzimage), "-append", c.cmdline,
            "-device", "e1000,netdev=net0",
            "-netdev", "user,id=net0,restrict=on,"
                       f"hostfwd=tcp:127.0.0.1:{self.port}-:22",
            *c.extra_args]

    def start(self) -> None:
        self.process = subprocess.Popen(
            self.qemu_argv(), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + self.config.boot_timeout_s
        last = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise GuestError("QEMU exited before SSH became ready")
            try:
                r = subprocess.run([*self.ssh, "true"], capture_output=True,
                                   text=True, timeout=10)
            except subprocess.TimeoutExpired:
                continue
            if r.returncode == 0:
                return
            last = r.stderr.strip()
            if "Permission denied" in last:
                raise GuestError(f"guest SSH rejected the key: {last}")
            time.sleep(3)
        raise GuestError(f"timed out waiting for guest SSH: {last or 'none'}")

    def run(self, command: str, *, timeout: float = 60) -> tuple[int, str]:
        r = subprocess.run([*self.ssh, command], capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr

    def put(self, source: Path, destination: str) -> None:
        subprocess.run([*self.scp, str(source),
                        "root@127.0.0.1:" + destination],
                       capture_output=True, timeout=300, check=True)

    def get(self, source: str, destination: Path) -> None:
        subprocess.run([*self.scp, "root@127.0.0.1:" + source,
                        str(destination)],
                       capture_output=True, timeout=300, check=True)

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
