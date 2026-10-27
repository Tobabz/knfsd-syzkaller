"""QEMU accelerator for the pipeline's guests: KVM when the host has it,
TCG otherwise.

KVM is a speed choice, not a correctness one: every guest boots the pinned
kernel either way.  TCG emulates the CPU in software, so a host without
``/dev/kvm`` still runs the pipeline, only slower.  ``TCG_SLOWDOWN`` is the
factor the generator scales the boot, fixture and execution budgets by; it
is also the slowdown syz-manager applies when its QEMU arguments contain
``-accel tcg`` (``pkg/mgrconfig`` ``initTimeouts``).

Standard library only: ``tools/`` scripts import this module too.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

Accel = Literal["kvm", "tcg"]
AccelChoice = Literal["auto", "kvm", "tcg"]

KVM_DEVICE = Path("/dev/kvm")
KVM_GET_API_VERSION = 0xAE00
KVM_API_VERSION = 12
TCG_SLOWDOWN = 10
#: Overrides automatic selection for tools that have no config file.
ENV_OVERRIDE = "KOOV_QEMU_ACCEL"

_ARGS: dict[str, tuple[str, ...]] = {
    "kvm": ("-enable-kvm", "-cpu", "host"),
    # syz-manager raises its slowdown only when it sees "-accel tcg".
    "tcg": ("-accel", "tcg,thread=multi", "-cpu", "max"),
}


class AccelError(RuntimeError):
    pass


def check_kvm(
    path: Path = KVM_DEVICE, *,
    opener: Callable[[Path, int], int] = os.open,
    ioctl: Callable[[int, int], int] = fcntl.ioctl,
    closer: Callable[[int], None] = os.close,
) -> str:
    """Describe a usable KVM device, or raise ``AccelError``."""
    try:
        info = path.stat()
    except OSError as exc:
        raise AccelError(f"{path} is unavailable: {exc}") from exc
    if not stat.S_ISCHR(info.st_mode):
        raise AccelError(f"not a character device: {path}")
    try:
        fd = opener(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise AccelError(f"cannot open {path}: {exc}") from exc
    try:
        version = ioctl(fd, KVM_GET_API_VERSION)
    except OSError as exc:
        raise AccelError(f"{path} rejected KVM_GET_API_VERSION: {exc}") from exc
    finally:
        closer(fd)
    if version != KVM_API_VERSION:
        raise AccelError(
            f"{path} reported KVM API {version}, expected {KVM_API_VERSION}")
    return f"{path} opened successfully with KVM API {version}"


def kvm_usable(path: Path = KVM_DEVICE) -> bool:
    try:
        check_kvm(path)
    except AccelError:
        return False
    return True


def resolve(choice: str = "auto", *, kvm_path: Path = KVM_DEVICE,
            probe: Callable[[Path], bool] = kvm_usable) -> Accel:
    """``kvm`` or ``tcg``; ``auto`` picks KVM when the host can use it."""
    if choice == "auto":
        return "kvm" if probe(kvm_path) else "tcg"
    if choice not in _ARGS:
        raise AccelError(f"unknown QEMU accelerator: {choice!r}")
    return choice  # type: ignore[return-value]


def from_env(*, kvm_path: Path = KVM_DEVICE,
             probe: Callable[[Path], bool] = kvm_usable) -> Accel:
    """``resolve`` with the ``KOOV_QEMU_ACCEL`` override (default auto)."""
    return resolve(os.environ.get(ENV_OVERRIDE, "auto") or "auto",
                   kvm_path=kvm_path, probe=probe)


def qemu_args(accel: Accel) -> tuple[str, ...]:
    return _ARGS[accel]


def slowdown(accel: Accel) -> int:
    return TCG_SLOWDOWN if accel == "tcg" else 1


def accel_of(args: Sequence[str] | str) -> Accel | None:
    """The accelerator a QEMU argument list selects, None if neither."""
    tokens = args.split() if isinstance(args, str) else list(args)
    if "-enable-kvm" in tokens:
        return "kvm"
    for index, token in enumerate(tokens[:-1]):
        if token in ("-accel", "--accel"):
            name = tokens[index + 1].split(",", 1)[0]
            if name in _ARGS:
                return name  # type: ignore[return-value]
    return None
